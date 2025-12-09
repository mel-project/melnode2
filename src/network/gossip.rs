use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
    time::Duration,
};

use anyhow::ensure;
use bytes::Bytes;
use futures_util::{
    AsyncRead, AsyncWrite, TryFutureExt,
    io::{AsyncReadExt, AsyncWriteExt},
};
use rand::seq::IndexedRandom;
use serde::{Deserialize, Serialize};
use sillad::{Pipe, listener::Listener};
use smol::{
    Task,
    channel::{Receiver, Sender},
    future::FutureExt,
};

use crate::network::NetAddr;

const MAX_WIRE_MSG_SIZE: usize = 1024 * 1024;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GossipMsg {
    pub protocol: String,
    pub origin: u64,
    pub index: u64,
    pub inner: Bytes,
}

pub struct GossipNet {
    send_outgoing: Sender<GossipMsg>,
    _task: Task<()>,
}

#[derive(Clone, Default)]
struct MessageRecorder {
    messages: Arc<RwLock<BTreeMap<u64, BTreeMap<u64, GossipMsg>>>>,
}

impl MessageRecorder {
    fn record(&self, msg: GossipMsg) -> bool {
        let mut guard = self.messages.write().expect("recorder poisoned");
        let entry = guard.entry(msg.origin).or_default();
        if entry.contains_key(&msg.index) {
            return false;
        }
        entry.insert(msg.index, msg);
        true
    }

    fn after(&self, origin: u64, after_idx: u64) -> Vec<GossipMsg> {
        let guard = self.messages.read().expect("recorder poisoned");
        guard
            .get(&origin)
            .into_iter()
            .flat_map(|msgs| msgs.range(after_idx.saturating_add(1)..))
            .map(|(_, msg)| msg.clone())
            .collect()
    }

    fn latest_index(&self, origin: u64) -> Option<u64> {
        let guard = self.messages.read().expect("recorder poisoned");
        guard
            .get(&origin)
            .and_then(|msgs| msgs.keys().rev().next())
            .copied()
    }

    fn known_origins(&self) -> Vec<u64> {
        let guard = self.messages.read().expect("recorder poisoned");
        guard.keys().copied().collect()
    }
}

#[derive(Clone)]
struct IncomingPush {
    from: Option<NetAddr>,
    msg: GossipMsg,
}

impl GossipNet {
    pub fn new(protocol: String, listen: NetAddr, peers: Vec<NetAddr>) -> Self {
        let protocol = Arc::<str>::from(protocol);
        let (send_outgoing, recv_outgoing) = smol::channel::bounded(1);
        Self {
            send_outgoing,
            _task: smol::spawn(async move {
                let protocol = protocol.clone();
                loop {
                    if let Err(err) = gossip_net_loop(
                        protocol.clone(),
                        recv_outgoing.clone(),
                        listen.clone(),
                        peers.clone(),
                    )
                    .await
                    {
                        tracing::warn!(err = debug(err), "gossip inner loop failed");
                    }
                    smol::Timer::after(Duration::from_secs(1)).await;
                }
            }),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
enum GossipWireMsg {
    Push(Bytes),
    Pull { origin: u64, after_idx: u64 },
}

async fn gossip_net_loop(
    protocol: Arc<str>,
    recv_outgoing: Receiver<GossipMsg>,
    listen: NetAddr,
    peers: Vec<NetAddr>,
) -> anyhow::Result<()> {
    let recorder = MessageRecorder::default();
    let (send_incoming, recv_incoming) = smol::channel::unbounded();

    let send_to_peers = peers
        .iter()
        .map(|peer| {
            let (send_to_peer, recv_to_peer) = smol::channel::unbounded();
            smol::spawn(connect_loop(
                peer.clone(),
                recv_to_peer,
                send_to_peer.clone(),
                send_incoming.clone(),
                recorder.clone(),
            ))
            .detach();
            (peer.clone(), send_to_peer)
        })
        .collect::<BTreeMap<_, _>>();
    let listen_loop = listen_loop(listen.clone(), send_incoming.clone(), recorder.clone());

    let fanout = if send_to_peers.is_empty() {
        0
    } else {
        send_to_peers.len().ilog2().max(1) as usize
    };

    tracing::debug!(
        peer_count = peers.len(),
        fanout,
        listen = %listen,
        "starting gossip loop"
    );

    let forward_loop = forward_loop(
        protocol.clone(),
        recv_outgoing,
        &peers,
        &send_to_peers,
        fanout,
        recorder.clone(),
    );
    let backward_loop = backward_loop(&peers, &send_to_peers, fanout, recorder.clone());
    let incoming_loop = incoming_loop(
        recv_incoming,
        &peers,
        &send_to_peers,
        fanout,
        recorder.clone(),
        protocol.clone(),
    );

    forward_loop
        .race(backward_loop)
        .race(incoming_loop)
        .race(listen_loop)
        .await?;
    Ok(())
}

async fn forward_loop(
    protocol: Arc<str>,
    recv_outgoing: Receiver<GossipMsg>,
    peers: &[NetAddr],
    send_to_peers: &BTreeMap<NetAddr, Sender<GossipWireMsg>>,
    fanout: usize,
    recorder: MessageRecorder,
) -> anyhow::Result<()> {
    loop {
        let mut msg = recv_outgoing.recv().await?;
        if msg.protocol != *protocol {
            tracing::warn!(
                incoming_protocol = %msg.protocol,
                expected_protocol = %protocol,
                "overriding outgoing gossip protocol"
            );
            msg.protocol = protocol.to_string();
        }
        let is_new = recorder.record(msg.clone());
        tracing::debug!(
            protocol = %msg.protocol,
            origin = msg.origin,
            index = msg.index,
            is_new,
            "outgoing gossip message"
        );
        fan_out(&msg, peers, send_to_peers, fanout, "outgoing")?;
    }
}

async fn backward_loop(
    peers: &[NetAddr],
    send_to_peers: &BTreeMap<NetAddr, Sender<GossipWireMsg>>,
    fanout: usize,
    recorder: MessageRecorder,
) -> anyhow::Result<()> {
    loop {
        smol::Timer::after(Duration::from_secs(5)).await;

        if fanout == 0 || peers.is_empty() {
            continue;
        }

        let origins = (0..peers.len()).map(|idx| idx as u64);

        let selected_peers = peers
            .choose_multiple(&mut rand::rng(), fanout)
            .cloned()
            .collect::<Vec<_>>();

        for peer in &selected_peers {
            if let Some(sender) = send_to_peers.get(peer) {
                for origin in origins.clone() {
                    let after_idx = recorder.latest_index(origin).unwrap_or(0);
                    tracing::debug!(
                        peer = %peer,
                        origin,
                        after_idx,
                        "sending gossip pull"
                    );
                    let _ = sender.try_send(GossipWireMsg::Pull { origin, after_idx });
                }
            }
        }
    }
}

async fn incoming_loop(
    recv_incoming: Receiver<IncomingPush>,
    peers: &[NetAddr],
    send_to_peers: &BTreeMap<NetAddr, Sender<GossipWireMsg>>,
    fanout: usize,
    recorder: MessageRecorder,
    protocol: Arc<str>,
) -> anyhow::Result<()> {
    while let Ok(incoming) = recv_incoming.recv().await {
        let IncomingPush { from, msg } = incoming;
        if msg.protocol != *protocol {
            tracing::warn!(
                from = from.as_ref().map(ToString::to_string),
                incoming_protocol = %msg.protocol,
                expected_protocol = %protocol,
                "rejecting gossip with wrong protocol"
            );
            continue;
        }
        let is_new = recorder.record(msg.clone());
        tracing::debug!(
            protocol = %msg.protocol,
            origin = msg.origin,
            index = msg.index,
            from = from.as_ref().map(ToString::to_string),
            is_new,
            "received gossip message"
        );

        if is_new {
            fan_out(&msg, peers, send_to_peers, fanout, "propagate incoming")?;
        }
    }

    Ok(())
}

#[tracing::instrument(skip(recv_to_peer, send_to_peer, send_incoming, recorder))]
async fn connect_loop(
    peer: NetAddr,
    recv_to_peer: Receiver<GossipWireMsg>,
    send_to_peer: Sender<GossipWireMsg>,
    send_incoming: Sender<IncomingPush>,
    recorder: MessageRecorder,
) {
    loop {
        let peer = peer.clone();
        let recv_to_peer = recv_to_peer.clone();
        let send_to_peer_inner = send_to_peer.clone();
        let send_incoming = send_incoming.clone();
        let recorder = recorder.clone();
        let inner = async move {
            let pipe = peer.connect().await?;
            tracing::debug!(peer = %peer, "connected to gossip peer");
            single_pipe(
                pipe,
                Some(peer.clone()),
                recv_to_peer,
                send_to_peer_inner,
                send_incoming,
                recorder,
            )
            .await
        };
        if let Err(err) = inner.await {
            tracing::warn!(err = debug(err), "restarting peer loop due to error");
        }
    }
}

async fn listen_loop(
    listen: NetAddr,
    send_incoming: Sender<IncomingPush>,
    recorder: MessageRecorder,
) -> anyhow::Result<()> {
    let mut listener = listen.bind().await?;
    tracing::debug!(addr = %listen, "listening for gossip connections");
    loop {
        let pipe = listener.accept().await?;
        tracing::debug!(addr = %listen, "accepted incoming gossip connection");
        let (send_to_peer, recv_to_peer) = smol::channel::unbounded();
        let send_incoming = send_incoming.clone();
        let recorder = recorder.clone();
        smol::spawn(
            single_pipe(
                pipe,
                None,
                recv_to_peer,
                send_to_peer,
                send_incoming,
                recorder,
            )
            .map_err(|err| {
                tracing::warn!(err = debug(&err), "listen-accepted pipe died due to error");
                err
            }),
        )
        .detach();
    }
}

async fn single_pipe(
    pipe: impl Pipe,
    peer: Option<NetAddr>,
    recv_to_peer: Receiver<GossipWireMsg>,
    send_to_peer: Sender<GossipWireMsg>,
    send_incoming: Sender<IncomingPush>,
    recorder: MessageRecorder,
) -> anyhow::Result<()> {
    let (mut read, mut write) = pipe.split();
    let out_loop = async move {
        while let Ok(out_msg) = recv_to_peer.recv().await {
            tracing::debug!(
                msg_type = wire_msg_kind(&out_msg),
                "sending wire gossip message"
            );
            write_wire_msg(&mut write, &out_msg).await?;
        }
        anyhow::Ok(())
    };
    let in_loop = async move {
        loop {
            let msg = read_wire_msg(&mut read).await?;
            match msg {
                GossipWireMsg::Push(bytes) => {
                    tracing::debug!(msg_type = "push", "received wire gossip push");
                    match bcs::from_bytes::<GossipMsg>(&bytes) {
                        Ok(msg) => {
                            let incoming = IncomingPush {
                                from: peer.clone(),
                                msg,
                            };
                            let _ = send_incoming.send(incoming).await;
                        }
                        Err(err) => {
                            tracing::warn!(err = debug(err), "failed to decode gossip push");
                        }
                    }
                }
                GossipWireMsg::Pull { origin, after_idx } => {
                    tracing::debug!(
                        msg_type = "pull",
                        origin,
                        after_idx,
                        peer = peer.as_ref().map(ToString::to_string),
                        "received gossip pull"
                    );
                    for msg in recorder.after(origin, after_idx) {
                        let payload = GossipWireMsg::Push(bcs::to_bytes(&msg)?.into());
                        let _ = send_to_peer.send(payload).await;
                    }
                }
            }
        }
    };
    out_loop.race(in_loop).await
}

async fn read_wire_msg(mut rdr: impl AsyncRead + Unpin) -> anyhow::Result<GossipWireMsg> {
    let mut len_bytes = [0u8; 4];
    rdr.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    ensure!(
        len <= MAX_WIRE_MSG_SIZE,
        "wire message too large: {len} bytes"
    );

    let mut buff = vec![0u8; len];
    rdr.read_exact(&mut buff).await?;
    Ok(bcs::from_bytes(&buff)?)
}

async fn write_wire_msg(
    mut wtr: impl AsyncWrite + Unpin,
    msg: &GossipWireMsg,
) -> anyhow::Result<()> {
    let buff = bcs::to_bytes(msg)?;
    ensure!(
        buff.len() <= MAX_WIRE_MSG_SIZE,
        "wire message too large: {} bytes",
        buff.len()
    );

    let len = u32::try_from(buff.len())?.to_be_bytes();
    wtr.write_all(&len).await?;
    wtr.write_all(&buff).await?;
    wtr.flush().await?;
    Ok(())
}

fn fan_out(
    msg: &GossipMsg,
    peers: &[NetAddr],
    send_to_peers: &BTreeMap<NetAddr, Sender<GossipWireMsg>>,
    fanout: usize,
    reason: &str,
) -> anyhow::Result<()> {
    if fanout == 0 || peers.is_empty() {
        return Ok(());
    }

    let selected_peers = peers
        .choose_multiple(&mut rand::rng(), fanout)
        .cloned()
        .collect::<Vec<_>>();

    tracing::debug!(
        protocol = %msg.protocol,
        origin = msg.origin,
        index = msg.index,
        fanout,
        selected_peers = ?selected_peers,
        reason,
        "gossip fanout"
    );

    let wire_msg = GossipWireMsg::Push(bcs::to_bytes(msg)?.into());
    for peer in &selected_peers {
        if let Some(sender) = send_to_peers.get(peer) {
            let _ = sender.try_send(wire_msg.clone());
        }
    }
    Ok(())
}

fn wire_msg_kind(msg: &GossipWireMsg) -> &'static str {
    match msg {
        GossipWireMsg::Push(_) => "push",
        GossipWireMsg::Pull { .. } => "pull",
    }
}
