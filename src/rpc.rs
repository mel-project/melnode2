use async_trait::async_trait;
use bytes::Bytes;

use futures_util::{AsyncWriteExt, future::TryFutureExt};
use mel2_stf::Block;
use nanorpc::{JrpcRequest, JrpcResponse, RpcService, RpcTransport, nanorpc_derive};
use serde::{Deserialize, Serialize};
use smol::{
    io::{AsyncBufReadExt, AsyncReadExt, BufReader},
    net::{TcpListener, TcpStream},
};
use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

/// A pooled, RPC client to a given destination.
pub struct RpcClient {
    pool: Mutex<VecDeque<TcpStream>>,
    dest: SocketAddr,
}

impl RpcClient {
    pub fn new(dest: SocketAddr) -> Self {
        Self {
            pool: Mutex::new(VecDeque::new()),
            dest,
        }
    }
}

#[async_trait]
impl RpcTransport for RpcClient {
    type Error = anyhow::Error;

    async fn call_raw(&self, req: JrpcRequest) -> Result<JrpcResponse, Self::Error> {
        // Try to get an existing connection from the pool
        let maybe_conn = {
            let mut guard = self.pool.lock().unwrap();
            guard.pop_front()
        };

        // Otherwise, establish a new connection
        let mut conn = if let Some(conn) = maybe_conn {
            conn
        } else {
            TcpStream::connect(self.dest).await?
        };

        // Prepare to write request and read response line-delimited JSON
        let mut buff = String::new();
        let mut reader = BufReader::new(conn.clone());
        let req_line = serde_json::to_string(&req)? + "\n";
        conn.write_all(req_line.as_bytes()).await?;
        (&mut reader).take(10000).read_line(&mut buff).await?;
        let resp: JrpcResponse = serde_json::from_str(&buff)?;

        // Return the connection to the pool for reuse
        {
            let mut guard = self.pool.lock().unwrap();
            guard.push_back(conn);
        }

        Ok(resp)
    }
}

/// Run a RPC server bound to the given address.
pub async fn run_rpc_server(addr: SocketAddr, srv: impl RpcService) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let srv = Arc::new(srv);
    loop {
        let (mut conn, remote_addr) = listener.accept().await?;
        tracing::debug!(
            remote_addr = display(remote_addr),
            "accepted TCP stream for RPC"
        );
        let srv = srv.clone();
        smol::spawn::<anyhow::Result<()>>(
            async move {
                let mut read = BufReader::new(conn.clone());
                let mut buff = String::new();
                loop {
                    (&mut read).take(10000).read_line(&mut buff).await?;
                    let resp = serde_json::to_string(
                        &srv.respond_raw(serde_json::from_str(&buff)?).await,
                    )? + "\n";
                    conn.write_all(resp.as_bytes()).await?;
                }
            }
            .map_err(|e| {
                tracing::debug!(err = debug(&e), "RPC stream closed");
                e
            }),
        )
        .detach();
    }
}

#[nanorpc_derive]
#[async_trait]
pub trait NodeProtocol {
    async fn get_block(&self, height: u64) -> Option<BlockWithProof>;
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BlockWithProof {
    pub block: Block,
    pub proof: BlockProof,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum BlockProof {
    SingleSig(Bytes),
    Dummy,
}
