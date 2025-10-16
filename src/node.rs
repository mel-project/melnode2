use std::{net::SocketAddr, sync::Arc, thread::JoinHandle, time::Duration};

use async_trait::async_trait;

use crate::{
    rpc::{
        BlockProof, BlockWithProof, NodeClient, NodeProtocol, NodeService, RpcClient,
        run_rpc_server,
    },
    storage::Storage,
};

pub struct NodeHandle {
    client_thread: Option<JoinHandle<()>>,
    server_thread: Option<JoinHandle<()>>,
}

impl NodeHandle {
    pub fn spawn(
        connect: Option<SocketAddr>,
        listen: Option<SocketAddr>,
        storage: Arc<Storage>,
    ) -> Self {
        let client_thread = connect.map(|addr| {
            let storage = storage.clone();
            std::thread::Builder::new()
                .name("node-client".into())
                .spawn(move || client_thread(addr, storage))
                .expect("failed to spawn client thread")
        });

        let server_thread = listen.map(|addr| {
            let storage = storage.clone();
            std::thread::Builder::new()
                .name("node-server".into())
                .spawn(move || server_thread(addr, storage))
                .expect("failed to spawn server thread")
        });

        Self {
            client_thread,
            server_thread,
        }
    }
}

#[tracing::instrument(skip(storage))]
fn client_thread(connect: SocketAddr, storage: Arc<Storage>) {
    let client = NodeClient(RpcClient::new(connect));
    loop {
        match sync_next_block(&client, &storage) {
            Err(err) => {
                tracing::warn!(err = debug(err), "syncing next block failed")
            }
            Ok(true) => continue,
            Ok(false) => {}
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn sync_next_block(client: &NodeClient<RpcClient>, storage: &Storage) -> anyhow::Result<bool> {
    let next = storage.highest_height()? + 1;
    tracing::debug!(next, "obtaining next block");
    if let Some(blk) = smol::future::block_on(client.get_block(next))? {
        match blk.proof {
            BlockProof::SingleSig(_) => {
                anyhow::bail!("rejecting all single-signature proofs")
            }
            BlockProof::Dummy => {
                // Allow dummy proofs
            }
        }
        storage.apply_block(&blk.block)?;
        Ok(true)
    } else {
        tracing::debug!(next, "no such block yet...");
        Ok(false)
    }
}

fn server_thread(listen: SocketAddr, storage: Arc<Storage>) {
    smol::future::block_on(run_rpc_server(listen, NodeService(RpcServerImpl(storage))))
        .expect("serving thread just died")
}

struct RpcServerImpl(Arc<Storage>);

#[async_trait]
impl NodeProtocol for RpcServerImpl {
    async fn get_block(&self, height: u64) -> Option<BlockWithProof> {
        let block = self.0.get_block(height).expect("storage failed")?;
        Some(BlockWithProof {
            block,
            proof: BlockProof::Dummy,
        })
    }
}
