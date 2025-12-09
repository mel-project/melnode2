use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use clap::Parser;
use mel2_stf::{Address, Block, ChainId};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use crate::{
    node::NodeHandle,
    staker::{StakerConfig, StakerHandle},
    storage::Storage,
};

pub mod network;
mod node;
mod rpc;
mod staker;
mod storage;

#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Args {
    #[arg(long)]
    staker: bool,

    #[arg(long)]
    connect: Option<SocketAddr>,
    #[arg(long)]
    listen: Option<SocketAddr>,

    #[arg(long)]
    db_path: Option<PathBuf>,

    #[arg(long, default_value_t = 2068)]
    chain_id: u16,
}

fn main() {
    tracing_subscriber::registry()
        // Standard logs to stderr (for console display)
        .with(fmt::layer().compact().with_writer(std::io::stderr))
        // Set filtering based on environment or defaults
        .with(
            EnvFilter::builder()
                .with_default_directive("melnode2=debug".parse().unwrap())
                .from_env_lossy(),
        )
        .init();

    let args = Args::parse();
    let chain_id = ChainId(args.chain_id);
    let db_path = args
        .db_path
        .unwrap_or_else(|| dirs::data_dir().unwrap().join("melnode"));
    let storage = Arc::new(
        Storage::open(&db_path, chain_id, || match chain_id {
            ChainId::BETANET => Block::betanet_genesis(),
            ChainId::TESTNET => Block::testnet_genesis(),
            _ => unimplemented!("custom chain ID not supported yet"),
        })
        .expect("could not initialize storage"),
    );

    if args.staker {
        StakerHandle::spawn(
            StakerConfig {
                staker_sk_seed: "jskldfjsdf".into(),
                proposer_addr: Address::ZERO,
            },
            storage.clone(),
        );
    }

    // Spawn node networking (client/server) based on CLI args
    let _node = NodeHandle::spawn(args.connect, args.listen, storage);

    loop {
        std::thread::park();
    }
}
