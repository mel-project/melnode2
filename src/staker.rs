mod consensus_state;

use std::{sync::Arc, thread::JoinHandle, time::Duration};

use mel2_stf::{Address, Quantity, SealingInfo};
use serde::{Deserialize, Serialize};

use crate::storage::Storage;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StakerConfig {
    pub staker_sk_seed: String,
    pub proposer_addr: Address,
}

pub struct StakerHandle {
    thread: JoinHandle<()>,
}

impl StakerHandle {
    pub fn spawn(cfg: StakerConfig, storage: Arc<Storage>) -> Self {
        let thread = std::thread::Builder::new()
            .name("staker".into())
            .spawn(move || {
                while let Err(err) = staker_thread(&storage) {
                    tracing::warn!(err = debug(err), "staker thread restarted");
                }
            })
            .unwrap();
        Self { thread }
    }
}

fn staker_thread(storage: &Storage) -> anyhow::Result<()> {
    let mut crystal = smol::Timer::interval(Duration::from_secs(30));
    loop {
        let block = storage.highest_block()?;
        let next_block = block
            .next_block(&storage.node_store())
            .sealed(SealingInfo {
                proposer: Address::ZERO,
                new_gas_price: Quantity(1_000_000),
            })?;
        tracing::debug!(height = debug(next_block.header.height), "produced a block");
        storage.apply_block(&next_block)?;
        smol::future::block_on(&mut crystal);
    }
}
