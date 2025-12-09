use std::{collections::BTreeMap, convert::TryFrom};

use anyhow::Context;
use mel2_stf::{Address, ERA_LENGTH, Quantity};
use serde::{Deserialize, Serialize};
use smol::{
    Task,
    channel::{Receiver, Sender},
};
use tmelcrypt::{Ed25519PK, Ed25519SK, HashVal};

use crate::{
    network::NetAddr,
    staker::consensus_state::{ConsensusConfig, ConsensusMsg, ConsensusState},
    storage::Storage,
};

pub struct StakeNetConfig {
    pub era: u64,
    pub storage: Storage,
    pub stakers: BTreeMap<Ed25519PK, StakerDescriptor>,

    pub my_sk: Ed25519SK,
    pub listen_net_addr: NetAddr,
}

pub struct StakerDescriptor {
    pub net_addr: NetAddr,
    pub reward_addr: Address,
    pub sym_staked: Quantity,
}

type StakeNetAndAddr = (StakeNetMsg, NetAddr);

#[derive(Serialize, Deserialize, Clone)]
struct StakeNetMsg {
    ttl: u8,
    inner: ConsensusMsg,
}

fn staker_inner_loop(
    cfg: StakeNetConfig,
    recv_incoming: Receiver<StakeNetAndAddr>,
    send_outgoing: Sender<StakeNetAndAddr>,
) -> anyhow::Result<()> {
    let genesis_height = cfg.storage.highest_height()? / ERA_LENGTH;

    let vote_weights = cfg
        .stakers
        .iter()
        .map(|(pk, desc)| {
            let weight =
                u64::try_from(desc.sym_staked.0).context("staked amount exceeds u64 range")?;
            Ok((*pk, weight))
        })
        .collect::<anyhow::Result<BTreeMap<_, _>>>()?;

    let state = ConsensusState::new(
        ConsensusConfig {
            genesis: cfg.storage.get_block(genesis_height)?.context(format!(
                "could not get block for era-genesis {genesis_height}"
            ))?,
            vote_weights,
            seed: HashVal::default(), // it should be majority-beacon instead!
        },
        cfg.my_sk,
        0,
    );

    todo!()
}
