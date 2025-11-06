use std::{collections::BTreeMap, time::Instant};

use anyhow::Context;
use arrayref::array_ref;
use mel2_stf::Block;
use novasmt::NodeStore;
use serde::{Deserialize, Serialize};
use tmelcrypt::{Ed25519PK, Ed25519SK, HashVal};

const PROPOSE_DOMAIN: &[u8] = b"sl-internal-propose";
const VOTE_DOMAIN: &[u8] = b"sl-internal-vote";

pub struct ConsensusState {
    seed: HashVal,
    genesis: Block,
    epoch_to_block: BTreeMap<u64, Vec<HashVal>>,
    blocks: BTreeMap<HashVal, BlockInfo>,
    vote_weights: BTreeMap<Ed25519PK, u64>,
    my_sk: Ed25519SK,

    current_epoch: u64,

    outgoing_msg: Vec<ConsensusMsg>,
}

struct BlockInfo {
    received: Instant,
    block: Block,
    epoch: u64,
    votes: BTreeMap<Ed25519PK, Vec<u8>>,
}

pub struct ConsensusConfig {
    pub genesis: Block,
    pub vote_weights: BTreeMap<Ed25519PK, u64>,
    pub seed: HashVal,
}

impl ConsensusState {
    pub fn new(cfg: ConsensusConfig, my_sk: Ed25519SK, current_epoch: u64) -> Self {
        Self {
            seed: cfg.seed,
            genesis: cfg.genesis,
            epoch_to_block: Default::default(),
            blocks: Default::default(),
            vote_weights: cfg.vote_weights,
            my_sk,
            current_epoch,

            outgoing_msg: vec![],
        }
    }

    pub fn propose(&mut self, gen_prop: impl FnOnce(&Block) -> Block) {
        if self.proposer_for_epoch(self.current_epoch) == self.my_sk.to_public() {
            let longest_chain = self.longest_notarized_chain();
            let parent_hash = longest_chain
                .last()
                .copied()
                .unwrap_or_else(|| self.genesis_hash());

            let proposal = {
                let parent_block = self
                    .get_block(parent_hash)
                    .expect("parent block for proposal must exist");
                gen_prop(parent_block)
            };

            assert_eq!(
                proposal.header.prev, parent_hash,
                "generated proposal must extend the parent block"
            );

            let header_hash = tmelcrypt::hash_single(
                &bcs::to_bytes(&proposal.header).expect("header serializes"),
            );
            let signature = self
                .my_sk
                .sign(&tmelcrypt::hash_keyed(PROPOSE_DOMAIN, header_hash));
            self.outgoing_msg.push(ConsensusMsg::Propose(
                proposal.clone(),
                self.current_epoch,
                signature,
            ));
        }
    }

    pub fn process_msg(&mut self, msg: ConsensusMsg, store: &impl NodeStore) -> anyhow::Result<()> {
        match msg {
            ConsensusMsg::Propose(block, epoch, signature) => {
                self.add_proposal(block, epoch, signature, store)?;
                self.generate_votes()
            }
            ConsensusMsg::Vote(block_hash, voter, vote) => self.add_vote(block_hash, voter, vote),
        }
    }

    pub fn drain_msg(&mut self) -> Vec<ConsensusMsg> {
        std::mem::take(&mut self.outgoing_msg)
    }

    pub fn tick_epoch(&mut self) {
        self.current_epoch += 1;
    }

    fn get_block(&self, hash: HashVal) -> anyhow::Result<&Block> {
        if hash == self.genesis_hash() {
            Ok(&self.genesis)
        } else {
            Ok(&self.blocks.get(&hash).context("no such block")?.block)
        }
    }

    fn add_proposal(
        &mut self,
        block: Block,
        epoch: u64,
        signature: Vec<u8>,
        store: &impl NodeStore,
    ) -> anyhow::Result<()> {
        let proposer = self.proposer_for_epoch(epoch);
        let block_hash = tmelcrypt::hash_single(&bcs::to_bytes(&block.header)?);
        let sig_msg = tmelcrypt::hash_keyed(PROPOSE_DOMAIN, block_hash);
        if !proposer.verify(&sig_msg, &signature) {
            anyhow::bail!("proposal signature invalid or proposer mismatch");
        }

        let prev = self
            .get_block(block.header.prev)
            .context("parent block does not exist")?;
        let block = prev.apply_and_validate(&block, store)?;

        let bhash = tmelcrypt::hash_single(bcs::to_bytes(&block.header)?);
        self.blocks.insert(
            bhash,
            BlockInfo {
                received: Instant::now(),
                block,
                epoch,
                votes: Default::default(),
            },
        );
        self.epoch_to_block.entry(epoch).or_default().push(bhash);
        Ok(())
    }

    fn add_vote(
        &mut self,
        block_hash: HashVal,
        voter: Ed25519PK,
        vote: Vec<u8>,
    ) -> anyhow::Result<()> {
        if !self.blocks.contains_key(&block_hash) {
            anyhow::bail!("block being voted for doesn't exist")
        }
        if !voter.verify(&tmelcrypt::hash_keyed(VOTE_DOMAIN, block_hash), &vote) {
            anyhow::bail!("vote signature is wrong")
        }
        self.blocks
            .get_mut(&block_hash)
            .unwrap()
            .votes
            .insert(voter, vote);
        Ok(())
    }

    pub fn debug_graphviz(&self) -> String {
        let genesis_hash = self.genesis_hash();

        let mut hashes: Vec<HashVal> = self.blocks.keys().copied().collect();
        hashes.push(genesis_hash);
        hashes.sort_by_key(|hash| hash.to_string());
        hashes.dedup();

        let mut graph = String::from("digraph Consensus {\n    node [shape=box];\n");
        let total_weight = self.total_votes() as f64;

        for hash in &hashes {
            let hash_str = hash.to_string();
            let short_hash: String = hash_str.chars().take(10).collect();
            let (epoch, weight) = if let Some(info) = self.blocks.get(hash) {
                (info.epoch, self.block_vote_weight(info))
            } else {
                (0, 0)
            };
            let weight_percentage = if total_weight > 0.0 {
                (weight as f64 / total_weight) * 100.0
            } else {
                0.0
            };

            graph.push_str(&format!(
                "    \"{}\" [label=\"{}\\nEpoch: {}\\nWeight: {:.2}%\"",
                hash_str, short_hash, epoch, weight_percentage
            ));

            if self.is_finalized(hash) {
                graph.push_str(", style=\"filled\", fillcolor=\"gold\"");
            } else if self.is_notarized(hash) {
                graph.push_str(", style=\"filled\", fillcolor=\"lightblue\"");
            }

            graph.push_str("];\n");
        }

        let mut edges: Vec<String> = self
            .blocks
            .iter()
            .map(|(hash, info)| {
                format!(
                    "    \"{}\" -> \"{}\";\n",
                    hash.to_string(),
                    info.block.header.prev.to_string()
                )
            })
            .collect();
        edges.sort();

        for edge in edges {
            graph.push_str(&edge);
        }

        graph.push('}');
        graph
    }

    fn generate_votes(&mut self) -> anyhow::Result<()> {
        let lnc = self.longest_notarized_chain();
        for proposal in self
            .epoch_to_block
            .get(&self.current_epoch)
            .cloned()
            .unwrap_or_default()
        {
            let nfo = self.blocks.get(&proposal).unwrap();
            if nfo.block.header.prev == *lnc.last().unwrap() {
                // we found the right one to vote for
                let vote = ConsensusMsg::Vote(
                    proposal,
                    self.my_sk.to_public(),
                    self.my_sk.sign(&tmelcrypt::hash_keyed(
                        VOTE_DOMAIN,
                        tmelcrypt::hash_single(&bcs::to_bytes(&nfo.block.header)?),
                    )),
                );
                self.outgoing_msg.push(vote);
            }
        }
        Ok(())
    }

    fn longest_notarized_chain(&self) -> Vec<HashVal> {
        let genesis_hash = self.genesis_hash();

        // Build parent -> children mapping
        let mut children: BTreeMap<HashVal, Vec<HashVal>> = BTreeMap::new();
        for (bhash, block_info) in &self.blocks {
            children
                .entry(block_info.block.header.prev)
                .or_default()
                .push(*bhash);
        }

        // DFS to find longest notarized chain
        fn dfs<F>(
            current: HashVal,
            children: &BTreeMap<HashVal, Vec<HashVal>>,
            is_notarized: &F,
        ) -> Vec<HashVal>
        where
            F: Fn(&HashVal) -> bool,
        {
            let mut longest = vec![current];

            if let Some(child_hashes) = children.get(&current) {
                for child in child_hashes {
                    if is_notarized(child) {
                        let child_chain = dfs(*child, children, is_notarized);
                        if child_chain.len() + 1 > longest.len() {
                            longest = vec![current];
                            longest.extend(child_chain);
                        }
                    }
                }
            }

            longest
        }

        let is_notarized = |bhash: &HashVal| self.is_notarized(bhash);

        dfs(genesis_hash, &children, &is_notarized)
    }

    fn quorum(&self) -> u64 {
        let n = self.total_votes();
        2 * n / 3 + 1
    }

    fn genesis_hash(&self) -> HashVal {
        tmelcrypt::hash_single(
            bcs::to_bytes(&self.genesis.header).expect("genesis serialization failed"),
        )
    }

    fn block_vote_weight(&self, block: &BlockInfo) -> u64 {
        block
            .votes
            .keys()
            .filter_map(|voter| self.vote_weights.get(voter))
            .copied()
            .sum()
    }

    fn total_votes(&self) -> u64 {
        self.vote_weights.values().copied().sum::<u64>()
    }

    fn block_epoch(&self, hash: &HashVal) -> Option<u64> {
        if *hash == self.genesis_hash() {
            Some(0)
        } else {
            self.blocks.get(hash).map(|info| info.epoch)
        }
    }

    fn is_ancestor(&self, ancestor: &HashVal, mut descendant: HashVal) -> bool {
        if ancestor == &descendant {
            return true;
        }

        let genesis_hash = self.genesis_hash();
        loop {
            if descendant == genesis_hash {
                return ancestor == &genesis_hash;
            }
            let info = match self.blocks.get(&descendant) {
                Some(info) => info,
                None => return false,
            };
            descendant = info.block.header.prev;
            if ancestor == &descendant {
                return true;
            }
        }
    }

    fn is_finalized(&self, bhash: &HashVal) -> bool {
        if *bhash == self.genesis_hash() {
            return true;
        }
        if !self.blocks.contains_key(bhash) {
            return false;
        }

        let mut children: BTreeMap<HashVal, Vec<HashVal>> = BTreeMap::new();
        for (hash, info) in &self.blocks {
            children
                .entry(info.block.header.prev)
                .or_default()
                .push(*hash);
        }

        for (middle_hash, middle_info) in &self.blocks {
            if !self.is_notarized(middle_hash) {
                continue;
            }
            let parent_hash = middle_info.block.header.prev;
            if !self.is_notarized(&parent_hash) {
                continue;
            }
            let Some(parent_epoch) = self.block_epoch(&parent_hash) else {
                continue;
            };
            if parent_epoch + 1 != middle_info.epoch {
                continue;
            }
            let Some(child_hashes) = children.get(middle_hash) else {
                continue;
            };

            for child_hash in child_hashes {
                if !self.is_notarized(child_hash) {
                    continue;
                }
                let Some(child_info) = self.blocks.get(child_hash) else {
                    continue;
                };
                if middle_info.epoch + 1 != child_info.epoch {
                    continue;
                }
                if self.is_ancestor(bhash, *middle_hash) {
                    return true;
                }
            }
        }

        false
    }

    fn is_notarized(&self, bhash: &HashVal) -> bool {
        if bhash == &self.genesis_hash() {
            return true;
        }

        self.blocks
            .get(bhash)
            .map(|block| self.block_vote_weight(block) >= self.quorum())
            .unwrap_or(false)
    }

    fn proposer_for_epoch(&self, epoch: u64) -> Ed25519PK {
        let total_votes = self.total_votes();
        let rando = uniform_rand_modulo(
            tmelcrypt::hash_keyed(self.seed, epoch.to_be_bytes()),
            total_votes,
        );
        let mut sum = 0;
        for (voter, weight) in self.vote_weights.iter() {
            sum += *weight;
            if sum > rando {
                return *voter;
            }
        }
        unreachable!()
    }
}

fn uniform_rand_modulo(mut seed: HashVal, modulo: u64) -> u64 {
    let safe_modulo = modulo.next_power_of_two();
    loop {
        seed = tmelcrypt::hash_single(seed); // guard against nonrandom seeds being passed in
        let rand = u64::from_be_bytes(*array_ref![seed.0, 0, 8]) % safe_modulo;
        if rand < modulo {
            return rand;
        }
    }
}

#[derive(Serialize, Deserialize)]
pub enum ConsensusMsg {
    Propose(Block, u64, Vec<u8>),
    Vote(HashVal, Ed25519PK, Vec<u8>),
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use mel2_stf::Block;
    use novasmt::InMemoryStore;
    use tmelcrypt::{Ed25519SK, HashVal};

    use crate::staker::consensus_state::{ConsensusConfig, ConsensusMsg, ConsensusState};

    fn clone_msg(msg: &ConsensusMsg) -> ConsensusMsg {
        match msg {
            ConsensusMsg::Propose(block, epoch, sig) => {
                ConsensusMsg::Propose(block.clone(), *epoch, sig.clone())
            }
            ConsensusMsg::Vote(hash, voter, vote) => {
                ConsensusMsg::Vote(*hash, *voter, vote.clone())
            }
        }
    }

    fn flush_network(
        validators: &mut [ConsensusState],
        store: &InMemoryStore,
        lost_idx: usize,
    ) -> bool {
        let mut lost_sent = false;
        loop {
            let mut sent_any = false;
            for idx in 0..validators.len() {
                let outgoing = {
                    let state = &mut validators[idx];
                    state.drain_msg()
                };
                if outgoing.is_empty() {
                    continue;
                }
                sent_any = true;
                if idx == lost_idx {
                    lost_sent = true;
                    continue;
                }
                for msg in outgoing {
                    for validator in validators.iter_mut() {
                        validator
                            .process_msg(clone_msg(&msg), store)
                            .expect("processing consensus message");
                    }
                }
            }
            if !sent_any {
                break;
            }
        }
        lost_sent
    }

    #[test]
    fn basic_consensus() {
        let nstore = InMemoryStore::default();
        let one_staker_sk = Ed25519SK::generate();
        let genesis = Block::testnet_genesis();
        let cfg = ConsensusConfig {
            seed: Default::default(),
            genesis: genesis.clone(),
            vote_weights: BTreeMap::from([(one_staker_sk.to_public(), 1u64)]),
        };
        let mut state = ConsensusState::new(cfg, one_staker_sk, 0);

        for _ in 0..5 {
            state.propose(|block| block.next_block(&nstore).sealed(block.seal_info).unwrap());
            for msg in state.drain_msg() {
                state.process_msg(msg, &nstore).unwrap();
            }
            for msg in state.drain_msg() {
                state.process_msg(msg, &nstore).unwrap();
            }
            state.tick_epoch();
        }

        let graphviz = state.debug_graphviz();
        println!("{graphviz}");
        assert!(graphviz.contains("digraph Consensus"));
    }

    #[test]
    fn streamlet_finalization_rule() {
        let nstore = InMemoryStore::default();
        let staker_sk = Ed25519SK::generate();
        let genesis = Block::testnet_genesis();
        let cfg = ConsensusConfig {
            seed: Default::default(),
            genesis: genesis.clone(),
            vote_weights: BTreeMap::from([(staker_sk.to_public(), 1u64)]),
        };
        let mut state = ConsensusState::new(cfg, staker_sk, 0);

        for _ in 0..2 {
            state.propose(|block| block.next_block(&nstore).sealed(block.seal_info).unwrap());
            for msg in state.drain_msg() {
                state.process_msg(msg, &nstore).unwrap();
            }
            for msg in state.drain_msg() {
                state.process_msg(msg, &nstore).unwrap();
            }
            state.tick_epoch();
        }

        let chain = state.longest_notarized_chain();
        assert!(
            chain.len() >= 3,
            "expected at least genesis plus two notarized blocks"
        );
        let first = chain[1];
        let second = chain[2];
        assert!(
            !state.is_finalized(&first),
            "block requires a notarized grandchild to finalize"
        );
        assert!(
            !state.is_finalized(&second),
            "second block finalizes only with a notarized child at the next epoch"
        );

        state.propose(|block| block.next_block(&nstore).sealed(block.seal_info).unwrap());
        for msg in state.drain_msg() {
            state.process_msg(msg, &nstore).unwrap();
        }
        for msg in state.drain_msg() {
            state.process_msg(msg, &nstore).unwrap();
        }
        state.tick_epoch();

        let chain = state.longest_notarized_chain();
        assert!(
            chain.len() >= 4,
            "expected genesis plus three notarized blocks"
        );
        let genesis_hash = chain[0];
        let third = chain[3];

        assert!(state.is_finalized(&genesis_hash));
        assert!(state.is_finalized(&first));
        assert!(state.is_finalized(&second));
        assert!(
            !state.is_finalized(&third),
            "third block finalizes only once it gains a notarized child"
        );
    }

    #[test]
    fn five_validators_with_blackholed_peer() {
        const VALIDATOR_COUNT: usize = 5;
        let lost_idx = VALIDATOR_COUNT - 1;
        let nstore = InMemoryStore::default();
        let genesis = Block::testnet_genesis();
        let seed = HashVal::random();

        let mut validator_sks = Vec::with_capacity(VALIDATOR_COUNT);
        for _ in 0..VALIDATOR_COUNT {
            validator_sks.push(Ed25519SK::generate());
        }
        let vote_weights = validator_sks
            .iter()
            .map(|sk| (sk.to_public(), 1u64))
            .collect::<BTreeMap<_, _>>();

        let mut validators: Vec<ConsensusState> = validator_sks
            .into_iter()
            .map(|sk| {
                ConsensusState::new(
                    ConsensusConfig {
                        seed,
                        genesis: genesis.clone(),
                        vote_weights: vote_weights.clone(),
                    },
                    sk,
                    0,
                )
            })
            .collect();

        let mut lost_emitted = false;
        for _ in 0..8 {
            for validator in validators.iter_mut() {
                validator
                    .propose(|block| block.next_block(&nstore).sealed(block.seal_info).unwrap());
            }
            lost_emitted |= flush_network(&mut validators, &nstore, lost_idx);
            for validator in validators.iter_mut() {
                validator.tick_epoch();
            }
        }

        assert!(lost_emitted, "the black-holed validator never produced a message");
        let reference_chain = validators[0].longest_notarized_chain();
        assert!(
            reference_chain.len() >= 4,
            "expected at least genesis plus three notarized blocks"
        );
        for (idx, state) in validators.iter().enumerate() {
            if idx == lost_idx {
                continue;
            }
            assert_eq!(
                state.longest_notarized_chain().last(),
                reference_chain.last(),
                "validator {idx} disagrees on the notarized head"
            );
        }
    }
}
