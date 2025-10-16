use std::{collections::HashMap, time::Instant};

use mel2_stf::Header;
use serde::{Deserialize, Serialize};
use tmelcrypt::{Ed25519PK, Ed25519SK, HashVal};

pub struct ConsensusState {
    genesis: Header,
    epoch_to_block: HashMap<u64, Vec<HashVal>>,
    blocks: HashMap<HashVal, BlockInfo>,
    vote_weights: HashMap<Ed25519PK, u64>,
    my_sk: Ed25519SK,

    current_epoch: u64,
}

struct BlockInfo {
    received: Instant,
    header: Header,
    epoch: u64,
    votes: HashMap<Ed25519PK, Vec<u8>>,
}

pub struct ConsensusConfig {
    pub genesis: Header,
    pub vote_weights: HashMap<Ed25519PK, u64>,
}

impl ConsensusState {
    pub fn new(cfg: ConsensusConfig, my_sk: Ed25519SK, current_epoch: u64) -> Self {
        Self {
            genesis: cfg.genesis,
            epoch_to_block: Default::default(),
            blocks: Default::default(),
            vote_weights: cfg.vote_weights,
            my_sk,
            current_epoch,
        }
    }

    pub fn add_block(&mut self, header: Header, epoch: u64) -> anyhow::Result<()> {
        if !self.blocks.contains_key(&header.prev) {
            anyhow::bail!("parent block doesn't exist")
        }
        // TODO: actually validate the block!!
        let bhash = tmelcrypt::hash_single(bcs::to_bytes(&header)?);
        self.blocks.insert(
            bhash,
            BlockInfo {
                received: Instant::now(),
                header,
                epoch,
                votes: Default::default(),
            },
        );
        self.epoch_to_block.entry(epoch).or_default().push(bhash);
        Ok(())
    }

    pub fn add_vote(
        &mut self,
        block_hash: HashVal,
        voter: Ed25519PK,
        vote: Vec<u8>,
    ) -> anyhow::Result<()> {
        if !self.blocks.contains_key(&block_hash) {
            anyhow::bail!("block being voted for doesn't exist")
        }
        if !voter.verify(
            &tmelcrypt::hash_keyed(b"sl-internal-vote", block_hash),
            &vote,
        ) {
            anyhow::bail!("vote signature is wrong")
        }
        self.blocks
            .get_mut(&block_hash)
            .unwrap()
            .votes
            .insert(voter, vote);
        Ok(())
    }

    pub fn process_msg(&mut self, msg: ConsensusMsg) -> anyhow::Result<()> {
        match msg {
            ConsensusMsg::Propose(header, epoch) => {
                self.add_block(header, epoch)?;
                self.generate_votes()
            }
            ConsensusMsg::Vote(block_hash, voter, vote) => self.add_vote(block_hash, voter, vote),
        }
    }

    pub fn debug_graphviz(&self) -> String {
        let genesis_hash = self.genesis_hash();

        let mut hashes: Vec<HashVal> = self.blocks.keys().copied().collect();
        hashes.push(genesis_hash);
        hashes.sort_by_key(|hash| hash.to_string());
        hashes.dedup();

        let mut graph = String::from("digraph Consensus {\n    node [shape=box];\n");

        for hash in &hashes {
            let hash_str = hash.to_string();
            let short_hash: String = hash_str.chars().take(10).collect();
            let (epoch, weight) = if let Some(info) = self.blocks.get(hash) {
                (info.epoch, self.block_vote_weight(info))
            } else {
                (0, 0)
            };

            graph.push_str(&format!(
                "    \"{}\" [label=\"{}\\nEpoch: {}\\nWeight: {}\"",
                hash_str, short_hash, epoch, weight
            ));

            if self.is_notarized(hash) {
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
                    info.header.prev.to_string()
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
            if nfo.header.prev == *lnc.last().unwrap() {
                // we found the right one to vote for
                self.add_vote(
                    proposal,
                    self.my_sk.to_public(),
                    self.my_sk.sign(&tmelcrypt::hash_keyed(
                        b"sl-internal-vote",
                        tmelcrypt::hash_single(&bcs::to_bytes(&nfo.header)?),
                    )),
                )?;
            }
        }
        Ok(())
    }

    fn longest_notarized_chain(&self) -> Vec<HashVal> {
        let genesis_hash = self.genesis_hash();

        // Build parent -> children mapping
        let mut children: HashMap<HashVal, Vec<HashVal>> = HashMap::new();
        for (bhash, block_info) in &self.blocks {
            children
                .entry(block_info.header.prev)
                .or_default()
                .push(*bhash);
        }

        // DFS to find longest notarized chain
        fn dfs<F>(
            current: HashVal,
            children: &HashMap<HashVal, Vec<HashVal>>,
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
        let n = self.vote_weights.values().copied().sum::<u64>();
        2 * n / 3 + 1
    }

    fn genesis_hash(&self) -> HashVal {
        tmelcrypt::hash_single(bcs::to_bytes(&self.genesis).expect("genesis serialization failed"))
    }

    fn block_vote_weight(&self, block: &BlockInfo) -> u64 {
        block
            .votes
            .keys()
            .filter_map(|voter| self.vote_weights.get(voter))
            .copied()
            .sum()
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
}

#[derive(Serialize, Deserialize)]
pub enum ConsensusMsg {
    Propose(Header, u64),
    Vote(HashVal, Ed25519PK, Vec<u8>),
}

#[cfg(test)]
mod tests {
    use mel2_stf::Block;
    use tmelcrypt::Ed25519SK;

    use crate::staker::consensus::{ConsensusConfig, ConsensusState};

    #[test]
    fn basic_consensus() {
        let one_staker_sk = Ed25519SK::generate();
        let genesis = Block::testnet_genesis().header;
        let cfg = ConsensusConfig {
            genesis,
            vote_weights: [(one_staker_sk, 1)].iter().cloned().collect(),
        };
        let state = ConsensusState::new(cfg, one_staker_sk, 0);
        todo!()
    }
}
