use std::{path::Path, str::FromStr, sync::Arc};

use mel2_stf::{Block, ChainId};
use novasmt::NodeStore;
use sqlx::{SqlitePool, pool::PoolOptions, sqlite::SqliteConnectOptions};

/// The main storage system of the node, which stores the blockchain history etc.
pub struct Storage {
    mesha: Arc<meshanina::Mapping>,
    sqlite: SqlitePool,
}

impl Storage {
    pub fn open(
        root_path: &Path,
        chain_id: ChainId,
        genesis: impl FnOnce() -> Block,
    ) -> anyhow::Result<Self> {
        let root_path = root_path.join(format!("chain-{}", chain_id.0));
        std::fs::create_dir_all(&root_path)?;

        // open SMT store
        let mesha = Arc::new(meshanina::Mapping::open(&root_path.join("smt.db"))?);

        // open SQLite store
        let options =
            SqliteConnectOptions::from_str(&root_path.join("metadata.db").to_string_lossy())?
                .create_if_missing(true);
        let sqlite = PoolOptions::new()
            .min_connections(8)
            .max_connections(8)
            .connect_lazy_with(options);

        smol::future::block_on(async {
            sqlx::migrate!().run(&sqlite).await?;

            // Check if we have block 0
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blocks")
                .fetch_one(&sqlite)
                .await?;

            if count == 0 {
                let genesis = genesis();
                sqlx::query("INSERT INTO blocks (height, header, block) VALUES (?1, ?2, ?3)")
                    .bind(genesis.header.height as i64)
                    .bind(bcs::to_bytes(&genesis.header)?)
                    .bind(bcs::to_bytes(&genesis)?)
                    .execute(&sqlite)
                    .await?;
            }

            anyhow::Ok(())
        })?;

        Ok(Self { mesha, sqlite })
    }

    pub fn apply_block(&self, block: &Block) -> anyhow::Result<()> {
        let latest_block = self.latest_block()?;
        let next_block = latest_block.apply_and_validate(block, &self.node_store())?;
        self.mesha.flush();
        smol::future::block_on(async move {
            sqlx::query("insert into blocks values ($1, $2, $3)")
                .bind(next_block.header.height as i64)
                .bind(bcs::to_bytes(&next_block.header)?)
                .bind(bcs::to_bytes(&next_block)?)
                .execute(&self.sqlite)
                .await?;
            Ok(())
        })
    }

    pub fn latest_block(&self) -> anyhow::Result<Block> {
        smol::future::block_on(async move {
            let blk: Vec<u8> =
                sqlx::query_scalar("select block from blocks order by height desc limit 1")
                    .fetch_one(&self.sqlite)
                    .await?;
            Ok(bcs::from_bytes(&blk)?)
        })
    }

    pub fn node_store(&self) -> impl NodeStore {
        MeshaNodeSource(self.mesha.clone())
    }
}

struct MeshaNodeSource(Arc<meshanina::Mapping>);

impl NodeStore for MeshaNodeSource {
    fn get(&self, key: &[u8]) -> Result<Option<std::borrow::Cow<'_, [u8]>>, novasmt::SmtError> {
        Ok(self.0.get(tmelcrypt::hash_single(&key).0))
    }

    fn insert(&self, key: &[u8], value: &[u8]) -> Result<(), novasmt::SmtError> {
        self.0.insert(tmelcrypt::hash_single(&key).0, value);
        Ok(())
    }
}

// put this in the same file/module as `Storage` (or adjust visibility as needed)
#[cfg(test)]
mod tests {
    use mel2_stf::{Address, SealingInfo};

    use super::*;
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn tmp_root() -> PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        PathBuf::from(format!("/tmp/storage/{now}"))
    }

    fn make_genesis() -> mel2_stf::Block {
        mel2_stf::Block::testnet_genesis()
    }

    #[test]
    fn open_initializes_once_and_uses_tmp() -> anyhow::Result<()> {
        // Arrange a fresh root in /tmp and a chain id
        let root = tmp_root();
        let chain_id = mel2_stf::ChainId::BETANET;

        // Act: first open should create `/tmp/.../chain-7` and insert genesis
        let storage = Storage::open(&root, chain_id, || make_genesis())?;

        for _ in 0..10 {
            let latest = storage.latest_block()?;
            let next = latest
                .next_block(&storage.node_store())
                .sealed(SealingInfo {
                    proposer: Address::ZERO,
                    new_gas_price: mel2_stf::Quantity(1_000_000),
                })?;
            storage.apply_block(&next)?;
        }

        Ok(())
    }

    #[test]
    fn concurrent_apply_block_fail() -> anyhow::Result<()> {
        // Arrange a fresh root in /tmp and a chain id
        let root = tmp_root();
        let chain_id = mel2_stf::ChainId::BETANET;

        // Act: first open should create `/tmp/.../chain-7` and insert genesis
        let storage = Storage::open(&root, chain_id, || make_genesis())?;

        std::thread::scope(|s| {
            for _ in 0..10 {
                s.spawn(|| {
                    let latest = storage.latest_block().unwrap();
                    let next = latest
                        .next_block(&storage.node_store())
                        .sealed(SealingInfo {
                            proposer: Address::ZERO,
                            new_gas_price: mel2_stf::Quantity(1_000_000),
                        })
                        .unwrap();
                    let succeeded = storage.apply_block(&next).is_ok();
                    dbg!(succeeded);
                });
            }
        });

        eprintln!("{:?}", storage.latest_block()?.header);

        Ok(())
    }
}
