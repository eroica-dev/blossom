//! Durable block indexing by epoch nonce and block hash.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use borsh::BorshDeserialize;
use bytes::Bytes;
use indextreemap::SharedIndexTreeMap;

use crate::block::Block;
use crate::error::{BlossomError, Result};
use crate::hash::HashType;

pub type BlockIndex = SharedIndexTreeMap<HashType, BlockHandle>;

#[derive(Debug)]
pub struct BlockRecord {
    block: Block,
    encoded: Bytes,
    hash: HashType,
}

impl BlockRecord {
    pub fn new(block: Block) -> Result<Self> {
        let hash = block.hash;
        let encoded = Bytes::from(
            borsh::to_vec(&block).map_err(|err| BlossomError::WireProtocol(err.to_string()))?,
        );
        Ok(Self {
            block,
            encoded,
            hash,
        })
    }

    pub fn block(&self) -> &Block {
        &self.block
    }

    pub fn encoded(&self) -> &Bytes {
        &self.encoded
    }

    pub fn encoded_len(&self) -> usize {
        self.encoded.len()
    }

    pub fn hash(&self) -> HashType {
        self.hash
    }
}

#[derive(Debug, Clone)]
pub struct BlockHandle {
    inner: Arc<BlockRecord>,
}

impl BlockHandle {
    pub fn new(block: Block) -> Result<Self> {
        Ok(Self {
            inner: Arc::new(BlockRecord::new(block)?),
        })
    }

    pub fn block(&self) -> &Block {
        self.inner.block()
    }

    pub fn encoded(&self) -> &Bytes {
        self.inner.encoded()
    }

    pub fn encoded_len(&self) -> usize {
        self.inner.encoded_len()
    }

    pub fn hash(&self) -> HashType {
        self.inner.hash()
    }

    pub fn to_owned_block(&self) -> Block {
        self.block().clone()
    }

    pub fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

impl AsRef<Block> for BlockHandle {
    fn as_ref(&self) -> &Block {
        self.block()
    }
}

#[derive(Debug, Clone)]
pub struct DurableBlockStore {
    root: PathBuf,
}

impl DurableBlockStore {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let store = Self { root: root.into() };
        fs::create_dir_all(store.blocks_dir()).map_err(|err| BlossomError::Io(err.to_string()))?;
        fs::create_dir_all(store.nonces_dir()).map_err(|err| BlossomError::Io(err.to_string()))?;
        Ok(store)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn put(&self, block: &Block) -> Result<()> {
        if block.hash != block.body.hash() {
            return Err(BlossomError::InvalidBlockHash);
        }
        let encoded =
            borsh::to_vec(block).map_err(|err| BlossomError::WireProtocol(err.to_string()))?;
        write_atomic(&self.block_path(block.hash), &encoded)?;

        let nonce_dir = self.nonce_dir(block.body.nonce);
        fs::create_dir_all(&nonce_dir).map_err(|err| BlossomError::Io(err.to_string()))?;
        write_atomic(
            &nonce_dir.join(hash_file_name(block.hash)),
            block.hash.to_string().as_bytes(),
        )
    }

    pub fn get_by_hash(&self, hash: HashType) -> Result<Option<Block>> {
        let path = self.block_path(hash);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(path).map_err(|err| BlossomError::Io(err.to_string()))?;
        let block = Block::deserialize_reader(&mut bytes.as_slice())
            .map_err(|err| BlossomError::WireProtocol(err.to_string()))?;
        if block.hash != hash || block.hash != block.body.hash() {
            return Err(BlossomError::InvalidBlockHash);
        }
        Ok(Some(block))
    }

    pub fn get_by_nonce(&self, nonce: crate::nonce::Nonce) -> Result<Vec<Block>> {
        let nonce_dir = self.nonce_dir(nonce);
        if !nonce_dir.exists() {
            return Ok(Vec::new());
        }
        let mut hashes = Vec::new();
        for entry in fs::read_dir(nonce_dir).map_err(|err| BlossomError::Io(err.to_string()))? {
            let entry = entry.map_err(|err| BlossomError::Io(err.to_string()))?;
            let Some(file_name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Some(hash_hex) = file_name.strip_suffix(".ref") else {
                continue;
            };
            let bytes = hex::decode(hash_hex).map_err(|_| BlossomError::InvalidHex)?;
            let hash_bytes: [u8; 32] =
                bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| BlossomError::InvalidLength {
                        expected: 32,
                        actual: bytes.len(),
                    })?;
            let hash = HashType(hash_bytes);
            hashes.push(hash);
        }
        hashes.sort();

        let mut blocks = Vec::with_capacity(hashes.len());
        for hash in hashes {
            if let Some(block) = self.get_by_hash(hash)? {
                blocks.push(block);
            }
        }
        Ok(blocks)
    }

    pub fn get_first_by_nonce(&self, nonce: crate::nonce::Nonce) -> Result<Option<Block>> {
        Ok(self.get_by_nonce(nonce)?.into_iter().next())
    }

    fn blocks_dir(&self) -> PathBuf {
        self.root.join("blocks")
    }

    fn nonces_dir(&self) -> PathBuf {
        self.root.join("nonces")
    }

    fn block_path(&self, hash: HashType) -> PathBuf {
        self.blocks_dir().join(hash_file_name(hash))
    }

    fn nonce_dir(&self, nonce: crate::nonce::Nonce) -> PathBuf {
        self.nonces_dir().join(nonce.value().to_string())
    }
}

fn hash_file_name(hash: HashType) -> String {
    format!("{hash}.ref")
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|err| BlossomError::Io(err.to_string()))?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes).map_err(|err| BlossomError::Io(err.to_string()))?;
    fs::rename(&tmp, path).map_err(|err| BlossomError::Io(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Keypair, Nonce, Transaction};

    fn signed_block() -> Block {
        let keypair = Keypair::generate();
        let mut block = Block::empty_with_nonce(Nonce::new(7));
        block.body.txs.push(Transaction::new("shared"));
        block.sign(&keypair.secret);
        block
    }

    #[test]
    fn handle_clones_share_the_same_record() {
        let handle = BlockHandle::new(signed_block()).unwrap();
        let clone = handle.clone();

        assert!(handle.ptr_eq(&clone));
        assert_eq!(handle.hash(), clone.hash());
        assert_eq!(handle.encoded_len(), clone.encoded_len());
    }

    #[test]
    fn cached_encoding_matches_borsh_encoding() {
        let block = signed_block();
        let encoded = borsh::to_vec(&block).unwrap();
        let handle = BlockHandle::new(block).unwrap();

        assert_eq!(handle.encoded().as_ref(), encoded.as_slice());
        assert_eq!(handle.encoded_len(), encoded.len());
    }

    #[test]
    fn durable_store_round_trips_blocks_by_hash_and_nonce() {
        let root = std::env::temp_dir().join(format!(
            "blossom-durable-block-store-{}",
            std::process::id()
        ));
        let store = DurableBlockStore::open(&root).unwrap();
        let block = signed_block();
        let hash = block.hash;
        let nonce = block.body.nonce;

        store.put(&block).unwrap();
        assert_eq!(store.get_by_hash(hash).unwrap().unwrap().hash, hash);
        assert_eq!(store.get_first_by_nonce(nonce).unwrap().unwrap().hash, hash);
        assert_eq!(store.get_by_nonce(nonce).unwrap().len(), 1);

        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn durable_store_fails_closed_on_truncated_block_file() {
        let root = std::env::temp_dir().join(format!(
            "blossom-durable-block-store-corrupt-{}",
            std::process::id()
        ));
        let store = DurableBlockStore::open(&root).unwrap();
        let block = signed_block();
        let hash = block.hash;

        store.put(&block).unwrap();
        std::fs::write(store.block_path(hash), b"truncated").unwrap();

        assert!(store.get_by_hash(hash).is_err());
        std::fs::remove_dir_all(root).ok();
    }
}
