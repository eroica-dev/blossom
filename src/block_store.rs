use std::sync::Arc;

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
}
