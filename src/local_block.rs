use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

use crate::block::{Block, Transaction};
use crate::crypto::{PubKey, SecKey};
use crate::error::{BlossomError, Result};
use crate::hash::HashType;
use crate::nonce::Nonce;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LocalBlock {
    pub build_block: Block,
    pub block_deque: VecDeque<Block>,
    pub block_cap: usize,
}

impl LocalBlock {
    pub fn new(block_cap: usize) -> Self {
        Self {
            build_block: Block::default(),
            block_deque: VecDeque::new(),
            block_cap,
        }
    }

    pub fn add_transaction(&mut self, tx: Transaction) -> HashType {
        let hash = tx.hash;
        self.build_block.body.txs.push(tx);
        self.build_block.body.merkle_root = self.build_block.body.compute_merkle_root();
        self.build_block.set_hash();
        hash
    }

    pub fn close_block(
        &mut self,
        secret_key: &SecKey,
        last_epoch: HashType,
        nonce: Nonce,
    ) -> Result<HashType> {
        self.build_block.body.last_epoch = last_epoch;
        self.build_block.body.nonce = nonce;
        self.build_block.sign(secret_key);

        let hash = self.enqueue_block(self.build_block.clone())?;
        self.build_block = Block::default();
        Ok(hash)
    }

    pub fn enqueue_block(&mut self, block: Block) -> Result<HashType> {
        block.verify_integrity()?;
        if self
            .block_deque
            .iter()
            .any(|queued| queued.body.nonce == block.body.nonce)
        {
            return Err(BlossomError::DuplicateBlock);
        }
        if self.block_deque.len() >= self.block_cap {
            return Err(BlossomError::BlockQueueFull);
        }

        let hash = block.hash;
        self.block_deque.push_back(block);
        Ok(hash)
    }

    pub fn dequeue_block(
        &mut self,
        validator: Option<PubKey>,
        last_epoch: HashType,
        nonce: Nonce,
        _round: u8,
    ) -> Result<Option<Block>> {
        while let Some(block) = self.block_deque.pop_front() {
            if block.body.nonce.value() < nonce.value() {
                continue;
            }
            if block.body.nonce.value() > nonce.value() {
                let actual = block.body.nonce;
                self.block_deque.push_front(block);
                return Err(BlossomError::InvalidBlockNonce {
                    expected: nonce,
                    actual,
                });
            }
            if block.body.last_epoch != last_epoch {
                continue;
            }
            if validator.is_some_and(|validator| block.body.validator != validator) {
                return Err(BlossomError::UnknownSender);
            }
            return Ok(Some(block));
        }

        Ok(None)
    }

    pub fn contains_nonce(&self, nonce: Nonce) -> bool {
        self.block_deque
            .iter()
            .any(|block| block.body.nonce == nonce)
    }

    pub fn len(&self) -> usize {
        self.block_deque.len()
    }

    pub fn is_empty(&self) -> bool {
        self.block_deque.is_empty()
    }
}

impl Default for LocalBlock {
    fn default() -> Self {
        Self::new(100)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::Transaction;
    use crate::crypto::Keypair;

    #[test]
    fn rejects_duplicate_nonces() {
        let keypair = Keypair::generate();
        let mut queue = LocalBlock::new(2);
        let mut block = Block::default();
        block.body.last_epoch = HashType([7; 32]);
        block.body.nonce = Nonce::new(1);
        block.sign(&keypair.secret);

        assert!(queue.enqueue_block(block.clone()).is_ok());
        assert_eq!(
            queue.enqueue_block(block),
            Err(BlossomError::DuplicateBlock)
        );
    }

    #[test]
    fn closes_build_block_into_signed_queue() {
        let keypair = Keypair::generate();
        let mut queue = LocalBlock::new(2);
        queue.add_transaction(Transaction::new("tx"));

        let hash = queue
            .close_block(&keypair.secret, HashType([1; 32]), Nonce::new(1))
            .unwrap();

        assert_eq!(queue.len(), 1);
        assert_ne!(hash, HashType::default());
    }

    #[test]
    fn capacity_is_enforced() {
        let keypair = Keypair::generate();
        let mut queue = LocalBlock::new(1);
        let mut first = Block::default();
        first.body.last_epoch = HashType([1; 32]);
        first.body.nonce = Nonce::new(1);
        first.sign(&keypair.secret);
        let mut second = Block::default();
        second.body.last_epoch = HashType([1; 32]);
        second.body.nonce = Nonce::new(2);
        second.sign(&keypair.secret);

        assert!(queue.enqueue_block(first).is_ok());
        assert_eq!(
            queue.enqueue_block(second),
            Err(BlossomError::BlockQueueFull)
        );
    }

    #[test]
    fn dequeue_drops_stale_blocks() {
        let keypair = Keypair::generate();
        let mut queue = LocalBlock::new(2);
        let mut stale = Block::default();
        stale.body.last_epoch = HashType([1; 32]);
        stale.body.nonce = Nonce::new(1);
        stale.sign(&keypair.secret);
        queue.enqueue_block(stale).unwrap();

        assert!(matches!(
            queue.dequeue_block(None, HashType([1; 32]), Nonce::new(2), 0),
            Ok(None)
        ));
        assert!(queue.is_empty());
    }

    #[test]
    fn dequeue_keeps_future_blocks() {
        let keypair = Keypair::generate();
        let mut queue = LocalBlock::new(2);
        let mut future = Block::default();
        future.body.last_epoch = HashType([1; 32]);
        future.body.nonce = Nonce::new(3);
        future.sign(&keypair.secret);
        queue.enqueue_block(future).unwrap();

        assert!(matches!(
            queue.dequeue_block(None, HashType([1; 32]), Nonce::new(2), 0),
            Err(BlossomError::InvalidBlockNonce { expected, actual })
                if expected == Nonce::new(2) && actual == Nonce::new(3)
        ));
        assert!(queue.contains_nonce(Nonce::new(3)));
    }

    #[test]
    fn dequeue_rejects_wrong_validator() {
        let keypair = Keypair::generate();
        let mut queue = LocalBlock::new(2);
        let mut block = Block::default();
        block.body.last_epoch = HashType([1; 32]);
        block.body.nonce = Nonce::new(1);
        block.sign(&keypair.secret);
        queue.enqueue_block(block).unwrap();

        assert!(matches!(
            queue.dequeue_block(Some(PubKey([99; 32])), HashType([1; 32]), Nonce::new(1), 0),
            Err(BlossomError::UnknownSender)
        ));
        assert!(queue.is_empty());
    }
}
