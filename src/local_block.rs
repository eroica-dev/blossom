use std::collections::VecDeque;
use std::mem;

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

        self.ensure_enqueueable(&self.build_block)?;
        let hash = self.build_block.hash;
        let block = mem::take(&mut self.build_block);
        self.block_deque.push_back(block);
        Ok(hash)
    }

    pub fn enqueue_block(&mut self, block: Block) -> Result<HashType> {
        block.verify_integrity()?;
        self.enqueue_preverified_block(block)
    }

    /// Enqueue a block after the caller has already applied the appropriate
    /// integrity checks for its trust boundary.
    pub fn enqueue_preverified_block(&mut self, block: Block) -> Result<HashType> {
        self.ensure_enqueueable(&block)?;
        let hash = block.hash;
        self.block_deque.push_back(block);
        Ok(hash)
    }

    fn ensure_enqueueable(&self, block: &Block) -> Result<()> {
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

        Ok(())
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
    fn add_transaction_defers_block_hash_work_until_close() {
        let keypair = Keypair::generate();
        let mut queue = LocalBlock::new(2);
        let initial_hash = queue.build_block.hash;
        let tx_hash = queue.add_transaction(Transaction::new("tx"));

        assert_eq!(tx_hash, HashType::hash(b"tx"));
        assert_eq!(queue.build_block.hash, initial_hash);
        assert_eq!(queue.build_block.body.merkle_root, HashType::default());

        let block_hash = queue
            .close_block(&keypair.secret, HashType([1; 32]), Nonce::new(1))
            .unwrap();
        let block = queue.block_deque.front().unwrap();

        assert_eq!(block.hash, block_hash);
        assert_ne!(block.body.merkle_root, HashType::default());
        assert!(block.verify_integrity().is_ok());
    }

    #[test]
    fn close_block_preserves_pending_block_when_queue_full() {
        let keypair = Keypair::generate();
        let mut queue = LocalBlock::new(0);
        queue.add_transaction(Transaction::new("tx"));

        assert_eq!(
            queue.close_block(&keypair.secret, HashType([1; 32]), Nonce::new(1)),
            Err(BlossomError::BlockQueueFull)
        );
        assert_eq!(queue.build_block.body.txs.len(), 1);
        assert_eq!(queue.len(), 0);
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
    fn preverified_enqueue_allows_trust_mode_unsigned_blocks() {
        let keypair = Keypair::generate();
        let mut queue = LocalBlock::new(1);
        let mut block = Block::default();
        block.body.last_epoch = HashType([1; 32]);
        block.body.nonce = Nonce::new(1);
        block.seal_unsigned(keypair.public);

        assert_eq!(
            queue.enqueue_block(block.clone()),
            Err(BlossomError::SignatureError)
        );
        let hash = queue.enqueue_preverified_block(block).unwrap();

        assert_ne!(hash, HashType::default());
        assert_eq!(queue.len(), 1);
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
