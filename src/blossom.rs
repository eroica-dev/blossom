use std::any::Any;
use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::block::Block;
use crate::crypto::{PubKey, Signature};
use crate::error::Result;
use crate::hash::{DoHash, HashType};
use crate::messages::{MSGKey, Msg};
use crate::node::NodeIdentity;
use crate::nonce::Nonce;
use crate::state::LocalState;

const MESSAGE_SIGNATURE_DOMAIN: &[u8] = b"blossom.message-signature.v1";

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Default)]
pub struct Header {
    pub sender: PubKey,
    pub last_epoch: HashType,
    pub nonce: Nonce,
    pub round: u8,
    pub signature: Signature,
}

impl Header {
    pub fn signature_hash<B: BlossomBody>(&self, kind: MSGKey, body: &B) -> HashType {
        Self::signature_hash_for_body(
            &self.sender,
            &self.last_epoch,
            self.nonce,
            self.round,
            kind,
            body,
        )
    }

    pub fn signature_hash_for_body<B: BlossomBody>(
        sender: &PubKey,
        last_epoch: &HashType,
        nonce: Nonce,
        round: u8,
        kind: MSGKey,
        body: &B,
    ) -> HashType {
        let mut sha256 = Sha256::new();
        Self::update_signature_context(&mut sha256, sender, last_epoch, nonce, round, kind);
        body.update_signing_hash(&mut sha256);
        HashType::from_byte_hash(sha256.finalize().into())
    }

    pub fn signature_hash_for_bytes(
        sender: &PubKey,
        last_epoch: &HashType,
        nonce: Nonce,
        round: u8,
        kind: MSGKey,
        body_bytes: &[u8],
    ) -> HashType {
        let mut sha256 = Sha256::new();
        Self::update_signature_context(&mut sha256, sender, last_epoch, nonce, round, kind);
        sha256.update(body_bytes);
        HashType::from_byte_hash(sha256.finalize().into())
    }

    fn update_signature_context(
        sha256: &mut Sha256,
        sender: &PubKey,
        last_epoch: &HashType,
        nonce: Nonce,
        round: u8,
        kind: MSGKey,
    ) {
        sha256.update(MESSAGE_SIGNATURE_DOMAIN);
        sha256.update([kind.signature_tag()]);
        sha256.update(sender.as_ref());
        sha256.update(last_epoch.as_ref());
        sha256.update(nonce.to_le_bytes());
        sha256.update([round]);
    }

    pub fn verify_signature<B: BlossomBody>(&self, kind: MSGKey, body: &B) -> Result<()> {
        self.signature
            .verify(self.signature_hash(kind, body).as_ref(), &self.sender)
    }

    pub fn verify_header(&self, state: &mut LocalState) -> Option<bool> {
        let consensus = state.get_mut_consensus(&self.last_epoch, self.nonce);
        if !consensus.is_peer_member_of_round(&self.sender, self.round) {
            log::error!("unknown sender {} for round {}", self.sender, self.round);
            return Some(false);
        }
        Some(true)
    }
}

pub trait BlossomMessage: std::fmt::Debug + Sized {
    fn kind(&self) -> MSGKey;

    fn as_any(&self) -> &dyn Any
    where
        Self: 'static,
    {
        self
    }

    fn header(&self) -> &Header;

    fn sender(&self) -> &PubKey {
        &self.header().sender
    }

    fn body_hash(&self) -> HashType;

    fn verify_header(&self, state: &mut LocalState) -> Option<bool> {
        self.header().verify_header(state)
    }

    fn last_epoch(&self) -> HashType {
        self.header().last_epoch
    }

    fn round(&self) -> u8 {
        self.header().round
    }

    fn msg(&self) -> Msg;
}

pub trait BlossomBody {
    fn signature(&self, node: &NodeIdentity) -> Result<Signature> {
        node.sign(self.signing_hash().as_ref())
    }

    fn verify(&self, signature: &Signature, pub_key: &PubKey) -> Result<()> {
        signature.verify(self.signing_hash().as_ref(), pub_key)
    }

    fn signing_hash(&self) -> HashType {
        let mut sha256 = Sha256::new();
        self.update_signing_hash(&mut sha256);
        HashType::from_byte_hash(sha256.finalize().into())
    }

    fn update_signing_hash(&self, sha256: &mut Sha256) {
        sha256.update(self.to_bytes());
    }

    fn to_bytes(&self) -> Vec<u8>;
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Default)]
pub struct SignatureTree(pub BTreeMap<HashType, SignaturesForHash>);

pub type StSignatures = Vec<(PubKey, Signature)>;
pub type SignaturesForHash = (StSignatures, BTreeMap<HashType, ()>);

impl SignatureTree {
    pub fn hash(&self) -> HashType {
        self.0.hash()
    }

    pub fn insert(
        &mut self,
        signed_by: &PubKey,
        signature: &Signature,
        blocks: &BTreeMap<HashType, ()>,
    ) {
        let key = blocks.hash();
        match self.0.get(&key) {
            Some((signers, value)) => {
                let mut signature_list = signers.clone();
                signature_list.push((*signed_by, *signature));
                self.0.insert(key, (signature_list, value.clone()));
            }
            None => {
                self.0
                    .insert(key, (vec![(*signed_by, *signature)], blocks.clone()));
            }
        }
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn get(&self, key: &HashType) -> Option<&SignaturesForHash> {
        self.0.get(key)
    }

    pub fn remove(&mut self, key: &HashType) -> Option<SignaturesForHash> {
        self.0.remove(key)
    }

    pub fn verify(&self) -> bool {
        for (blocks_hash, (signatures, blocks)) in &self.0 {
            if blocks.hash() != *blocks_hash {
                return false;
            }

            for (pub_key, signature) in signatures {
                if signature.verify(blocks_hash.as_ref(), pub_key).is_err() {
                    return false;
                }
            }
        }
        true
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct Dispatch {
    pub header: Header,
    pub body: DispatchBody,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Default)]
pub struct DispatchBody {
    pub blocks: BTreeMap<HashType, Block>,
    pub blocks_hash: HashType,
    pub signature_tree: SignatureTree,
    pub signature_tree_hash: HashType,
}

impl DispatchBody {
    pub fn verify_body(
        &self,
        already_verified_blocks: &BTreeMap<HashType, Block>,
    ) -> (BTreeMap<HashType, Block>, HashType, SignatureTree, HashType) {
        self.verify_body_with_signature_checks(already_verified_blocks, true)
    }

    pub fn verify_body_trusted(
        &self,
        already_verified_blocks: &BTreeMap<HashType, Block>,
    ) -> (BTreeMap<HashType, Block>, HashType, SignatureTree, HashType) {
        self.verify_body_with_signature_checks(already_verified_blocks, false)
    }

    fn verify_body_with_signature_checks(
        &self,
        already_verified_blocks: &BTreeMap<HashType, Block>,
        verify_signatures: bool,
    ) -> (BTreeMap<HashType, Block>, HashType, SignatureTree, HashType) {
        let mut accepted_blocks = BTreeMap::new();

        if self.blocks.hash() != self.blocks_hash {
            return (
                accepted_blocks,
                HashType::default(),
                SignatureTree::default(),
                HashType::default(),
            );
        }

        for (sent_hash, block) in &self.blocks {
            if already_verified_blocks.contains_key(sent_hash) {
                continue;
            }
            if *sent_hash != block.hash() {
                continue;
            }
            let block_ok = if verify_signatures {
                block.verify_signature().is_ok()
            } else {
                block.verify_unsigned_integrity().is_ok()
            };
            if !block_ok {
                continue;
            }
            accepted_blocks.insert(*sent_hash, block.clone());
        }

        let signature_tree = if verify_signatures {
            if self.signature_tree.verify() {
                self.signature_tree.clone()
            } else {
                SignatureTree::default()
            }
        } else if self.signature_tree.hash() == self.signature_tree_hash {
            self.signature_tree.clone()
        } else {
            SignatureTree::default()
        };
        let signature_tree_hash = signature_tree.hash();

        (
            accepted_blocks.clone(),
            accepted_blocks.hash(),
            signature_tree,
            signature_tree_hash,
        )
    }
}

impl BlossomBody for DispatchBody {
    fn update_signing_hash(&self, sha256: &mut Sha256) {
        sha256.update(self.blocks_hash.as_ref());
        sha256.update(self.signature_tree_hash.as_ref());
    }

    fn to_bytes(&self) -> Vec<u8> {
        [self.blocks_hash.as_ref(), self.signature_tree_hash.as_ref()].concat()
    }
}

impl Dispatch {
    pub fn verify(&self, state: &mut LocalState) -> bool {
        let quorum = state.get_mut_quorum(
            &self.header.last_epoch,
            self.header.nonce,
            self.header.round,
        );
        quorum.received_dispatches.push(self.header.sender);
        quorum.pending_dispatches.push(self.clone());
        true
    }

    pub fn add_blocks(
        pending_blocks: &mut BTreeMap<HashType, Block>,
        blocks: &BTreeMap<HashType, Block>,
    ) {
        for (hash, block) in blocks {
            if !block.body.txs.is_empty() {
                pending_blocks.insert(*hash, block.clone());
            }
        }
    }
}

impl BlossomMessage for Dispatch {
    fn kind(&self) -> MSGKey {
        MSGKey::Dispatch
    }

    fn header(&self) -> &Header {
        &self.header
    }

    fn body_hash(&self) -> HashType {
        self.body.blocks_hash
    }

    fn msg(&self) -> Msg {
        Msg::Dispatch(self.clone())
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct EchoResponse {
    pub header: Header,
    pub body: EchoResponseBody,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Default)]
pub struct EchoResponseBody {
    pub sender: PubKey,
    pub blocks_hash: HashType,
    pub signature_tree_hash: HashType,
}

impl BlossomBody for EchoResponseBody {
    fn update_signing_hash(&self, sha256: &mut Sha256) {
        sha256.update(self.sender.as_ref());
        sha256.update(self.blocks_hash.as_ref());
        sha256.update(self.signature_tree_hash.as_ref());
    }

    fn to_bytes(&self) -> Vec<u8> {
        [
            self.sender.as_ref(),
            self.blocks_hash.as_ref(),
            self.signature_tree_hash.as_ref(),
        ]
        .concat()
    }
}

impl BlossomMessage for EchoResponse {
    fn kind(&self) -> MSGKey {
        MSGKey::EchoResponse
    }

    fn header(&self) -> &Header {
        &self.header
    }

    fn body_hash(&self) -> HashType {
        self.body.blocks_hash
    }

    fn msg(&self) -> Msg {
        Msg::EchoResponse(self.clone())
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct EchoRequest {
    pub header: Header,
    pub requested_blocks: BTreeMap<HashType, ()>,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct EchoReDispatch {
    pub header: Header,
    pub redispatched_blocks: BTreeMap<HashType, Block>,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct Verification {
    pub header: Header,
    pub body: VerificationBody,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Default)]
pub struct VerificationBody {
    pub blocks_hash: HashType,
    pub blocks: BTreeMap<HashType, ()>,
}

impl BlossomBody for VerificationBody {
    fn update_signing_hash(&self, sha256: &mut Sha256) {
        sha256.update(self.blocks_hash.as_ref());
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.blocks_hash.as_ref().to_vec()
    }
}

impl BlossomMessage for Verification {
    fn kind(&self) -> MSGKey {
        MSGKey::Verification
    }

    fn header(&self) -> &Header {
        &self.header
    }

    fn body_hash(&self) -> HashType {
        self.body.blocks_hash
    }

    fn msg(&self) -> Msg {
        Msg::Verification(self.clone())
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct Proposal {
    pub header: Header,
    pub body: ProposalBody,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Default)]
pub struct ProposalBody {
    pub consensus: bool,
    pub approved_blocks: Option<BTreeMap<HashType, ()>>,
    pub approved_hash: Option<HashType>,
    pub verif: Option<Vec<(PubKey, Signature)>>,
    pub signature_tree: Option<BTreeMap<HashType, ()>>,
    pub signature_tree_hash: Option<HashType>,
}

impl BlossomBody for ProposalBody {
    fn update_signing_hash(&self, sha256: &mut Sha256) {
        if !self.consensus {
            sha256.update([0]);
            return;
        }

        sha256.update(self.approved_hash.unwrap_or_default().as_ref());
        sha256.update(self.signature_tree_hash.unwrap_or_default().as_ref());
    }

    fn to_bytes(&self) -> Vec<u8> {
        if !self.consensus {
            return vec![0];
        }

        [
            self.approved_hash.unwrap_or_default().as_ref(),
            self.signature_tree_hash.unwrap_or_default().as_ref(),
        ]
        .concat()
    }
}

impl BlossomMessage for Proposal {
    fn kind(&self) -> MSGKey {
        MSGKey::Proposal
    }

    fn header(&self) -> &Header {
        &self.header
    }

    fn body_hash(&self) -> HashType {
        self.body.approved_hash.unwrap_or_default()
    }

    fn msg(&self) -> Msg {
        Msg::Proposal(self.clone())
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct Commit {
    pub header: Header,
    pub body: CommitBody,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Default)]
pub struct CommitBody {
    pub consensus: bool,
    pub signature_tree_insert: Option<BTreeMap<HashType, SignaturesForHash>>,
}

impl BlossomBody for CommitBody {
    fn update_signing_hash(&self, sha256: &mut Sha256) {
        match &self.signature_tree_insert {
            Some(tree) => {
                for key in tree.keys() {
                    sha256.update(key.as_ref());
                }
            }
            None => sha256.update([0]),
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        match &self.signature_tree_insert {
            Some(tree) => {
                let mut bytes = Vec::with_capacity(tree.len() * 32);
                for key in tree.keys() {
                    bytes.extend_from_slice(key.as_ref());
                }
                bytes
            }
            None => vec![0],
        }
    }
}

impl BlossomMessage for Commit {
    fn kind(&self) -> MSGKey {
        MSGKey::Commit
    }

    fn header(&self) -> &Header {
        &self.header
    }

    fn body_hash(&self) -> HashType {
        self.body
            .signature_tree_insert
            .as_ref()
            .and_then(|tree| tree.keys().next().copied())
            .unwrap_or_default()
    }

    fn msg(&self) -> Msg {
        Msg::Commit(self.clone())
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct EpochStarted {
    pub header: Header,
    pub body: EpochStartedBody,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Default)]
pub struct EpochStartedBody {}

impl BlossomBody for EpochStartedBody {
    fn update_signing_hash(&self, sha256: &mut Sha256) {
        sha256.update([0]);
    }

    fn to_bytes(&self) -> Vec<u8> {
        vec![0]
    }
}

impl BlossomMessage for EpochStarted {
    fn kind(&self) -> MSGKey {
        MSGKey::EpochStarted
    }

    fn header(&self) -> &Header {
        &self.header
    }

    fn body_hash(&self) -> HashType {
        HashType::default()
    }

    fn msg(&self) -> Msg {
        Msg::EpochStarted(self.clone())
    }
}

impl BlossomMessage for EchoRequest {
    fn kind(&self) -> MSGKey {
        MSGKey::EchoRequest
    }

    fn header(&self) -> &Header {
        &self.header
    }

    fn body_hash(&self) -> HashType {
        self.requested_blocks.hash()
    }

    fn msg(&self) -> Msg {
        Msg::EchoRequest(self.clone())
    }
}

impl BlossomMessage for EchoReDispatch {
    fn kind(&self) -> MSGKey {
        MSGKey::EchoReDispatch
    }

    fn header(&self) -> &Header {
        &self.header
    }

    fn body_hash(&self) -> HashType {
        self.redispatched_blocks.hash()
    }

    fn msg(&self) -> Msg {
        Msg::EchoReDispatch(self.clone())
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct Ballot {
    pub ballot: (String, Vec<Verification>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{Block, Transaction};
    use crate::crypto::Keypair;
    use crate::node::NodeIdentity;
    use crate::nonce::Nonce;

    fn node(keypair: &Keypair) -> NodeIdentity {
        NodeIdentity::new(
            keypair.public,
            Some(keypair.secret),
            "tcp",
            "127.0.0.1",
            8080,
            false,
        )
    }

    fn signed_block(keypair: &Keypair) -> Block {
        let mut block = Block::default();
        block.body.nonce = Nonce::new(1);
        block.body.txs.push(Transaction::new("tx"));
        block.sign(&keypair.secret);
        block
    }

    #[test]
    fn signature_tree_insert_verify_get_and_remove() {
        let keypair = Keypair::generate();
        let mut blocks = BTreeMap::new();
        blocks.insert(HashType([1; 32]), ());
        let blocks_hash = blocks.hash();
        let signature = Signature::sign(blocks_hash.as_ref(), &keypair.secret);
        let mut tree = SignatureTree::default();

        tree.insert(&keypair.public, &signature, &blocks);

        assert_eq!(tree.len(), 1);
        assert!(!tree.is_empty());
        assert!(tree.verify());
        assert!(tree.get(&blocks_hash).is_some());
        assert!(tree.remove(&blocks_hash).is_some());
        assert!(tree.is_empty());
    }

    #[test]
    fn signature_tree_rejects_bad_hashes_and_signatures() {
        let keypair = Keypair::generate();
        let mut blocks = BTreeMap::new();
        blocks.insert(HashType([1; 32]), ());
        let signature = Signature::sign(HashType([9; 32]).as_ref(), &keypair.secret);
        let mut tree = SignatureTree::default();
        tree.0
            .insert(blocks.hash(), (vec![(keypair.public, signature)], blocks));

        assert!(!tree.verify());
    }

    #[test]
    fn dispatch_body_accepts_valid_blocks_and_rejects_bad_body_hash() {
        let keypair = Keypair::generate();
        let block = signed_block(&keypair);
        let mut blocks = BTreeMap::new();
        blocks.insert(block.hash, block.clone());
        let body = DispatchBody {
            blocks_hash: blocks.hash(),
            blocks: blocks.clone(),
            signature_tree: SignatureTree::default(),
            signature_tree_hash: SignatureTree::default().hash(),
        };

        let (accepted, accepted_hash, tree, tree_hash) = body.verify_body(&BTreeMap::new());
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted.get(&block.hash).unwrap().hash, block.hash);
        assert_eq!(accepted_hash, accepted.hash());
        assert_eq!(tree_hash, tree.hash());

        let mut bad_body = body;
        bad_body.blocks_hash = HashType([9; 32]);
        let (accepted, accepted_hash, _, tree_hash) = bad_body.verify_body(&BTreeMap::new());
        assert!(accepted.is_empty());
        assert_eq!(accepted_hash, HashType::default());
        assert_eq!(tree_hash, HashType::default());
    }

    #[test]
    fn trusted_dispatch_body_accepts_unsigned_integrity_checked_blocks() {
        let keypair = Keypair::generate();
        let mut block = Block::default();
        block.body.nonce = Nonce::new(1);
        block.body.txs.push(Transaction::new("tx"));
        block.seal_unsigned(keypair.public);
        let mut blocks = BTreeMap::new();
        blocks.insert(block.hash, block.clone());
        let body = DispatchBody {
            blocks_hash: blocks.hash(),
            blocks,
            signature_tree: SignatureTree::default(),
            signature_tree_hash: SignatureTree::default().hash(),
        };

        let (verified, _, _, _) = body.verify_body(&BTreeMap::new());
        assert!(verified.is_empty());

        let (trusted, trusted_hash, _, _) = body.verify_body_trusted(&BTreeMap::new());
        assert_eq!(trusted.len(), 1);
        assert_eq!(trusted.get(&block.hash).unwrap().hash, block.hash);
        assert_eq!(trusted_hash, trusted.hash());
    }

    #[test]
    fn dispatch_add_blocks_skips_empty_blocks() {
        let keypair = Keypair::generate();
        let full = signed_block(&keypair);
        let mut empty = Block::default();
        empty.body.nonce = Nonce::new(1);
        empty.sign(&keypair.secret);
        let mut incoming = BTreeMap::new();
        incoming.insert(full.hash, full.clone());
        incoming.insert(empty.hash, empty);
        let mut pending = BTreeMap::new();

        Dispatch::add_blocks(&mut pending, &incoming);

        assert_eq!(pending.len(), 1);
        assert!(pending.contains_key(&full.hash));
    }

    #[test]
    fn body_signatures_verify_against_sender_identity() {
        let keypair = Keypair::generate();
        let node = node(&keypair);
        let body = VerificationBody {
            blocks_hash: HashType([3; 32]),
            blocks: BTreeMap::new(),
        };
        let signature = body.signature(&node).unwrap();

        assert!(body.verify(&signature, &keypair.public).is_ok());
        assert!(body.verify(&signature, &PubKey([9; 32])).is_err());
    }

    #[test]
    fn header_signature_binds_message_context() {
        let keypair = Keypair::generate();
        let body = VerificationBody {
            blocks_hash: HashType([3; 32]),
            blocks: BTreeMap::new(),
        };
        let last_epoch = HashType([2; 32]);
        let nonce = Nonce::new(7);
        let round = 1;
        let signature_hash = Header::signature_hash_for_body(
            &keypair.public,
            &last_epoch,
            nonce,
            round,
            MSGKey::Verification,
            &body,
        );
        let header = Header {
            sender: keypair.public,
            last_epoch,
            nonce,
            round,
            signature: keypair.signer().sign(signature_hash.as_ref()),
        };

        assert!(header.verify_signature(MSGKey::Verification, &body).is_ok());

        let mut replayed = header;
        replayed.round = 2;
        assert!(
            replayed
                .verify_signature(MSGKey::Verification, &body)
                .is_err()
        );
    }
}
