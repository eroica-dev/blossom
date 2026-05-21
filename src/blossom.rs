use std::any::Any;
use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::block::Block;
use crate::crypto::{PubKey, Signature, verify_batch};
use crate::error::{BlossomError, Result};
use crate::hash::{DoHash, HashType, ProtocolHasher};
use crate::messages::{MSGKey, Msg};
use crate::node::NodeIdentity;
use crate::nonce::Nonce;
use crate::state::{
    LocalState, PendingDispatch, configured_max_pending_raw_dispatch_bytes,
    configured_max_pending_raw_dispatch_bytes_per_sender,
};

const MESSAGE_SIGNATURE_DOMAIN: &[u8] = b"blossom.message-signature.v1";
const BATCH_SIGNATURE_VERIFY_THRESHOLD: usize = 4;

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
        let mut hasher = ProtocolHasher::new();
        Self::update_signature_context(&mut hasher, sender, last_epoch, nonce, round, kind);
        body.update_signing_hash(&mut hasher);
        hasher.finalize()
    }

    pub fn signature_hash_for_bytes(
        sender: &PubKey,
        last_epoch: &HashType,
        nonce: Nonce,
        round: u8,
        kind: MSGKey,
        body_bytes: &[u8],
    ) -> HashType {
        let mut hasher = ProtocolHasher::new();
        Self::update_signature_context(&mut hasher, sender, last_epoch, nonce, round, kind);
        hasher.update(body_bytes);
        hasher.finalize()
    }

    fn update_signature_context(
        hasher: &mut ProtocolHasher,
        sender: &PubKey,
        last_epoch: &HashType,
        nonce: Nonce,
        round: u8,
        kind: MSGKey,
    ) {
        hasher.update(MESSAGE_SIGNATURE_DOMAIN);
        hasher.update([kind.signature_tag()]);
        hasher.update(sender.as_ref());
        hasher.update(last_epoch.as_ref());
        hasher.update(nonce.to_le_bytes());
        hasher.update([round]);
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
        let mut hasher = ProtocolHasher::new();
        self.update_signing_hash(&mut hasher);
        hasher.finalize()
    }

    fn update_signing_hash(&self, hasher: &mut ProtocolHasher) {
        hasher.update(self.to_bytes());
    }

    fn to_bytes(&self) -> Vec<u8>;
}

impl BlossomBody for BTreeMap<HashType, ()> {
    fn update_signing_hash(&self, hasher: &mut ProtocolHasher) {
        hasher.update((self.len() as u64).to_le_bytes());
        for hash in self.keys() {
            hasher.update(hash.as_ref());
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 + (self.len() * 32));
        bytes.extend_from_slice(&(self.len() as u64).to_le_bytes());
        for hash in self.keys() {
            bytes.extend_from_slice(hash.as_ref());
        }
        bytes
    }
}

impl BlossomBody for BTreeMap<HashType, Block> {
    fn update_signing_hash(&self, hasher: &mut ProtocolHasher) {
        hasher.update((self.len() as u64).to_le_bytes());
        for (hash, block) in self {
            hasher.update(hash.as_ref());
            hasher.update(block.hash.as_ref());
            hasher.update(block.body.hash().as_ref());
            hasher.update(block.signature.as_ref());
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 + (self.len() * (32 + 32 + 32 + 64)));
        bytes.extend_from_slice(&(self.len() as u64).to_le_bytes());
        for (hash, block) in self {
            bytes.extend_from_slice(hash.as_ref());
            bytes.extend_from_slice(block.hash.as_ref());
            bytes.extend_from_slice(block.body.hash().as_ref());
            bytes.extend_from_slice(block.signature.as_ref());
        }
        bytes
    }
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
        match self.0.entry(key) {
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                entry.get_mut().0.push((*signed_by, *signature));
            }
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert((vec![(*signed_by, *signature)], blocks.clone()));
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
        let signature_count = self
            .0
            .values()
            .map(|(signatures, _)| signatures.len())
            .sum::<usize>();
        if signature_count >= BATCH_SIGNATURE_VERIFY_THRESHOLD {
            return self.verify_batched();
        }

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

    fn verify_batched(&self) -> bool {
        let mut messages = Vec::new();
        let mut signatures_to_verify = Vec::new();
        let mut public_keys = Vec::new();

        for (blocks_hash, (signatures, blocks)) in &self.0 {
            if blocks.hash() != *blocks_hash {
                return false;
            }

            for (pub_key, signature) in signatures {
                messages.push(blocks_hash.as_ref());
                signatures_to_verify.push(*signature);
                public_keys.push(*pub_key);
            }
        }

        verify_batch(&messages, &signatures_to_verify, &public_keys).is_ok()
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct Dispatch {
    pub header: Header,
    pub body: DispatchBody,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct DispatchBody {
    pub blocks: BTreeMap<HashType, Block>,
    pub blocks_hash: HashType,
    pub signature_tree: SignatureTree,
    pub signature_tree_hash: HashType,
}

impl Default for DispatchBody {
    fn default() -> Self {
        let blocks = BTreeMap::new();
        let signature_tree = SignatureTree::default();
        Self {
            blocks_hash: blocks.hash(),
            blocks,
            signature_tree_hash: signature_tree.hash(),
            signature_tree,
        }
    }
}

impl DispatchBody {
    pub fn validate(&self) -> Result<()> {
        if self.blocks.hash() != self.blocks_hash {
            return Err(BlossomError::WireProtocol(
                "dispatch blocks hash does not match block set".to_string(),
            ));
        }
        if self.signature_tree.hash() != self.signature_tree_hash {
            return Err(BlossomError::WireProtocol(
                "dispatch signature-tree hash does not match signature tree".to_string(),
            ));
        }
        Ok(())
    }

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

        if self.validate().is_err() {
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
            let block_ok = if verify_signatures {
                block.verify_integrity_with_hash(*sent_hash).is_ok()
            } else {
                block
                    .verify_unsigned_integrity_with_hash(*sent_hash)
                    .is_ok()
            };
            if !block_ok {
                continue;
            }
            accepted_blocks.insert(*sent_hash, block.clone());
        }

        let accepted_blocks_hash = accepted_blocks.hash();
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
            accepted_blocks,
            accepted_blocks_hash,
            signature_tree,
            signature_tree_hash,
        )
    }
}

impl BlossomBody for DispatchBody {
    fn update_signing_hash(&self, hasher: &mut ProtocolHasher) {
        hasher.update(self.blocks_hash.as_ref());
        hasher.update(self.signature_tree_hash.as_ref());
    }

    fn to_bytes(&self) -> Vec<u8> {
        [self.blocks_hash.as_ref(), self.signature_tree_hash.as_ref()].concat()
    }
}

impl Dispatch {
    pub fn try_accept_into_state(self, state: &mut LocalState) -> Result<()> {
        let sender = self.header.sender;
        let quorum = state.get_mut_quorum(
            &self.header.last_epoch,
            self.header.nonce,
            self.header.round,
        );
        if quorum.received_dispatches.contains(&sender) {
            return Err(BlossomError::WireProtocol(format!(
                "duplicate dispatch from {sender}"
            )));
        }
        quorum.try_push_pending_dispatch(
            PendingDispatch::Decoded(self.clone()),
            configured_max_pending_raw_dispatch_bytes(),
            configured_max_pending_raw_dispatch_bytes_per_sender(),
        )?;
        quorum.msg_matrix.update(true, Msg::Dispatch(self));
        quorum.received_dispatches.push(sender);
        Ok(())
    }

    pub fn accept_into_state(self, state: &mut LocalState) -> bool {
        self.try_accept_into_state(state).is_ok()
    }

    pub fn verify(&self, state: &mut LocalState) -> bool {
        self.clone().accept_into_state(state)
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
    fn update_signing_hash(&self, hasher: &mut ProtocolHasher) {
        hasher.update(self.sender.as_ref());
        hasher.update(self.blocks_hash.as_ref());
        hasher.update(self.signature_tree_hash.as_ref());
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

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct VerificationBody {
    pub blocks_hash: HashType,
    pub blocks: BTreeMap<HashType, ()>,
}

impl Default for VerificationBody {
    fn default() -> Self {
        let blocks = BTreeMap::new();
        Self {
            blocks_hash: blocks.hash(),
            blocks,
        }
    }
}

impl VerificationBody {
    pub fn validate(&self) -> Result<()> {
        if self.blocks.hash() != self.blocks_hash {
            return Err(BlossomError::WireProtocol(
                "verification blocks hash does not match block set".to_string(),
            ));
        }
        Ok(())
    }
}

impl BlossomBody for VerificationBody {
    fn update_signing_hash(&self, hasher: &mut ProtocolHasher) {
        hasher.update(self.blocks_hash.as_ref());
        self.blocks.update_signing_hash(hasher);
    }

    fn to_bytes(&self) -> Vec<u8> {
        [self.blocks_hash.as_ref(), self.blocks.to_bytes().as_slice()].concat()
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

impl ProposalBody {
    pub fn validate(&self) -> Result<()> {
        if !self.consensus {
            return Ok(());
        }

        let approved_blocks = self.approved_blocks.as_ref().ok_or_else(|| {
            BlossomError::WireProtocol(
                "consensus proposal must include approved blocks".to_string(),
            )
        })?;
        let approved_hash = self.approved_hash.ok_or_else(|| {
            BlossomError::WireProtocol("consensus proposal must include approved hash".to_string())
        })?;
        if approved_blocks.hash() != approved_hash {
            return Err(BlossomError::WireProtocol(
                "proposal approved hash does not match approved blocks".to_string(),
            ));
        }

        match (&self.signature_tree, self.signature_tree_hash) {
            (Some(signature_tree), Some(signature_tree_hash))
                if signature_tree.hash() != signature_tree_hash =>
            {
                return Err(BlossomError::WireProtocol(
                    "proposal signature-tree hash does not match signature tree".to_string(),
                ));
            }
            _ => {}
        }

        Ok(())
    }
}

impl BlossomBody for ProposalBody {
    fn update_signing_hash(&self, hasher: &mut ProtocolHasher) {
        hasher.update([self.consensus as u8]);
        if !self.consensus {
            return;
        }

        match &self.approved_blocks {
            Some(blocks) => {
                hasher.update([1]);
                blocks.update_signing_hash(hasher);
            }
            None => hasher.update([0]),
        }
        match self.approved_hash {
            Some(hash) => {
                hasher.update([1]);
                hasher.update(hash.as_ref());
            }
            None => hasher.update([0]),
        }
        match &self.verif {
            Some(verifications) => {
                hasher.update([1]);
                hasher.update((verifications.len() as u64).to_le_bytes());
                for (pubkey, signature) in verifications {
                    hasher.update(pubkey.as_ref());
                    hasher.update(signature.as_ref());
                }
            }
            None => hasher.update([0]),
        }
        match &self.signature_tree {
            Some(tree) => {
                hasher.update([1]);
                tree.update_signing_hash(hasher);
            }
            None => hasher.update([0]),
        }
        match self.signature_tree_hash {
            Some(hash) => {
                hasher.update([1]);
                hasher.update(hash.as_ref());
            }
            None => hasher.update([0]),
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.signing_hash().to_bytes()
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
    fn update_signing_hash(&self, hasher: &mut ProtocolHasher) {
        hasher.update([self.consensus as u8]);
        match &self.signature_tree_insert {
            Some(tree) => {
                hasher.update([1]);
                hasher.update((tree.len() as u64).to_le_bytes());
                for key in tree.keys() {
                    hasher.update(key.as_ref());
                }
            }
            None => hasher.update([0]),
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.consensus as u8);
        match &self.signature_tree_insert {
            Some(tree) => {
                bytes.push(1);
                bytes.extend_from_slice(&(tree.len() as u64).to_le_bytes());
                for key in tree.keys() {
                    bytes.extend_from_slice(key.as_ref());
                }
                bytes
            }
            None => {
                bytes.push(0);
                bytes
            }
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
    fn update_signing_hash(&self, hasher: &mut ProtocolHasher) {
        hasher.update([0]);
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
    use crate::error::BlossomError;
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

        assert!(body.validate().is_ok());
        let (accepted, accepted_hash, tree, tree_hash) = body.verify_body(&BTreeMap::new());
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted.get(&block.hash).unwrap().hash, block.hash);
        assert_eq!(accepted_hash, accepted.hash());
        assert_eq!(tree_hash, tree.hash());

        let mut bad_body = body;
        bad_body.blocks_hash = HashType([9; 32]);
        assert!(matches!(
            bad_body.validate(),
            Err(BlossomError::WireProtocol(message))
                if message.contains("dispatch blocks hash")
        ));
        let (accepted, accepted_hash, _, tree_hash) = bad_body.verify_body(&BTreeMap::new());
        assert!(accepted.is_empty());
        assert_eq!(accepted_hash, HashType::default());
        assert_eq!(tree_hash, HashType::default());
    }

    #[test]
    fn dispatch_body_rejects_bad_signature_tree_hash() {
        let keypair = Keypair::generate();
        let block = signed_block(&keypair);
        let mut blocks = BTreeMap::new();
        blocks.insert(block.hash, block);
        let body = DispatchBody {
            blocks_hash: blocks.hash(),
            blocks,
            signature_tree: SignatureTree::default(),
            signature_tree_hash: HashType([9; 32]),
        };

        assert!(matches!(
            body.validate(),
            Err(BlossomError::WireProtocol(message))
                if message.contains("dispatch signature-tree hash")
        ));
    }

    #[test]
    fn verified_dispatch_rejects_signed_blocks_with_bad_merkle_roots() {
        let keypair = Keypair::generate();
        let signer = keypair.signer();
        let mut block = Block::default();
        block.body.validator = keypair.public;
        block.body.nonce = Nonce::new(1);
        block.body.txs.push(Transaction::new("tx"));
        block.body.merkle_root = HashType([9; 32]);
        block.hash = block.body.hash();
        block.signature = signer.sign(block.hash.as_ref());

        assert!(block.verify_signature().is_ok());
        assert_eq!(
            block.verify_integrity(),
            Err(BlossomError::InvalidBlockHash)
        );

        let mut blocks = BTreeMap::new();
        blocks.insert(block.hash, block);
        let body = DispatchBody {
            blocks_hash: blocks.hash(),
            blocks,
            signature_tree: SignatureTree::default(),
            signature_tree_hash: SignatureTree::default().hash(),
        };

        let (accepted, accepted_hash, _, _) = body.verify_body(&BTreeMap::new());

        assert!(accepted.is_empty());
        assert_eq!(accepted_hash, accepted.hash());
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

    #[test]
    fn header_signature_binds_verification_block_set() {
        let keypair = Keypair::generate();
        let mut blocks = BTreeMap::new();
        blocks.insert(HashType([1; 32]), ());
        let body = VerificationBody {
            blocks_hash: blocks.hash(),
            blocks,
        };
        let header = Header {
            sender: keypair.public,
            last_epoch: HashType([2; 32]),
            nonce: Nonce::new(7),
            round: 1,
            signature: keypair.signer().sign(
                Header::signature_hash_for_body(
                    &keypair.public,
                    &HashType([2; 32]),
                    Nonce::new(7),
                    1,
                    MSGKey::Verification,
                    &body,
                )
                .as_ref(),
            ),
        };
        let mut tampered = body.clone();
        tampered.blocks.insert(HashType([9; 32]), ());

        assert!(header.verify_signature(MSGKey::Verification, &body).is_ok());
        assert!(
            header
                .verify_signature(MSGKey::Verification, &tampered)
                .is_err()
        );
    }

    #[test]
    fn verification_body_validate_rejects_mismatched_block_hash() {
        let mut blocks = BTreeMap::new();
        blocks.insert(HashType([1; 32]), ());
        let body = VerificationBody {
            blocks_hash: HashType([9; 32]),
            blocks,
        };

        assert!(matches!(
            body.validate(),
            Err(BlossomError::WireProtocol(message))
                if message.contains("verification blocks hash")
        ));
    }

    #[test]
    fn proposal_signature_binds_embedded_proof_fields() {
        let keypair = Keypair::generate();
        let mut approved_blocks = BTreeMap::new();
        approved_blocks.insert(HashType([1; 32]), ());
        let body = ProposalBody {
            consensus: true,
            approved_hash: Some(approved_blocks.hash()),
            approved_blocks: Some(approved_blocks.clone()),
            verif: Some(vec![(keypair.public, Signature([7; 64]))]),
            signature_tree: Some(approved_blocks.clone()),
            signature_tree_hash: Some(approved_blocks.hash()),
        };
        let header = signed_header_for_body(&keypair, MSGKey::Proposal, &body);
        let mut tampered = body.clone();
        tampered.verif = Some(vec![(keypair.public, Signature([8; 64]))]);

        assert!(body.validate().is_ok());
        assert!(header.verify_signature(MSGKey::Proposal, &body).is_ok());
        assert!(
            header
                .verify_signature(MSGKey::Proposal, &tampered)
                .is_err()
        );
    }

    #[test]
    fn proposal_body_validate_rejects_missing_and_mismatched_proofs() {
        let missing_blocks = ProposalBody {
            consensus: true,
            approved_blocks: None,
            approved_hash: Some(HashType([1; 32])),
            verif: None,
            signature_tree: None,
            signature_tree_hash: None,
        };
        assert!(matches!(
            missing_blocks.validate(),
            Err(BlossomError::WireProtocol(message))
                if message.contains("approved blocks")
        ));

        let mut approved_blocks = BTreeMap::new();
        approved_blocks.insert(HashType([1; 32]), ());
        let mismatched_hash = ProposalBody {
            consensus: true,
            approved_blocks: Some(approved_blocks.clone()),
            approved_hash: Some(HashType([9; 32])),
            verif: None,
            signature_tree: None,
            signature_tree_hash: None,
        };
        assert!(matches!(
            mismatched_hash.validate(),
            Err(BlossomError::WireProtocol(message))
                if message.contains("approved hash")
        ));

        let mismatched_tree = ProposalBody {
            consensus: true,
            approved_hash: Some(approved_blocks.hash()),
            approved_blocks: Some(approved_blocks.clone()),
            verif: None,
            signature_tree: Some(approved_blocks),
            signature_tree_hash: Some(HashType([8; 32])),
        };
        assert!(matches!(
            mismatched_tree.validate(),
            Err(BlossomError::WireProtocol(message))
                if message.contains("signature-tree hash")
        ));
    }

    #[test]
    fn commit_signature_binds_consensus_decision() {
        let keypair = Keypair::generate();
        let body = CommitBody {
            consensus: true,
            signature_tree_insert: None,
        };
        let header = signed_header_for_body(&keypair, MSGKey::Commit, &body);
        let tampered = CommitBody {
            consensus: false,
            signature_tree_insert: None,
        };

        assert!(header.verify_signature(MSGKey::Commit, &body).is_ok());
        assert!(header.verify_signature(MSGKey::Commit, &tampered).is_err());
    }

    #[test]
    fn echo_recovery_signatures_bind_requested_and_redispatched_blocks() {
        let keypair = Keypair::generate();
        let mut requested = BTreeMap::new();
        requested.insert(HashType([1; 32]), ());
        let request_header = signed_header_for_body(&keypair, MSGKey::EchoRequest, &requested);
        let mut tampered_requested = requested.clone();
        tampered_requested.insert(HashType([2; 32]), ());

        assert!(
            request_header
                .verify_signature(MSGKey::EchoRequest, &requested)
                .is_ok()
        );
        assert!(
            request_header
                .verify_signature(MSGKey::EchoRequest, &tampered_requested)
                .is_err()
        );

        let block = signed_block(&keypair);
        let mut redispatched = BTreeMap::new();
        redispatched.insert(block.hash, block.clone());
        let redispatch_header =
            signed_header_for_body(&keypair, MSGKey::EchoReDispatch, &redispatched);
        let mut tampered_block = block;
        tampered_block.body.txs.push(Transaction::new("tamper"));
        let mut tampered_redispatched = BTreeMap::new();
        tampered_redispatched.insert(tampered_block.hash, tampered_block);

        assert!(
            redispatch_header
                .verify_signature(MSGKey::EchoReDispatch, &redispatched)
                .is_ok()
        );
        assert!(
            redispatch_header
                .verify_signature(MSGKey::EchoReDispatch, &tampered_redispatched)
                .is_err()
        );
    }

    fn signed_header_for_body<T: BlossomBody>(keypair: &Keypair, kind: MSGKey, body: &T) -> Header {
        let last_epoch = HashType([2; 32]);
        let nonce = Nonce::new(7);
        let round = 1;
        Header {
            sender: keypair.public,
            last_epoch,
            nonce,
            round,
            signature: keypair.signer().sign(
                Header::signature_hash_for_body(
                    &keypair.public,
                    &last_epoch,
                    nonce,
                    round,
                    kind,
                    body,
                )
                .as_ref(),
            ),
        }
    }
}
