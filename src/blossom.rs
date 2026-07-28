//! Consensus message records, signature checks, and state transitions.

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
use crate::round_skip::{DataDisseminationManifest, RoundSkipCertificate, RoundSkipVote};
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
        let identity = (self.header.signature, self.body.blocks_hash);
        let quorum = state.get_mut_quorum(
            &self.header.last_epoch,
            self.header.nonce,
            self.header.round,
        );
        if let Some(recorded) = quorum.received_dispatch_identities.get(&sender) {
            if *recorded == identity {
                return Ok(());
            }
            return Err(BlossomError::WireProtocol(format!(
                "conflicting dispatch from {sender}"
            )));
        }
        quorum.try_push_pending_dispatch(
            PendingDispatch::Decoded(self.clone()),
            configured_max_pending_raw_dispatch_bytes(),
            configured_max_pending_raw_dispatch_bytes_per_sender(),
        )?;
        quorum.msg_matrix.update(true, Msg::Dispatch(self));
        quorum.received_dispatch_identities.insert(sender, identity);
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

/// A mutable, monotonic trusted-network acknowledgement of locally available
/// blocks.
///
/// This is deliberately separate from [`Verification`]. Trusted nodes may
/// expand their acknowledgement as delayed blocks arrive, but durably emit at
/// most one immutable verification/confirmation for a round.
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct TrustedAcknowledgement {
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

impl BlossomMessage for TrustedAcknowledgement {
    fn kind(&self) -> MSGKey {
        MSGKey::TrustedAcknowledgement
    }

    fn header(&self) -> &Header {
        &self.header
    }

    fn body_hash(&self) -> HashType {
        self.body.blocks_hash
    }

    fn msg(&self) -> Msg {
        Msg::TrustedAcknowledgement(self.clone())
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
    #[serde(default)]
    pub epoch_hash: Option<HashType>,
    #[serde(default)]
    pub epoch_signature: Option<Signature>,
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
        match (self.epoch_hash, self.epoch_signature) {
            (Some(epoch_hash), Some(epoch_signature)) => {
                hasher.update([1]);
                hasher.update(epoch_hash.as_ref());
                hasher.update(epoch_signature.as_ref());
            }
            _ => hasher.update([0]),
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
            }
            None => {
                bytes.push(0);
            }
        }
        match (self.epoch_hash, self.epoch_signature) {
            (Some(epoch_hash), Some(epoch_signature)) => {
                bytes.push(1);
                bytes.extend_from_slice(epoch_hash.as_ref());
                bytes.extend_from_slice(epoch_signature.as_ref());
            }
            _ => bytes.push(0),
        }
        bytes
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
        self.body.epoch_hash.unwrap_or_else(|| {
            self.body
                .signature_tree_insert
                .as_ref()
                .and_then(|tree| tree.keys().next().copied())
                .unwrap_or_default()
        })
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
pub struct RoundSkipVoteMessage {
    pub header: Header,
    pub body: RoundSkipVoteBody,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Default)]
pub struct RoundSkipVoteBody {
    pub vote: RoundSkipVote,
    pub manifest: DataDisseminationManifest,
}

impl BlossomBody for RoundSkipVoteBody {
    fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).unwrap_or_default()
    }
}

impl BlossomMessage for RoundSkipVoteMessage {
    fn kind(&self) -> MSGKey {
        MSGKey::RoundSkipVote
    }

    fn header(&self) -> &Header {
        &self.header
    }

    fn body_hash(&self) -> HashType {
        self.body.manifest.hash()
    }

    fn msg(&self) -> Msg {
        Msg::RoundSkipVote(self.clone())
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct RoundSkipCertificateMessage {
    pub header: Header,
    pub body: RoundSkipCertificateBody,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Default)]
pub struct RoundSkipCertificateBody {
    pub certificate: RoundSkipCertificate,
    pub manifest: DataDisseminationManifest,
}

impl BlossomBody for RoundSkipCertificateBody {
    fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).unwrap_or_default()
    }
}

impl BlossomMessage for RoundSkipCertificateMessage {
    fn kind(&self) -> MSGKey {
        MSGKey::RoundSkipCertificate
    }

    fn header(&self) -> &Header {
        &self.header
    }

    fn body_hash(&self) -> HashType {
        self.body.certificate.manifest_hash
    }

    fn msg(&self) -> Msg {
        Msg::RoundSkipCertificate(self.clone())
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct ReconcileAppraisal {
    pub header: Header,
    pub body: ReconcileAppraisalBody,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Default)]
pub struct ReconcileAppraisalBody {
    pub blocks_hash: HashType,
    pub blocks: BTreeMap<HashType, ()>,
    pub manifest_hash: HashType,
}

impl BlossomBody for ReconcileAppraisalBody {
    fn update_signing_hash(&self, hasher: &mut ProtocolHasher) {
        hasher.update(self.blocks_hash.as_ref());
        self.blocks.update_signing_hash(hasher);
        hasher.update(self.manifest_hash.as_ref());
    }

    fn to_bytes(&self) -> Vec<u8> {
        [
            self.blocks_hash.as_ref(),
            self.blocks.to_bytes().as_slice(),
            self.manifest_hash.as_ref(),
        ]
        .concat()
    }
}

impl BlossomMessage for ReconcileAppraisal {
    fn kind(&self) -> MSGKey {
        MSGKey::ReconcileAppraisal
    }

    fn header(&self) -> &Header {
        &self.header
    }

    fn body_hash(&self) -> HashType {
        self.body.blocks_hash
    }

    fn msg(&self) -> Msg {
        Msg::ReconcileAppraisal(self.clone())
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct ReconcileRequest {
    pub header: Header,
    pub body: ReconcileRequestBody,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Default)]
pub struct ReconcileRequestBody {
    pub blocks_hash: HashType,
    pub missing_blocks: BTreeMap<HashType, ()>,
}

impl BlossomBody for ReconcileRequestBody {
    fn update_signing_hash(&self, hasher: &mut ProtocolHasher) {
        hasher.update(self.blocks_hash.as_ref());
        self.missing_blocks.update_signing_hash(hasher);
    }

    fn to_bytes(&self) -> Vec<u8> {
        [
            self.blocks_hash.as_ref(),
            self.missing_blocks.to_bytes().as_slice(),
        ]
        .concat()
    }
}

impl BlossomMessage for ReconcileRequest {
    fn kind(&self) -> MSGKey {
        MSGKey::ReconcileRequest
    }

    fn header(&self) -> &Header {
        &self.header
    }

    fn body_hash(&self) -> HashType {
        self.body.blocks_hash
    }

    fn msg(&self) -> Msg {
        Msg::ReconcileRequest(self.clone())
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct ReconcileResponse {
    pub header: Header,
    pub body: ReconcileResponseBody,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Default)]
pub struct ReconcileResponseBody {
    pub blocks_hash: HashType,
    pub blocks: BTreeMap<HashType, Block>,
}

impl BlossomBody for ReconcileResponseBody {
    fn update_signing_hash(&self, hasher: &mut ProtocolHasher) {
        hasher.update(self.blocks_hash.as_ref());
        self.blocks.update_signing_hash(hasher);
    }

    fn to_bytes(&self) -> Vec<u8> {
        [self.blocks_hash.as_ref(), self.blocks.to_bytes().as_slice()].concat()
    }
}

impl BlossomMessage for ReconcileResponse {
    fn kind(&self) -> MSGKey {
        MSGKey::ReconcileResponse
    }

    fn header(&self) -> &Header {
        &self.header
    }

    fn body_hash(&self) -> HashType {
        self.body.blocks_hash
    }

    fn msg(&self) -> Msg {
        Msg::ReconcileResponse(self.clone())
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct ReconcileCommit {
    pub header: Header,
    pub body: ReconcileCommitBody,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Default)]
pub struct ReconcileCommitBody {
    pub blocks_hash: HashType,
    pub epoch_hash: HashType,
    pub signatures: Vec<(PubKey, Signature)>,
}

impl BlossomBody for ReconcileCommitBody {
    fn update_signing_hash(&self, hasher: &mut ProtocolHasher) {
        hasher.update(self.blocks_hash.as_ref());
        hasher.update(self.epoch_hash.as_ref());
        hasher.update((self.signatures.len() as u64).to_le_bytes());
        for (pubkey, signature) in &self.signatures {
            hasher.update(pubkey.as_ref());
            hasher.update(signature.as_ref());
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.signing_hash().to_bytes()
    }
}

impl BlossomMessage for ReconcileCommit {
    fn kind(&self) -> MSGKey {
        MSGKey::ReconcileCommit
    }

    fn header(&self) -> &Header {
        &self.header
    }

    fn body_hash(&self) -> HashType {
        self.body.blocks_hash
    }

    fn msg(&self) -> Msg {
        Msg::ReconcileCommit(self.clone())
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct Ballot {
    pub ballot: (String, Vec<Verification>),
}

#[cfg(test)]
mod tests;
