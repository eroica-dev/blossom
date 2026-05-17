use std::any::Any;
use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::block::Block;
use crate::crypto::{PubKey, Signature};
use crate::error::Result;
use crate::hash::{DoHash, HashType};
use crate::messages::{MSGKey, Msg};
use crate::node::NodeIdentity;
use crate::nonce::Nonce;
use crate::state::LocalState;

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Default)]
pub struct Header {
    pub sender: PubKey,
    pub last_epoch: HashType,
    pub nonce: Nonce,
    pub round: u8,
    pub signature: Signature,
}

impl Header {
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
        node.sign(&self.to_bytes())
    }

    fn verify(&self, signature: &Signature, pub_key: &PubKey) -> Result<()> {
        signature.verify(&self.to_bytes(), pub_key)
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
            if block.verify_signature().is_err() {
                continue;
            }
            accepted_blocks.insert(*sent_hash, block.clone());
        }

        let signature_tree = if self.signature_tree.verify() {
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
