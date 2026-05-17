use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use borsh::{BorshDeserialize, BorshSerialize};
use indextreemap::IndexTreeMap;
use serde::{Deserialize, Serialize};

use crate::address_book::{AddressBook, Service, ServiceKind};
use crate::block::{Block, BlockApplicationState};
use crate::blossom::{
    BlossomBody, Commit, Dispatch, DispatchBody, EchoReDispatch, EchoRequest, EchoResponse,
    EpochStarted, Header, Proposal, SignatureTree, Verification,
};
use crate::crypto::{SecretSigner, Signature};
use crate::error::{BlossomError, Result};
use crate::hash::{DoHash, HashType};
use crate::local_block::LocalBlock;
use crate::messages::{MSGKey, Msg};
use crate::node::NodeIdentity;
use crate::nonce::Nonce;
use crate::overlay::{
    BroadcastReport, FanOutStrategy, add_self_consensus_service, broadcast_wire_request,
    select_fanout_targets,
};
use crate::state::{
    Epoch, EpochBody, LocalState, PendingDispatch, configured_max_pending_raw_dispatch_bytes,
    configured_max_pending_raw_dispatch_bytes_per_sender,
};
use crate::wire::{HotDispatch, WireRequest};

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub self_node: NodeIdentity,
    pub genesis: Option<Epoch>,
    pub address_book: AddressBook,
    pub block_cap: usize,
    pub trust_mode: TrustMode,
    pub mode: RuntimeMode,
}

impl RuntimeConfig {
    pub fn new(self_node: NodeIdentity) -> Self {
        Self {
            self_node,
            genesis: None,
            address_book: AddressBook::new(),
            block_cap: 100,
            trust_mode: TrustMode::Verified,
            mode: RuntimeMode::Consensus,
        }
    }

    pub fn overlay(self_node: NodeIdentity) -> Self {
        let mut config = Self::new(self_node);
        config.mode = RuntimeMode::Overlay;
        config
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeMode {
    Consensus,
    Overlay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustMode {
    Verified,
    Trusted,
}

impl TrustMode {
    pub fn is_trusted(self) -> bool {
        self == Self::Trusted
    }
}

#[derive(Clone)]
pub struct NodeRuntime {
    inner: Arc<RuntimeInner>,
}

struct RuntimeInner {
    state: RwLock<LocalState>,
    local_blocks: RwLock<LocalBlock>,
    address_book: RwLock<AddressBook>,
    signer: Option<SecretSigner>,
    trust_mode: TrustMode,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct EpochTarget {
    pub last_epoch: HashType,
    pub nonce: Nonce,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct NodeStatus {
    pub node: NodeIdentity,
    pub last_epoch: HashType,
    pub last_epoch_nonce: Nonce,
    pub next_nonce: Nonce,
    pub pending_blocks: usize,
    pub services: Vec<Service>,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct AcceptedBlock {
    pub hash: HashType,
    pub nonce: Nonce,
    pub application_state_bytes: usize,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct MessageReceipt {
    pub kind: String,
    pub accepted: bool,
}

impl NodeRuntime {
    pub fn new(mut config: RuntimeConfig) -> Self {
        let signer = config.self_node.signer().ok();
        let genesis = config
            .genesis
            .take()
            .unwrap_or_else(|| genesis_epoch([config.self_node.clone()]));
        add_self_consensus_service(&mut config.address_book, &config.self_node);

        Self {
            inner: Arc::new(RuntimeInner {
                state: RwLock::new(LocalState::new(config.self_node, genesis)),
                local_blocks: RwLock::new(LocalBlock::new(config.block_cap)),
                address_book: RwLock::new(config.address_book),
                signer,
                trust_mode: config.trust_mode,
            }),
        }
    }

    pub fn self_node(&self) -> NodeIdentity {
        self.inner
            .state
            .read()
            .expect("state lock poisoned")
            .self_node
            .clone()
    }

    pub fn status(&self) -> Result<NodeStatus> {
        let state = self.inner.state.read().expect("state lock poisoned");
        let epoch = state
            .epochchain
            .epochchain
            .last()
            .ok_or(BlossomError::EmptyEpochChain)?;
        let pending_blocks = self
            .inner
            .local_blocks
            .read()
            .expect("block lock poisoned")
            .len();
        let services = self.address_book();

        let mut node = state.self_node.clone();
        node.secret_key = None;

        Ok(NodeStatus {
            node,
            last_epoch: epoch.hash,
            last_epoch_nonce: epoch.body.nonce,
            next_nonce: epoch.body.nonce.new_next(),
            pending_blocks,
            services,
        })
    }

    pub fn address_book(&self) -> Vec<Service> {
        self.inner
            .address_book
            .read()
            .expect("address book lock poisoned")
            .clone()
            .into_services()
    }

    pub fn register_service(&self, service: Service) -> Option<Service> {
        self.inner
            .address_book
            .write()
            .expect("address book lock poisoned")
            .add(service)
    }

    pub fn set_application_state(&self, bytes: impl Into<Vec<u8>>) -> Result<()> {
        self.inner
            .local_blocks
            .write()
            .expect("block lock poisoned")
            .set_application_state(bytes)
    }

    pub fn application_state(&self) -> BlockApplicationState {
        self.inner
            .local_blocks
            .read()
            .expect("block lock poisoned")
            .application_state()
            .clone()
    }

    pub fn fanout_targets(&self, strategy: &FanOutStrategy) -> Vec<Service> {
        let self_node = self.self_node();
        let address_book = self
            .inner
            .address_book
            .read()
            .expect("address book lock poisoned");
        select_fanout_targets(&self_node, &address_book, strategy)
    }

    pub async fn broadcast(&self, msg: Msg, strategy: FanOutStrategy) -> Result<BroadcastReport> {
        self.broadcast_request(WireRequest::Message(msg), strategy)
            .await
    }

    pub async fn broadcast_request(
        &self,
        request: WireRequest,
        strategy: FanOutStrategy,
    ) -> Result<BroadcastReport> {
        let targets = self.fanout_targets(&strategy);
        broadcast_wire_request(request, targets).await
    }

    pub fn next_epoch_target(&self) -> Result<EpochTarget> {
        let state = self.inner.state.read().expect("state lock poisoned");
        let epoch = state
            .epochchain
            .epochchain
            .last()
            .ok_or(BlossomError::EmptyEpochChain)?;
        Ok(EpochTarget {
            last_epoch: epoch.hash,
            nonce: epoch.body.nonce.new_next(),
        })
    }

    pub fn submit_block(&self, block: Block) -> Result<AcceptedBlock> {
        let target = self.next_epoch_target()?;
        if block.body.last_epoch != target.last_epoch {
            return Err(BlossomError::InvalidBlockLastEpoch);
        }
        if block.body.nonce != target.nonce {
            return Err(BlossomError::InvalidBlockNonce {
                expected: target.nonce,
                actual: block.body.nonce,
            });
        }

        self.verify_block_integrity(&block)?;
        self.validate_block_service(&block)?;

        let application_state_bytes = block.application_state_len();
        let hash = self
            .inner
            .local_blocks
            .write()
            .expect("block lock poisoned")
            .enqueue_preverified_block(block)?;
        Ok(AcceptedBlock {
            hash,
            nonce: target.nonce,
            application_state_bytes,
        })
    }

    pub fn dispatch_local_block(&self, round: u8) -> Result<Dispatch> {
        let target = self.next_epoch_target()?;
        let self_node = self.self_node();
        let block_service = self.block_service();

        let (maybe_block, application_state) = {
            let mut local_blocks = self
                .inner
                .local_blocks
                .write()
                .expect("block lock poisoned");
            let maybe_block = local_blocks.dequeue_block(
                block_service.as_ref().map(|service| service.public_key),
                target.last_epoch,
                target.nonce,
                round,
            )?;
            (maybe_block, local_blocks.application_state().clone())
        };

        let block = match maybe_block {
            Some(block) => block,
            None => self.empty_block(&self_node, &target, application_state)?,
        };

        let mut blocks = BTreeMap::new();
        blocks.insert(block.hash, block);
        let signature_tree = SignatureTree::default();
        let signature_tree_hash = signature_tree.hash();
        let body = DispatchBody {
            blocks_hash: blocks.hash(),
            blocks,
            signature_tree,
            signature_tree_hash,
        };
        let header = Header {
            sender: self_node.public_key(),
            last_epoch: target.last_epoch,
            nonce: target.nonce,
            round,
            signature: self.sign_body(
                &self_node,
                MSGKey::Dispatch,
                target.last_epoch,
                target.nonce,
                round,
                &body,
            )?,
        };

        let mut state = self.inner.state.write().expect("state lock poisoned");
        let quorum = state.get_mut_quorum(&target.last_epoch, target.nonce, round);
        quorum.dispatch_status = Some(true);
        Ok(Dispatch { header, body })
    }

    pub fn receive_message(&self, message: Msg) -> Result<MessageReceipt> {
        match message {
            Msg::Dispatch(message) => {
                self.verify_message_signature(&message.header, MSGKey::Dispatch, &message.body)?;
                let mut state = self.inner.state.write().expect("state lock poisoned");
                if message.header.verify_header(&mut state) == Some(false) {
                    return Err(BlossomError::UnknownSender);
                }
                message.try_accept_into_state(&mut state)?;
                Ok(MessageReceipt::accepted("dispatch"))
            }
            Msg::EchoResponse(message) => self.receive_echo_response(message),
            Msg::Verification(message) => self.receive_verification(message),
            Msg::Proposal(message) => self.receive_proposal(message),
            Msg::Commit(message) => self.receive_commit(message),
            Msg::EpochStarted(message) => self.receive_epoch_started(message),
            Msg::EchoRequest(message) => self.receive_echo_request(message),
            Msg::EchoReDispatch(message) => self.receive_echo_redispatch(message),
            Msg::Ok => Ok(MessageReceipt::accepted("ok")),
            Msg::Fail => Ok(MessageReceipt::accepted("fail")),
        }
    }

    pub fn receive_hot_dispatch(&self, message: HotDispatch) -> Result<MessageReceipt> {
        if !self.inner.trust_mode.is_trusted() {
            message.verify_signature()?;
        }
        let mut state = self.inner.state.write().expect("state lock poisoned");
        if message.header.verify_header(&mut state) == Some(false) {
            return Err(BlossomError::UnknownSender);
        }
        let sender = message.header.sender;
        let quorum = state.get_mut_quorum(
            &message.header.last_epoch,
            message.header.nonce,
            message.header.round,
        );
        if quorum.received_dispatches.contains(&sender) {
            return Err(BlossomError::WireProtocol(format!(
                "duplicate dispatch from {sender}"
            )));
        }
        quorum.try_push_pending_dispatch(
            PendingDispatch::Hot(message),
            configured_max_pending_raw_dispatch_bytes(),
            configured_max_pending_raw_dispatch_bytes_per_sender(),
        )?;
        quorum.received_dispatches.push(sender);
        Ok(MessageReceipt::accepted("dispatch"))
    }

    fn receive_echo_request(&self, message: EchoRequest) -> Result<MessageReceipt> {
        let mut state = self.inner.state.write().expect("state lock poisoned");
        if message.header.verify_header(&mut state) == Some(false) {
            return Err(BlossomError::UnknownSender);
        }
        Ok(MessageReceipt::accepted("echo_request"))
    }

    fn receive_echo_redispatch(&self, message: EchoReDispatch) -> Result<MessageReceipt> {
        let mut state = self.inner.state.write().expect("state lock poisoned");
        if message.header.verify_header(&mut state) == Some(false) {
            return Err(BlossomError::UnknownSender);
        }
        Ok(MessageReceipt::accepted("echo_redispatch"))
    }

    fn receive_echo_response(&self, message: EchoResponse) -> Result<MessageReceipt> {
        self.verify_message_signature(&message.header, MSGKey::EchoResponse, &message.body)?;
        let mut state = self.inner.state.write().expect("state lock poisoned");
        if message.header.verify_header(&mut state) == Some(false) {
            return Err(BlossomError::UnknownSender);
        }
        Ok(MessageReceipt::accepted("echo_response"))
    }

    fn receive_verification(&self, message: Verification) -> Result<MessageReceipt> {
        self.verify_message_signature(&message.header, MSGKey::Verification, &message.body)?;
        let mut state = self.inner.state.write().expect("state lock poisoned");
        if message.header.verify_header(&mut state) == Some(false) {
            return Err(BlossomError::UnknownSender);
        }
        let quorum = state.get_mut_quorum(
            &message.header.last_epoch,
            message.header.nonce,
            message.header.round,
        );
        quorum.verifications.record(message);
        Ok(MessageReceipt::accepted("verification"))
    }

    fn receive_proposal(&self, message: Proposal) -> Result<MessageReceipt> {
        self.verify_message_signature(&message.header, MSGKey::Proposal, &message.body)?;
        let mut state = self.inner.state.write().expect("state lock poisoned");
        if message.header.verify_header(&mut state) == Some(false) {
            return Err(BlossomError::UnknownSender);
        }
        let quorum = state.get_mut_quorum(
            &message.header.last_epoch,
            message.header.nonce,
            message.header.round,
        );
        if let Some(hash) = message.body.approved_hash {
            *quorum.proposals.count.entry(hash).or_default() += 1;
        }
        quorum
            .proposals
            .proposals
            .insert(message.header.sender, message);
        Ok(MessageReceipt::accepted("proposal"))
    }

    fn receive_commit(&self, message: Commit) -> Result<MessageReceipt> {
        self.verify_message_signature(&message.header, MSGKey::Commit, &message.body)?;
        let mut state = self.inner.state.write().expect("state lock poisoned");
        if message.header.verify_header(&mut state) == Some(false) {
            return Err(BlossomError::UnknownSender);
        }
        let quorum = state.get_mut_quorum(
            &message.header.last_epoch,
            message.header.nonce,
            message.header.round,
        );
        quorum.commit_sent = quorum.commit_sent || message.body.consensus;
        Ok(MessageReceipt::accepted("commit"))
    }

    fn receive_epoch_started(&self, message: EpochStarted) -> Result<MessageReceipt> {
        self.verify_message_signature(&message.header, MSGKey::EpochStarted, &message.body)?;
        let mut state = self.inner.state.write().expect("state lock poisoned");
        if message.header.verify_header(&mut state) == Some(false) {
            return Err(BlossomError::UnknownSender);
        }
        state.get_mut_quorum(
            &message.header.last_epoch,
            message.header.nonce,
            message.header.round,
        );
        Ok(MessageReceipt::accepted("epoch_started"))
    }

    fn validate_block_service(&self, block: &Block) -> Result<()> {
        if let Some(service) = self.block_service()
            && block.body.validator != service.public_key
        {
            return Err(BlossomError::UnknownSender);
        }
        Ok(())
    }

    fn block_service(&self) -> Option<Service> {
        self.inner
            .address_book
            .read()
            .expect("address book lock poisoned")
            .service(ServiceKind::Block)
            .cloned()
    }

    fn empty_block(
        &self,
        self_node: &NodeIdentity,
        target: &EpochTarget,
        application_state: BlockApplicationState,
    ) -> Result<Block> {
        let mut block = Block::default();
        block.body.last_epoch = target.last_epoch;
        block.body.nonce = target.nonce;
        block.body.application_state = application_state;
        if self.inner.trust_mode.is_trusted() {
            block.seal_unsigned(self_node.public_key());
            return Ok(block);
        }
        match self.inner.signer.as_ref() {
            Some(signer) => block.sign_with(signer),
            None => {
                let secret_key = self_node.secret_key.ok_or(BlossomError::MissingSecretKey)?;
                block.sign(&secret_key);
            }
        }
        Ok(block)
    }

    fn verify_block_integrity(&self, block: &Block) -> Result<()> {
        if self.inner.trust_mode.is_trusted() {
            block.verify_unsigned_integrity()
        } else {
            block.verify_integrity()
        }
    }

    fn verify_message_signature<T: BlossomBody>(
        &self,
        header: &Header,
        kind: MSGKey,
        body: &T,
    ) -> Result<()> {
        if self.inner.trust_mode.is_trusted() {
            Ok(())
        } else {
            header.verify_signature(kind, body)
        }
    }

    fn sign_body<T: BlossomBody>(
        &self,
        self_node: &NodeIdentity,
        kind: MSGKey,
        last_epoch: HashType,
        nonce: Nonce,
        round: u8,
        body: &T,
    ) -> Result<Signature> {
        if self.inner.trust_mode.is_trusted() {
            return Ok(Signature::default());
        }

        let message_hash = Header::signature_hash_for_body(
            &self_node.public_key(),
            &last_epoch,
            nonce,
            round,
            kind,
            body,
        );
        match self.inner.signer.as_ref() {
            Some(signer) => Ok(signer.sign(message_hash.as_ref())),
            None => self_node.sign(message_hash.as_ref()),
        }
    }
}

impl MessageReceipt {
    fn accepted(kind: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            accepted: true,
        }
    }
}

pub fn genesis_epoch(nodes: impl IntoIterator<Item = NodeIdentity>) -> Epoch {
    let mut verifiers = IndexTreeMap::new();
    for node in nodes {
        verifiers.insert(node.public_key(), node);
    }

    let mut epoch = Epoch {
        body: EpochBody {
            verifiers,
            nonce: Nonce::new(0),
            ..Default::default()
        },
        ..Default::default()
    };
    epoch.set_hash();
    epoch
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blossom::DispatchBody;
    use crate::crypto::Keypair;

    fn runtime() -> (NodeRuntime, Keypair) {
        let keypair = Keypair::generate();
        let node = NodeIdentity::new(
            keypair.public,
            Some(keypair.secret),
            "tcp",
            "127.0.0.1",
            8080,
            false,
        );
        (NodeRuntime::new(RuntimeConfig::new(node)), keypair)
    }

    fn runtime_with_peers() -> (NodeRuntime, Vec<Keypair>, EpochTarget) {
        runtime_with_peers_mode(TrustMode::Verified)
    }

    fn runtime_with_peers_mode(trust_mode: TrustMode) -> (NodeRuntime, Vec<Keypair>, EpochTarget) {
        let keypairs = (0..6).map(|_| Keypair::generate()).collect::<Vec<_>>();
        let nodes = keypairs
            .iter()
            .enumerate()
            .map(|(index, keypair)| {
                NodeIdentity::new(
                    keypair.public,
                    (index == 0).then_some(keypair.secret),
                    "tcp",
                    "127.0.0.1",
                    8000 + index as u16,
                    false,
                )
            })
            .collect::<Vec<_>>();
        let genesis = genesis_epoch(nodes.clone());
        let mut config = RuntimeConfig::new(nodes[0].clone());
        config.genesis = Some(genesis.clone());
        config.trust_mode = trust_mode;
        let runtime = NodeRuntime::new(config);
        let target = EpochTarget {
            last_epoch: genesis.hash,
            nonce: genesis.body.nonce.new_next(),
        };
        (runtime, keypairs, target)
    }

    #[test]
    fn submits_block_for_next_nonce() {
        let (runtime, keypair) = runtime();
        let target = runtime.next_epoch_target().unwrap();
        let mut block = Block::default();
        block.body.last_epoch = target.last_epoch;
        block.body.nonce = target.nonce;
        block.sign(&keypair.secret);

        let accepted = runtime.submit_block(block).unwrap();
        assert_eq!(accepted.nonce, target.nonce);
        assert_eq!(accepted.application_state_bytes, 0);
        assert_eq!(runtime.status().unwrap().pending_blocks, 1);
    }

    #[test]
    fn rejects_wrong_nonce() {
        let (runtime, keypair) = runtime();
        let target = runtime.next_epoch_target().unwrap();
        let mut block = Block::default();
        block.body.last_epoch = target.last_epoch;
        block.body.nonce = target.nonce.new_next();
        block.sign(&keypair.secret);

        assert_eq!(
            runtime.submit_block(block),
            Err(BlossomError::InvalidBlockNonce {
                expected: target.nonce,
                actual: target.nonce.new_next()
            })
        );
    }

    #[test]
    fn builds_dispatch_from_local_block() {
        let (runtime, keypair) = runtime();
        let target = runtime.next_epoch_target().unwrap();
        let mut block = Block::default();
        block.body.last_epoch = target.last_epoch;
        block.body.nonce = target.nonce;
        block.sign(&keypair.secret);
        runtime.submit_block(block).unwrap();

        let dispatch = runtime.dispatch_local_block(0).unwrap();
        assert_eq!(dispatch.header.nonce, target.nonce);
        assert_eq!(dispatch.body.blocks.len(), 1);
        assert_eq!(runtime.status().unwrap().pending_blocks, 0);
    }

    #[test]
    fn fanout_targets_use_registered_consensus_services() {
        let (runtime, keypairs, _) = runtime_with_peers();
        for (index, keypair) in keypairs.iter().enumerate().skip(1) {
            runtime.register_service(Service::new(
                ServiceKind::Consensus,
                keypair.public,
                "tcp",
                "127.0.0.1",
                8000 + index as u16,
            ));
        }

        let targets =
            runtime.fanout_targets(&FanOutStrategy::unshuffled_topology(HashType::default()));

        assert_eq!(targets.len(), 5);
        assert!(
            targets
                .iter()
                .all(|service| service.public_key != keypairs[0].public)
        );
    }

    #[test]
    fn status_omits_secret_key_and_registers_consensus_service() {
        let (runtime, keypair) = runtime();
        let status = runtime.status().unwrap();

        assert_eq!(status.node.public_key(), keypair.public);
        assert_eq!(status.node.secret_key, None);
        assert!(
            status
                .services
                .iter()
                .any(|service| service.kind == ServiceKind::Consensus
                    && service.public_key == keypair.public)
        );
    }

    #[test]
    fn submit_block_enforces_registered_block_service_key() {
        let (runtime, keypair) = runtime();
        let block_keypair = Keypair::generate();
        runtime.register_service(Service::new(
            ServiceKind::Block,
            block_keypair.public,
            "tcp",
            "127.0.0.1",
            9000,
        ));
        let target = runtime.next_epoch_target().unwrap();
        let mut block = Block::default();
        block.body.last_epoch = target.last_epoch;
        block.body.nonce = target.nonce;
        block.sign(&keypair.secret);

        assert_eq!(
            runtime.submit_block(block),
            Err(BlossomError::UnknownSender)
        );
    }

    #[test]
    fn dispatch_without_queued_block_sends_signed_empty_block() {
        let (runtime, _) = runtime();
        runtime
            .set_application_state(b"v1:bandwidth=1048576")
            .unwrap();
        let target = runtime.next_epoch_target().unwrap();

        let dispatch = runtime.dispatch_local_block(0).unwrap();

        assert_eq!(dispatch.header.nonce, target.nonce);
        assert_eq!(dispatch.body.blocks.len(), 1);
        let block = dispatch.body.blocks.values().next().unwrap();
        assert!(block.is_empty());
        assert_eq!(block.application_state(), b"v1:bandwidth=1048576");
        assert!(block.verify_integrity().is_ok());
    }

    #[test]
    fn receive_message_rejects_unknown_sender_and_bad_signature() {
        let (runtime, keypairs, target) = runtime_with_peers();
        let unknown = Keypair::generate();
        let body = DispatchBody::default();
        let unknown_signature_hash = Header::signature_hash_for_body(
            &unknown.public,
            &target.last_epoch,
            target.nonce,
            0,
            MSGKey::Dispatch,
            &body,
        );
        let unknown_dispatch = Dispatch {
            header: Header {
                sender: unknown.public,
                last_epoch: target.last_epoch,
                nonce: target.nonce,
                round: 0,
                signature: unknown.signer().sign(unknown_signature_hash.as_ref()),
            },
            body: body.clone(),
        };
        assert_eq!(
            runtime.receive_message(Msg::Dispatch(unknown_dispatch)),
            Err(BlossomError::UnknownSender)
        );

        let bad_signature_dispatch = Dispatch {
            header: Header {
                sender: keypairs[1].public,
                last_epoch: target.last_epoch,
                nonce: target.nonce,
                round: 0,
                signature: crate::Signature([1; 64]),
            },
            body,
        };
        assert_eq!(
            runtime.receive_message(Msg::Dispatch(bad_signature_dispatch)),
            Err(BlossomError::SignatureError)
        );
    }

    #[test]
    fn trusted_runtime_accepts_unsigned_known_member_work() {
        let (runtime, keypairs, target) = runtime_with_peers_mode(TrustMode::Trusted);
        let known_sender = {
            let mut state = runtime.inner.state.write().expect("state lock poisoned");
            state
                .get_mut_consensus(&target.last_epoch, target.nonce)
                .peers(0)
                .into_iter()
                .next()
                .expect("round should include a peer")
        };
        let body = DispatchBody::default();
        let dispatch = Dispatch {
            header: Header {
                sender: known_sender,
                last_epoch: target.last_epoch,
                nonce: target.nonce,
                round: 0,
                signature: crate::Signature::default(),
            },
            body,
        };

        let receipt = runtime.receive_message(Msg::Dispatch(dispatch)).unwrap();
        assert_eq!(receipt.kind, "dispatch");

        let mut block = Block::default();
        block.body.last_epoch = target.last_epoch;
        block.body.nonce = target.nonce;
        block.seal_unsigned(keypairs[0].public);

        let accepted = runtime.submit_block(block).unwrap();
        assert_eq!(accepted.nonce, target.nonce);
        assert_eq!(accepted.application_state_bytes, 0);
        assert_eq!(runtime.status().unwrap().pending_blocks, 1);
    }

    #[test]
    fn trusted_runtime_still_rejects_unsigned_unknown_sender() {
        let (runtime, _, target) = runtime_with_peers_mode(TrustMode::Trusted);
        let unknown = Keypair::generate();
        let dispatch = Dispatch {
            header: Header {
                sender: unknown.public,
                last_epoch: target.last_epoch,
                nonce: target.nonce,
                round: 0,
                signature: crate::Signature::default(),
            },
            body: DispatchBody::default(),
        };

        assert_eq!(
            runtime.receive_message(Msg::Dispatch(dispatch)),
            Err(BlossomError::UnknownSender)
        );
    }

    #[test]
    fn echo_recovery_messages_reject_unknown_senders() {
        let (runtime, _, target) = runtime_with_peers();
        let unknown = Keypair::generate();
        let header = Header {
            sender: unknown.public,
            last_epoch: target.last_epoch,
            nonce: target.nonce,
            round: 0,
            signature: crate::Signature::default(),
        };

        assert_eq!(
            runtime.receive_message(Msg::EchoRequest(EchoRequest {
                header: header.clone(),
                requested_blocks: BTreeMap::new(),
            })),
            Err(BlossomError::UnknownSender)
        );
        assert_eq!(
            runtime.receive_message(Msg::EchoReDispatch(EchoReDispatch {
                header,
                redispatched_blocks: BTreeMap::new(),
            })),
            Err(BlossomError::UnknownSender)
        );
    }
}
