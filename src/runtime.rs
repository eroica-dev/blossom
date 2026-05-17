use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use borsh::{BorshDeserialize, BorshSerialize};
use indextreemap::IndexTreeMap;
use serde::{Deserialize, Serialize};

use crate::address_book::{AddressBook, Service, ServiceKind};
use crate::block::Block;
use crate::blossom::{
    BlossomBody, Commit, Dispatch, DispatchBody, EchoResponse, EpochStarted, Header, Proposal,
    SignatureTree, Verification,
};
use crate::crypto::{SecretSigner, Signature};
use crate::error::{BlossomError, Result};
use crate::hash::{DoHash, HashType};
use crate::local_block::LocalBlock;
use crate::messages::Msg;
use crate::node::NodeIdentity;
use crate::nonce::Nonce;
use crate::state::{Epoch, EpochBody, LocalState};

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub self_node: NodeIdentity,
    pub genesis: Option<Epoch>,
    pub address_book: AddressBook,
    pub block_cap: usize,
}

impl RuntimeConfig {
    pub fn new(self_node: NodeIdentity) -> Self {
        Self {
            self_node,
            genesis: None,
            address_book: AddressBook::new(),
            block_cap: 100,
        }
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
        config.address_book.add(Service::new(
            ServiceKind::Consensus,
            config.self_node.public_key(),
            config.self_node.protocol.clone(),
            config.self_node.host.clone(),
            config.self_node.port,
        ));

        Self {
            inner: Arc::new(RuntimeInner {
                state: RwLock::new(LocalState::new(config.self_node, genesis)),
                local_blocks: RwLock::new(LocalBlock::new(config.block_cap)),
                address_book: RwLock::new(config.address_book),
                signer,
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

        block.verify_integrity()?;
        self.validate_block_service(&block)?;

        let hash = self
            .inner
            .local_blocks
            .write()
            .expect("block lock poisoned")
            .enqueue_block(block)?;
        Ok(AcceptedBlock {
            hash,
            nonce: target.nonce,
        })
    }

    pub fn dispatch_local_block(&self, round: u8) -> Result<Dispatch> {
        let target = self.next_epoch_target()?;
        let self_node = self.self_node();
        let block_service = self.block_service();

        let maybe_block = self
            .inner
            .local_blocks
            .write()
            .expect("block lock poisoned")
            .dequeue_block(
                block_service.as_ref().map(|service| service.public_key),
                target.last_epoch,
                target.nonce,
                round,
            )?;

        let block = match maybe_block {
            Some(block) => block,
            None => self.empty_block(&self_node, &target)?,
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
            signature: self.sign_body(&self_node, &body)?,
        };

        let mut state = self.inner.state.write().expect("state lock poisoned");
        let quorum = state.get_mut_quorum(&target.last_epoch, target.nonce, round);
        quorum.dispatch_status = Some(true);
        Ok(Dispatch { header, body })
    }

    pub fn receive_message(&self, message: Msg) -> Result<MessageReceipt> {
        match message {
            Msg::Dispatch(message) => {
                message
                    .body
                    .verify(&message.header.signature, &message.header.sender)?;
                let mut state = self.inner.state.write().expect("state lock poisoned");
                if message.header.verify_header(&mut state) == Some(false) {
                    return Err(BlossomError::UnknownSender);
                }
                message.verify(&mut state);
                Ok(MessageReceipt::accepted("dispatch"))
            }
            Msg::EchoResponse(message) => self.receive_echo_response(message),
            Msg::Verification(message) => self.receive_verification(message),
            Msg::Proposal(message) => self.receive_proposal(message),
            Msg::Commit(message) => self.receive_commit(message),
            Msg::EpochStarted(message) => self.receive_epoch_started(message),
            Msg::EchoRequest(_) => Ok(MessageReceipt::accepted("echo_request")),
            Msg::EchoReDispatch(_) => Ok(MessageReceipt::accepted("echo_redispatch")),
            Msg::Ok => Ok(MessageReceipt::accepted("ok")),
            Msg::Fail => Ok(MessageReceipt::accepted("fail")),
        }
    }

    fn receive_echo_response(&self, message: EchoResponse) -> Result<MessageReceipt> {
        message
            .body
            .verify(&message.header.signature, &message.header.sender)?;
        let mut state = self.inner.state.write().expect("state lock poisoned");
        if message.header.verify_header(&mut state) == Some(false) {
            return Err(BlossomError::UnknownSender);
        }
        Ok(MessageReceipt::accepted("echo_response"))
    }

    fn receive_verification(&self, message: Verification) -> Result<MessageReceipt> {
        message
            .body
            .verify(&message.header.signature, &message.header.sender)?;
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
        message
            .body
            .verify(&message.header.signature, &message.header.sender)?;
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
        message
            .body
            .verify(&message.header.signature, &message.header.sender)?;
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
        message
            .body
            .verify(&message.header.signature, &message.header.sender)?;
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

    fn empty_block(&self, self_node: &NodeIdentity, target: &EpochTarget) -> Result<Block> {
        let mut block = Block::default();
        block.body.last_epoch = target.last_epoch;
        block.body.nonce = target.nonce;
        match self.inner.signer.as_ref() {
            Some(signer) => block.sign_with(signer),
            None => {
                let secret_key = self_node.secret_key.ok_or(BlossomError::MissingSecretKey)?;
                block.sign(&secret_key);
            }
        }
        Ok(block)
    }

    fn sign_body<T: BlossomBody>(&self, self_node: &NodeIdentity, body: &T) -> Result<Signature> {
        let body_bytes = body.to_bytes();
        match self.inner.signer.as_ref() {
            Some(signer) => Ok(signer.sign(&body_bytes)),
            None => self_node.sign(&body_bytes),
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
    use crate::blossom::{BlossomBody, DispatchBody};
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
        let target = runtime.next_epoch_target().unwrap();

        let dispatch = runtime.dispatch_local_block(0).unwrap();

        assert_eq!(dispatch.header.nonce, target.nonce);
        assert_eq!(dispatch.body.blocks.len(), 1);
        let block = dispatch.body.blocks.values().next().unwrap();
        assert!(block.is_empty());
        assert!(block.verify_integrity().is_ok());
    }

    #[test]
    fn receive_message_rejects_unknown_sender_and_bad_signature() {
        let (runtime, keypairs, target) = runtime_with_peers();
        let unknown = Keypair::generate();
        let body = DispatchBody::default();
        let unknown_dispatch = Dispatch {
            header: Header {
                sender: unknown.public,
                last_epoch: target.last_epoch,
                nonce: target.nonce,
                round: 0,
                signature: body
                    .signature(&NodeIdentity::new(
                        unknown.public,
                        Some(unknown.secret),
                        "tcp",
                        "127.0.0.1",
                        9999,
                        false,
                    ))
                    .unwrap(),
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
}
