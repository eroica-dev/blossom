use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use borsh::{BorshDeserialize, BorshSerialize};
use indextreemap::IndexTreeMap;
use serde::{Deserialize, Serialize};

use crate::address_book::{AddressBook, Service, ServiceKind};
use crate::admission::NodeAdmission;
#[cfg(feature = "availability-gossip")]
use crate::availability::{
    AvailabilityEntry, AvailabilityGossip, AvailabilityGossipBody, AvailabilityReceipt,
    AvailabilityStore, FilteredPayloadBatchDelivery, FilteredPayloadBatchDeliveryBody,
    FilteredPayloadBatchFetch, FilteredPayloadBatchFetchBody, FilteredPayloadDelivery,
    FilteredPayloadFetch, FilteredPayloadRequest,
};
use crate::block::{Block, BlockApplicationState};
use crate::blossom::{
    BlossomBody, Commit, Dispatch, DispatchBody, EchoReDispatch, EchoRequest, EchoResponse,
    EpochStarted, Header, Proposal, ProposalBody, SignatureTree, Verification, VerificationBody,
};
use crate::crypto::{PubKey, SecretSigner, Signature};
use crate::encounter::{EncounterOutcome, EncounterPhase, EncounterRecord, EncounterRecordBody};
use crate::error::{BlossomError, Result};
use crate::group::ConsensusGroupId;
use crate::hash::{DoHash, HashType};
use crate::local_block::LocalBlock;
use crate::membership::ConsensusNodeRemovalPolicy;
use crate::messages::{MSGKey, Msg};
use crate::node::NodeIdentity;
use crate::nonce::Nonce;
use crate::overlay::{
    BroadcastReport, FanOutStrategy, add_self_consensus_service, broadcast_wire_request,
    select_fanout_targets,
};
use crate::state::{
    Epoch, EpochBody, LocalState, PendingDispatch, TempQuorum,
    configured_max_pending_raw_dispatch_bytes,
    configured_max_pending_raw_dispatch_bytes_per_sender,
};
use crate::telemetry::{TelemetryEvent, TelemetryHandle};
use crate::wire::{HotDispatch, WireRequest};

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub group_id: ConsensusGroupId,
    pub self_node: NodeIdentity,
    pub genesis: Option<Epoch>,
    pub address_book: AddressBook,
    pub block_cap: usize,
    pub trust_mode: TrustMode,
    pub mode: RuntimeMode,
    pub consensus_node_removal_policy: ConsensusNodeRemovalPolicy,
    pub telemetry: TelemetryHandle,
}

impl RuntimeConfig {
    pub fn new(self_node: NodeIdentity) -> Self {
        Self {
            group_id: ConsensusGroupId::root(),
            self_node,
            genesis: None,
            address_book: AddressBook::new(),
            block_cap: 100,
            trust_mode: TrustMode::Verified,
            mode: RuntimeMode::Consensus,
            consensus_node_removal_policy: ConsensusNodeRemovalPolicy::disabled(),
            telemetry: TelemetryHandle::default(),
        }
    }

    pub fn overlay(self_node: NodeIdentity) -> Self {
        let mut config = Self::new(self_node);
        config.mode = RuntimeMode::Overlay;
        config
    }

    pub fn for_group(self_node: NodeIdentity, group_id: ConsensusGroupId) -> Self {
        let mut config = Self::new(self_node);
        config.group_id = group_id;
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
    group_id: ConsensusGroupId,
    state: RwLock<LocalState>,
    local_blocks: RwLock<LocalBlock>,
    #[cfg(feature = "availability-gossip")]
    availability: RwLock<AvailabilityStore>,
    address_book: RwLock<AddressBook>,
    signer: Option<SecretSigner>,
    trust_mode: TrustMode,
    mode: RuntimeMode,
    telemetry: TelemetryHandle,
    next_telemetry_span_id: AtomicU64,
}

#[derive(Debug, Clone)]
struct RuntimeTelemetryMeta {
    stage: &'static str,
    event: &'static str,
    last_epoch: Option<HashType>,
    nonce: Option<Nonce>,
    round: Option<u8>,
    peer: Option<PubKey>,
    message_kind: Option<&'static str>,
}

#[derive(Debug, Clone)]
struct RuntimeTelemetrySpan {
    span_id: u64,
    meta: RuntimeTelemetryMeta,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct EpochTarget {
    pub group_id: ConsensusGroupId,
    pub last_epoch: HashType,
    pub nonce: Nonce,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct NodeStatus {
    pub group_id: ConsensusGroupId,
    pub node: NodeIdentity,
    pub last_epoch: HashType,
    pub last_epoch_nonce: Nonce,
    pub next_nonce: Nonce,
    pub pending_blocks: usize,
    pub services: Vec<Service>,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct AcceptedBlock {
    pub group_id: ConsensusGroupId,
    pub hash: HashType,
    pub nonce: Nonce,
    pub application_state_bytes: usize,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct MessageReceipt {
    pub kind: String,
    pub accepted: bool,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct PeerApplicationState {
    pub group_id: ConsensusGroupId,
    pub peer: PubKey,
    pub block_hash: HashType,
    pub last_epoch: HashType,
    pub nonce: Nonce,
    pub application_state: BlockApplicationState,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct ObservedEncounterRecord {
    pub group_id: ConsensusGroupId,
    pub block_hash: HashType,
    pub block_validator: PubKey,
    pub record: EncounterRecord,
}

impl NodeRuntime {
    pub fn new(mut config: RuntimeConfig) -> Self {
        let signer = config.self_node.signer().ok();
        let requested_group_id = config.group_id;
        let genesis = config.genesis.take().unwrap_or_else(|| {
            genesis_epoch_for_group(config.group_id, [config.self_node.clone()])
        });
        assert!(
            requested_group_id == ConsensusGroupId::root()
                || requested_group_id == genesis.body.group_id,
            "runtime config group id does not match genesis group id"
        );
        let group_id = genesis.body.group_id;
        add_self_consensus_service(&mut config.address_book, &config.self_node);

        Self {
            inner: Arc::new(RuntimeInner {
                group_id,
                state: RwLock::new(LocalState::new_with_consensus_node_removal_policy(
                    config.self_node,
                    genesis,
                    config.consensus_node_removal_policy,
                )),
                local_blocks: RwLock::new(LocalBlock::new(config.block_cap)),
                #[cfg(feature = "availability-gossip")]
                availability: RwLock::new(AvailabilityStore::default()),
                address_book: RwLock::new(config.address_book),
                signer,
                trust_mode: config.trust_mode,
                mode: config.mode,
                telemetry: config.telemetry,
                next_telemetry_span_id: AtomicU64::new(1),
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

    pub fn mode(&self) -> RuntimeMode {
        self.inner.mode
    }

    pub fn group_id(&self) -> ConsensusGroupId {
        self.inner.group_id
    }

    pub fn emit_telemetry_event(
        &self,
        stage: impl Into<String>,
        event: impl Into<String>,
        target: Option<&EpochTarget>,
    ) {
        let mut telemetry =
            TelemetryEvent::new(crate::telemetry::TelemetryEventKind::Event, stage, event)
                .with_node(self.self_node().public_key())
                .with_group_id(self.inner.group_id);
        telemetry = match target {
            Some(target) => telemetry.with_target(target.last_epoch, target.nonce),
            None => telemetry,
        };
        self.inner.telemetry.record(telemetry);
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
            group_id: self.inner.group_id,
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

    pub fn current_verifiers(&self) -> Vec<NodeIdentity> {
        let state = self.inner.state.read().expect("state lock poisoned");
        state
            .epochchain
            .epochchain
            .last()
            .map(|epoch| {
                epoch
                    .body
                    .verifiers
                    .values()
                    .cloned()
                    .map(|mut node| {
                        node.secret_key = None;
                        node
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Registers or replaces a local service endpoint in this node's address book.
    ///
    /// This is reachability metadata only. It does not admit `service.public_key`
    /// into the epoch verifier set or bypass consensus-message membership checks.
    pub fn register_service(&self, service: Service) -> Option<Service> {
        self.inner
            .address_book
            .write()
            .expect("address book lock poisoned")
            .add(service)
    }

    /// Stages a signed public-node admission into this node's next local block.
    ///
    /// The admission enters verifier membership only if that block is committed
    /// into the next epoch by consensus.
    pub fn stage_node_admission(&self, admission: NodeAdmission) -> Result<Option<NodeIdentity>> {
        self.ensure_consensus_mode("stage node admission")?;
        admission.verify()?;
        let target = self.next_epoch_target()?;
        if admission.body.last_epoch != target.last_epoch || admission.body.nonce != target.nonce {
            return Err(BlossomError::InvalidEpochNonce);
        }
        let node = admission.body.node.clone();
        if self.is_current_verifier(&node.public_key()) {
            return Ok(None);
        }
        self.inner
            .local_blocks
            .write()
            .expect("block lock poisoned")
            .add_node_admission(admission)?;
        Ok(Some(node))
    }

    /// Sets the opaque application state that will be piggy-backed onto this
    /// node's next dispatched block.
    ///
    /// Blossom validates only the size budget and commits these bytes into the
    /// block hash; parsing and versioning stay with the application.
    pub fn set_application_state(&self, bytes: impl Into<Vec<u8>>) -> Result<()> {
        self.ensure_consensus_mode("set application state")?;
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

    /// Adds a signed encounter record to the next locally dispatched block.
    ///
    /// Encounter records are protocol-owned evidence, not membership state.
    /// They are hash-committed into the block and independently signed by the
    /// observing node.
    pub fn add_encounter_record(&self, record: EncounterRecord) -> Result<HashType> {
        self.ensure_consensus_mode("add encounter record")?;
        let self_key = self.self_node().public_key();
        if record.body.observer != self_key {
            return Err(BlossomError::KeyMismatch);
        }
        self.inner
            .local_blocks
            .write()
            .expect("block lock poisoned")
            .add_encounter_record(record)
    }

    pub fn sign_encounter_record(
        &self,
        subject: PubKey,
        round: u8,
        phase: EncounterPhase,
        outcome: EncounterOutcome,
        evidence_hash: Option<HashType>,
        observed_at_micros: u128,
    ) -> Result<EncounterRecord> {
        self.ensure_consensus_mode("sign encounter record")?;
        let self_node = self.self_node();
        let target = self.next_epoch_target()?;
        let mut body = EncounterRecordBody::new(
            self_node.public_key(),
            subject,
            target.last_epoch,
            target.nonce,
            round,
            phase,
            outcome,
        )
        .observed_at_micros(observed_at_micros);
        body.evidence_hash = evidence_hash;

        match self.inner.signer.as_ref() {
            Some(signer) => EncounterRecord::signed(body, signer),
            None => {
                let secret_key = self_node.secret_key.ok_or(BlossomError::MissingSecretKey)?;
                EncounterRecord::signed(body, &SecretSigner::new(secret_key))
            }
        }
    }

    pub fn record_encounter(
        &self,
        subject: PubKey,
        round: u8,
        phase: EncounterPhase,
        outcome: EncounterOutcome,
        evidence_hash: Option<HashType>,
        observed_at_micros: u128,
    ) -> Result<HashType> {
        let record = self.sign_encounter_record(
            subject,
            round,
            phase,
            outcome,
            evidence_hash,
            observed_at_micros,
        )?;
        self.add_encounter_record(record)
    }

    pub fn record_missing_signature(
        &self,
        subject: PubKey,
        round: u8,
        phase: EncounterPhase,
        observed_at_micros: u128,
    ) -> Result<HashType> {
        self.record_encounter(
            subject,
            round,
            phase,
            EncounterOutcome::MissingSignature,
            None,
            observed_at_micros,
        )
    }

    /// Returns round members that have not produced a signed message for the
    /// requested consensus phase, from this node's current local view.
    pub fn missing_signature_subjects(
        &self,
        round: u8,
        phase: EncounterPhase,
    ) -> Result<Vec<PubKey>> {
        self.ensure_consensus_mode("inspect missing signatures")?;
        let target = self.next_epoch_target()?;
        let mut state = self.inner.state.write().expect("state lock poisoned");
        let consensus = state.get_mut_consensus(&target.last_epoch, target.nonce);
        let mut missing = consensus.peers(round);
        let Some(quorum) = consensus.quorum.get(&round) else {
            return Ok(missing);
        };

        missing.retain(|subject| !quorum_has_signature_from(quorum, *subject, phase));
        Ok(missing)
    }

    /// Queues signed missing-signature records for every expected peer that has
    /// not produced a signed message for the requested phase.
    pub fn record_missing_signatures(
        &self,
        round: u8,
        phase: EncounterPhase,
        observed_at_micros: u128,
    ) -> Result<Vec<HashType>> {
        let subjects = self.missing_signature_subjects(round, phase)?;
        subjects
            .into_iter()
            .map(|subject| self.record_missing_signature(subject, round, phase, observed_at_micros))
            .collect()
    }

    pub fn pending_encounter_records(&self) -> Vec<EncounterRecord> {
        self.inner
            .local_blocks
            .read()
            .expect("block lock poisoned")
            .encounter_records()
            .to_vec()
    }

    /// Returns signed encounter evidence observed in committed or verified
    /// blocks. This is intentionally just evidence; membership decisions should
    /// be derived by a deterministic reducer over committed records.
    pub fn observed_encounter_records(&self) -> Vec<ObservedEncounterRecord> {
        let state = self.inner.state.read().expect("state lock poisoned");
        let mut records = Vec::new();

        for epoch in &state.epochchain.epochchain {
            for (block_hash, block) in &epoch.body.blocks {
                record_observed_encounters(&mut records, epoch.body.group_id, *block_hash, block);
            }
        }

        for consensus in state.consensus.values() {
            for quorum in consensus.quorum.values() {
                for (block_hash, block) in &quorum.verified_blocks {
                    record_observed_encounters(
                        &mut records,
                        self.inner.group_id,
                        *block_hash,
                        block,
                    );
                }
            }
        }

        records
    }

    /// Returns the latest verified or committed application state observed for
    /// each peer.
    ///
    /// This is the read side of [`NodeRuntime::set_application_state`]: peer
    /// bytes arrive in normal consensus blocks rather than through a separate
    /// application message channel.
    pub fn peer_application_states(&self) -> BTreeMap<PubKey, PeerApplicationState> {
        let state = self.inner.state.read().expect("state lock poisoned");
        let self_key = state.self_node.public_key();
        let mut peer_states = BTreeMap::new();

        for epoch in &state.epochchain.epochchain {
            for (block_hash, block) in &epoch.body.blocks {
                if block.body.validator != self_key {
                    record_peer_application_state(
                        &mut peer_states,
                        epoch.body.group_id,
                        *block_hash,
                        block,
                        block.body.last_epoch,
                        block.body.nonce,
                    );
                }
            }
        }

        for consensus in state.consensus.values() {
            for quorum in consensus.quorum.values() {
                for (block_hash, block) in &quorum.verified_blocks {
                    if block.body.validator != self_key {
                        record_peer_application_state(
                            &mut peer_states,
                            self.inner.group_id,
                            *block_hash,
                            block,
                            block.body.last_epoch,
                            block.body.nonce,
                        );
                    }
                }
            }
        }

        peer_states
    }

    #[cfg(feature = "availability-gossip")]
    pub fn store_filtered_payload_from_transaction(
        &self,
        tx: &crate::block::Transaction,
    ) -> Result<Option<AvailabilityEntry>> {
        let holder = self.self_node().public_key();
        self.inner
            .availability
            .write()
            .expect("availability lock poisoned")
            .store_transaction(self.inner.group_id, holder, tx)
    }

    #[cfg(feature = "availability-gossip")]
    pub fn local_availability_entries(&self) -> Vec<AvailabilityEntry> {
        self.inner
            .availability
            .read()
            .expect("availability lock poisoned")
            .local_entries(self.inner.group_id)
    }

    #[cfg(feature = "availability-gossip")]
    pub fn peer_availability_entries(&self) -> Vec<(PubKey, AvailabilityEntry)> {
        self.inner
            .availability
            .read()
            .expect("availability lock poisoned")
            .peer_entries()
    }

    #[cfg(feature = "availability-gossip")]
    pub fn availability_gossip(&self) -> Result<AvailabilityGossip> {
        let self_node = self.self_node();
        let body = AvailabilityGossipBody {
            scope: self.inner.group_id,
            holder: self_node.public_key(),
            entries: self.local_availability_entries(),
        };
        if self.inner.trust_mode.is_trusted() {
            return AvailabilityGossip::trusted(body);
        }
        match self.inner.signer.as_ref() {
            Some(signer) => AvailabilityGossip::signed(body, signer),
            None => {
                let secret_key = self_node.secret_key.ok_or(BlossomError::MissingSecretKey)?;
                AvailabilityGossip::signed(body, &SecretSigner::new(secret_key))
            }
        }
    }

    #[cfg(feature = "availability-gossip")]
    pub fn receive_availability_gossip(
        &self,
        gossip: AvailabilityGossip,
    ) -> Result<AvailabilityReceipt> {
        if gossip.body.scope != self.inner.group_id {
            return Err(BlossomError::WireProtocol(format!(
                "availability gossip scope {} does not match runtime group {}",
                gossip.body.scope, self.inner.group_id
            )));
        }
        if !self.is_known_member(&gossip.body.holder) {
            return Err(BlossomError::UnknownSender);
        }
        if !self.inner.trust_mode.is_trusted() {
            gossip.verify()?;
        } else {
            gossip.body.validate()?;
        }
        let accepted = self
            .inner
            .availability
            .write()
            .expect("availability lock poisoned")
            .record_gossip(&gossip)?;
        Ok(AvailabilityReceipt {
            scope: self.inner.group_id,
            holder: gossip.body.holder,
            entries_accepted: accepted,
        })
    }

    #[cfg(feature = "availability-gossip")]
    pub fn filtered_payload_fetch(
        &self,
        slot_hash: HashType,
        payload_commitment: HashType,
    ) -> Result<FilteredPayloadFetch> {
        let self_node = self.self_node();
        let body = crate::availability::FilteredPayloadFetchBody {
            scope: self.inner.group_id,
            requester: self_node.public_key(),
            slot_hash,
            payload_commitment,
        };
        if self.inner.trust_mode.is_trusted() {
            return Ok(FilteredPayloadFetch::trusted(body));
        }
        match self.inner.signer.as_ref() {
            Some(signer) => Ok(FilteredPayloadFetch::signed(body, signer)),
            None => {
                let secret_key = self_node.secret_key.ok_or(BlossomError::MissingSecretKey)?;
                Ok(FilteredPayloadFetch::signed(
                    body,
                    &SecretSigner::new(secret_key),
                ))
            }
        }
    }

    #[cfg(feature = "availability-gossip")]
    pub fn filtered_payload_batch_fetch(
        &self,
        requests: Vec<FilteredPayloadRequest>,
    ) -> Result<FilteredPayloadBatchFetch> {
        let self_node = self.self_node();
        let body = FilteredPayloadBatchFetchBody {
            scope: self.inner.group_id,
            requester: self_node.public_key(),
            requests,
        };
        if self.inner.trust_mode.is_trusted() {
            return FilteredPayloadBatchFetch::trusted(body);
        }
        match self.inner.signer.as_ref() {
            Some(signer) => FilteredPayloadBatchFetch::signed(body, signer),
            None => {
                let secret_key = self_node.secret_key.ok_or(BlossomError::MissingSecretKey)?;
                FilteredPayloadBatchFetch::signed(body, &SecretSigner::new(secret_key))
            }
        }
    }

    #[cfg(feature = "availability-gossip")]
    pub fn serve_filtered_payload_fetch(
        &self,
        fetch: FilteredPayloadFetch,
    ) -> Result<Option<FilteredPayloadDelivery>> {
        if fetch.body.scope != self.inner.group_id {
            return Err(BlossomError::WireProtocol(format!(
                "filtered payload fetch scope {} does not match runtime group {}",
                fetch.body.scope, self.inner.group_id
            )));
        }
        if !self.is_known_member(&fetch.body.requester) {
            return Err(BlossomError::UnknownSender);
        }
        if !self.inner.trust_mode.is_trusted() {
            fetch.verify()?;
        }
        let Some(payload) = self
            .inner
            .availability
            .read()
            .expect("availability lock poisoned")
            .get_local_payload(
                self.inner.group_id,
                &fetch.body.slot_hash,
                &fetch.body.payload_commitment,
                &fetch.body.requester,
            )?
        else {
            return Ok(None);
        };
        let body = payload.delivery_body();
        if self.inner.trust_mode.is_trusted() {
            return FilteredPayloadDelivery::trusted(body).map(Some);
        }
        match self.inner.signer.as_ref() {
            Some(signer) => FilteredPayloadDelivery::signed(body, signer).map(Some),
            None => {
                let self_node = self.self_node();
                let secret_key = self_node.secret_key.ok_or(BlossomError::MissingSecretKey)?;
                FilteredPayloadDelivery::signed(body, &SecretSigner::new(secret_key)).map(Some)
            }
        }
    }

    #[cfg(feature = "availability-gossip")]
    pub fn serve_filtered_payload_batch_fetch(
        &self,
        fetch: FilteredPayloadBatchFetch,
    ) -> Result<FilteredPayloadBatchDelivery> {
        if fetch.body.scope != self.inner.group_id {
            return Err(BlossomError::WireProtocol(format!(
                "filtered payload batch fetch scope {} does not match runtime group {}",
                fetch.body.scope, self.inner.group_id
            )));
        }
        if !self.is_known_member(&fetch.body.requester) {
            return Err(BlossomError::UnknownSender);
        }
        if !self.inner.trust_mode.is_trusted() {
            fetch.verify()?;
        } else {
            fetch.body.validate()?;
        }

        let mut items = Vec::new();
        {
            let availability = self
                .inner
                .availability
                .read()
                .expect("availability lock poisoned");
            for request in &fetch.body.requests {
                if let Some(payload) = availability.get_local_payload(
                    self.inner.group_id,
                    &request.slot_hash,
                    &request.payload_commitment,
                    &fetch.body.requester,
                )? {
                    items.push(payload.delivery_item());
                }
            }
        }

        let body = FilteredPayloadBatchDeliveryBody {
            scope: self.inner.group_id,
            holder: self.self_node().public_key(),
            items,
        };
        if self.inner.trust_mode.is_trusted() {
            return FilteredPayloadBatchDelivery::trusted(body);
        }
        match self.inner.signer.as_ref() {
            Some(signer) => FilteredPayloadBatchDelivery::signed(body, signer),
            None => {
                let self_node = self.self_node();
                let secret_key = self_node.secret_key.ok_or(BlossomError::MissingSecretKey)?;
                FilteredPayloadBatchDelivery::signed(body, &SecretSigner::new(secret_key))
            }
        }
    }

    #[cfg(feature = "availability-gossip")]
    pub fn receive_filtered_payload(
        &self,
        delivery: FilteredPayloadDelivery,
    ) -> Result<AvailabilityReceipt> {
        if delivery.body.scope != self.inner.group_id {
            return Err(BlossomError::WireProtocol(format!(
                "filtered payload scope {} does not match runtime group {}",
                delivery.body.scope, self.inner.group_id
            )));
        }
        if !self.is_known_member(&delivery.body.holder) {
            return Err(BlossomError::UnknownSender);
        }
        if !delivery.body.slot.is_target(&self.self_node().public_key()) {
            return Err(BlossomError::WireProtocol(format!(
                "this node is not a target for filtered payload {}",
                delivery.body.slot_hash
            )));
        }
        if !self.inner.trust_mode.is_trusted() {
            delivery.verify()?;
        } else {
            delivery.body.validate()?;
        }
        let holder = self.self_node().public_key();
        self.inner
            .availability
            .write()
            .expect("availability lock poisoned")
            .store_local(
                self.inner.group_id,
                holder,
                delivery.body.slot.clone(),
                delivery.body.payload.clone(),
            )?;
        Ok(AvailabilityReceipt {
            scope: self.inner.group_id,
            holder: delivery.body.holder,
            entries_accepted: 1,
        })
    }

    #[cfg(feature = "availability-gossip")]
    pub fn receive_filtered_payload_batch(
        &self,
        delivery: FilteredPayloadBatchDelivery,
    ) -> Result<AvailabilityReceipt> {
        if delivery.body.scope != self.inner.group_id {
            return Err(BlossomError::WireProtocol(format!(
                "filtered payload batch scope {} does not match runtime group {}",
                delivery.body.scope, self.inner.group_id
            )));
        }
        if !self.is_known_member(&delivery.body.holder) {
            return Err(BlossomError::UnknownSender);
        }
        let self_key = self.self_node().public_key();
        for item in &delivery.body.items {
            if !item.slot.is_target(&self_key) {
                return Err(BlossomError::WireProtocol(format!(
                    "this node is not a target for filtered payload {}",
                    item.slot_hash
                )));
            }
        }
        if !self.inner.trust_mode.is_trusted() {
            delivery.verify()?;
        } else {
            delivery.body.validate()?;
        }

        let mut accepted = 0usize;
        let mut availability = self
            .inner
            .availability
            .write()
            .expect("availability lock poisoned");
        for item in &delivery.body.items {
            availability.store_local(
                self.inner.group_id,
                self_key,
                item.slot.clone(),
                item.payload.clone(),
            )?;
            accepted += 1;
        }
        Ok(AvailabilityReceipt {
            scope: self.inner.group_id,
            holder: delivery.body.holder,
            entries_accepted: accepted,
        })
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

    #[cfg(feature = "availability-gossip")]
    pub async fn broadcast_availability_gossip(
        &self,
        strategy: FanOutStrategy,
    ) -> Result<BroadcastReport> {
        self.broadcast_request(
            WireRequest::AvailabilityGossip(self.availability_gossip()?),
            strategy,
        )
        .await
    }

    pub fn next_epoch_target(&self) -> Result<EpochTarget> {
        self.ensure_consensus_mode("select next epoch target")?;
        let state = self.inner.state.read().expect("state lock poisoned");
        let epoch = state
            .epochchain
            .epochchain
            .last()
            .ok_or(BlossomError::EmptyEpochChain)?;
        Ok(EpochTarget {
            group_id: self.inner.group_id,
            last_epoch: epoch.hash,
            nonce: epoch.body.nonce.new_next(),
        })
    }

    pub fn contains_epoch_hash(&self, epoch_hash: &HashType) -> bool {
        let state = self.inner.state.read().expect("state lock poisoned");
        state
            .epochchain
            .epochchain
            .iter()
            .any(|epoch| epoch.hash == *epoch_hash)
    }

    pub fn submit_block(&self, block: Block) -> Result<AcceptedBlock> {
        let target = self.next_epoch_target()?;
        let span = self.start_telemetry_span(self.target_telemetry_meta(
            "block_formation",
            "block_submitted",
            &target,
            None,
            Some(block.body.validator),
            None,
        ));
        let result = (|| {
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
            #[cfg(feature = "availability-gossip")]
            self.store_filtered_payloads_from_block(&block)?;

            let application_state_bytes = block.application_state_len();
            let hash = self
                .inner
                .local_blocks
                .write()
                .expect("block lock poisoned")
                .enqueue_preverified_block(block)?;
            Ok(AcceptedBlock {
                group_id: self.inner.group_id,
                hash,
                nonce: target.nonce,
                application_state_bytes,
            })
        })();
        self.finish_telemetry_span(span, &result);
        result
    }

    pub fn dispatch_local_block(&self, round: u8) -> Result<Dispatch> {
        let target = self.next_epoch_target()?;
        let span = self.start_telemetry_span(self.target_telemetry_meta(
            "dispatch",
            "dispatch_local_block",
            &target,
            Some(round),
            None,
            Some("Dispatch"),
        ));
        let result = (|| {
            let self_node = self.self_node();
            let block_service = self.block_service();

            let (maybe_block, application_state, encounter_records, node_admissions) = {
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
                let encounter_records = if maybe_block.is_none() {
                    local_blocks.take_encounter_records()
                } else {
                    Vec::new()
                };
                let node_admissions = if maybe_block.is_none() {
                    local_blocks.take_node_admissions()
                } else {
                    Vec::new()
                };
                (
                    maybe_block,
                    local_blocks.application_state().clone(),
                    encounter_records,
                    node_admissions,
                )
            };

            let block = match maybe_block {
                Some(block) => block,
                None => self.empty_block(
                    &self_node,
                    &target,
                    application_state,
                    encounter_records,
                    node_admissions,
                )?,
            };
            #[cfg(feature = "availability-gossip")]
            self.store_filtered_payloads_from_block(&block)?;

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
            record_verified_dispatch_blocks(quorum, body.blocks.clone());
            Ok(Dispatch { header, body })
        })();
        self.finish_telemetry_span(span, &result);
        result
    }

    pub fn receive_message(&self, message: Msg) -> Result<MessageReceipt> {
        let span = self.start_telemetry_span(message_telemetry_meta(&message));
        let result = (|| {
            self.ensure_consensus_mode("receive consensus message")?;
            match message {
                Msg::Dispatch(message) => {
                    self.verify_message_signature(
                        &message.header,
                        MSGKey::Dispatch,
                        &message.body,
                    )?;
                    let mut state = self.inner.state.write().expect("state lock poisoned");
                    if message.header.verify_header(&mut state) == Some(false) {
                        return Err(BlossomError::UnknownSender);
                    }
                    drop(state);
                    self.verify_dispatch_payload(&message.header, &message.body)?;
                    let header = message.header.clone();
                    let verified_blocks = message.body.blocks.clone();
                    let mut state = self.inner.state.write().expect("state lock poisoned");
                    message.try_accept_into_state(&mut state)?;
                    let quorum =
                        state.get_mut_quorum(&header.last_epoch, header.nonce, header.round);
                    record_verified_dispatch_blocks(quorum, verified_blocks);
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
        })();
        self.finish_telemetry_span(span, &result);
        result
    }

    pub fn receive_hot_dispatch(&self, message: HotDispatch) -> Result<MessageReceipt> {
        let span = self.start_telemetry_span(header_telemetry_meta(
            "dispatch",
            "hot_dispatch_received",
            &message.header,
            Some("HotDispatch"),
        ));
        let result = (|| {
            self.ensure_consensus_mode("receive hot dispatch")?;
            self.ensure_current_header_target(&message.header)?;
            if !self.inner.trust_mode.is_trusted() {
                message.verify_signature()?;
            }
            let mut state = self.inner.state.write().expect("state lock poisoned");
            if message.header.verify_header(&mut state) == Some(false) {
                return Err(BlossomError::UnknownSender);
            }
            drop(state);
            if self.inner.trust_mode.is_trusted() {
                let scan = message.scan_trusted()?;
                let mut state = self.inner.state.write().expect("state lock poisoned");
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
                quorum.msg_matrix.update_dispatch_received(true, sender);
                quorum.timers.verified_tx = quorum
                    .timers
                    .verified_tx
                    .saturating_add(scan.transaction_count);
                quorum.received_dispatches.push(sender);
                return Ok(MessageReceipt::accepted("dispatch"));
            }
            let decoded_message = message.to_dispatch()?;
            self.verify_dispatch_payload(&decoded_message.header, &decoded_message.body)?;
            let mut state = self.inner.state.write().expect("state lock poisoned");
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
            quorum.msg_matrix.update_dispatch_received(true, sender);
            let verified_blocks = decoded_message.body.blocks;
            record_verified_dispatch_blocks(quorum, verified_blocks);
            quorum.received_dispatches.push(sender);
            Ok(MessageReceipt::accepted("dispatch"))
        })();
        self.finish_telemetry_span(span, &result);
        result
    }

    fn receive_echo_request(&self, message: EchoRequest) -> Result<MessageReceipt> {
        self.verify_message_signature(
            &message.header,
            MSGKey::EchoRequest,
            &message.requested_blocks,
        )?;
        let mut state = self.inner.state.write().expect("state lock poisoned");
        if message.header.verify_header(&mut state) == Some(false) {
            return Err(BlossomError::UnknownSender);
        }
        Ok(MessageReceipt::accepted("echo_request"))
    }

    fn receive_echo_redispatch(&self, message: EchoReDispatch) -> Result<MessageReceipt> {
        self.verify_message_signature(
            &message.header,
            MSGKey::EchoReDispatch,
            &message.redispatched_blocks,
        )?;
        self.verify_redispatched_blocks(&message.redispatched_blocks)?;
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
        let quorum = state.get_mut_quorum(
            &message.header.last_epoch,
            message.header.nonce,
            message.header.round,
        );
        if quorum
            .msg_matrix
            .find_key_index(&message.body.sender)
            .is_none()
        {
            return Err(BlossomError::UnknownSender);
        }
        quorum.msg_matrix.update(true, Msg::EchoResponse(message));
        Ok(MessageReceipt::accepted("echo_response"))
    }

    fn receive_verification(&self, message: Verification) -> Result<MessageReceipt> {
        self.verify_message_signature(&message.header, MSGKey::Verification, &message.body)?;
        message.body.validate()?;
        let mut state = self.inner.state.write().expect("state lock poisoned");
        if message.header.verify_header(&mut state) == Some(false) {
            return Err(BlossomError::UnknownSender);
        }
        let quorum = state.get_mut_quorum(
            &message.header.last_epoch,
            message.header.nonce,
            message.header.round,
        );
        if message.body.blocks != quorum.verified_blocks()
            || message.body.blocks_hash != quorum.verified_blocks_hash()
        {
            return Err(BlossomError::WireProtocol(
                "verification references block set that has not been locally verified".to_string(),
            ));
        }
        quorum.verifications.record(message);
        Ok(MessageReceipt::accepted("verification"))
    }

    fn receive_proposal(&self, message: Proposal) -> Result<MessageReceipt> {
        self.verify_message_signature(&message.header, MSGKey::Proposal, &message.body)?;
        message.body.validate()?;
        let mut state = self.inner.state.write().expect("state lock poisoned");
        if message.header.verify_header(&mut state) == Some(false) {
            return Err(BlossomError::UnknownSender);
        }
        let quorum = state.get_mut_quorum(
            &message.header.last_epoch,
            message.header.nonce,
            message.header.round,
        );
        self.verify_proposal_proof(&message.header, &message.body, quorum)?;
        quorum.proposals.record(message);
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
        if message.body.consensus && quorum.proposals.consensus() != Some(true) {
            return Err(BlossomError::WireProtocol(
                "true commit requires a local proposal supermajority".to_string(),
            ));
        }
        let sender = message.header.sender;
        quorum.commit_senders.insert(sender);
        if message.body.consensus {
            quorum.commit_true_senders.insert(sender);
        } else {
            quorum.commit_true_senders.remove(&sender);
        }
        quorum.commit_sent =
            quorum.commit_true_senders.len() >= quorum.proposals.supermajority as usize;
        if quorum.commit_sent {
            state.advance_epoch(
                &message.header.last_epoch,
                message.header.nonce,
                message.header.round,
                true,
            );
        }
        Ok(MessageReceipt::accepted("commit"))
    }

    fn receive_epoch_started(&self, message: EpochStarted) -> Result<MessageReceipt> {
        self.verify_message_signature(&message.header, MSGKey::EpochStarted, &message.body)?;
        let mut state = self.inner.state.write().expect("state lock poisoned");
        if message.header.verify_header(&mut state) == Some(false) {
            return Err(BlossomError::UnknownSender);
        }
        state
            .get_mut_quorum(
                &message.header.last_epoch,
                message.header.nonce,
                message.header.round,
            )
            .epoch_started_senders
            .insert(message.header.sender);
        Ok(MessageReceipt::accepted("epoch_started"))
    }

    fn start_telemetry_span(&self, meta: RuntimeTelemetryMeta) -> RuntimeTelemetrySpan {
        let span_id = self
            .inner
            .next_telemetry_span_id
            .fetch_add(1, Ordering::Relaxed);
        let mut event = TelemetryEvent::span_start(span_id, meta.stage, meta.event)
            .with_node(self.self_node().public_key())
            .with_group_id(self.inner.group_id);
        event = apply_telemetry_meta(event, &meta);
        self.inner.telemetry.record(event);
        RuntimeTelemetrySpan { span_id, meta }
    }

    fn finish_telemetry_span<T>(&self, span: RuntimeTelemetrySpan, result: &Result<T>) {
        let mut event = TelemetryEvent::span_end(span.span_id, span.meta.stage, span.meta.event)
            .with_node(self.self_node().public_key())
            .with_group_id(self.inner.group_id)
            .with_outcome(if result.is_ok() { "ok" } else { "error" });
        event = apply_telemetry_meta(event, &span.meta);
        if let Err(err) = result {
            event = event.with_error(err.to_string());
        }
        self.inner.telemetry.record(event);
    }

    fn target_telemetry_meta(
        &self,
        stage: &'static str,
        event: &'static str,
        target: &EpochTarget,
        round: Option<u8>,
        peer: Option<PubKey>,
        message_kind: Option<&'static str>,
    ) -> RuntimeTelemetryMeta {
        RuntimeTelemetryMeta {
            stage,
            event,
            last_epoch: Some(target.last_epoch),
            nonce: Some(target.nonce),
            round,
            peer,
            message_kind,
        }
    }

    fn ensure_consensus_mode(&self, action: &str) -> Result<()> {
        if self.inner.mode == RuntimeMode::Overlay {
            return Err(BlossomError::WireProtocol(format!(
                "{action} requires consensus runtime mode"
            )));
        }
        Ok(())
    }

    fn validate_block_service(&self, block: &Block) -> Result<()> {
        match self.block_service() {
            Some(service) if block.body.validator != service.public_key => {
                Err(BlossomError::UnknownSender)
            }
            _ => Ok(()),
        }
    }

    #[cfg(feature = "availability-gossip")]
    fn store_filtered_payloads_from_block(&self, block: &Block) -> Result<()> {
        for tx in &block.body.txs {
            self.store_filtered_payload_from_transaction(tx)?;
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

    fn is_current_verifier(&self, public_key: &PubKey) -> bool {
        let state = self.inner.state.read().expect("state lock poisoned");
        state
            .epochchain
            .epochchain
            .last()
            .is_some_and(|epoch| epoch.body.verifiers.keys().any(|key| key == public_key))
    }

    #[cfg(feature = "availability-gossip")]
    fn is_known_member(&self, public_key: &PubKey) -> bool {
        self.is_current_verifier(public_key)
    }

    fn empty_block(
        &self,
        self_node: &NodeIdentity,
        target: &EpochTarget,
        application_state: BlockApplicationState,
        encounter_records: Vec<EncounterRecord>,
        node_admissions: Vec<NodeAdmission>,
    ) -> Result<Block> {
        let mut block = Block::default();
        block.body.last_epoch = target.last_epoch;
        block.body.nonce = target.nonce;
        block.body.application_state = application_state;
        block.body.encounter_records = encounter_records;
        block.body.node_admissions = node_admissions;
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

    fn verify_dispatch_payload(&self, header: &Header, body: &DispatchBody) -> Result<()> {
        body.validate()?;
        for (hash, block) in &body.blocks {
            if block.body.last_epoch != header.last_epoch {
                return Err(BlossomError::InvalidBlockLastEpoch);
            }
            if block.body.nonce != header.nonce {
                return Err(BlossomError::InvalidBlockNonce {
                    expected: header.nonce,
                    actual: block.body.nonce,
                });
            }
            if self.inner.trust_mode.is_trusted() {
                block.verify_unsigned_integrity_with_hash(*hash)?;
            } else {
                block.verify_integrity_with_hash(*hash)?;
            }
        }
        if !self.inner.trust_mode.is_trusted() && !body.signature_tree.verify() {
            return Err(BlossomError::WireProtocol(
                "dispatch signature tree failed verification".to_string(),
            ));
        }
        Ok(())
    }

    fn verify_block_integrity(&self, block: &Block) -> Result<()> {
        if self.inner.trust_mode.is_trusted() {
            block.verify_unsigned_integrity()
        } else {
            block.verify_integrity()
        }
    }

    fn verify_redispatched_blocks(&self, blocks: &BTreeMap<HashType, Block>) -> Result<()> {
        for (hash, block) in blocks {
            if self.inner.trust_mode.is_trusted() {
                block.verify_unsigned_integrity_with_hash(*hash)?;
            } else {
                block.verify_integrity_with_hash(*hash)?;
            }
        }
        Ok(())
    }

    fn verify_message_signature<T: BlossomBody>(
        &self,
        header: &Header,
        kind: MSGKey,
        body: &T,
    ) -> Result<()> {
        self.ensure_current_header_target(header)?;
        if self.inner.trust_mode.is_trusted() {
            Ok(())
        } else {
            header.verify_signature(kind, body)
        }
    }

    fn verify_proposal_proof(
        &self,
        header: &Header,
        body: &ProposalBody,
        quorum: &TempQuorum,
    ) -> Result<()> {
        if !body.consensus {
            return Ok(());
        }

        let approved_blocks = body.approved_blocks.as_ref().ok_or_else(|| {
            BlossomError::WireProtocol(
                "consensus proposal must include approved blocks".to_string(),
            )
        })?;
        let approved_hash = body.approved_hash.ok_or_else(|| {
            BlossomError::WireProtocol("consensus proposal must include approved hash".to_string())
        })?;

        if approved_blocks != &quorum.verified_blocks()
            || Some(approved_hash) != quorum.verified_blocks_hash
        {
            return Err(BlossomError::WireProtocol(
                "proposal references block set that has not been locally verified".to_string(),
            ));
        }

        let verification_proof = body.verif.as_ref().ok_or_else(|| {
            BlossomError::WireProtocol(
                "consensus proposal must include verification proof".to_string(),
            )
        })?;
        let verification_body = VerificationBody {
            blocks_hash: approved_hash,
            blocks: approved_blocks.clone(),
        };
        let mut distinct_verifiers = BTreeSet::new();

        for (verifier, signature) in verification_proof {
            if !quorum.msg_matrix.quorum_nodes.contains(verifier) {
                return Err(BlossomError::UnknownSender);
            }
            if !distinct_verifiers.insert(*verifier) {
                continue;
            }
            if !self.inner.trust_mode.is_trusted() {
                let signature_hash = Header::signature_hash_for_body(
                    verifier,
                    &header.last_epoch,
                    header.nonce,
                    header.round,
                    MSGKey::Verification,
                    &verification_body,
                );
                signature.verify(signature_hash.as_ref(), verifier)?;
            }
        }

        if distinct_verifiers.len() < quorum.proposals.supermajority as usize {
            return Err(BlossomError::WireProtocol(format!(
                "consensus proposal verification proof has {} distinct verifier signatures, need {}",
                distinct_verifiers.len(),
                quorum.proposals.supermajority
            )));
        }

        Ok(())
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

    fn ensure_current_header_target(&self, header: &Header) -> Result<()> {
        let state = self.inner.state.read().expect("state lock poisoned");
        let latest = state
            .epochchain
            .epochchain
            .last()
            .ok_or(BlossomError::EmptyEpochChain)?;
        if !state
            .epochchain
            .epochchain
            .iter()
            .any(|epoch| epoch.hash == header.last_epoch)
        {
            return Err(BlossomError::WireProtocol(format!(
                "unknown consensus epoch {} for group {}",
                header.last_epoch, self.inner.group_id
            )));
        }

        let expected_nonce = latest.body.nonce.new_next();
        if header.last_epoch != latest.hash || header.nonce != expected_nonce {
            return Err(BlossomError::WireProtocol(format!(
                "stale consensus target {}/{} for group {}; current target is {}/{}",
                header.last_epoch, header.nonce, self.inner.group_id, latest.hash, expected_nonce
            )));
        }

        Ok(())
    }
}

#[derive(Clone)]
pub struct MultiGroupRuntime {
    inner: Arc<MultiGroupRuntimeInner>,
}

struct MultiGroupRuntimeInner {
    root_group: ConsensusGroupId,
    groups: RwLock<BTreeMap<ConsensusGroupId, NodeRuntime>>,
}

impl MultiGroupRuntime {
    pub fn new(root_runtime: NodeRuntime) -> Self {
        let root_group = root_runtime.group_id();
        let mut groups = BTreeMap::new();
        groups.insert(root_group, root_runtime);

        Self {
            inner: Arc::new(MultiGroupRuntimeInner {
                root_group,
                groups: RwLock::new(groups),
            }),
        }
    }

    pub fn with_groups(
        root_runtime: NodeRuntime,
        groups: impl IntoIterator<Item = NodeRuntime>,
    ) -> Self {
        let runtime = Self::new(root_runtime);
        for group in groups {
            runtime.insert_group(group);
        }
        runtime
    }

    pub fn root_group(&self) -> ConsensusGroupId {
        self.inner.root_group
    }

    pub fn root_runtime(&self) -> NodeRuntime {
        self.group(&self.inner.root_group)
            .expect("root runtime should always be present")
    }

    pub fn insert_group(&self, runtime: NodeRuntime) -> Option<NodeRuntime> {
        let group_id = runtime.group_id();
        self.inner
            .groups
            .write()
            .expect("group runtime lock poisoned")
            .insert(group_id, runtime)
    }

    pub fn group(&self, group_id: &ConsensusGroupId) -> Option<NodeRuntime> {
        self.inner
            .groups
            .read()
            .expect("group runtime lock poisoned")
            .get(group_id)
            .cloned()
    }

    pub fn group_for_epoch(&self, epoch_hash: &HashType) -> Option<NodeRuntime> {
        self.inner
            .groups
            .read()
            .expect("group runtime lock poisoned")
            .values()
            .find(|runtime| runtime.contains_epoch_hash(epoch_hash))
            .cloned()
    }

    pub fn group_ids(&self) -> Vec<ConsensusGroupId> {
        self.inner
            .groups
            .read()
            .expect("group runtime lock poisoned")
            .keys()
            .copied()
            .collect()
    }

    pub fn len(&self) -> usize {
        self.inner
            .groups
            .read()
            .expect("group runtime lock poisoned")
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn apply_telemetry_meta(mut event: TelemetryEvent, meta: &RuntimeTelemetryMeta) -> TelemetryEvent {
    event = match (meta.last_epoch, meta.nonce) {
        (Some(last_epoch), Some(nonce)) => event.with_target(last_epoch, nonce),
        _ => event,
    };
    event = match meta.round {
        Some(round) => event.with_round(round),
        None => event,
    };
    event = match meta.peer {
        Some(peer) => event.with_peer(peer),
        None => event,
    };
    event = match meta.message_kind {
        Some(message_kind) => event.with_message_kind(message_kind),
        None => event,
    };
    event
}

fn message_telemetry_meta(message: &Msg) -> RuntimeTelemetryMeta {
    match message {
        Msg::Dispatch(message) => header_telemetry_meta(
            "dispatch",
            "dispatch_received",
            &message.header,
            Some("Dispatch"),
        ),
        Msg::EchoResponse(message) => header_telemetry_meta(
            "echo",
            "echo_response_received",
            &message.header,
            Some("EchoResponse"),
        ),
        Msg::Verification(message) => header_telemetry_meta(
            "verification",
            "verification_received",
            &message.header,
            Some("Verification"),
        ),
        Msg::Proposal(message) => header_telemetry_meta(
            "proposal",
            "proposal_received",
            &message.header,
            Some("Proposal"),
        ),
        Msg::Commit(message) => {
            header_telemetry_meta("commit", "commit_received", &message.header, Some("Commit"))
        }
        Msg::EpochStarted(message) => header_telemetry_meta(
            "epoch_finality",
            "epoch_started_received",
            &message.header,
            Some("EpochStarted"),
        ),
        Msg::EchoRequest(message) => header_telemetry_meta(
            "echo",
            "echo_request_received",
            &message.header,
            Some("EchoRequest"),
        ),
        Msg::EchoReDispatch(message) => header_telemetry_meta(
            "echo",
            "echo_redispatch_received",
            &message.header,
            Some("EchoReDispatch"),
        ),
        Msg::Ok => RuntimeTelemetryMeta {
            stage: "runtime",
            event: "ok_received",
            last_epoch: None,
            nonce: None,
            round: None,
            peer: None,
            message_kind: Some("Ok"),
        },
        Msg::Fail => RuntimeTelemetryMeta {
            stage: "runtime",
            event: "fail_received",
            last_epoch: None,
            nonce: None,
            round: None,
            peer: None,
            message_kind: Some("Fail"),
        },
    }
}

fn header_telemetry_meta(
    stage: &'static str,
    event: &'static str,
    header: &Header,
    message_kind: Option<&'static str>,
) -> RuntimeTelemetryMeta {
    RuntimeTelemetryMeta {
        stage,
        event,
        last_epoch: Some(header.last_epoch),
        nonce: Some(header.nonce),
        round: Some(header.round),
        peer: Some(header.sender),
        message_kind,
    }
}

fn record_peer_application_state(
    peer_states: &mut BTreeMap<PubKey, PeerApplicationState>,
    group_id: ConsensusGroupId,
    block_hash: HashType,
    block: &Block,
    last_epoch: HashType,
    nonce: Nonce,
) {
    let peer = block.body.validator;
    let candidate = PeerApplicationState {
        group_id,
        peer,
        block_hash,
        last_epoch,
        nonce,
        application_state: block.body.application_state.clone(),
    };

    match peer_states.get(&peer) {
        Some(existing) if existing.nonce.value() > nonce.value() => {}
        _ => {
            peer_states.insert(peer, candidate);
        }
    }
}

fn record_observed_encounters(
    records: &mut Vec<ObservedEncounterRecord>,
    group_id: ConsensusGroupId,
    block_hash: HashType,
    block: &Block,
) {
    records.extend(block.body.encounter_records.iter().cloned().map(|record| {
        ObservedEncounterRecord {
            group_id,
            block_hash,
            block_validator: block.body.validator,
            record,
        }
    }));
}

fn quorum_has_signature_from(quorum: &TempQuorum, subject: PubKey, phase: EncounterPhase) -> bool {
    match phase {
        EncounterPhase::Dispatch => quorum.received_dispatches.contains(&subject),
        EncounterPhase::Verification => quorum.verifications.verifications.contains_key(&subject),
        EncounterPhase::Proposal => quorum.proposals.proposals.contains_key(&subject),
        EncounterPhase::Commit => quorum.commit_senders.contains(&subject),
        EncounterPhase::EpochStarted => quorum.epoch_started_senders.contains(&subject),
        EncounterPhase::CatchUp => false,
    }
}

fn record_verified_dispatch_blocks(quorum: &mut TempQuorum, blocks: BTreeMap<HashType, Block>) {
    quorum.verified_blocks.extend(blocks);
    quorum.verified_blocks_hash = Some(quorum.verified_blocks_hash());
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
    genesis_epoch_for_group(ConsensusGroupId::root(), nodes)
}

pub fn genesis_epoch_for_group(
    group_id: ConsensusGroupId,
    nodes: impl IntoIterator<Item = NodeIdentity>,
) -> Epoch {
    let mut verifiers = IndexTreeMap::new();
    for node in nodes {
        verifiers.insert(node.public_key(), node);
    }

    let mut epoch = Epoch {
        body: EpochBody {
            group_id,
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

    #[cfg(feature = "availability-gossip")]
    use crate::FilteredPayloadDeliveryItem;
    use crate::blossom::{
        BlossomBody, CommitBody, DispatchBody, EchoResponseBody, EpochStartedBody, ProposalBody,
        VerificationBody,
    };
    use crate::crypto::Keypair;
    use crate::telemetry::InMemoryTelemetrySink;

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
        runtime_with_peers_mode_and_telemetry(trust_mode, None)
    }

    fn runtime_with_peers_mode_and_telemetry(
        trust_mode: TrustMode,
        telemetry: Option<TelemetryHandle>,
    ) -> (NodeRuntime, Vec<Keypair>, EpochTarget) {
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
        if let Some(telemetry) = telemetry {
            config.telemetry = telemetry;
        }
        let runtime = NodeRuntime::new(config);
        let target = EpochTarget {
            group_id: genesis.body.group_id,
            last_epoch: genesis.hash,
            nonce: genesis.body.nonce.new_next(),
        };
        (runtime, keypairs, target)
    }

    fn signed_test_header<T: BlossomBody>(
        signer: &Keypair,
        target: &EpochTarget,
        kind: MSGKey,
        body: &T,
    ) -> Header {
        signed_test_header_for_round(signer, target, 0, kind, body)
    }

    fn signed_test_header_for_round<T: BlossomBody>(
        signer: &Keypair,
        target: &EpochTarget,
        round: u8,
        kind: MSGKey,
        body: &T,
    ) -> Header {
        let signature_hash = Header::signature_hash_for_body(
            &signer.public,
            &target.last_epoch,
            target.nonce,
            round,
            kind,
            body,
        );
        Header {
            sender: signer.public,
            last_epoch: target.last_epoch,
            nonce: target.nonce,
            round,
            signature: signer.signer().sign(signature_hash.as_ref()),
        }
    }

    fn round_signer<'a>(
        runtime: &NodeRuntime,
        keypairs: &'a [Keypair],
        target: &EpochTarget,
        round: u8,
    ) -> &'a Keypair {
        let sender = {
            let mut state = runtime.inner.state.write().expect("state lock poisoned");
            state
                .get_mut_consensus(&target.last_epoch, target.nonce)
                .peers(round)
                .into_iter()
                .next()
                .expect("round should include a peer")
        };
        keypairs
            .iter()
            .find(|keypair| keypair.public == sender)
            .expect("round sender should have a test keypair")
    }

    fn signed_block_for_target(
        signer: &Keypair,
        target: &EpochTarget,
        payload: impl Into<Vec<u8>>,
    ) -> Block {
        let mut block = Block::default();
        block.body.last_epoch = target.last_epoch;
        block.body.nonce = target.nonce;
        block.body.txs.push(crate::block::Transaction::new(payload));
        block.sign(&signer.secret);
        block
    }

    fn signed_dispatch_for_blocks(
        signer: &Keypair,
        target: &EpochTarget,
        blocks: BTreeMap<HashType, Block>,
    ) -> Dispatch {
        let body = DispatchBody {
            blocks_hash: blocks.hash(),
            blocks,
            signature_tree: crate::SignatureTree::default(),
            signature_tree_hash: crate::SignatureTree::default().hash(),
        };
        Dispatch {
            header: signed_test_header(signer, target, MSGKey::Dispatch, &body),
            body,
        }
    }

    fn receive_valid_dispatch(
        runtime: &NodeRuntime,
        keypairs: &[Keypair],
        target: &EpochTarget,
        payload: impl Into<Vec<u8>>,
    ) -> (Dispatch, BTreeMap<HashType, ()>) {
        let signer = round_signer(runtime, keypairs, target, 0);
        let block = signed_block_for_target(signer, target, payload);
        let mut blocks = BTreeMap::new();
        blocks.insert(block.hash, block);
        let dispatch = signed_dispatch_for_blocks(signer, target, blocks);
        runtime
            .receive_message(Msg::Dispatch(dispatch.clone()))
            .unwrap();
        let approved_blocks = dispatch
            .body
            .blocks
            .keys()
            .map(|hash| (*hash, ()))
            .collect::<BTreeMap<_, _>>();
        (dispatch, approved_blocks)
    }

    fn verification_proof_for(
        keypairs: &[Keypair],
        target: &EpochTarget,
        round: u8,
        approved_blocks: &BTreeMap<HashType, ()>,
        signers: &[PubKey],
    ) -> Vec<(PubKey, Signature)> {
        let verification_body = VerificationBody {
            blocks_hash: approved_blocks.hash(),
            blocks: approved_blocks.clone(),
        };
        signers
            .iter()
            .map(|signer| {
                let keypair = keypairs
                    .iter()
                    .find(|keypair| keypair.public == *signer)
                    .expect("proof signer should have a test keypair");
                (
                    *signer,
                    signed_test_header_for_round(
                        keypair,
                        target,
                        round,
                        MSGKey::Verification,
                        &verification_body,
                    )
                    .signature,
                )
            })
            .collect()
    }

    fn consensus_proposal_body(
        approved_blocks: &BTreeMap<HashType, ()>,
        verif: Option<Vec<(PubKey, Signature)>>,
    ) -> ProposalBody {
        ProposalBody {
            consensus: true,
            approved_blocks: Some(approved_blocks.clone()),
            approved_hash: Some(approved_blocks.hash()),
            verif,
            signature_tree: Some(approved_blocks.clone()),
            signature_tree_hash: Some(approved_blocks.hash()),
        }
    }

    fn receive_proposal_supermajority(
        runtime: &NodeRuntime,
        keypairs: &[Keypair],
        target: &EpochTarget,
        payload: impl Into<Vec<u8>>,
    ) -> (Dispatch, BTreeMap<HashType, ()>) {
        let (dispatch, approved_blocks) =
            receive_valid_dispatch(runtime, keypairs, target, payload);
        let round_peers = {
            let mut state = runtime.inner.state.write().expect("state lock poisoned");
            state
                .get_mut_consensus(&target.last_epoch, target.nonce)
                .peers(dispatch.header.round)
        };
        let proof = verification_proof_for(
            keypairs,
            target,
            dispatch.header.round,
            &approved_blocks,
            &round_peers[..4],
        );

        for peer in round_peers.iter().take(4) {
            let signer = keypairs
                .iter()
                .find(|keypair| keypair.public == *peer)
                .unwrap();
            let body = consensus_proposal_body(&approved_blocks, Some(proof.clone()));
            runtime
                .receive_message(Msg::Proposal(Proposal {
                    header: signed_test_header_for_round(
                        signer,
                        target,
                        dispatch.header.round,
                        MSGKey::Proposal,
                        &body,
                    ),
                    body,
                }))
                .unwrap();
        }

        (dispatch, approved_blocks)
    }

    #[test]
    fn genesis_epoch_group_id_is_hash_committed() {
        let keypairs = (0..6).map(|_| Keypair::generate()).collect::<Vec<_>>();
        let nodes = keypairs
            .iter()
            .enumerate()
            .map(|(index, keypair)| {
                NodeIdentity::new(
                    keypair.public,
                    None,
                    "tcp",
                    "127.0.0.1",
                    8000 + index as u16,
                    false,
                )
            })
            .collect::<Vec<_>>();
        let root = genesis_epoch(nodes.clone());
        let subnet = genesis_epoch_for_group(ConsensusGroupId::named("cache-hotset-a"), nodes);

        assert_eq!(root.body.group_id, ConsensusGroupId::root());
        assert_eq!(
            subnet.body.group_id,
            ConsensusGroupId::named("cache-hotset-a")
        );
        assert_ne!(root.hash, subnet.hash);
    }

    #[test]
    fn parallel_groups_keep_targets_and_application_state_separate() {
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

        let root_genesis = genesis_epoch(nodes.clone());
        let subnet_id = ConsensusGroupId::named("cache-hotset-a");
        let subnet_genesis = genesis_epoch_for_group(subnet_id, nodes[..3].to_vec());
        assert_ne!(root_genesis.hash, subnet_genesis.hash);

        let mut root_config = RuntimeConfig::new(nodes[0].clone());
        root_config.genesis = Some(root_genesis.clone());
        let root_runtime = NodeRuntime::new(root_config);

        let mut subnet_config = RuntimeConfig::new(nodes[0].clone());
        subnet_config.group_id = subnet_id;
        subnet_config.genesis = Some(subnet_genesis.clone());
        let subnet_runtime = NodeRuntime::new(subnet_config);

        root_runtime.set_application_state(b"root-visible").unwrap();
        subnet_runtime
            .set_application_state(b"subnet-visible")
            .unwrap();

        let root_target = root_runtime.next_epoch_target().unwrap();
        let subnet_target = subnet_runtime.next_epoch_target().unwrap();
        assert_ne!(root_target.last_epoch, subnet_target.last_epoch);

        let root_dispatch = root_runtime.dispatch_local_block(0).unwrap();
        let subnet_dispatch = subnet_runtime.dispatch_local_block(0).unwrap();
        let root_block = root_dispatch.body.blocks.values().next().unwrap();
        let subnet_block = subnet_dispatch.body.blocks.values().next().unwrap();

        assert_eq!(root_block.application_state(), b"root-visible");
        assert_eq!(subnet_block.application_state(), b"subnet-visible");
        assert_eq!(root_dispatch.header.last_epoch, root_target.last_epoch);
        assert_eq!(subnet_dispatch.header.last_epoch, subnet_target.last_epoch);
        assert!(matches!(
            subnet_runtime.receive_message(Msg::Dispatch(root_dispatch.clone())),
            Err(BlossomError::WireProtocol(message))
                if message.contains("unknown consensus epoch")
        ));

        let multi = MultiGroupRuntime::with_groups(root_runtime.clone(), [subnet_runtime.clone()]);
        assert_eq!(multi.root_group(), ConsensusGroupId::root());
        assert_eq!(multi.len(), 2);
        assert_eq!(multi.group(&subnet_id).unwrap().group_id(), subnet_id);
        assert_eq!(
            multi
                .group_for_epoch(&subnet_target.last_epoch)
                .unwrap()
                .group_id(),
            subnet_id
        );
    }

    #[cfg(feature = "availability-gossip")]
    #[test]
    fn availability_gossip_fetches_filtered_payload_for_targets() {
        let keypairs = (0..6).map(|_| Keypair::generate()).collect::<Vec<_>>();
        let genesis_nodes = keypairs
            .iter()
            .enumerate()
            .map(|(index, keypair)| {
                NodeIdentity::new(
                    keypair.public,
                    None,
                    "tcp",
                    "127.0.0.1",
                    8000 + index as u16,
                    false,
                )
            })
            .collect::<Vec<_>>();
        let genesis = genesis_epoch(genesis_nodes);

        let runtime_for = |index: usize| {
            let node = NodeIdentity::new(
                keypairs[index].public,
                Some(keypairs[index].secret),
                "tcp",
                "127.0.0.1",
                8000 + index as u16,
                false,
            );
            let mut config = RuntimeConfig::new(node);
            config.genesis = Some(genesis.clone());
            NodeRuntime::new(config)
        };
        let holder = runtime_for(0);
        let target = runtime_for(1);
        let outsider = runtime_for(2);

        let payload = b"stable-kvcache-value".to_vec();
        let tx = crate::Transaction::filtered_full(
            HashType::hash(b"stable-cache-key"),
            1,
            vec![target.self_node().public_key()],
            payload.clone(),
            crate::FilteredDeliveryPolicy::Gossip,
        )
        .unwrap();
        let slot = tx.filtered_slot().unwrap().clone();
        let entry = holder
            .store_filtered_payload_from_transaction(&tx)
            .unwrap()
            .unwrap();

        let gossip = holder.availability_gossip().unwrap();
        let receipt = target.receive_availability_gossip(gossip).unwrap();
        assert_eq!(receipt.entries_accepted, 1);
        assert_eq!(target.peer_availability_entries().len(), 1);

        let fetch = target
            .filtered_payload_fetch(entry.slot_hash, slot.payload_commitment)
            .unwrap();
        let delivery = holder
            .serve_filtered_payload_fetch(fetch)
            .unwrap()
            .expect("holder should return filtered payload");
        assert_eq!(delivery.body.payload, payload);
        target.receive_filtered_payload(delivery).unwrap();
        assert_eq!(target.local_availability_entries().len(), 1);

        let outsider_fetch = outsider
            .filtered_payload_fetch(entry.slot_hash, slot.payload_commitment)
            .unwrap();
        assert!(matches!(
            holder.serve_filtered_payload_fetch(outsider_fetch),
            Err(BlossomError::WireProtocol(message)) if message.contains("not authorized")
        ));
    }

    #[cfg(feature = "availability-gossip")]
    #[test]
    fn trusted_batch_gossip_still_rejects_unknown_fetch_requesters() {
        let (holder, _, _) = runtime_with_peers_mode(TrustMode::Trusted);
        let unknown = Keypair::generate();

        let payload = b"private-cache-value".to_vec();
        let tx = crate::Transaction::filtered_full(
            HashType::hash(b"private-cache-key"),
            1,
            vec![holder.self_node().public_key()],
            payload,
            crate::FilteredDeliveryPolicy::Gossip,
        )
        .unwrap();
        let slot = tx.filtered_slot().unwrap().clone();
        let entry = holder
            .store_filtered_payload_from_transaction(&tx)
            .unwrap()
            .unwrap();
        let fetch = FilteredPayloadBatchFetch::trusted(FilteredPayloadBatchFetchBody {
            scope: holder.group_id(),
            requester: unknown.public,
            requests: vec![FilteredPayloadRequest::new(
                entry.slot_hash,
                slot.payload_commitment,
            )],
        })
        .unwrap();

        assert!(matches!(
            holder.serve_filtered_payload_batch_fetch(fetch),
            Err(BlossomError::UnknownSender)
        ));
    }

    #[cfg(feature = "availability-gossip")]
    #[test]
    fn trusted_batch_delivery_still_rejects_unauthorized_targets_and_tampering() {
        let (target, keypairs, _) = runtime_with_peers_mode(TrustMode::Trusted);
        let authorized_peer = keypairs[1].public;
        let holder_peer = keypairs[2].public;

        let payload = b"authorized-only-value".to_vec();
        let tx = crate::Transaction::filtered_full(
            HashType::hash(b"authorized-only-key"),
            1,
            vec![authorized_peer],
            payload.clone(),
            crate::FilteredDeliveryPolicy::Gossip,
        )
        .unwrap();
        let slot = tx.filtered_slot().unwrap().clone();
        let delivery = FilteredPayloadBatchDelivery::trusted(FilteredPayloadBatchDeliveryBody {
            scope: target.group_id(),
            holder: holder_peer,
            items: vec![FilteredPayloadDeliveryItem {
                slot_hash: slot.hash(),
                slot: slot.clone(),
                payload: payload.clone(),
            }],
        })
        .unwrap();

        assert!(matches!(
            target.receive_filtered_payload_batch(delivery),
            Err(BlossomError::WireProtocol(message)) if message.contains("not a target")
        ));

        let tx = crate::Transaction::filtered_full(
            HashType::hash(b"tamper-key"),
            1,
            vec![target.self_node().public_key()],
            b"original-value".to_vec(),
            crate::FilteredDeliveryPolicy::Gossip,
        )
        .unwrap();
        let slot = tx.filtered_slot().unwrap().clone();
        let mut delivery =
            FilteredPayloadBatchDelivery::trusted(FilteredPayloadBatchDeliveryBody {
                scope: target.group_id(),
                holder: holder_peer,
                items: vec![FilteredPayloadDeliveryItem {
                    slot_hash: slot.hash(),
                    slot,
                    payload: b"original-value".to_vec(),
                }],
            })
            .unwrap();
        delivery.body.items[0].payload = b"tampered-value".to_vec();

        assert!(matches!(
            target.receive_filtered_payload_batch(delivery),
            Err(BlossomError::InvalidBlockHash)
        ));
    }

    #[cfg(feature = "availability-gossip")]
    #[test]
    fn duplicate_gossip_is_idempotent_for_peer_availability() {
        let keypairs = (0..3).map(|_| Keypair::generate()).collect::<Vec<_>>();
        let genesis_nodes = keypairs
            .iter()
            .enumerate()
            .map(|(index, keypair)| {
                NodeIdentity::new(
                    keypair.public,
                    None,
                    "tcp",
                    "127.0.0.1",
                    8100 + index as u16,
                    false,
                )
            })
            .collect::<Vec<_>>();
        let genesis = genesis_epoch(genesis_nodes);
        let runtime_for = |index: usize| {
            let node = NodeIdentity::new(
                keypairs[index].public,
                Some(keypairs[index].secret),
                "tcp",
                "127.0.0.1",
                8100 + index as u16,
                false,
            );
            let mut config = RuntimeConfig::new(node);
            config.genesis = Some(genesis.clone());
            NodeRuntime::new(config)
        };
        let holder = runtime_for(0);
        let target = runtime_for(1);

        let tx = crate::Transaction::filtered_full(
            HashType::hash(b"duplicate-gossip-key"),
            1,
            vec![target.self_node().public_key()],
            b"duplicate-gossip-value".to_vec(),
            crate::FilteredDeliveryPolicy::Gossip,
        )
        .unwrap();
        holder
            .store_filtered_payload_from_transaction(&tx)
            .unwrap()
            .unwrap();
        let gossip = holder.availability_gossip().unwrap();

        assert_eq!(
            target
                .receive_availability_gossip(gossip.clone())
                .unwrap()
                .entries_accepted,
            1
        );
        assert_eq!(
            target
                .receive_availability_gossip(gossip)
                .unwrap()
                .entries_accepted,
            1
        );
        assert_eq!(target.peer_availability_entries().len(), 1);
    }

    #[cfg(feature = "availability-gossip")]
    #[test]
    fn stale_availability_metadata_returns_empty_batch_delivery() {
        let keypairs = (0..3).map(|_| Keypair::generate()).collect::<Vec<_>>();
        let genesis_nodes = keypairs
            .iter()
            .enumerate()
            .map(|(index, keypair)| {
                NodeIdentity::new(
                    keypair.public,
                    None,
                    "tcp",
                    "127.0.0.1",
                    8200 + index as u16,
                    false,
                )
            })
            .collect::<Vec<_>>();
        let genesis = genesis_epoch(genesis_nodes);
        let runtime_for = |index: usize| {
            let node = NodeIdentity::new(
                keypairs[index].public,
                Some(keypairs[index].secret),
                "tcp",
                "127.0.0.1",
                8200 + index as u16,
                false,
            );
            let mut config = RuntimeConfig::new(node);
            config.genesis = Some(genesis.clone());
            NodeRuntime::new(config)
        };
        let holder = runtime_for(0);
        let target = runtime_for(1);

        let tx = crate::Transaction::filtered_full(
            HashType::hash(b"stale-gossip-key"),
            1,
            vec![target.self_node().public_key()],
            b"stale-gossip-value".to_vec(),
            crate::FilteredDeliveryPolicy::Gossip,
        )
        .unwrap();
        let slot = tx.filtered_slot().unwrap().clone();
        let entry = AvailabilityEntry::new(slot.clone()).unwrap();
        let gossip = AvailabilityGossip::signed(
            AvailabilityGossipBody {
                scope: holder.group_id(),
                holder: holder.self_node().public_key(),
                entries: vec![entry.clone()],
            },
            &keypairs[0].signer(),
        )
        .unwrap();

        target.receive_availability_gossip(gossip).unwrap();
        let fetch = target
            .filtered_payload_batch_fetch(vec![FilteredPayloadRequest::new(
                entry.slot_hash,
                slot.payload_commitment,
            )])
            .unwrap();
        let delivery = holder.serve_filtered_payload_batch_fetch(fetch).unwrap();

        assert!(delivery.body.items.is_empty());
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
    fn submit_block_rejects_wrong_last_epoch() {
        let (runtime, keypair) = runtime();
        let target = runtime.next_epoch_target().unwrap();
        let mut block = Block::default();
        block.body.last_epoch = HashType([9; 32]);
        block.body.nonce = target.nonce;
        block.sign(&keypair.secret);

        assert_eq!(
            runtime.submit_block(block),
            Err(BlossomError::InvalidBlockLastEpoch)
        );
        assert_eq!(runtime.status().unwrap().pending_blocks, 0);
    }

    #[test]
    fn submit_block_rejects_invalid_hash_and_signature_before_queueing() {
        let (runtime, keypair) = runtime();
        let target = runtime.next_epoch_target().unwrap();
        let mut tampered = signed_block_for_target(&keypair, &target, b"tx".to_vec());
        tampered
            .body
            .txs
            .push(crate::block::Transaction::new("tampered-after-sign"));

        assert_eq!(
            runtime.submit_block(tampered),
            Err(BlossomError::InvalidBlockHash)
        );
        assert_eq!(runtime.status().unwrap().pending_blocks, 0);

        let mut bad_signature = signed_block_for_target(&keypair, &target, b"tx".to_vec());
        bad_signature.signature = crate::Signature([1; 64]);

        assert_eq!(
            runtime.submit_block(bad_signature),
            Err(BlossomError::SignatureError)
        );
        assert_eq!(runtime.status().unwrap().pending_blocks, 0);
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
    fn dispatch_local_block_commits_targeted_signed_block() {
        let (runtime, keypair) = runtime();
        let target = runtime.next_epoch_target().unwrap();
        let block = signed_block_for_target(&keypair, &target, b"dispatch-tx".to_vec());
        runtime.submit_block(block).unwrap();

        let dispatch = runtime.dispatch_local_block(0).unwrap();

        assert!(dispatch.body.validate().is_ok());
        assert!(
            dispatch
                .header
                .verify_signature(MSGKey::Dispatch, &dispatch.body)
                .is_ok()
        );
        let (block_hash, block) = dispatch.body.blocks.iter().next().unwrap();
        assert_eq!(dispatch.body.blocks_hash, dispatch.body.blocks.hash());
        assert_eq!(block.body.last_epoch, target.last_epoch);
        assert_eq!(block.body.nonce, target.nonce);
        assert!(block.verify_integrity_with_hash(*block_hash).is_ok());
    }

    #[test]
    fn dispatch_local_block_records_local_verified_blocks() {
        let (runtime, keypair) = runtime();
        let target = runtime.next_epoch_target().unwrap();
        let block = signed_block_for_target(&keypair, &target, b"local-verified-dispatch");
        let block_hash = block.hash;
        runtime.submit_block(block).unwrap();

        let dispatch = runtime.dispatch_local_block(0).unwrap();

        let state = runtime.inner.state.read().expect("state lock poisoned");
        let quorum = state
            .get_quorum(&target.last_epoch, target.nonce, dispatch.header.round)
            .expect("local dispatch should initialize quorum state");
        assert!(quorum.verified_blocks.contains_key(&block_hash));
        assert_eq!(
            quorum.verified_blocks_hash,
            Some(quorum.verified_blocks_hash())
        );
    }

    #[test]
    fn runtime_emits_stage_telemetry_spans() {
        let sink = std::sync::Arc::new(InMemoryTelemetrySink::default());
        let (runtime, keypairs, target) = runtime_with_peers_mode_and_telemetry(
            TrustMode::Verified,
            Some(TelemetryHandle::new(sink.clone())),
        );

        let local_block = signed_block_for_target(&keypairs[0], &target, b"telemetry-local");
        runtime.submit_block(local_block).unwrap();
        runtime.dispatch_local_block(0).unwrap();

        let signer = round_signer(&runtime, &keypairs, &target, 0);
        let remote_block = signed_block_for_target(signer, &target, b"telemetry-remote");
        let mut blocks = BTreeMap::new();
        blocks.insert(remote_block.hash, remote_block);
        let dispatch = signed_dispatch_for_blocks(signer, &target, blocks);
        runtime.receive_message(Msg::Dispatch(dispatch)).unwrap();

        let events = sink.events();
        assert!(events.iter().any(|event| {
            event.kind == crate::telemetry::TelemetryEventKind::SpanStart
                && event.stage == "block_formation"
                && event.event == "block_submitted"
        }));
        assert!(events.iter().any(|event| {
            event.kind == crate::telemetry::TelemetryEventKind::SpanEnd
                && event.stage == "dispatch"
                && event.event == "dispatch_local_block"
                && event.outcome.as_deref() == Some("ok")
        }));
        assert!(events.iter().any(|event| {
            event.kind == crate::telemetry::TelemetryEventKind::SpanEnd
                && event.stage == "dispatch"
                && event.event == "dispatch_received"
                && event.message_kind.as_deref() == Some("Dispatch")
                && event.peer == Some(signer.public)
                && event.outcome.as_deref() == Some("ok")
        }));
        assert_eq!(
            events
                .iter()
                .filter(|event| event.kind == crate::telemetry::TelemetryEventKind::SpanStart)
                .count(),
            events
                .iter()
                .filter(|event| event.kind == crate::telemetry::TelemetryEventKind::SpanEnd)
                .count()
        );
    }

    #[test]
    fn receive_dispatch_updates_pending_state_and_message_matrix() {
        let (runtime, keypairs, target) = runtime_with_peers();
        let signer = round_signer(&runtime, &keypairs, &target, 0);
        let remote_block = signed_block_for_target(signer, &target, b"matrix-dispatch");
        let mut blocks = BTreeMap::new();
        blocks.insert(remote_block.hash, remote_block);
        let dispatch = signed_dispatch_for_blocks(signer, &target, blocks);

        let receipt = runtime
            .receive_message(Msg::Dispatch(dispatch.clone()))
            .unwrap();
        assert_eq!(receipt.kind, "dispatch");

        let state = runtime.inner.state.read().expect("state lock poisoned");
        let quorum = state
            .get_quorum(&target.last_epoch, target.nonce, 0)
            .expect("dispatch should initialize quorum state");
        assert_eq!(quorum.pending_dispatches.len(), 1);
        match &quorum.pending_dispatches[0] {
            PendingDispatch::Decoded(recorded) => {
                assert_eq!(recorded.header.sender, signer.public);
                assert_eq!(recorded.header.signature, dispatch.header.signature);
            }
            other => panic!("expected decoded pending dispatch, got {other:?}"),
        }
        assert!(quorum.received_dispatches.contains(&signer.public));

        let sender_index = quorum
            .msg_matrix
            .find_key_index(&signer.public)
            .expect("sender should be in matrix");
        let receiver_index = quorum
            .msg_matrix
            .find_key_index(&keypairs[0].public)
            .expect("runtime self should be in matrix");
        assert_eq!(
            quorum.msg_matrix.matrix[receiver_index][sender_index],
            crate::register::Status::DispatchReceived
        );
        match &quorum.msg_matrix.message_matrix[sender_index][receiver_index] {
            Some(Msg::Dispatch(recorded)) => {
                assert_eq!(recorded.header.sender, signer.public);
                assert_eq!(recorded.header.signature, dispatch.header.signature);
            }
            other => panic!("expected dispatch matrix message, got {other:?}"),
        }
    }

    #[test]
    fn receive_echo_response_updates_message_matrix() {
        let (runtime, keypairs, target) = runtime_with_peers();
        let round_peers = {
            let mut state = runtime.inner.state.write().expect("state lock poisoned");
            state
                .get_mut_consensus(&target.last_epoch, target.nonce)
                .peers(0)
        };
        let dispatch_subject = keypairs
            .iter()
            .find(|keypair| keypair.public == round_peers[0])
            .unwrap();
        let echoer = keypairs
            .iter()
            .find(|keypair| keypair.public == round_peers[1])
            .unwrap();
        let body = EchoResponseBody {
            sender: dispatch_subject.public,
            blocks_hash: HashType([3; 32]),
            signature_tree_hash: HashType([4; 32]),
        };
        let echo = EchoResponse {
            header: signed_test_header(echoer, &target, MSGKey::EchoResponse, &body),
            body,
        };

        let receipt = runtime
            .receive_message(Msg::EchoResponse(echo.clone()))
            .unwrap();
        assert_eq!(receipt.kind, "echo_response");

        let state = runtime.inner.state.read().expect("state lock poisoned");
        let quorum = state
            .get_quorum(&target.last_epoch, target.nonce, 0)
            .expect("echo response should initialize quorum state");
        let sender_index = quorum
            .msg_matrix
            .find_key_index(&dispatch_subject.public)
            .expect("dispatch subject should be in matrix");
        let receiver_index = quorum
            .msg_matrix
            .find_key_index(&echoer.public)
            .expect("echoer should be in matrix");
        assert_eq!(
            quorum.msg_matrix.matrix[receiver_index][sender_index],
            crate::register::Status::EchoReceived
        );
        match &quorum.msg_matrix.message_matrix[sender_index][receiver_index] {
            Some(Msg::EchoResponse(recorded)) => {
                assert_eq!(recorded.header.sender, echoer.public);
                assert_eq!(recorded.body.sender, dispatch_subject.public);
            }
            other => panic!("expected echo response matrix message, got {other:?}"),
        }
    }

    #[test]
    fn receive_echo_response_rejects_unknown_subject_without_matrix_update() {
        let (runtime, keypairs, target) = runtime_with_peers();
        let echoer = round_signer(&runtime, &keypairs, &target, 0);
        let unknown = Keypair::generate();
        let body = EchoResponseBody {
            sender: unknown.public,
            blocks_hash: HashType([3; 32]),
            signature_tree_hash: HashType([4; 32]),
        };
        let echo = EchoResponse {
            header: signed_test_header(echoer, &target, MSGKey::EchoResponse, &body),
            body,
        };

        assert_eq!(
            runtime.receive_message(Msg::EchoResponse(echo)),
            Err(BlossomError::UnknownSender)
        );

        let state = runtime.inner.state.read().expect("state lock poisoned");
        let quorum = state
            .get_quorum(&target.last_epoch, target.nonce, 0)
            .expect("header validation should initialize quorum state");
        assert!(
            quorum
                .msg_matrix
                .message_matrix
                .iter()
                .all(|row| { row.iter().all(Option::is_none) })
        );
        assert!(quorum.msg_matrix.matrix.iter().all(|row| {
            row.iter()
                .all(|status| *status != crate::register::Status::EchoReceived)
        }));
    }

    #[test]
    fn receive_verification_requires_locally_verified_block_set() {
        let (runtime, keypairs, target) = runtime_with_peers();
        let signer = round_signer(&runtime, &keypairs, &target, 0);
        let block = signed_block_for_target(signer, &target, b"verified-before-vote");
        let mut verification_blocks = BTreeMap::new();
        verification_blocks.insert(block.hash, ());
        let verification_body = VerificationBody {
            blocks_hash: verification_blocks.hash(),
            blocks: verification_blocks.clone(),
        };
        let unverified_vote = Verification {
            header: signed_test_header(signer, &target, MSGKey::Verification, &verification_body),
            body: verification_body.clone(),
        };

        assert!(matches!(
            runtime.receive_message(Msg::Verification(unverified_vote)),
            Err(BlossomError::WireProtocol(message))
                if message.contains("not been locally verified")
        ));
        {
            let state = runtime.inner.state.read().expect("state lock poisoned");
            let quorum = state
                .get_quorum(&target.last_epoch, target.nonce, 0)
                .expect("verification header should initialize quorum state");
            assert!(quorum.verifications.verifications.is_empty());
        }

        let mut dispatch_blocks = BTreeMap::new();
        dispatch_blocks.insert(block.hash, block);
        let dispatch = signed_dispatch_for_blocks(signer, &target, dispatch_blocks);
        runtime.receive_message(Msg::Dispatch(dispatch)).unwrap();
        let verified_vote = Verification {
            header: signed_test_header(signer, &target, MSGKey::Verification, &verification_body),
            body: verification_body,
        };

        let receipt = runtime
            .receive_message(Msg::Verification(verified_vote))
            .unwrap();
        assert_eq!(receipt.kind, "verification");
        let state = runtime.inner.state.read().expect("state lock poisoned");
        let quorum = state
            .get_quorum(&target.last_epoch, target.nonce, 0)
            .expect("verified vote should keep quorum state");
        assert_eq!(quorum.verifications.verifications.len(), 1);
        assert_eq!(
            quorum.verifications.count.get(&verification_blocks.hash()),
            Some(&1)
        );
    }

    #[test]
    fn runtime_verification_replaces_equivocating_sender_vote() {
        let (runtime, keypairs, target) = runtime_with_peers();
        let signer = round_signer(&runtime, &keypairs, &target, 0);
        let first_block = signed_block_for_target(signer, &target, b"first-verified-set");
        let mut first_dispatch_blocks = BTreeMap::new();
        first_dispatch_blocks.insert(first_block.hash, first_block.clone());
        runtime
            .receive_message(Msg::Dispatch(signed_dispatch_for_blocks(
                signer,
                &target,
                first_dispatch_blocks,
            )))
            .unwrap();

        let mut first_vote_blocks = BTreeMap::new();
        first_vote_blocks.insert(first_block.hash, ());
        let first_body = VerificationBody {
            blocks_hash: first_vote_blocks.hash(),
            blocks: first_vote_blocks,
        };
        runtime
            .receive_message(Msg::Verification(Verification {
                header: signed_test_header(signer, &target, MSGKey::Verification, &first_body),
                body: first_body.clone(),
            }))
            .unwrap();

        let second_block = signed_block_for_target(signer, &target, b"second-verified-set");
        let mut second_dispatch_blocks = BTreeMap::new();
        second_dispatch_blocks.insert(second_block.hash, second_block.clone());
        let second_dispatch = signed_dispatch_for_blocks(
            round_signer(&runtime, &keypairs, &target, 0),
            &target,
            second_dispatch_blocks,
        );
        {
            let mut state = runtime.inner.state.write().expect("state lock poisoned");
            let quorum = state.get_mut_quorum(&target.last_epoch, target.nonce, 0);
            record_verified_dispatch_blocks(quorum, second_dispatch.body.blocks.clone());
        }

        let mut second_vote_blocks = BTreeMap::new();
        second_vote_blocks.insert(first_block.hash, ());
        second_vote_blocks.insert(second_block.hash, ());
        let second_body = VerificationBody {
            blocks_hash: second_vote_blocks.hash(),
            blocks: second_vote_blocks,
        };
        runtime
            .receive_message(Msg::Verification(Verification {
                header: signed_test_header(signer, &target, MSGKey::Verification, &second_body),
                body: second_body.clone(),
            }))
            .unwrap();

        let state = runtime.inner.state.read().expect("state lock poisoned");
        let quorum = state
            .get_quorum(&target.last_epoch, target.nonce, 0)
            .expect("verification should keep quorum state");
        assert_eq!(quorum.verifications.verifications.len(), 1);
        assert_eq!(
            quorum.verifications.count.get(&first_body.blocks_hash),
            None
        );
        assert_eq!(
            quorum.verifications.count.get(&second_body.blocks_hash),
            Some(&1)
        );
    }

    #[test]
    fn runtime_verification_supermajority_requires_distinct_valid_senders() {
        let (runtime, keypairs, target) = runtime_with_peers();
        let round_peers = {
            let mut state = runtime.inner.state.write().expect("state lock poisoned");
            state
                .get_mut_consensus(&target.last_epoch, target.nonce)
                .peers(0)
        };
        let body = VerificationBody::default();
        let repeated_sender = keypairs
            .iter()
            .find(|keypair| keypair.public == round_peers[0])
            .unwrap();

        for _ in 0..4 {
            runtime
                .receive_message(Msg::Verification(Verification {
                    header: signed_test_header(
                        repeated_sender,
                        &target,
                        MSGKey::Verification,
                        &body,
                    ),
                    body: body.clone(),
                }))
                .unwrap();
        }
        {
            let state = runtime.inner.state.read().expect("state lock poisoned");
            let quorum = state
                .get_quorum(&target.last_epoch, target.nonce, 0)
                .expect("verification should initialize quorum state");
            assert_eq!(quorum.verifications.verifications.len(), 1);
            assert_eq!(quorum.verifications.consensus_hash(), None);
        }

        for peer in round_peers.iter().take(4).skip(1) {
            let signer = keypairs
                .iter()
                .find(|keypair| keypair.public == *peer)
                .unwrap();
            runtime
                .receive_message(Msg::Verification(Verification {
                    header: signed_test_header(signer, &target, MSGKey::Verification, &body),
                    body: body.clone(),
                }))
                .unwrap();
        }

        let state = runtime.inner.state.read().expect("state lock poisoned");
        let quorum = state
            .get_quorum(&target.last_epoch, target.nonce, 0)
            .expect("verification should keep quorum state");
        assert_eq!(quorum.verifications.verifications.len(), 4);
        assert_eq!(
            quorum.verifications.consensus_hash(),
            Some(body.blocks_hash)
        );
    }

    #[test]
    fn receive_proposal_rejects_missing_verification_proof() {
        let (runtime, keypairs, target) = runtime_with_peers();
        let (dispatch, approved_blocks) =
            receive_valid_dispatch(&runtime, &keypairs, &target, b"proposal-missing-proof");
        let proposal_signer = round_signer(&runtime, &keypairs, &target, dispatch.header.round);
        let body = consensus_proposal_body(&approved_blocks, None);
        let proposal = Proposal {
            header: signed_test_header_for_round(
                proposal_signer,
                &target,
                dispatch.header.round,
                MSGKey::Proposal,
                &body,
            ),
            body,
        };

        assert!(matches!(
            runtime.receive_message(Msg::Proposal(proposal)),
            Err(BlossomError::WireProtocol(message))
                if message.contains("verification proof")
        ));

        let state = runtime.inner.state.read().expect("state lock poisoned");
        let quorum = state
            .get_quorum(&target.last_epoch, target.nonce, dispatch.header.round)
            .expect("dispatch should initialize quorum state");
        assert!(quorum.proposals.proposals.is_empty());
    }

    #[test]
    fn receive_proposal_requires_distinct_verification_supermajority() {
        let (runtime, keypairs, target) = runtime_with_peers();
        let (dispatch, approved_blocks) =
            receive_valid_dispatch(&runtime, &keypairs, &target, b"proposal-duplicate-proof");
        let proposal_signer = round_signer(&runtime, &keypairs, &target, dispatch.header.round);
        let repeated_proof = verification_proof_for(
            &keypairs,
            &target,
            dispatch.header.round,
            &approved_blocks,
            &[
                proposal_signer.public,
                proposal_signer.public,
                proposal_signer.public,
                proposal_signer.public,
            ],
        );
        let body = consensus_proposal_body(&approved_blocks, Some(repeated_proof));
        let proposal = Proposal {
            header: signed_test_header_for_round(
                proposal_signer,
                &target,
                dispatch.header.round,
                MSGKey::Proposal,
                &body,
            ),
            body,
        };

        assert!(matches!(
            runtime.receive_message(Msg::Proposal(proposal)),
            Err(BlossomError::WireProtocol(message))
                if message.contains("distinct verifier signatures")
        ));

        let state = runtime.inner.state.read().expect("state lock poisoned");
        let quorum = state
            .get_quorum(&target.last_epoch, target.nonce, dispatch.header.round)
            .expect("dispatch should initialize quorum state");
        assert!(quorum.proposals.proposals.is_empty());
    }

    #[test]
    fn receive_proposal_rejects_non_quorum_verification_proof_signer() {
        let (runtime, keypairs, target) = runtime_with_peers();
        let (dispatch, approved_blocks) =
            receive_valid_dispatch(&runtime, &keypairs, &target, b"proposal-outsider-proof");
        let proposal_signer = round_signer(&runtime, &keypairs, &target, dispatch.header.round);
        let unknown = Keypair::generate();
        let verification_body = VerificationBody {
            blocks_hash: approved_blocks.hash(),
            blocks: approved_blocks.clone(),
        };
        let unknown_header = signed_test_header_for_round(
            &unknown,
            &target,
            dispatch.header.round,
            MSGKey::Verification,
            &verification_body,
        );
        let mut proof = verification_proof_for(
            &keypairs,
            &target,
            dispatch.header.round,
            &approved_blocks,
            &[proposal_signer.public],
        );
        proof.push((unknown.public, unknown_header.signature));
        let body = consensus_proposal_body(&approved_blocks, Some(proof));
        let proposal = Proposal {
            header: signed_test_header_for_round(
                proposal_signer,
                &target,
                dispatch.header.round,
                MSGKey::Proposal,
                &body,
            ),
            body,
        };

        assert_eq!(
            runtime.receive_message(Msg::Proposal(proposal)),
            Err(BlossomError::UnknownSender)
        );

        let state = runtime.inner.state.read().expect("state lock poisoned");
        let quorum = state
            .get_quorum(&target.last_epoch, target.nonce, dispatch.header.round)
            .expect("dispatch should initialize quorum state");
        assert!(quorum.proposals.proposals.is_empty());
    }

    #[test]
    fn receive_proposal_accepts_verified_supermajority_proof() {
        let (runtime, keypairs, target) = runtime_with_peers();
        let (dispatch, approved_blocks) =
            receive_valid_dispatch(&runtime, &keypairs, &target, b"proposal-valid-proof");
        let round_peers = {
            let mut state = runtime.inner.state.write().expect("state lock poisoned");
            state
                .get_mut_consensus(&target.last_epoch, target.nonce)
                .peers(dispatch.header.round)
        };
        let proposal_signer = keypairs
            .iter()
            .find(|keypair| keypair.public == round_peers[0])
            .unwrap();
        let proof = verification_proof_for(
            &keypairs,
            &target,
            dispatch.header.round,
            &approved_blocks,
            &round_peers[..4],
        );
        let body = consensus_proposal_body(&approved_blocks, Some(proof));
        let proposal = Proposal {
            header: signed_test_header_for_round(
                proposal_signer,
                &target,
                dispatch.header.round,
                MSGKey::Proposal,
                &body,
            ),
            body: body.clone(),
        };

        let receipt = runtime.receive_message(Msg::Proposal(proposal)).unwrap();
        assert_eq!(receipt.kind, "proposal");

        let state = runtime.inner.state.read().expect("state lock poisoned");
        let quorum = state
            .get_quorum(&target.last_epoch, target.nonce, dispatch.header.round)
            .expect("proposal should keep quorum state");
        assert_eq!(quorum.proposals.proposals.len(), 1);
        assert_eq!(
            quorum.proposals.count.get(&body.approved_hash.unwrap()),
            Some(&1)
        );
    }

    #[test]
    fn receive_commit_requires_distinct_true_supermajority() {
        let (runtime, keypairs, target) = runtime_with_peers();
        receive_proposal_supermajority(&runtime, &keypairs, &target, b"commit-threshold-proposals");
        let round_peers = {
            let mut state = runtime.inner.state.write().expect("state lock poisoned");
            state
                .get_mut_consensus(&target.last_epoch, target.nonce)
                .peers(0)
        };
        let commit_body = CommitBody {
            consensus: true,
            signature_tree_insert: None,
        };
        let repeated_signer = keypairs
            .iter()
            .find(|keypair| keypair.public == round_peers[0])
            .unwrap();

        for _ in 0..4 {
            runtime
                .receive_message(Msg::Commit(Commit {
                    header: signed_test_header(
                        repeated_signer,
                        &target,
                        MSGKey::Commit,
                        &commit_body,
                    ),
                    body: commit_body.clone(),
                }))
                .unwrap();
        }
        {
            let state = runtime.inner.state.read().expect("state lock poisoned");
            let quorum = state
                .get_quorum(&target.last_epoch, target.nonce, 0)
                .expect("commit should initialize quorum state");
            assert_eq!(quorum.commit_senders.len(), 1);
            assert!(!quorum.commit_sent);
        }

        for peer in round_peers.iter().take(4).skip(1) {
            let signer = keypairs
                .iter()
                .find(|keypair| keypair.public == *peer)
                .unwrap();
            runtime
                .receive_message(Msg::Commit(Commit {
                    header: signed_test_header(signer, &target, MSGKey::Commit, &commit_body),
                    body: commit_body.clone(),
                }))
                .unwrap();
        }

        let state = runtime.inner.state.read().expect("state lock poisoned");
        let quorum = state
            .get_quorum(&target.last_epoch, target.nonce, 0)
            .expect("commit should keep quorum state");
        assert_eq!(quorum.commit_senders.len(), 4);
        assert!(quorum.commit_sent);
    }

    #[test]
    fn receive_commit_replaces_equivocating_sender_vote() {
        let (runtime, keypairs, target) = runtime_with_peers();
        receive_proposal_supermajority(
            &runtime,
            &keypairs,
            &target,
            b"commit-equivocation-proposals",
        );
        let round_peers = {
            let mut state = runtime.inner.state.write().expect("state lock poisoned");
            state
                .get_mut_consensus(&target.last_epoch, target.nonce)
                .peers(0)
        };
        let true_body = CommitBody {
            consensus: true,
            signature_tree_insert: None,
        };
        let false_body = CommitBody {
            consensus: false,
            signature_tree_insert: None,
        };
        let equivocator = keypairs
            .iter()
            .find(|keypair| keypair.public == round_peers[0])
            .unwrap();

        runtime
            .receive_message(Msg::Commit(Commit {
                header: signed_test_header(equivocator, &target, MSGKey::Commit, &true_body),
                body: true_body.clone(),
            }))
            .unwrap();
        runtime
            .receive_message(Msg::Commit(Commit {
                header: signed_test_header(equivocator, &target, MSGKey::Commit, &false_body),
                body: false_body,
            }))
            .unwrap();

        for peer in round_peers.iter().take(4).skip(1) {
            let signer = keypairs
                .iter()
                .find(|keypair| keypair.public == *peer)
                .unwrap();
            runtime
                .receive_message(Msg::Commit(Commit {
                    header: signed_test_header(signer, &target, MSGKey::Commit, &true_body),
                    body: true_body.clone(),
                }))
                .unwrap();
        }
        {
            let state = runtime.inner.state.read().expect("state lock poisoned");
            let quorum = state
                .get_quorum(&target.last_epoch, target.nonce, 0)
                .expect("commit should keep quorum state");
            assert_eq!(quorum.commit_senders.len(), 4);
            assert!(!quorum.commit_sent);
        }

        runtime
            .receive_message(Msg::Commit(Commit {
                header: signed_test_header(equivocator, &target, MSGKey::Commit, &true_body),
                body: true_body,
            }))
            .unwrap();

        let state = runtime.inner.state.read().expect("state lock poisoned");
        let quorum = state
            .get_quorum(&target.last_epoch, target.nonce, 0)
            .expect("commit should keep quorum state");
        assert!(quorum.commit_sent);
    }

    #[test]
    fn receive_commit_rejects_true_without_local_proposal_supermajority() {
        let (runtime, keypairs, target) = runtime_with_peers();
        let signer = round_signer(&runtime, &keypairs, &target, 0);
        let body = CommitBody {
            consensus: true,
            signature_tree_insert: None,
        };
        let commit = Commit {
            header: signed_test_header(signer, &target, MSGKey::Commit, &body),
            body,
        };

        assert!(matches!(
            runtime.receive_message(Msg::Commit(commit)),
            Err(BlossomError::WireProtocol(message))
                if message.contains("proposal supermajority")
        ));

        let state = runtime.inner.state.read().expect("state lock poisoned");
        let quorum = state
            .get_quorum(&target.last_epoch, target.nonce, 0)
            .expect("header validation should initialize quorum state");
        assert!(quorum.commit_senders.is_empty());
        assert!(quorum.commit_true_senders.is_empty());
        assert!(!quorum.commit_sent);
    }

    #[test]
    fn receive_commit_supermajority_advances_epoch() {
        let (runtime, keypairs, target) = runtime_with_peers();
        let (_, approved_blocks) =
            receive_proposal_supermajority(&runtime, &keypairs, &target, b"commit-finalizes-epoch");
        let round_peers = {
            let mut state = runtime.inner.state.write().expect("state lock poisoned");
            state
                .get_mut_consensus(&target.last_epoch, target.nonce)
                .peers(0)
        };
        let body = CommitBody {
            consensus: true,
            signature_tree_insert: None,
        };

        for peer in round_peers.iter().take(4) {
            let signer = keypairs
                .iter()
                .find(|keypair| keypair.public == *peer)
                .unwrap();
            runtime
                .receive_message(Msg::Commit(Commit {
                    header: signed_test_header(signer, &target, MSGKey::Commit, &body),
                    body: body.clone(),
                }))
                .unwrap();
        }

        let state = runtime.inner.state.read().expect("state lock poisoned");
        assert_eq!(state.epochchain.epochchain.len(), 2);
        let latest = state.epochchain.epochchain.last().unwrap();
        assert_eq!(latest.body.last_epoch, target.last_epoch);
        assert_eq!(latest.body.nonce, target.nonce);
        for block_hash in approved_blocks.keys() {
            assert!(latest.body.blocks.contains_key(block_hash));
        }
    }

    #[test]
    fn receive_message_rejects_stale_epoch_target_after_finality() {
        let (runtime, keypairs, target) = runtime_with_peers();
        receive_proposal_supermajority(
            &runtime,
            &keypairs,
            &target,
            b"stale-message-finalized-epoch",
        );
        let round_peers = {
            let mut state = runtime.inner.state.write().expect("state lock poisoned");
            state
                .get_mut_consensus(&target.last_epoch, target.nonce)
                .peers(0)
        };
        let body = CommitBody {
            consensus: true,
            signature_tree_insert: None,
        };

        for peer in round_peers.iter().take(4) {
            let signer = keypairs
                .iter()
                .find(|keypair| keypair.public == *peer)
                .unwrap();
            runtime
                .receive_message(Msg::Commit(Commit {
                    header: signed_test_header(signer, &target, MSGKey::Commit, &body),
                    body: body.clone(),
                }))
                .unwrap();
        }

        let stale_signer = keypairs
            .iter()
            .find(|keypair| keypair.public == round_peers[4])
            .unwrap();
        let stale_commit = Commit {
            header: signed_test_header(stale_signer, &target, MSGKey::Commit, &body),
            body,
        };

        assert!(matches!(
            runtime.receive_message(Msg::Commit(stale_commit)),
            Err(BlossomError::WireProtocol(message))
                if message.contains("stale consensus target")
        ));
    }

    #[test]
    fn receive_dispatch_rejects_bad_body_hash_before_sender_accounting() {
        let (runtime, keypairs, target) = runtime_with_peers();
        let signer = round_signer(&runtime, &keypairs, &target, 0);
        let block = signed_block_for_target(signer, &target, b"dispatch-tx".to_vec());
        let mut blocks = BTreeMap::new();
        blocks.insert(block.hash, block);
        let valid_dispatch = signed_dispatch_for_blocks(signer, &target, blocks);
        let mut bad_dispatch = valid_dispatch.clone();
        bad_dispatch.body.blocks_hash = HashType([9; 32]);
        bad_dispatch.header =
            signed_test_header(signer, &target, MSGKey::Dispatch, &bad_dispatch.body);

        assert!(matches!(
            runtime.receive_message(Msg::Dispatch(bad_dispatch)),
            Err(BlossomError::WireProtocol(message))
                if message.contains("dispatch blocks hash")
        ));

        let receipt = runtime
            .receive_message(Msg::Dispatch(valid_dispatch))
            .unwrap();
        assert_eq!(receipt.kind, "dispatch");
        let state = runtime.inner.state.read().expect("state lock poisoned");
        let quorum = state
            .get_quorum(&target.last_epoch, target.nonce, 0)
            .unwrap();
        assert_eq!(quorum.pending_dispatches.len(), 1);
        assert!(quorum.received_dispatches.contains(&signer.public));
    }

    #[test]
    fn receive_dispatch_rejects_invalid_block_before_sender_accounting() {
        let (runtime, keypairs, target) = runtime_with_peers();
        let signer = round_signer(&runtime, &keypairs, &target, 0);
        let valid_block = signed_block_for_target(signer, &target, b"valid-tx".to_vec());
        let mut valid_blocks = BTreeMap::new();
        valid_blocks.insert(valid_block.hash, valid_block);
        let valid_dispatch = signed_dispatch_for_blocks(signer, &target, valid_blocks);

        let mut invalid_block = signed_block_for_target(signer, &target, b"bad-tx".to_vec());
        let invalid_block_hash = invalid_block.hash;
        invalid_block
            .body
            .txs
            .push(crate::block::Transaction::new("tampered-after-sign"));
        let mut invalid_blocks = BTreeMap::new();
        invalid_blocks.insert(invalid_block_hash, invalid_block);
        let invalid_dispatch = signed_dispatch_for_blocks(signer, &target, invalid_blocks);

        assert_eq!(
            runtime.receive_message(Msg::Dispatch(invalid_dispatch)),
            Err(BlossomError::InvalidBlockHash)
        );

        let receipt = runtime
            .receive_message(Msg::Dispatch(valid_dispatch))
            .unwrap();
        assert_eq!(receipt.kind, "dispatch");
        let state = runtime.inner.state.read().expect("state lock poisoned");
        let quorum = state
            .get_quorum(&target.last_epoch, target.nonce, 0)
            .unwrap();
        assert_eq!(quorum.pending_dispatches.len(), 1);
    }

    #[test]
    fn receive_dispatch_rejects_wrong_block_target_before_sender_accounting() {
        let (runtime, keypairs, target) = runtime_with_peers();
        let signer = round_signer(&runtime, &keypairs, &target, 0);
        let valid_block = signed_block_for_target(signer, &target, b"valid-tx".to_vec());
        let mut valid_blocks = BTreeMap::new();
        valid_blocks.insert(valid_block.hash, valid_block);
        let valid_dispatch = signed_dispatch_for_blocks(signer, &target, valid_blocks);

        let mut wrong_nonce = signed_block_for_target(signer, &target, b"wrong-nonce".to_vec());
        wrong_nonce.body.nonce = target.nonce.new_next();
        wrong_nonce.sign(&signer.secret);
        let mut wrong_blocks = BTreeMap::new();
        wrong_blocks.insert(wrong_nonce.hash, wrong_nonce.clone());
        let wrong_dispatch = signed_dispatch_for_blocks(signer, &target, wrong_blocks);

        assert_eq!(
            runtime.receive_message(Msg::Dispatch(wrong_dispatch)),
            Err(BlossomError::InvalidBlockNonce {
                expected: target.nonce,
                actual: wrong_nonce.body.nonce,
            })
        );

        let receipt = runtime
            .receive_message(Msg::Dispatch(valid_dispatch))
            .unwrap();
        assert_eq!(receipt.kind, "dispatch");
        let state = runtime.inner.state.read().expect("state lock poisoned");
        let quorum = state
            .get_quorum(&target.last_epoch, target.nonce, 0)
            .unwrap();
        assert_eq!(quorum.pending_dispatches.len(), 1);
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
    fn staged_node_admission_is_committed_at_epoch_boundary() {
        let (runtime, keypairs, target) = runtime_with_peers();
        let joiner = Keypair::generate();
        let service = Service::new(
            ServiceKind::Consensus,
            joiner.public,
            "tcp",
            "127.0.0.1",
            9100,
        );
        let admission = NodeAdmission::signed_for_consensus_service(
            service,
            target.last_epoch,
            target.nonce,
            &joiner.signer(),
        )
        .unwrap();

        let staged = runtime.stage_node_admission(admission).unwrap();
        assert_eq!(staged.map(|node| node.public_key()), Some(joiner.public));

        let dispatch = runtime.dispatch_local_block(0).unwrap();
        let local_admission = dispatch
            .body
            .blocks
            .values()
            .flat_map(|block| block.body.node_admissions.iter())
            .next()
            .cloned()
            .expect("local dispatch should carry staged admission");
        assert!(
            dispatch
                .body
                .blocks
                .values()
                .any(|block| block.body.node_admissions.len() == 1)
        );

        {
            let mut state = runtime.inner.state.write().expect("state lock poisoned");
            {
                let quorum = state.get_mut_quorum(&target.last_epoch, target.nonce, 0);
                for signer in &keypairs[1..4] {
                    let mut block = Block::default();
                    block.body.last_epoch = target.last_epoch;
                    block.body.nonce = target.nonce;
                    block.body.node_admissions.push(local_admission.clone());
                    block.sign(&signer.secret);
                    quorum.verified_blocks.insert(block.hash, block);
                }
            }
            assert!(state.advance_epoch(&target.last_epoch, target.nonce, 0, true));
        }

        assert!(
            runtime
                .current_verifiers()
                .iter()
                .any(|node| node.public_key() == joiner.public)
        );
    }

    #[test]
    fn stage_node_admission_rejects_stale_target() {
        let (runtime, _keypairs, target) = runtime_with_peers();
        let joiner = Keypair::generate();
        let service = Service::new(
            ServiceKind::Consensus,
            joiner.public,
            "tcp",
            "127.0.0.1",
            9100,
        );
        let admission = NodeAdmission::signed_for_consensus_service(
            service,
            target.last_epoch,
            target.nonce.new_next(),
            &joiner.signer(),
        )
        .unwrap();

        assert_eq!(
            runtime.stage_node_admission(admission),
            Err(BlossomError::InvalidEpochNonce)
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
    fn overlay_mode_rejects_consensus_entrypoints() {
        let keypair = Keypair::generate();
        let node = NodeIdentity::new(
            keypair.public,
            Some(keypair.secret),
            "tcp",
            "127.0.0.1",
            8080,
            false,
        );
        let runtime = NodeRuntime::new(RuntimeConfig::overlay(node));

        assert_eq!(runtime.mode(), RuntimeMode::Overlay);
        assert!(matches!(
            runtime.next_epoch_target(),
            Err(BlossomError::WireProtocol(error)) if error.contains("consensus runtime mode")
        ));
        assert!(matches!(
            runtime.set_application_state(b"v1:state"),
            Err(BlossomError::WireProtocol(error)) if error.contains("consensus runtime mode")
        ));
        assert!(matches!(
            runtime.receive_message(Msg::Ok),
            Err(BlossomError::WireProtocol(error)) if error.contains("consensus runtime mode")
        ));
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
    fn missing_signature_encounter_is_added_to_next_empty_block() {
        let (runtime, keypairs, target) = runtime_with_peers();
        let subject = keypairs[1].public;

        let record_hash = runtime
            .record_missing_signature(subject, 0, EncounterPhase::Verification, 123)
            .unwrap();

        assert_ne!(record_hash, HashType::default());
        assert_eq!(runtime.pending_encounter_records().len(), 1);

        let dispatch = runtime.dispatch_local_block(0).unwrap();
        let block = dispatch.body.blocks.values().next().unwrap();
        assert_eq!(block.body.last_epoch, target.last_epoch);
        assert_eq!(block.body.nonce, target.nonce);
        assert_eq!(block.body.encounter_records.len(), 1);
        assert_eq!(
            block.body.encounter_records[0].body.observer,
            keypairs[0].public
        );
        assert_eq!(block.body.encounter_records[0].body.subject, subject);
        assert_eq!(
            block.body.encounter_records[0].body.phase,
            EncounterPhase::Verification
        );
        assert_eq!(
            block.body.encounter_records[0].body.outcome,
            EncounterOutcome::MissingSignature
        );
        assert_eq!(block.body.encounter_records[0].body.evidence_hash, None);
        assert!(block.body.encounter_records[0].verify().is_ok());
        assert!(block.verify_integrity().is_ok());
        assert!(runtime.pending_encounter_records().is_empty());
    }

    #[test]
    fn missing_signature_subjects_compare_expected_quorum_to_seen_signatures() {
        let (runtime, keypairs, target) = runtime_with_peers();
        let signer = {
            let mut state = runtime.inner.state.write().expect("state lock poisoned");
            let sender = state
                .get_mut_consensus(&target.last_epoch, target.nonce)
                .peers(0)
                .into_iter()
                .next()
                .expect("round should include a peer");
            keypairs
                .iter()
                .find(|keypair| keypair.public == sender)
                .unwrap()
                .clone()
        };
        let blocks = BTreeMap::new();
        let body = VerificationBody {
            blocks_hash: blocks.hash(),
            blocks,
        };
        let signature_hash = Header::signature_hash_for_body(
            &signer.public,
            &target.last_epoch,
            target.nonce,
            0,
            MSGKey::Verification,
            &body,
        );
        let verification = Verification {
            header: Header {
                sender: signer.public,
                last_epoch: target.last_epoch,
                nonce: target.nonce,
                round: 0,
                signature: signer.signer().sign(signature_hash.as_ref()),
            },
            body,
        };

        runtime
            .receive_message(Msg::Verification(verification))
            .unwrap();

        let missing = runtime
            .missing_signature_subjects(0, EncounterPhase::Verification)
            .unwrap();
        assert!(!missing.contains(&signer.public));
        assert_eq!(missing.len(), 4);
    }

    #[test]
    fn record_missing_signatures_queues_evidence_for_absent_signers() {
        let (runtime, keypairs, target) = runtime_with_peers();
        let expected_missing = {
            let mut state = runtime.inner.state.write().expect("state lock poisoned");
            state
                .get_mut_consensus(&target.last_epoch, target.nonce)
                .peers(0)
        };

        let hashes = runtime
            .record_missing_signatures(0, EncounterPhase::Dispatch, 456)
            .unwrap();

        assert_eq!(hashes.len(), expected_missing.len());
        let records = runtime.pending_encounter_records();
        assert_eq!(records.len(), expected_missing.len());
        for record in records {
            assert_eq!(record.body.observer, keypairs[0].public);
            assert!(expected_missing.contains(&record.body.subject));
            assert_eq!(record.body.outcome, EncounterOutcome::MissingSignature);
            assert_eq!(record.body.phase, EncounterPhase::Dispatch);
            assert!(record.verify().is_ok());
        }
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
    fn consensus_messages_reject_known_members_in_wrong_round_without_accounting() {
        let (runtime, keypairs, target) = runtime_with_peers();
        let signer = round_signer(&runtime, &keypairs, &target, 0);
        let wrong_round = 1;

        for (label, message) in consensus_messages_for_target(signer, &target, wrong_round) {
            assert_eq!(
                runtime.receive_message(message),
                Err(BlossomError::UnknownSender),
                "{label} should reject a known member outside the addressed round"
            );
        }

        let state = runtime.inner.state.read().expect("state lock poisoned");
        let consensus = state
            .get_consensus(&target.last_epoch, target.nonce)
            .expect("header checks should initialize consensus");
        assert!(
            !consensus.quorum.contains_key(&wrong_round),
            "wrong-round traffic must not create quorum accounting"
        );
        let round_zero = consensus.quorum.get(&0);
        assert!(
            round_zero.is_none_or(|quorum| {
                quorum.received_dispatches.is_empty()
                    && quorum.verifications.verifications.is_empty()
                    && quorum.proposals.proposals.is_empty()
                    && quorum.commit_senders.is_empty()
                    && quorum.epoch_started_senders.is_empty()
            }),
            "wrong-round traffic must not be recorded in the valid round"
        );
    }

    #[test]
    fn consensus_messages_reject_non_members_without_accounting() {
        let (runtime, _, target) = runtime_with_peers();
        let unknown = Keypair::generate();

        for (label, message) in consensus_messages_for_target(&unknown, &target, 0) {
            assert_eq!(
                runtime.receive_message(message),
                Err(BlossomError::UnknownSender),
                "{label} should reject non-member senders"
            );
        }

        let state = runtime.inner.state.read().expect("state lock poisoned");
        let consensus = state
            .get_consensus(&target.last_epoch, target.nonce)
            .expect("header checks should initialize consensus");
        assert!(
            consensus.quorum.is_empty(),
            "non-member traffic must not create quorum accounting"
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
    fn peer_application_states_reports_verified_peer_blocks() {
        let (runtime, _, target) = runtime_with_peers_mode(TrustMode::Trusted);
        let known_sender = {
            let mut state = runtime.inner.state.write().expect("state lock poisoned");
            state
                .get_mut_consensus(&target.last_epoch, target.nonce)
                .peers(0)
                .into_iter()
                .next()
                .expect("round should include a peer")
        };
        let mut block = Block::default();
        block.body.last_epoch = target.last_epoch;
        block.body.nonce = target.nonce;
        block
            .set_application_state(b"v1:cache-pressure=low")
            .unwrap();
        block.seal_unsigned(known_sender);

        {
            let mut state = runtime.inner.state.write().expect("state lock poisoned");
            state
                .get_mut_quorum(&target.last_epoch, target.nonce, 0)
                .verified_blocks
                .insert(block.hash, block.clone());
        }

        let states = runtime.peer_application_states();
        let state = states.get(&known_sender).expect("peer state should exist");
        assert_eq!(state.peer, known_sender);
        assert_eq!(state.block_hash, block.hash);
        assert_eq!(state.last_epoch, target.last_epoch);
        assert_eq!(state.nonce, target.nonce);
        assert_eq!(state.application_state.as_slice(), b"v1:cache-pressure=low");
    }

    #[test]
    fn observed_encounter_records_reports_verified_peer_blocks() {
        let (runtime, keypairs, target) = runtime_with_peers();
        let observer = &keypairs[1];
        let subject = keypairs[2].public;
        let record = EncounterRecord::signed(
            EncounterRecordBody::new(
                observer.public,
                subject,
                target.last_epoch,
                target.nonce,
                0,
                EncounterPhase::Verification,
                EncounterOutcome::MissingSignature,
            ),
            &observer.signer(),
        )
        .unwrap();
        let mut block = Block::default();
        block.body.last_epoch = target.last_epoch;
        block.body.nonce = target.nonce;
        block.body.encounter_records.push(record.clone());
        block.sign(&observer.secret);
        assert!(block.verify_integrity().is_ok());

        {
            let mut state = runtime.inner.state.write().expect("state lock poisoned");
            state
                .get_mut_quorum(&target.last_epoch, target.nonce, 0)
                .verified_blocks
                .insert(block.hash, block.clone());
        }

        let records = runtime.observed_encounter_records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].group_id, target.group_id);
        assert_eq!(records[0].block_hash, block.hash);
        assert_eq!(records[0].block_validator, observer.public);
        assert_eq!(records[0].record, record);
    }

    #[test]
    fn echo_recovery_messages_reject_unknown_senders() {
        let (runtime, _, target) = runtime_with_peers();
        let unknown = Keypair::generate();
        let requested_blocks = BTreeMap::new();
        let request_header =
            signed_test_header(&unknown, &target, MSGKey::EchoRequest, &requested_blocks);
        let redispatched_blocks = BTreeMap::new();
        let redispatch_header = signed_test_header(
            &unknown,
            &target,
            MSGKey::EchoReDispatch,
            &redispatched_blocks,
        );

        assert_eq!(
            runtime.receive_message(Msg::EchoRequest(EchoRequest {
                header: request_header,
                requested_blocks,
            })),
            Err(BlossomError::UnknownSender)
        );
        assert_eq!(
            runtime.receive_message(Msg::EchoReDispatch(EchoReDispatch {
                header: redispatch_header,
                redispatched_blocks,
            })),
            Err(BlossomError::UnknownSender)
        );
    }

    #[test]
    fn echo_recovery_messages_reject_bad_signatures() {
        let (runtime, keypairs, target) = runtime_with_peers();
        let signer = &keypairs[1];
        let mut requested_blocks = BTreeMap::new();
        requested_blocks.insert(HashType([1; 32]), ());
        let header = signed_test_header(signer, &target, MSGKey::EchoRequest, &requested_blocks);
        requested_blocks.insert(HashType([2; 32]), ());

        assert_eq!(
            runtime.receive_message(Msg::EchoRequest(EchoRequest {
                header,
                requested_blocks,
            })),
            Err(BlossomError::SignatureError)
        );
    }

    fn consensus_messages_for_target(
        signer: &Keypair,
        target: &EpochTarget,
        round: u8,
    ) -> Vec<(&'static str, Msg)> {
        let dispatch_body = DispatchBody::default();
        let echo_response_body = EchoResponseBody::default();
        let verification_body = VerificationBody::default();
        let proposal_body = ProposalBody::default();
        let commit_body = CommitBody::default();
        let epoch_started_body = EpochStartedBody::default();
        let requested_blocks = BTreeMap::new();
        let redispatched_blocks = BTreeMap::new();

        vec![
            (
                "dispatch",
                Msg::Dispatch(Dispatch {
                    header: signed_test_header_for_round(
                        signer,
                        target,
                        round,
                        MSGKey::Dispatch,
                        &dispatch_body,
                    ),
                    body: dispatch_body,
                }),
            ),
            (
                "echo_response",
                Msg::EchoResponse(EchoResponse {
                    header: signed_test_header_for_round(
                        signer,
                        target,
                        round,
                        MSGKey::EchoResponse,
                        &echo_response_body,
                    ),
                    body: echo_response_body,
                }),
            ),
            (
                "verification",
                Msg::Verification(Verification {
                    header: signed_test_header_for_round(
                        signer,
                        target,
                        round,
                        MSGKey::Verification,
                        &verification_body,
                    ),
                    body: verification_body,
                }),
            ),
            (
                "proposal",
                Msg::Proposal(Proposal {
                    header: signed_test_header_for_round(
                        signer,
                        target,
                        round,
                        MSGKey::Proposal,
                        &proposal_body,
                    ),
                    body: proposal_body,
                }),
            ),
            (
                "commit",
                Msg::Commit(Commit {
                    header: signed_test_header_for_round(
                        signer,
                        target,
                        round,
                        MSGKey::Commit,
                        &commit_body,
                    ),
                    body: commit_body,
                }),
            ),
            (
                "epoch_started",
                Msg::EpochStarted(EpochStarted {
                    header: signed_test_header_for_round(
                        signer,
                        target,
                        round,
                        MSGKey::EpochStarted,
                        &epoch_started_body,
                    ),
                    body: epoch_started_body,
                }),
            ),
            (
                "echo_request",
                Msg::EchoRequest(EchoRequest {
                    header: signed_test_header_for_round(
                        signer,
                        target,
                        round,
                        MSGKey::EchoRequest,
                        &requested_blocks,
                    ),
                    requested_blocks,
                }),
            ),
            (
                "echo_redispatch",
                Msg::EchoReDispatch(EchoReDispatch {
                    header: signed_test_header_for_round(
                        signer,
                        target,
                        round,
                        MSGKey::EchoReDispatch,
                        &redispatched_blocks,
                    ),
                    redispatched_blocks,
                }),
            ),
        ]
    }
}
