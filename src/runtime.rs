use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use borsh::{BorshDeserialize, BorshSerialize};
use indextreemap::IndexTreeMap;
use serde::{Deserialize, Serialize};

use crate::address_book::{AddressBook, Service, ServiceKind};
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
    EpochStarted, Header, Proposal, SignatureTree, Verification,
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

    pub fn register_service(&self, service: Service) -> Option<Service> {
        self.inner
            .address_book
            .write()
            .expect("address book lock poisoned")
            .add(service)
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
    }

    pub fn dispatch_local_block(&self, round: u8) -> Result<Dispatch> {
        let target = self.next_epoch_target()?;
        let self_node = self.self_node();
        let block_service = self.block_service();

        let (maybe_block, application_state, encounter_records) = {
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
            (
                maybe_block,
                local_blocks.application_state().clone(),
                encounter_records,
            )
        };

        let block = match maybe_block {
            Some(block) => block,
            None => self.empty_block(&self_node, &target, application_state, encounter_records)?,
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
        Ok(Dispatch { header, body })
    }

    pub fn receive_message(&self, message: Msg) -> Result<MessageReceipt> {
        self.ensure_consensus_mode("receive consensus message")?;
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
        self.ensure_consensus_mode("receive hot dispatch")?;
        self.ensure_known_header_epoch(&message.header)?;
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
        self.ensure_known_header_epoch(&message.header)?;
        let mut state = self.inner.state.write().expect("state lock poisoned");
        if message.header.verify_header(&mut state) == Some(false) {
            return Err(BlossomError::UnknownSender);
        }
        Ok(MessageReceipt::accepted("echo_request"))
    }

    fn receive_echo_redispatch(&self, message: EchoReDispatch) -> Result<MessageReceipt> {
        self.ensure_known_header_epoch(&message.header)?;
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
        quorum.commit_senders.insert(message.header.sender);
        quorum.commit_sent = quorum.commit_sent || message.body.consensus;
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

    fn ensure_consensus_mode(&self, action: &str) -> Result<()> {
        if self.inner.mode == RuntimeMode::Overlay {
            return Err(BlossomError::WireProtocol(format!(
                "{action} requires consensus runtime mode"
            )));
        }
        Ok(())
    }

    fn validate_block_service(&self, block: &Block) -> Result<()> {
        if let Some(service) = self.block_service()
            && block.body.validator != service.public_key
        {
            return Err(BlossomError::UnknownSender);
        }
        Ok(())
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

    #[cfg(feature = "availability-gossip")]
    fn is_known_member(&self, public_key: &PubKey) -> bool {
        let state = self.inner.state.read().expect("state lock poisoned");
        state
            .epochchain
            .epochchain
            .last()
            .is_some_and(|epoch| epoch.body.verifiers.keys().any(|key| key == public_key))
    }

    fn empty_block(
        &self,
        self_node: &NodeIdentity,
        target: &EpochTarget,
        application_state: BlockApplicationState,
        encounter_records: Vec<EncounterRecord>,
    ) -> Result<Block> {
        let mut block = Block::default();
        block.body.last_epoch = target.last_epoch;
        block.body.nonce = target.nonce;
        block.body.application_state = application_state;
        block.body.encounter_records = encounter_records;
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
        self.ensure_known_header_epoch(header)?;
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

    fn ensure_known_header_epoch(&self, header: &Header) -> Result<()> {
        if !self.contains_epoch_hash(&header.last_epoch) {
            return Err(BlossomError::WireProtocol(format!(
                "unknown consensus epoch {} for group {}",
                header.last_epoch, self.inner.group_id
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
    use crate::blossom::{DispatchBody, VerificationBody};
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
            group_id: genesis.body.group_id,
            last_epoch: genesis.hash,
            nonce: genesis.body.nonce.new_next(),
        };
        (runtime, keypairs, target)
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
        let body = VerificationBody {
            blocks_hash: HashType([7; 32]),
            blocks: BTreeMap::new(),
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
