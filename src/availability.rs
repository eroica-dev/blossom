use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::block::{FilteredPayloadView, FilteredTransactionSlot, Transaction};
use crate::crypto::{PubKey, SecretSigner, Signature};
use crate::error::{BlossomError, Result};
use crate::group::ConsensusGroupId;
use crate::hash::{HashType, ProtocolHasher};

pub const FILTERED_PAYLOAD_MAX_BYTES: usize = 32 * 1024 * 1024;

const AVAILABILITY_GOSSIP_DOMAIN: &[u8] = b"blossom-availability-gossip:v1";
const FILTERED_PAYLOAD_FETCH_DOMAIN: &[u8] = b"blossom-filtered-payload-fetch:v1";
const FILTERED_PAYLOAD_BATCH_FETCH_DOMAIN: &[u8] = b"blossom-filtered-payload-batch-fetch:v1";
const FILTERED_PAYLOAD_DELIVERY_DOMAIN: &[u8] = b"blossom-filtered-payload-delivery:v1";
const FILTERED_PAYLOAD_BATCH_DELIVERY_DOMAIN: &[u8] = b"blossom-filtered-payload-batch-delivery:v1";

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct AvailabilityEntry {
    pub slot_hash: HashType,
    pub slot: FilteredTransactionSlot,
}

impl AvailabilityEntry {
    pub fn new(slot: FilteredTransactionSlot) -> Result<Self> {
        let entry = Self {
            slot_hash: slot.hash(),
            slot,
        };
        entry.validate()?;
        Ok(entry)
    }

    pub fn validate(&self) -> Result<()> {
        self.slot.validate()?;
        if self.slot_hash != self.slot.hash() {
            return Err(BlossomError::InvalidBlockHash);
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct AvailabilityGossipBody {
    pub scope: ConsensusGroupId,
    pub holder: PubKey,
    pub entries: Vec<AvailabilityEntry>,
}

impl AvailabilityGossipBody {
    pub fn signature_hash(&self) -> HashType {
        let mut hasher = ProtocolHasher::new();
        hasher.update(AVAILABILITY_GOSSIP_DOMAIN);
        hasher.update(self.scope.as_ref());
        hasher.update(self.holder.as_ref());
        hasher.update((self.entries.len() as u64).to_le_bytes());
        for entry in &self.entries {
            hasher.update(entry.slot_hash.as_ref());
            entry.slot.update_hash(&mut hasher);
        }
        hasher.finalize()
    }

    pub fn validate(&self) -> Result<()> {
        if self.entries.is_empty() {
            return Err(BlossomError::WireProtocol(
                "availability gossip must include at least one entry".to_string(),
            ));
        }
        for entry in &self.entries {
            entry.validate()?;
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct AvailabilityGossip {
    pub body: AvailabilityGossipBody,
    pub signature: Signature,
}

impl AvailabilityGossip {
    pub fn signed(body: AvailabilityGossipBody, signer: &SecretSigner) -> Result<Self> {
        body.validate()?;
        Ok(Self {
            signature: signer.sign(body.signature_hash().as_ref()),
            body,
        })
    }

    pub fn trusted(body: AvailabilityGossipBody) -> Result<Self> {
        body.validate()?;
        Ok(Self {
            body,
            signature: Signature::default(),
        })
    }

    pub fn verify(&self) -> Result<()> {
        self.body.validate()?;
        self.signature
            .verify(self.body.signature_hash().as_ref(), &self.body.holder)
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct AvailabilityReceipt {
    pub scope: ConsensusGroupId,
    pub holder: PubKey,
    pub entries_accepted: usize,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct FilteredPayloadFetchBody {
    pub scope: ConsensusGroupId,
    pub requester: PubKey,
    pub slot_hash: HashType,
    pub payload_commitment: HashType,
}

impl FilteredPayloadFetchBody {
    pub fn signature_hash(&self) -> HashType {
        let mut hasher = ProtocolHasher::new();
        hasher.update(FILTERED_PAYLOAD_FETCH_DOMAIN);
        hasher.update(self.scope.as_ref());
        hasher.update(self.requester.as_ref());
        hasher.update(self.slot_hash.as_ref());
        hasher.update(self.payload_commitment.as_ref());
        hasher.finalize()
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct FilteredPayloadFetch {
    pub body: FilteredPayloadFetchBody,
    pub signature: Signature,
}

impl FilteredPayloadFetch {
    pub fn signed(body: FilteredPayloadFetchBody, signer: &SecretSigner) -> Self {
        Self {
            signature: signer.sign(body.signature_hash().as_ref()),
            body,
        }
    }

    pub fn trusted(body: FilteredPayloadFetchBody) -> Self {
        Self {
            body,
            signature: Signature::default(),
        }
    }

    pub fn verify(&self) -> Result<()> {
        self.signature
            .verify(self.body.signature_hash().as_ref(), &self.body.requester)
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct FilteredPayloadRequest {
    pub slot_hash: HashType,
    pub payload_commitment: HashType,
}

impl FilteredPayloadRequest {
    pub fn new(slot_hash: HashType, payload_commitment: HashType) -> Self {
        Self {
            slot_hash,
            payload_commitment,
        }
    }
}

impl From<&AvailabilityEntry> for FilteredPayloadRequest {
    fn from(entry: &AvailabilityEntry) -> Self {
        Self::new(entry.slot_hash, entry.slot.payload_commitment)
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct FilteredPayloadBatchFetchBody {
    pub scope: ConsensusGroupId,
    pub requester: PubKey,
    pub requests: Vec<FilteredPayloadRequest>,
}

impl FilteredPayloadBatchFetchBody {
    pub fn signature_hash(&self) -> HashType {
        let mut hasher = ProtocolHasher::new();
        hasher.update(FILTERED_PAYLOAD_BATCH_FETCH_DOMAIN);
        hasher.update(self.scope.as_ref());
        hasher.update(self.requester.as_ref());
        hasher.update((self.requests.len() as u64).to_le_bytes());
        for request in &self.requests {
            hasher.update(request.slot_hash.as_ref());
            hasher.update(request.payload_commitment.as_ref());
        }
        hasher.finalize()
    }

    pub fn validate(&self) -> Result<()> {
        if self.requests.is_empty() {
            return Err(BlossomError::WireProtocol(
                "filtered payload batch fetch must include at least one request".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct FilteredPayloadBatchFetch {
    pub body: FilteredPayloadBatchFetchBody,
    pub signature: Signature,
}

impl FilteredPayloadBatchFetch {
    pub fn signed(body: FilteredPayloadBatchFetchBody, signer: &SecretSigner) -> Result<Self> {
        body.validate()?;
        Ok(Self {
            signature: signer.sign(body.signature_hash().as_ref()),
            body,
        })
    }

    pub fn trusted(body: FilteredPayloadBatchFetchBody) -> Result<Self> {
        body.validate()?;
        Ok(Self {
            body,
            signature: Signature::default(),
        })
    }

    pub fn verify(&self) -> Result<()> {
        self.body.validate()?;
        self.signature
            .verify(self.body.signature_hash().as_ref(), &self.body.requester)
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct FilteredPayloadDeliveryBody {
    pub scope: ConsensusGroupId,
    pub holder: PubKey,
    pub slot_hash: HashType,
    pub slot: FilteredTransactionSlot,
    pub payload: Vec<u8>,
}

impl FilteredPayloadDeliveryBody {
    pub fn signature_hash(&self) -> HashType {
        let mut hasher = ProtocolHasher::new();
        hasher.update(FILTERED_PAYLOAD_DELIVERY_DOMAIN);
        hasher.update(self.scope.as_ref());
        hasher.update(self.holder.as_ref());
        hasher.update(self.slot_hash.as_ref());
        self.slot.update_hash(&mut hasher);
        hasher.update((self.payload.len() as u64).to_le_bytes());
        hasher.update(self.payload.as_slice());
        hasher.finalize()
    }

    pub fn validate(&self) -> Result<()> {
        validate_filtered_payload(&self.slot, &self.payload)?;
        if self.slot_hash != self.slot.hash() {
            return Err(BlossomError::InvalidBlockHash);
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct FilteredPayloadDeliveryItem {
    pub slot_hash: HashType,
    pub slot: FilteredTransactionSlot,
    pub payload: Vec<u8>,
}

impl FilteredPayloadDeliveryItem {
    pub fn validate(&self) -> Result<()> {
        validate_filtered_payload(&self.slot, &self.payload)?;
        if self.slot_hash != self.slot.hash() {
            return Err(BlossomError::InvalidBlockHash);
        }
        Ok(())
    }

    pub fn into_transaction(self) -> Transaction {
        Transaction::from_filtered_parts(
            self.slot_hash,
            self.slot,
            self.payload,
            crate::block::FilteredPayloadView::Full,
        )
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct FilteredPayloadBatchDeliveryBody {
    pub scope: ConsensusGroupId,
    pub holder: PubKey,
    pub items: Vec<FilteredPayloadDeliveryItem>,
}

impl FilteredPayloadBatchDeliveryBody {
    pub fn signature_hash(&self) -> HashType {
        let mut hasher = ProtocolHasher::new();
        hasher.update(FILTERED_PAYLOAD_BATCH_DELIVERY_DOMAIN);
        hasher.update(self.scope.as_ref());
        hasher.update(self.holder.as_ref());
        hasher.update((self.items.len() as u64).to_le_bytes());
        for item in &self.items {
            hasher.update(item.slot_hash.as_ref());
            item.slot.update_hash(&mut hasher);
            hasher.update((item.payload.len() as u64).to_le_bytes());
            hasher.update(item.payload.as_slice());
        }
        hasher.finalize()
    }

    pub fn validate(&self) -> Result<()> {
        for item in &self.items {
            item.validate()?;
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct FilteredPayloadBatchDelivery {
    pub body: FilteredPayloadBatchDeliveryBody,
    pub signature: Signature,
}

impl FilteredPayloadBatchDelivery {
    pub fn signed(body: FilteredPayloadBatchDeliveryBody, signer: &SecretSigner) -> Result<Self> {
        body.validate()?;
        Ok(Self {
            signature: signer.sign(body.signature_hash().as_ref()),
            body,
        })
    }

    pub fn trusted(body: FilteredPayloadBatchDeliveryBody) -> Result<Self> {
        body.validate()?;
        Ok(Self {
            body,
            signature: Signature::default(),
        })
    }

    pub fn verify(&self) -> Result<()> {
        self.body.validate()?;
        self.signature
            .verify(self.body.signature_hash().as_ref(), &self.body.holder)
    }

    pub fn into_transactions(self) -> Vec<Transaction> {
        self.body
            .items
            .into_iter()
            .map(FilteredPayloadDeliveryItem::into_transaction)
            .collect()
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct FilteredPayloadDelivery {
    pub body: FilteredPayloadDeliveryBody,
    pub signature: Signature,
}

impl FilteredPayloadDelivery {
    pub fn signed(body: FilteredPayloadDeliveryBody, signer: &SecretSigner) -> Result<Self> {
        body.validate()?;
        Ok(Self {
            signature: signer.sign(body.signature_hash().as_ref()),
            body,
        })
    }

    pub fn trusted(body: FilteredPayloadDeliveryBody) -> Result<Self> {
        body.validate()?;
        Ok(Self {
            body,
            signature: Signature::default(),
        })
    }

    pub fn verify(&self) -> Result<()> {
        self.body.validate()?;
        self.signature
            .verify(self.body.signature_hash().as_ref(), &self.body.holder)
    }

    pub fn into_transaction(self) -> Transaction {
        Transaction::from_filtered_parts(
            self.body.slot_hash,
            self.body.slot,
            self.body.payload,
            crate::block::FilteredPayloadView::Full,
        )
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct FilteredPayloadMissing {
    pub scope: ConsensusGroupId,
    pub holder: PubKey,
    pub slot_hash: HashType,
    pub payload_commitment: HashType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalFilteredPayload {
    pub scope: ConsensusGroupId,
    pub holder: PubKey,
    pub slot_hash: HashType,
    pub slot: FilteredTransactionSlot,
    pub payload: Vec<u8>,
}

impl LocalFilteredPayload {
    pub fn delivery_body(&self) -> FilteredPayloadDeliveryBody {
        FilteredPayloadDeliveryBody {
            scope: self.scope,
            holder: self.holder,
            slot_hash: self.slot_hash,
            slot: self.slot.clone(),
            payload: self.payload.clone(),
        }
    }

    pub fn delivery_item(&self) -> FilteredPayloadDeliveryItem {
        FilteredPayloadDeliveryItem {
            slot_hash: self.slot_hash,
            slot: self.slot.clone(),
            payload: self.payload.clone(),
        }
    }
}

#[derive(Debug, Default)]
pub struct AvailabilityStore {
    local_payloads: BTreeMap<HashType, LocalFilteredPayload>,
    peer_entries: BTreeMap<(PubKey, HashType), AvailabilityEntry>,
}

impl AvailabilityStore {
    pub fn store_local(
        &mut self,
        scope: ConsensusGroupId,
        holder: PubKey,
        slot: FilteredTransactionSlot,
        payload: impl Into<Vec<u8>>,
    ) -> Result<AvailabilityEntry> {
        let payload = payload.into();
        validate_filtered_payload(&slot, &payload)?;
        let entry = AvailabilityEntry::new(slot.clone())?;
        let record = LocalFilteredPayload {
            scope,
            holder,
            slot_hash: entry.slot_hash,
            slot,
            payload,
        };
        self.local_payloads.insert(entry.slot_hash, record);
        Ok(entry)
    }

    pub fn store_transaction(
        &mut self,
        scope: ConsensusGroupId,
        holder: PubKey,
        tx: &Transaction,
    ) -> Result<Option<AvailabilityEntry>> {
        let Some(slot) = tx.filtered_slot.as_ref() else {
            return Ok(None);
        };
        if tx.filtered_view != FilteredPayloadView::Full {
            return Ok(None);
        }
        self.store_local(scope, holder, slot.clone(), tx.payload.as_slice())
            .map(Some)
    }

    pub fn record_gossip(&mut self, gossip: &AvailabilityGossip) -> Result<usize> {
        gossip.body.validate()?;
        for entry in &gossip.body.entries {
            self.peer_entries
                .insert((gossip.body.holder, entry.slot_hash), entry.clone());
        }
        Ok(gossip.body.entries.len())
    }

    pub fn local_entries(&self, scope: ConsensusGroupId) -> Vec<AvailabilityEntry> {
        self.local_payloads
            .values()
            .filter(|record| record.scope == scope)
            .map(|record| AvailabilityEntry {
                slot_hash: record.slot_hash,
                slot: record.slot.clone(),
            })
            .collect()
    }

    pub fn peer_entries(&self) -> Vec<(PubKey, AvailabilityEntry)> {
        self.peer_entries
            .iter()
            .map(|((holder, _), entry)| (*holder, entry.clone()))
            .collect()
    }

    pub fn get_local_payload(
        &self,
        scope: ConsensusGroupId,
        slot_hash: &HashType,
        payload_commitment: &HashType,
        requester: &PubKey,
    ) -> Result<Option<LocalFilteredPayload>> {
        let Some(record) = self.local_payloads.get(slot_hash) else {
            return Ok(None);
        };
        if record.scope != scope || record.slot.payload_commitment != *payload_commitment {
            return Ok(None);
        }
        if !record.slot.is_target(requester) {
            return Err(BlossomError::WireProtocol(format!(
                "requester {requester} is not authorized for filtered payload {slot_hash}"
            )));
        }
        Ok(Some(record.clone()))
    }
}

pub fn validate_filtered_payload(slot: &FilteredTransactionSlot, payload: &[u8]) -> Result<()> {
    slot.validate()?;
    if payload.len() > FILTERED_PAYLOAD_MAX_BYTES {
        return Err(BlossomError::InvalidFrameSize(payload.len()));
    }
    if payload.len() as u64 != slot.payload_len {
        return Err(BlossomError::InvalidBlockHash);
    }
    if HashType::hash(payload) != slot.payload_commitment {
        return Err(BlossomError::InvalidBlockHash);
    }
    Ok(())
}

/// Idealized push-gossip rounds needed for one holder to reach `node_count`.
///
/// This is a topology-independent planning estimate, not a delivery guarantee:
/// it assumes each informed node reaches `fanout` new peers per round. Real
/// deployments should budget an extra round for overlap, packet loss, and
/// scheduling jitter.
pub fn ideal_push_gossip_rounds(node_count: usize, fanout: usize) -> Option<usize> {
    if node_count <= 1 {
        return Some(0);
    }
    if fanout == 0 {
        return None;
    }

    let mut reached = 1usize;
    let mut rounds = 0usize;
    while reached < node_count {
        reached = reached.checked_mul(fanout.checked_add(1)?)?;
        rounds = rounds.checked_add(1)?;
    }
    Some(rounds)
}

pub fn ideal_push_gossip_delay_ms(
    node_count: usize,
    fanout: usize,
    interval_ms: u64,
) -> Option<u64> {
    (ideal_push_gossip_rounds(node_count, fanout)? as u64).checked_mul(interval_ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::FilteredDeliveryPolicy;
    use crate::crypto::Keypair;

    #[test]
    fn signs_gossip_fetch_and_delivery() {
        let holder = Keypair::generate();
        let requester = Keypair::generate();
        let payload = b"target-only-payload".to_vec();
        let slot = FilteredTransactionSlot::for_payload(
            HashType::hash(b"cache-key"),
            1,
            vec![requester.public],
            &payload,
            FilteredDeliveryPolicy::Gossip,
        )
        .unwrap();
        let entry = AvailabilityEntry::new(slot.clone()).unwrap();
        let gossip = AvailabilityGossip::signed(
            AvailabilityGossipBody {
                scope: ConsensusGroupId::root(),
                holder: holder.public,
                entries: vec![entry.clone()],
            },
            &holder.signer(),
        )
        .unwrap();
        gossip.verify().unwrap();

        let fetch = FilteredPayloadFetch::signed(
            FilteredPayloadFetchBody {
                scope: ConsensusGroupId::root(),
                requester: requester.public,
                slot_hash: entry.slot_hash,
                payload_commitment: slot.payload_commitment,
            },
            &requester.signer(),
        );
        fetch.verify().unwrap();

        let delivery = FilteredPayloadDelivery::signed(
            FilteredPayloadDeliveryBody {
                scope: ConsensusGroupId::root(),
                holder: holder.public,
                slot_hash: entry.slot_hash,
                slot: slot.clone(),
                payload: payload.clone(),
            },
            &holder.signer(),
        )
        .unwrap();
        delivery.verify().unwrap();
        assert_eq!(delivery.into_transaction().hash, entry.slot_hash);

        let batch_fetch = FilteredPayloadBatchFetch::signed(
            FilteredPayloadBatchFetchBody {
                scope: ConsensusGroupId::root(),
                requester: requester.public,
                requests: vec![FilteredPayloadRequest::from(&entry)],
            },
            &requester.signer(),
        )
        .unwrap();
        batch_fetch.verify().unwrap();

        let batch_delivery = FilteredPayloadBatchDelivery::signed(
            FilteredPayloadBatchDeliveryBody {
                scope: ConsensusGroupId::root(),
                holder: holder.public,
                items: vec![FilteredPayloadDeliveryItem {
                    slot_hash: entry.slot_hash,
                    slot,
                    payload,
                }],
            },
            &holder.signer(),
        )
        .unwrap();
        batch_delivery.verify().unwrap();
        assert_eq!(batch_delivery.into_transactions().len(), 1);
    }

    #[test]
    fn store_authorizes_fetch_targets() {
        let holder = Keypair::generate();
        let requester = Keypair::generate();
        let outsider = Keypair::generate();
        let payload = b"value".to_vec();
        let slot = FilteredTransactionSlot::for_payload(
            HashType::hash(b"key"),
            1,
            vec![requester.public],
            &payload,
            FilteredDeliveryPolicy::Gossip,
        )
        .unwrap();
        let mut store = AvailabilityStore::default();
        let entry = store
            .store_local(
                ConsensusGroupId::root(),
                holder.public,
                slot.clone(),
                payload,
            )
            .unwrap();

        assert!(
            store
                .get_local_payload(
                    ConsensusGroupId::root(),
                    &entry.slot_hash,
                    &slot.payload_commitment,
                    &requester.public,
                )
                .unwrap()
                .is_some()
        );
        assert!(matches!(
            store.get_local_payload(
                ConsensusGroupId::root(),
                &entry.slot_hash,
                &slot.payload_commitment,
                &outsider.public,
            ),
            Err(BlossomError::WireProtocol(message)) if message.contains("not authorized")
        ));
    }

    #[test]
    fn estimates_push_gossip_rounds_for_stable_key_metadata() {
        assert_eq!(ideal_push_gossip_rounds(1, 6), Some(0));
        assert_eq!(ideal_push_gossip_rounds(36, 6), Some(2));
        assert_eq!(ideal_push_gossip_delay_ms(36, 6, 100), Some(200));
        assert_eq!(ideal_push_gossip_rounds(36, 0), None);
    }
}
