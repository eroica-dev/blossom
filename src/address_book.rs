use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::crypto::{PubKey, SecretSigner, Signature};
use crate::error::{BlossomError, Result};
use crate::group::ConsensusGroupId;
use crate::membership::{MemberCapability, MemberSet};

const SERVICE_RECORD_DOMAIN: &[u8] = b"blossom/signed-service-record/v1";
pub const MAX_SERVICE_RECORD_LIFETIME_MILLIS: u64 = 24 * 60 * 60 * 1_000;
pub const MAX_SERVICE_HOST_BYTES: usize = 1 << 10;
pub const MAX_SERVICE_PROTOCOL_BYTES: usize = 64;

#[derive(
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Default,
)]
#[serde(rename_all = "snake_case")]
pub enum ServiceKind {
    Relay,
    Block,
    #[default]
    Consensus,
    Engine,
    AddressBook,
}

impl fmt::Display for ServiceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Relay => write!(f, "relay"),
            Self::Block => write!(f, "block"),
            Self::Consensus => write!(f, "consensus"),
            Self::Engine => write!(f, "engine"),
            Self::AddressBook => write!(f, "address_book"),
        }
    }
}

impl FromStr for ServiceKind {
    type Err = BlossomError;

    fn from_str(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().replace('-', "_").as_str() {
            "relay" => Ok(Self::Relay),
            "block" => Ok(Self::Block),
            "consensus" => Ok(Self::Consensus),
            "engine" => Ok(Self::Engine),
            "address_book" | "addressbook" => Ok(Self::AddressBook),
            other => Err(BlossomError::UnknownService(other.to_string())),
        }
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct Service {
    pub kind: ServiceKind,
    pub public_key: PubKey,
    pub protocol: String,
    pub host: String,
    pub port: u16,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct ServiceRecordBody {
    pub group_id: ConsensusGroupId,
    pub owner: PubKey,
    pub service_kind: ServiceKind,
    pub protocol: String,
    pub host: String,
    pub port: u16,
    pub generation: u64,
    pub expires_at_unix_millis: u64,
    pub tombstone: bool,
}

impl ServiceRecordBody {
    pub fn service(&self) -> Service {
        Service::new(
            self.service_kind,
            self.owner,
            self.protocol.clone(),
            self.host.clone(),
            self.port,
        )
    }

    fn signing_bytes(&self) -> Result<Vec<u8>> {
        let encoded = borsh::to_vec(self).map_err(|error| {
            BlossomError::WireProtocol(format!("encode signed service record: {error}"))
        })?;
        let mut bytes = Vec::with_capacity(SERVICE_RECORD_DOMAIN.len() + encoded.len());
        bytes.extend_from_slice(SERVICE_RECORD_DOMAIN);
        bytes.extend_from_slice(&encoded);
        Ok(bytes)
    }

    fn validate_shape(&self) -> Result<()> {
        if self.generation == 0
            || self.expires_at_unix_millis == 0
            || self.protocol.is_empty()
            || self.protocol.len() > MAX_SERVICE_PROTOCOL_BYTES
            || self.host.is_empty()
            || self.host.len() > MAX_SERVICE_HOST_BYTES
            || self.port == 0
        {
            return Err(BlossomError::InvalidConfiguration(
                "signed service record has invalid endpoint, generation, or expiry".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct SignedServiceRecord {
    pub body: ServiceRecordBody,
    pub signature: Signature,
}

impl SignedServiceRecord {
    pub fn signed(body: ServiceRecordBody, signer: &SecretSigner) -> Result<Self> {
        body.validate_shape()?;
        if signer.public_key() != body.owner {
            return Err(BlossomError::KeyMismatch);
        }
        Ok(Self {
            signature: signer.sign(&body.signing_bytes()?),
            body,
        })
    }

    pub fn signed_tombstone(mut body: ServiceRecordBody, signer: &SecretSigner) -> Result<Self> {
        body.tombstone = true;
        Self::signed(body, signer)
    }

    pub fn verify(&self) -> Result<()> {
        self.body.validate_shape()?;
        self.signature
            .verify(&self.body.signing_bytes()?, &self.body.owner)
    }
}

impl Service {
    pub fn new(
        kind: ServiceKind,
        public_key: PubKey,
        protocol: impl Into<String>,
        host: impl Into<String>,
        port: u16,
    ) -> Self {
        Self {
            kind,
            public_key,
            protocol: protocol.into(),
            host: host.into(),
            port,
        }
    }

    pub fn base_url(&self) -> String {
        format!("{}://{}:{}", self.protocol, self.host, self.port)
    }

    pub fn socket_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Default, PartialEq, Eq,
)]
pub struct AddressBook {
    services: BTreeMap<(ServiceKind, PubKey), Service>,
    #[serde(default)]
    signed_records: BTreeMap<(ConsensusGroupId, ServiceKind, PubKey), SignedServiceRecord>,
}

impl AddressBook {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_services(services: impl IntoIterator<Item = Service>) -> Self {
        let mut book = Self::new();
        book.extend_services(services);
        book
    }

    /// Adds or replaces a service endpoint keyed by `(kind, public_key)`.
    ///
    /// The address book is local reachability metadata. It does not prove key
    /// ownership or change consensus verifier membership.
    pub fn add(&mut self, service: Service) -> Option<Service> {
        self.services
            .insert((service.kind, service.public_key), service)
    }

    pub fn apply_signed_record(
        &mut self,
        record: SignedServiceRecord,
        expected_group: ConsensusGroupId,
        members: &MemberSet,
        now_unix_millis: u64,
    ) -> Result<Option<Service>> {
        record.verify()?;
        if record.body.group_id != expected_group {
            return Err(BlossomError::InvalidConfiguration(
                "signed service record group mismatch".to_string(),
            ));
        }
        let member = members
            .get(&record.body.owner)
            .ok_or(BlossomError::UnknownSender)?;
        let authorized = match record.body.service_kind {
            ServiceKind::Relay => member.is_active_with(MemberCapability::Relay),
            ServiceKind::Consensus => member.is_active_with(MemberCapability::Validator),
            _ => member.is_active(),
        };
        if !authorized {
            return Err(BlossomError::UnknownSender);
        }
        if record.body.expires_at_unix_millis <= now_unix_millis
            || record.body.expires_at_unix_millis
                > now_unix_millis.saturating_add(MAX_SERVICE_RECORD_LIFETIME_MILLIS)
        {
            return Err(BlossomError::InvalidConfiguration(
                "signed service record is expired or exceeds the maximum lifetime".to_string(),
            ));
        }
        let record_key = (
            record.body.group_id,
            record.body.service_kind,
            record.body.owner,
        );
        if self
            .signed_records
            .get(&record_key)
            .is_some_and(|current| current.body.generation >= record.body.generation)
        {
            return Err(BlossomError::InvalidConfiguration(
                "signed service record generation did not advance".to_string(),
            ));
        }
        let service_key = (record.body.service_kind, record.body.owner);
        let previous = if record.body.tombstone {
            self.services.remove(&service_key)
        } else {
            self.services.insert(service_key, record.body.service())
        };
        self.signed_records.insert(record_key, record);
        Ok(previous)
    }

    pub fn signed_records(&self) -> impl Iterator<Item = &SignedServiceRecord> {
        self.signed_records.values()
    }

    pub fn active_signed_services(
        &self,
        group_id: ConsensusGroupId,
        now_unix_millis: u64,
    ) -> impl Iterator<Item = Service> + '_ {
        self.signed_records
            .values()
            .filter(move |record| {
                record.body.group_id == group_id
                    && !record.body.tombstone
                    && record.body.expires_at_unix_millis > now_unix_millis
            })
            .map(|record| record.body.service())
    }

    pub fn prune_expired_signed_records(&mut self, now_unix_millis: u64) {
        let expired = self
            .signed_records
            .iter()
            .filter_map(|(key, record)| {
                (record.body.expires_at_unix_millis <= now_unix_millis).then_some(*key)
            })
            .collect::<Vec<_>>();
        for key in expired {
            if let Some(record) = self.signed_records.remove(&key) {
                self.services
                    .remove(&(record.body.service_kind, record.body.owner));
            }
        }
    }

    pub fn extend_services(&mut self, services: impl IntoIterator<Item = Service>) {
        for service in services {
            self.add(service);
        }
    }

    pub fn service(&self, kind: ServiceKind) -> Option<&Service> {
        self.services
            .iter()
            .find_map(|((service_kind, _), service)| (*service_kind == kind).then_some(service))
    }

    pub fn service_for(&self, kind: ServiceKind, public_key: &PubKey) -> Option<&Service> {
        self.services.get(&(kind, *public_key))
    }

    pub fn services_for_kind(&self, kind: ServiceKind) -> impl Iterator<Item = &Service> {
        self.services
            .iter()
            .filter_map(move |((service_kind, _), service)| {
                (*service_kind == kind).then_some(service)
            })
    }

    pub fn remove(&mut self, kind: ServiceKind) -> Option<Service> {
        let key = self
            .services
            .keys()
            .find(|(service_kind, _)| *service_kind == kind)
            .copied()?;
        self.services.remove(&key)
    }

    pub fn remove_service(&mut self, kind: ServiceKind, public_key: &PubKey) -> Option<Service> {
        self.services.remove(&(kind, *public_key))
    }

    pub fn contains(&self, kind: ServiceKind) -> bool {
        self.services
            .keys()
            .any(|(service_kind, _)| *service_kind == kind)
    }

    pub fn len(&self) -> usize {
        self.services.len()
    }

    pub fn is_empty(&self) -> bool {
        self.services.is_empty()
    }

    pub fn services(&self) -> impl Iterator<Item = &Service> {
        self.services.values()
    }

    pub fn into_services(self) -> Vec<Service> {
        self.services.into_values().collect()
    }

    pub fn read_services_json(path: impl AsRef<Path>) -> Result<Vec<Service>> {
        let bytes = fs::read(path.as_ref()).map_err(|err| BlossomError::Io(err.to_string()))?;
        serde_json::from_slice(&bytes)
            .map_err(|err| BlossomError::WireProtocol(format!("invalid service json: {err}")))
    }

    pub fn write_services_json(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).map_err(|err| BlossomError::Io(err.to_string()))?;
        }
        let bytes = serde_json::to_vec_pretty(&self.services().cloned().collect::<Vec<_>>())
            .map_err(|err| BlossomError::WireProtocol(format!("encode service json: {err}")))?;
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("services.json");
        let temporary = path.with_file_name(format!("{file_name}.tmp"));
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temporary)
            .map_err(|err| BlossomError::Io(err.to_string()))?;
        file.write_all(&bytes)
            .map_err(|err| BlossomError::Io(err.to_string()))?;
        file.sync_all()
            .map_err(|err| BlossomError::Io(err.to_string()))?;
        drop(file);
        fs::rename(&temporary, path).map_err(|err| BlossomError::Io(err.to_string()))?;
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|err| BlossomError::Io(err.to_string()))?;
        }
        Ok(())
    }
}

pub fn unix_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;
    use crate::membership::MemberSet;
    use crate::node::NodeIdentity;
    use indextreemap::IndexTreeMap;

    #[test]
    fn stores_multiple_services_per_kind() {
        let mut book = AddressBook::new();
        let first = Service::new(
            ServiceKind::Block,
            PubKey([1; 32]),
            "tcp",
            "127.0.0.1",
            9000,
        );
        let second = Service::new(
            ServiceKind::Block,
            PubKey([2; 32]),
            "tcp",
            "127.0.0.1",
            9001,
        );

        assert!(book.add(first.clone()).is_none());
        assert!(book.add(second.clone()).is_none());
        assert_eq!(book.add(second.clone()), Some(second.clone()));
        assert_eq!(
            book.service_for(ServiceKind::Block, &first.public_key),
            Some(&first)
        );
        assert_eq!(
            book.services_for_kind(ServiceKind::Block)
                .cloned()
                .collect::<Vec<_>>(),
            vec![first.clone(), second.clone()]
        );
        assert_eq!(book.service(ServiceKind::Block), Some(&first));
    }

    #[test]
    fn parses_service_kinds_and_rejects_unknown_values() {
        assert_eq!("block".parse::<ServiceKind>(), Ok(ServiceKind::Block));
        assert_eq!(
            "address-book".parse::<ServiceKind>(),
            Ok(ServiceKind::AddressBook)
        );
        assert_eq!(
            "mystery".parse::<ServiceKind>(),
            Err(BlossomError::UnknownService("mystery".to_string()))
        );
    }

    #[test]
    fn service_formats_base_url_and_socket_addr() {
        let service = Service::new(
            ServiceKind::Engine,
            PubKey([3; 32]),
            "tcp",
            "127.0.0.1",
            7000,
        );

        assert_eq!(service.base_url(), "tcp://127.0.0.1:7000");
        assert_eq!(service.socket_addr(), "127.0.0.1:7000");
    }

    #[test]
    fn removes_services_and_returns_sorted_services() {
        let mut book = AddressBook::new();
        let consensus = Service::new(
            ServiceKind::Consensus,
            PubKey([1; 32]),
            "tcp",
            "127.0.0.1",
            8000,
        );
        let block = Service::new(
            ServiceKind::Block,
            PubKey([2; 32]),
            "tcp",
            "127.0.0.1",
            9000,
        );
        book.add(consensus.clone());
        book.add(block.clone());

        assert!(book.contains(ServiceKind::Block));
        assert_eq!(book.len(), 2);
        assert_eq!(book.remove(ServiceKind::Block), Some(block));
        assert!(!book.contains(ServiceKind::Block));

        let services = book.into_services();
        assert_eq!(services, vec![consensus]);
    }

    #[test]
    fn writes_and_reads_bootstrap_services_json() {
        let mut book = AddressBook::new();
        let consensus = Service::new(
            ServiceKind::Consensus,
            PubKey([4; 32]),
            "tcp",
            "127.0.0.1",
            8100,
        );
        let block = Service::new(
            ServiceKind::Block,
            PubKey([5; 32]),
            "tcp",
            "127.0.0.1",
            9100,
        );
        book.extend_services([consensus.clone(), block.clone()]);

        let path =
            std::env::temp_dir().join(format!("blossom-address-book-{}.json", std::process::id()));
        book.write_services_json(&path).unwrap();
        let services = AddressBook::read_services_json(&path).unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(services, vec![block, consensus]);
        assert_eq!(AddressBook::from_services(services).len(), 2);
    }

    #[test]
    fn signed_relay_records_are_monotonic_expiring_and_tombstoned() {
        let owner = Keypair::generate();
        let outsider = Keypair::generate();
        let identity = NodeIdentity::new(owner.public, None, "tcp", "relay", 7443, false);
        let mut verifiers = IndexTreeMap::new();
        verifiers.insert(owner.public, identity);
        let members = MemberSet::from_verifiers(&verifiers);
        let group_id = ConsensusGroupId::named("relay-record-test");
        let now = unix_time_millis();
        let body = ServiceRecordBody {
            group_id,
            owner: owner.public,
            service_kind: ServiceKind::Relay,
            protocol: "quic".to_string(),
            host: "relay.internal".to_string(),
            port: 7443,
            generation: 1,
            expires_at_unix_millis: now + 10_000,
            tombstone: false,
        };
        let record = SignedServiceRecord::signed(body.clone(), &owner.signer()).unwrap();
        let mut book = AddressBook::new();
        book.apply_signed_record(record.clone(), group_id, &members, now)
            .unwrap();
        assert_eq!(
            book.service_for(ServiceKind::Relay, &owner.public)
                .unwrap()
                .host,
            "relay.internal"
        );
        assert!(
            book.apply_signed_record(record, group_id, &members, now)
                .is_err()
        );

        let mut outsider_body = body.clone();
        outsider_body.owner = outsider.public;
        let outsider_record =
            SignedServiceRecord::signed(outsider_body, &outsider.signer()).unwrap();
        assert!(
            book.apply_signed_record(outsider_record, group_id, &members, now)
                .is_err()
        );

        let mut tombstone_body = body;
        tombstone_body.generation = 2;
        let tombstone =
            SignedServiceRecord::signed_tombstone(tombstone_body, &owner.signer()).unwrap();
        book.apply_signed_record(tombstone, group_id, &members, now)
            .unwrap();
        assert!(
            book.service_for(ServiceKind::Relay, &owner.public)
                .is_none()
        );
    }
}
