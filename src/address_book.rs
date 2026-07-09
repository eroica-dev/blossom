use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::Path;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::crypto::PubKey;
use crate::error::{BlossomError, Result};

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
        if let Some(parent) = path
            .as_ref()
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).map_err(|err| BlossomError::Io(err.to_string()))?;
        }
        let bytes = serde_json::to_vec_pretty(&self.services().cloned().collect::<Vec<_>>())
            .map_err(|err| BlossomError::WireProtocol(format!("encode service json: {err}")))?;
        fs::write(path.as_ref(), bytes).map_err(|err| BlossomError::Io(err.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
