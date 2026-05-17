use std::collections::HashMap;
use std::fmt;
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
    services: HashMap<ServiceKind, Service>,
}

impl AddressBook {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, service: Service) -> Option<Service> {
        self.services.insert(service.kind, service)
    }

    pub fn service(&self, kind: ServiceKind) -> Option<&Service> {
        self.services.get(&kind)
    }

    pub fn remove(&mut self, kind: ServiceKind) -> Option<Service> {
        self.services.remove(&kind)
    }

    pub fn contains(&self, kind: ServiceKind) -> bool {
        self.services.contains_key(&kind)
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
        let mut services = self.services.into_values().collect::<Vec<_>>();
        services.sort_by_key(|service| service.kind);
        services
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_one_service_per_kind() {
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
        assert_eq!(book.add(second.clone()), Some(first));
        assert_eq!(book.service(ServiceKind::Block), Some(&second));
    }
}
