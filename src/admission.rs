use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::address_book::{Service, ServiceKind};
use crate::crypto::{PubKey, SecretSigner, Signature};
use crate::error::{BlossomError, Result};
use crate::hash::{HashType, ProtocolHasher};
use crate::node::NodeIdentity;
use crate::nonce::Nonce;

pub const NODE_ADMISSION_DOMAIN: &[u8] = b"blossom-node-admission:v1";
pub const RECONNECT_VOTE_DOMAIN: &[u8] = b"blossom-reconnect-vote:v1";

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct NodeAdmissionBody {
    pub node: NodeIdentity,
    pub service: Service,
    pub last_epoch: HashType,
    pub nonce: Nonce,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct NodeAdmission {
    pub body: NodeAdmissionBody,
    pub signature: Signature,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct ReconnectVoteBody {
    pub voter: PubKey,
    pub candidate: PubKey,
    pub admission_hash: HashType,
    pub catchup_epoch: HashType,
    pub catchup_nonce: Nonce,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct ReconnectVote {
    pub body: ReconnectVoteBody,
    pub signature: Signature,
}

impl NodeAdmissionBody {
    pub fn new(
        node: NodeIdentity,
        service: Service,
        last_epoch: HashType,
        nonce: Nonce,
    ) -> Result<Self> {
        let node = node.public_only();
        validate_consensus_service_binding(&node, &service)?;
        Ok(Self {
            node,
            service,
            last_epoch,
            nonce,
        })
    }

    pub fn for_consensus_service(
        service: Service,
        last_epoch: HashType,
        nonce: Nonce,
    ) -> Result<Self> {
        let node = NodeIdentity::new(
            service.public_key,
            None,
            service.protocol.clone(),
            service.host.clone(),
            service.port,
            true,
        );
        Self::new(node, service, last_epoch, nonce)
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        self.append_bytes_to(&mut bytes);
        bytes
    }

    pub fn append_bytes_to(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(NODE_ADMISSION_DOMAIN);
        bytes.extend_from_slice(self.node.public_key().as_ref());
        append_str(bytes, &self.node.protocol);
        append_str(bytes, &self.node.host);
        bytes.extend_from_slice(&self.node.port.to_le_bytes());
        bytes.push(u8::from(self.node.shuffle));
        bytes.push(service_kind_byte(self.service.kind));
        bytes.extend_from_slice(self.service.public_key.as_ref());
        append_str(bytes, &self.service.protocol);
        append_str(bytes, &self.service.host);
        bytes.extend_from_slice(&self.service.port.to_le_bytes());
        bytes.extend_from_slice(self.last_epoch.as_ref());
        bytes.extend_from_slice(&self.nonce.to_le_bytes());
    }

    pub fn encoded_len(&self) -> usize {
        NODE_ADMISSION_DOMAIN.len()
            + 32
            + encoded_str_len(&self.node.protocol)
            + encoded_str_len(&self.node.host)
            + 2
            + 1
            + 1
            + 32
            + encoded_str_len(&self.service.protocol)
            + encoded_str_len(&self.service.host)
            + 2
            + 32
            + 8
    }

    pub fn hash(&self) -> HashType {
        let mut hasher = ProtocolHasher::new();
        self.update_hash(&mut hasher);
        hasher.finalize()
    }

    pub fn update_hash(&self, hasher: &mut ProtocolHasher) {
        hasher.update(self.signing_bytes());
    }
}

impl NodeAdmission {
    pub fn signed(body: NodeAdmissionBody, signer: &SecretSigner) -> Result<Self> {
        if !signer.matches_public_key(&body.node.public_key()) {
            return Err(BlossomError::KeyMismatch);
        }
        let signature = signer.sign(&body.signing_bytes());
        Ok(Self { body, signature })
    }

    pub fn signed_for_consensus_service(
        service: Service,
        last_epoch: HashType,
        nonce: Nonce,
        signer: &SecretSigner,
    ) -> Result<Self> {
        let body = NodeAdmissionBody::for_consensus_service(service, last_epoch, nonce)?;
        Self::signed(body, signer)
    }

    pub fn verify(&self) -> Result<()> {
        validate_consensus_service_binding(&self.body.node, &self.body.service)?;
        self.signature
            .verify(&self.body.signing_bytes(), &self.body.node.public_key())
    }
}

impl ReconnectVoteBody {
    pub fn for_admission(
        voter: PubKey,
        admission: &NodeAdmission,
        catchup_epoch: HashType,
        catchup_nonce: Nonce,
    ) -> Self {
        Self {
            voter,
            candidate: admission.body.node.public_key(),
            admission_hash: admission.body.hash(),
            catchup_epoch,
            catchup_nonce,
        }
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(RECONNECT_VOTE_DOMAIN.len() + 32 * 4 + 8);
        bytes.extend_from_slice(RECONNECT_VOTE_DOMAIN);
        bytes.extend_from_slice(self.voter.as_ref());
        bytes.extend_from_slice(self.candidate.as_ref());
        bytes.extend_from_slice(self.admission_hash.as_ref());
        bytes.extend_from_slice(self.catchup_epoch.as_ref());
        bytes.extend_from_slice(&self.catchup_nonce.to_le_bytes());
        bytes
    }
}

impl ReconnectVote {
    pub fn signed(body: ReconnectVoteBody, signer: &SecretSigner) -> Result<Self> {
        if !signer.matches_public_key(&body.voter) {
            return Err(BlossomError::KeyMismatch);
        }
        let signature = signer.sign(&body.signing_bytes());
        Ok(Self { body, signature })
    }

    pub fn signed_for_admission(
        admission: &NodeAdmission,
        catchup_epoch: HashType,
        catchup_nonce: Nonce,
        signer: &SecretSigner,
    ) -> Result<Self> {
        let body = ReconnectVoteBody::for_admission(
            signer.public_key(),
            admission,
            catchup_epoch,
            catchup_nonce,
        );
        Self::signed(body, signer)
    }

    pub fn verify(&self) -> Result<()> {
        self.signature
            .verify(&self.body.signing_bytes(), &self.body.voter)
    }
}

fn validate_consensus_service_binding(node: &NodeIdentity, service: &Service) -> Result<()> {
    if service.kind != ServiceKind::Consensus {
        return Err(BlossomError::WireProtocol(
            "node admission requires a consensus service".to_string(),
        ));
    }
    if service.public_key != node.public_key()
        || service.protocol != node.protocol
        || service.host != node.host
        || service.port != node.port
    {
        return Err(BlossomError::KeyMismatch);
    }
    Ok(())
}

fn append_str(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

fn encoded_str_len(value: &str) -> usize {
    4 + value.len()
}

fn service_kind_byte(kind: ServiceKind) -> u8 {
    match kind {
        ServiceKind::Relay => 1,
        ServiceKind::Block => 2,
        ServiceKind::Consensus => 3,
        ServiceKind::Engine => 4,
        ServiceKind::AddressBook => 5,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;

    #[test]
    fn node_admission_signature_proves_service_key() {
        let keypair = Keypair::generate();
        let service = Service::new(
            ServiceKind::Consensus,
            keypair.public,
            "tcp",
            "127.0.0.1",
            9000,
        );
        let admission = NodeAdmission::signed_for_consensus_service(
            service.clone(),
            HashType([1; 32]),
            Nonce::new(2),
            &keypair.signer(),
        )
        .unwrap();

        assert_eq!(admission.body.service, service);
        assert!(admission.verify().is_ok());
    }

    #[test]
    fn node_admission_rejects_key_mismatch() {
        let keypair = Keypair::generate();
        let other = Keypair::generate();
        let service = Service::new(
            ServiceKind::Consensus,
            keypair.public,
            "tcp",
            "127.0.0.1",
            9000,
        );

        assert_eq!(
            NodeAdmission::signed_for_consensus_service(
                service,
                HashType([1; 32]),
                Nonce::new(2),
                &other.signer(),
            ),
            Err(BlossomError::KeyMismatch)
        );
    }

    #[test]
    fn node_admission_verify_rejects_endpoint_mismatch() {
        let keypair = Keypair::generate();
        let node = NodeIdentity::new(keypair.public, None, "tcp", "127.0.0.1", 9000, true);
        let service = Service::new(
            ServiceKind::Consensus,
            keypair.public,
            "tcp",
            "127.0.0.1",
            9001,
        );
        let body = NodeAdmissionBody {
            node,
            service,
            last_epoch: HashType([1; 32]),
            nonce: Nonce::new(2),
        };
        let admission = NodeAdmission {
            signature: keypair.signer().sign(&body.signing_bytes()),
            body,
        };

        assert_eq!(admission.verify(), Err(BlossomError::KeyMismatch));
    }

    #[test]
    fn reconnect_vote_signature_binds_admission_and_checkpoint() {
        let voter = Keypair::generate();
        let candidate = Keypair::generate();
        let admission = NodeAdmission::signed_for_consensus_service(
            Service::new(
                ServiceKind::Consensus,
                candidate.public,
                "tcp",
                "127.0.0.1",
                9000,
            ),
            HashType([7; 32]),
            Nonce::new(8),
            &candidate.signer(),
        )
        .unwrap();
        let vote = ReconnectVote::signed_for_admission(
            &admission,
            HashType([9; 32]),
            Nonce::new(7),
            &voter.signer(),
        )
        .unwrap();

        assert!(vote.verify().is_ok());

        let mut tampered = vote.clone();
        tampered.body.catchup_nonce = Nonce::new(6);
        assert_eq!(tampered.verify(), Err(BlossomError::SignatureError));
    }
}
