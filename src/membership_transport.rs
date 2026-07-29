//! Authenticated membership-lease vote/install RPCs.
//!
//! These messages are transported as [`crate::ApplicationRequest`] values on
//! the existing group-routed Blossom TCP listener. Requester signatures bind
//! the target group, exact epoch, challenge, and absolute lease expiry. The
//! handler validates current committed membership and applies a per-requester
//! rate limit before invoking the runtime.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::{
    ApplicationRequest, ApplicationResponse, BlossomError, ConsensusGroupId, HashType,
    MembershipLeaseCertificate, MembershipLeaseRequest, MembershipLeaseVote, MultiGroupRuntime,
    PubKey, Result, SecretSigner, Signature,
};

const AUTHORIZATION_DOMAIN: &[u8] = b"blossom/membership-lease-rpc/v1";
const RATE_WINDOW: Duration = Duration::from_secs(1);
const MAX_REQUESTS_PER_WINDOW: u16 = 16;

/// Application message kind used on the existing Blossom TCP listener.
pub const MEMBERSHIP_LEASE_RPC_KIND: &str = "blossom/membership-lease/v1";
/// Strict request/response payload bound.
pub const MEMBERSHIP_LEASE_RPC_MAX_PAYLOAD_BYTES: usize = 128 * 1024;

/// Authenticated request for one validator vote.
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct MembershipLeaseVoteRequest {
    /// Group routed by the outer Blossom envelope.
    pub group_id: ConsensusGroupId,
    /// Exact epoch for which a lease is requested.
    pub epoch_hash: HashType,
    /// Exact epoch nonce.
    pub epoch_nonce: u64,
    /// Active requester identity.
    pub requester: PubKey,
    /// Fresh challenge, issuance time, and bounded lifetime.
    pub request: MembershipLeaseRequest,
    /// Requester signature over the complete request and absolute expiry.
    pub signature: Signature,
}

impl MembershipLeaseVoteRequest {
    /// Signs a request for the exact current epoch.
    pub fn signed(
        group_id: ConsensusGroupId,
        epoch_hash: HashType,
        epoch_nonce: u64,
        request: MembershipLeaseRequest,
        signer: &SecretSigner,
    ) -> Result<Self> {
        let mut value = Self {
            group_id,
            epoch_hash,
            epoch_nonce,
            requester: signer.public_key(),
            request,
            signature: Signature::default(),
        };
        value.signature = signer.sign(&value.signing_bytes()?);
        Ok(value)
    }

    fn verify(&self) -> Result<()> {
        self.signature
            .verify(&self.signing_bytes()?, &self.requester)
    }

    fn signing_bytes(&self) -> Result<Vec<u8>> {
        let expires_at = self
            .request
            .issued_at_unix_millis
            .checked_add(self.request.valid_for_millis)
            .ok_or(BlossomError::FailedConsensus)?;
        authorization_bytes(&(
            0_u8,
            self.group_id,
            self.epoch_hash,
            self.epoch_nonce,
            self.requester,
            self.request.challenge,
            expires_at,
            self.request,
        ))
    }
}

/// Authenticated installation of a quorum membership certificate.
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct MembershipLeaseInstallRequest {
    /// Active requester identity.
    pub requester: PubKey,
    /// Quorum certificate installed on the routed group.
    pub certificate: MembershipLeaseCertificate,
    /// Requester signature over the certificate's group, epoch, challenge,
    /// absolute expiry, and complete certificate bytes.
    pub signature: Signature,
}

impl MembershipLeaseInstallRequest {
    /// Signs a certificate installation request.
    pub fn signed(certificate: MembershipLeaseCertificate, signer: &SecretSigner) -> Result<Self> {
        let mut value = Self {
            requester: signer.public_key(),
            certificate,
            signature: Signature::default(),
        };
        value.signature = signer.sign(&value.signing_bytes()?);
        Ok(value)
    }

    fn verify(&self) -> Result<()> {
        self.signature
            .verify(&self.signing_bytes()?, &self.requester)
    }

    fn signing_bytes(&self) -> Result<Vec<u8>> {
        let statement = &self.certificate.statement;
        authorization_bytes(&(
            1_u8,
            statement.group_id,
            statement.epoch_hash,
            statement.epoch_nonce.0,
            self.requester,
            statement.challenge,
            statement.expires_at_unix_millis()?,
            &self.certificate,
        ))
    }
}

/// Typed lease request carried in an application payload.
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum MembershipLeaseRpc {
    /// Request a validator signature.
    Vote(MembershipLeaseVoteRequest),
    /// Install the resulting supermajority certificate.
    Install(MembershipLeaseInstallRequest),
}

impl MembershipLeaseRpc {
    /// Creates the bounded application envelope.
    pub fn into_application_request(self) -> Result<ApplicationRequest> {
        let payload = borsh::to_vec(&self).map_err(|error| {
            BlossomError::WireProtocol(format!("encode membership lease RPC: {error}"))
        })?;
        if payload.len() > MEMBERSHIP_LEASE_RPC_MAX_PAYLOAD_BYTES {
            return Err(BlossomError::InvalidConfiguration(
                "membership lease RPC exceeds its payload bound".to_string(),
            ));
        }
        Ok(ApplicationRequest::new(MEMBERSHIP_LEASE_RPC_KIND, payload))
    }
}

/// Typed lease response.
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum MembershipLeaseRpcResponse {
    /// Validator vote over the requested exact statement.
    Vote(MembershipLeaseVote),
    /// Certificate was installed for this exact epoch and expiry.
    Installed {
        /// Installed group.
        group_id: ConsensusGroupId,
        /// Installed epoch.
        epoch_hash: HashType,
        /// Installed epoch nonce.
        epoch_nonce: u64,
        /// Signed wall-clock expiry.
        expires_at_unix_millis: u64,
    },
}

impl MembershipLeaseRpcResponse {
    /// Decodes and validates the application response envelope.
    pub fn from_application_response(response: ApplicationResponse) -> Result<Self> {
        if response.kind != MEMBERSHIP_LEASE_RPC_KIND
            || response.payload.len() > MEMBERSHIP_LEASE_RPC_MAX_PAYLOAD_BYTES
        {
            return Err(BlossomError::WireProtocol(
                "invalid membership lease RPC response".to_string(),
            ));
        }
        borsh::from_slice(&response.payload).map_err(|error| {
            BlossomError::WireProtocol(format!("decode membership lease RPC response: {error}"))
        })
    }
}

#[derive(Debug)]
struct RateWindow {
    started: Instant,
    requests: u16,
}

/// Group-aware, rate-limited server for membership lease RPCs.
pub struct MembershipLeaseRpcService {
    runtime: MultiGroupRuntime,
    rate_windows: Mutex<BTreeMap<PubKey, RateWindow>>,
}

impl MembershipLeaseRpcService {
    /// Creates a service for every group in `runtime`.
    pub fn new(runtime: MultiGroupRuntime) -> Self {
        Self {
            runtime,
            rate_windows: Mutex::new(BTreeMap::new()),
        }
    }

    /// Handles one application request after the outer group route is known.
    pub fn handle(
        &self,
        routed_group: ConsensusGroupId,
        request: ApplicationRequest,
    ) -> Result<ApplicationResponse> {
        if request.kind != MEMBERSHIP_LEASE_RPC_KIND
            || request.payload.len() > MEMBERSHIP_LEASE_RPC_MAX_PAYLOAD_BYTES
        {
            return Err(BlossomError::WireProtocol(
                "invalid membership lease RPC request".to_string(),
            ));
        }
        let request: MembershipLeaseRpc = borsh::from_slice(&request.payload).map_err(|error| {
            BlossomError::WireProtocol(format!("decode membership lease RPC request: {error}"))
        })?;
        let runtime = self.runtime.group(&routed_group).ok_or_else(|| {
            BlossomError::WireProtocol(format!("unknown consensus group {routed_group}"))
        })?;
        let response = match request {
            MembershipLeaseRpc::Vote(request) => {
                request.verify()?;
                if request.group_id != routed_group {
                    return Err(BlossomError::InvalidEpochNonce);
                }
                validate_requester(
                    &runtime,
                    request.requester,
                    request.epoch_hash,
                    request.epoch_nonce,
                )?;
                self.claim_rate_limit(request.requester)?;
                MembershipLeaseRpcResponse::Vote(runtime.vote_membership_lease(request.request)?)
            }
            MembershipLeaseRpc::Install(request) => {
                request.verify()?;
                let statement = &request.certificate.statement;
                if statement.group_id != routed_group {
                    return Err(BlossomError::InvalidEpochNonce);
                }
                validate_requester(
                    &runtime,
                    request.requester,
                    statement.epoch_hash,
                    statement.epoch_nonce.0,
                )?;
                self.claim_rate_limit(request.requester)?;
                let view = runtime.install_membership_lease(request.certificate)?;
                MembershipLeaseRpcResponse::Installed {
                    group_id: view.group_id,
                    epoch_hash: view.epoch_hash,
                    epoch_nonce: view.epoch_nonce,
                    expires_at_unix_millis: view.lease_expires_at_unix_millis,
                }
            }
        };
        let payload = borsh::to_vec(&response).map_err(|error| {
            BlossomError::WireProtocol(format!("encode membership lease RPC response: {error}"))
        })?;
        if payload.len() > MEMBERSHIP_LEASE_RPC_MAX_PAYLOAD_BYTES {
            return Err(BlossomError::InvalidConfiguration(
                "membership lease RPC response exceeds its payload bound".to_string(),
            ));
        }
        Ok(ApplicationResponse::new(MEMBERSHIP_LEASE_RPC_KIND, payload))
    }

    fn claim_rate_limit(&self, requester: PubKey) -> Result<()> {
        let now = Instant::now();
        let mut windows = self.rate_windows.lock().map_err(|_| {
            BlossomError::ExternalService(
                "membership lease RPC rate-limit lock is unavailable".to_string(),
            )
        })?;
        let window = windows.entry(requester).or_insert(RateWindow {
            started: now,
            requests: 0,
        });
        if now.duration_since(window.started) >= RATE_WINDOW {
            window.started = now;
            window.requests = 0;
        }
        if window.requests >= MAX_REQUESTS_PER_WINDOW {
            return Err(BlossomError::ExternalService(
                "membership lease RPC requester is rate limited".to_string(),
            ));
        }
        window.requests = window.requests.saturating_add(1);
        Ok(())
    }
}

fn validate_requester(
    runtime: &crate::NodeRuntime,
    requester: PubKey,
    epoch_hash: HashType,
    epoch_nonce: u64,
) -> Result<()> {
    let receiver = runtime.watch_verified_membership();
    let view = receiver.borrow().clone();
    if view.group_id != runtime.group_id()
        || view.epoch_hash != epoch_hash
        || view.epoch_nonce != epoch_nonce
    {
        return Err(BlossomError::InvalidEpochNonce);
    }
    let member = view
        .members
        .get(&requester)
        .ok_or(BlossomError::UnknownSender)?;
    if !member.is_active() {
        return Err(BlossomError::UnknownSender);
    }
    Ok(())
}

fn authorization_bytes<T: BorshSerialize>(body: &T) -> Result<Vec<u8>> {
    let encoded = borsh::to_vec(body).map_err(|error| {
        BlossomError::WireProtocol(format!("encode membership lease authorization: {error}"))
    })?;
    let mut bytes = Vec::with_capacity(AUTHORIZATION_DOMAIN.len() + encoded.len());
    bytes.extend_from_slice(AUTHORIZATION_DOMAIN);
    bytes.extend_from_slice(&encoded);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Keypair, MembershipLeaseCertificate, NodeIdentity, NodeRuntime, RuntimeConfig, WireRequest,
        WireResponse, genesis_epoch,
    };

    fn runtime() -> (MultiGroupRuntime, Vec<Keypair>) {
        let keypairs = (0..4).map(|_| Keypair::generate()).collect::<Vec<_>>();
        let identities = keypairs
            .iter()
            .enumerate()
            .map(|(index, keypair)| {
                NodeIdentity::new(
                    keypair.public,
                    Some(keypair.secret.clone()),
                    "tcp",
                    "127.0.0.1",
                    7_000 + index as u16,
                    true,
                )
            })
            .collect::<Vec<_>>();
        let mut config = RuntimeConfig::new(identities[0].clone());
        config.genesis = Some(genesis_epoch(identities));
        (MultiGroupRuntime::new(NodeRuntime::new(config)), keypairs)
    }

    #[test]
    fn signed_vote_and_install_round_trip() {
        let (runtime, keypairs) = runtime();
        let group_id = runtime.root_group();
        let node = runtime.root_runtime();
        let receiver = node.watch_verified_membership();
        let view = receiver.borrow().clone();
        let request = MembershipLeaseRequest::fresh(5_000).expect("fresh lease request");
        let signed = MembershipLeaseVoteRequest::signed(
            group_id,
            view.epoch_hash,
            view.epoch_nonce,
            request,
            &keypairs[0].signer(),
        )
        .expect("signed lease request");
        let service = MembershipLeaseRpcService::new(runtime.clone());
        let response = service
            .handle(
                group_id,
                MembershipLeaseRpc::Vote(signed)
                    .into_application_request()
                    .expect("application request"),
            )
            .expect("lease vote");
        let vote = match MembershipLeaseRpcResponse::from_application_response(response)
            .expect("typed response")
        {
            MembershipLeaseRpcResponse::Vote(vote) => vote,
            response => panic!("expected vote, got {response:?}"),
        };
        assert_eq!(vote.statement.group_id, group_id);
        assert_eq!(vote.statement.challenge, request.challenge);

        let statement = vote.statement;
        let votes = keypairs
            .iter()
            .map(|keypair| {
                MembershipLeaseVote::signed(statement.clone(), &keypair.signer())
                    .expect("validator vote")
            })
            .collect::<Vec<_>>();
        let certificate =
            MembershipLeaseCertificate::from_votes(statement, votes).expect("certificate");
        let install = MembershipLeaseInstallRequest::signed(certificate, &keypairs[0].signer())
            .expect("signed install");
        let response = service
            .handle(
                group_id,
                MembershipLeaseRpc::Install(install)
                    .into_application_request()
                    .expect("application request"),
            )
            .expect("lease install");
        assert!(matches!(
            MembershipLeaseRpcResponse::from_application_response(response),
            Ok(MembershipLeaseRpcResponse::Installed {
                group_id: installed_group,
                ..
            }) if installed_group == group_id
        ));
        assert!(
            node.watch_verified_membership()
                .borrow()
                .require_fresh()
                .is_ok()
        );
    }

    #[tokio::test]
    async fn multi_group_tcp_handler_receives_the_routed_group() {
        let (runtime, _) = runtime();
        let expected = runtime.root_group();
        let node = crate::TcpMultiGroupNode::with_application_handler(
            runtime,
            move |group_id, request| {
                Box::pin(async move {
                    assert_eq!(group_id, expected);
                    Ok(ApplicationResponse::new(request.kind, request.payload))
                })
            },
        );
        let response = node
            .handle_request(WireRequest::Group {
                group_id: expected,
                request: Box::new(WireRequest::Application(ApplicationRequest::new(
                    "test/routed",
                    b"ok",
                ))),
            })
            .await
            .expect("group request");
        assert!(matches!(
            response,
            WireResponse::Application(response)
                if response.kind == "test/routed" && response.payload == b"ok"
        ));
    }

    #[test]
    fn requester_signature_and_rate_limit_fail_closed() {
        let (runtime, keypairs) = runtime();
        let group_id = runtime.root_group();
        let node = runtime.root_runtime();
        let receiver = node.watch_verified_membership();
        let view = receiver.borrow().clone();
        let service = MembershipLeaseRpcService::new(runtime);
        let request = MembershipLeaseRequest::fresh(5_000).expect("lease request");
        let mut signed = MembershipLeaseVoteRequest::signed(
            group_id,
            view.epoch_hash,
            view.epoch_nonce,
            request,
            &keypairs[0].signer(),
        )
        .expect("signed request");
        signed.epoch_nonce = signed.epoch_nonce.saturating_add(1);
        assert!(
            service
                .handle(
                    group_id,
                    MembershipLeaseRpc::Vote(signed)
                        .into_application_request()
                        .expect("application request"),
                )
                .is_err()
        );

        for index in 0..=MAX_REQUESTS_PER_WINDOW {
            let request = MembershipLeaseRequest::fresh(5_000).expect("lease request");
            let signed = MembershipLeaseVoteRequest::signed(
                group_id,
                view.epoch_hash,
                view.epoch_nonce,
                request,
                &keypairs[0].signer(),
            )
            .expect("signed request");
            let result = service.handle(
                group_id,
                MembershipLeaseRpc::Vote(signed)
                    .into_application_request()
                    .expect("application request"),
            );
            if index < MAX_REQUESTS_PER_WINDOW {
                assert!(result.is_ok());
            } else {
                assert!(result.is_err());
            }
        }
    }
}
