use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::blossom::{
    BlossomMessage, Commit, Dispatch, EchoReDispatch, EchoRequest, EchoResponse, EpochStarted,
    Proposal, ReconcileAppraisal, ReconcileCommit, ReconcileRequest, ReconcileResponse,
    RoundSkipCertificateMessage, RoundSkipVoteMessage, Verification,
};

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
pub enum Msg {
    Dispatch(Dispatch),
    EchoResponse(EchoResponse),
    EchoRequest(EchoRequest),
    EchoReDispatch(EchoReDispatch),
    Verification(Verification),
    Proposal(Proposal),
    Commit(Commit),
    EpochStarted(EpochStarted),
    RoundSkipVote(RoundSkipVoteMessage),
    RoundSkipCertificate(RoundSkipCertificateMessage),
    ReconcileAppraisal(ReconcileAppraisal),
    ReconcileRequest(ReconcileRequest),
    ReconcileResponse(ReconcileResponse),
    ReconcileCommit(ReconcileCommit),
    Ok,
    Fail,
}

impl Msg {
    pub fn from_message<M: BlossomMessage + 'static>(message: &M) -> Self {
        match message.kind() {
            MSGKey::Dispatch => message
                .as_any()
                .downcast_ref::<Dispatch>()
                .map(|msg| Msg::Dispatch(msg.clone()))
                .unwrap(),
            MSGKey::EchoRequest => message
                .as_any()
                .downcast_ref::<EchoRequest>()
                .map(|msg| Msg::EchoRequest(msg.clone()))
                .unwrap(),
            MSGKey::EchoResponse => message
                .as_any()
                .downcast_ref::<EchoResponse>()
                .map(|msg| Msg::EchoResponse(msg.clone()))
                .unwrap(),
            MSGKey::EchoReDispatch => message
                .as_any()
                .downcast_ref::<EchoReDispatch>()
                .map(|msg| Msg::EchoReDispatch(msg.clone()))
                .unwrap(),
            MSGKey::Verification => message
                .as_any()
                .downcast_ref::<Verification>()
                .map(|msg| Msg::Verification(msg.clone()))
                .unwrap(),
            MSGKey::Proposal => message
                .as_any()
                .downcast_ref::<Proposal>()
                .map(|msg| Msg::Proposal(msg.clone()))
                .unwrap(),
            MSGKey::Commit => message
                .as_any()
                .downcast_ref::<Commit>()
                .map(|msg| Msg::Commit(msg.clone()))
                .unwrap(),
            MSGKey::EpochStarted => message
                .as_any()
                .downcast_ref::<EpochStarted>()
                .map(|msg| Msg::EpochStarted(msg.clone()))
                .unwrap(),
            MSGKey::RoundSkipVote => message
                .as_any()
                .downcast_ref::<RoundSkipVoteMessage>()
                .map(|msg| Msg::RoundSkipVote(msg.clone()))
                .unwrap(),
            MSGKey::RoundSkipCertificate => message
                .as_any()
                .downcast_ref::<RoundSkipCertificateMessage>()
                .map(|msg| Msg::RoundSkipCertificate(msg.clone()))
                .unwrap(),
            MSGKey::ReconcileAppraisal => message
                .as_any()
                .downcast_ref::<ReconcileAppraisal>()
                .map(|msg| Msg::ReconcileAppraisal(msg.clone()))
                .unwrap(),
            MSGKey::ReconcileRequest => message
                .as_any()
                .downcast_ref::<ReconcileRequest>()
                .map(|msg| Msg::ReconcileRequest(msg.clone()))
                .unwrap(),
            MSGKey::ReconcileResponse => message
                .as_any()
                .downcast_ref::<ReconcileResponse>()
                .map(|msg| Msg::ReconcileResponse(msg.clone()))
                .unwrap(),
            MSGKey::ReconcileCommit => message
                .as_any()
                .downcast_ref::<ReconcileCommit>()
                .map(|msg| Msg::ReconcileCommit(msg.clone()))
                .unwrap(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MSGKey {
    Dispatch,
    EchoResponse,
    EchoRequest,
    EchoReDispatch,
    Verification,
    Proposal,
    Commit,
    EpochStarted,
    RoundSkipVote,
    RoundSkipCertificate,
    ReconcileAppraisal,
    ReconcileRequest,
    ReconcileResponse,
    ReconcileCommit,
}

impl fmt::Display for MSGKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dispatch => write!(f, "DISPATCH"),
            Self::EchoResponse => write!(f, "ECHORESPONSE"),
            Self::EchoRequest => write!(f, "ECHOREQUEST"),
            Self::EchoReDispatch => write!(f, "ECHOREDISPATCH"),
            Self::Verification => write!(f, "VERIFICATION"),
            Self::Proposal => write!(f, "PROPOSAL"),
            Self::Commit => write!(f, "COMMIT"),
            Self::EpochStarted => write!(f, "EPOCHSTARTED"),
            Self::RoundSkipVote => write!(f, "ROUNDSKIPVOTE"),
            Self::RoundSkipCertificate => write!(f, "ROUNDSKIPCERTIFICATE"),
            Self::ReconcileAppraisal => write!(f, "RECONCILEAPPRAISAL"),
            Self::ReconcileRequest => write!(f, "RECONCILEREQUEST"),
            Self::ReconcileResponse => write!(f, "RECONCILERESPONSE"),
            Self::ReconcileCommit => write!(f, "RECONCILECOMMIT"),
        }
    }
}

impl MSGKey {
    pub fn signature_tag(self) -> u8 {
        match self {
            Self::Dispatch => 0,
            Self::EchoResponse => 1,
            Self::EchoRequest => 2,
            Self::EchoReDispatch => 3,
            Self::Verification => 4,
            Self::Proposal => 5,
            Self::Commit => 6,
            Self::EpochStarted => 7,
            Self::RoundSkipVote => 8,
            Self::RoundSkipCertificate => 9,
            Self::ReconcileAppraisal => 10,
            Self::ReconcileRequest => 11,
            Self::ReconcileResponse => 12,
            Self::ReconcileCommit => 13,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blossom::{
        Commit, CommitBody, Dispatch, DispatchBody, EchoReDispatch, EchoRequest, EchoResponse,
        EchoResponseBody, EpochStarted, EpochStartedBody, Header, Proposal, ProposalBody,
        ReconcileAppraisal, ReconcileAppraisalBody, ReconcileCommit, ReconcileCommitBody,
        ReconcileRequest, ReconcileRequestBody, ReconcileResponse, ReconcileResponseBody,
        RoundSkipCertificateBody, RoundSkipCertificateMessage, RoundSkipVoteBody,
        RoundSkipVoteMessage, Verification, VerificationBody,
    };

    #[test]
    fn msg_from_message_preserves_all_protocol_variants() {
        let header = Header::default();
        assert!(matches!(
            Msg::from_message(&Dispatch {
                header: header.clone(),
                body: DispatchBody::default()
            }),
            Msg::Dispatch(_)
        ));
        assert!(matches!(
            Msg::from_message(&EchoResponse {
                header: header.clone(),
                body: EchoResponseBody::default()
            }),
            Msg::EchoResponse(_)
        ));
        assert!(matches!(
            Msg::from_message(&EchoRequest {
                header: header.clone(),
                requested_blocks: Default::default()
            }),
            Msg::EchoRequest(_)
        ));
        assert!(matches!(
            Msg::from_message(&EchoReDispatch {
                header: header.clone(),
                redispatched_blocks: Default::default()
            }),
            Msg::EchoReDispatch(_)
        ));
        assert!(matches!(
            Msg::from_message(&Verification {
                header: header.clone(),
                body: VerificationBody::default()
            }),
            Msg::Verification(_)
        ));
        assert!(matches!(
            Msg::from_message(&Proposal {
                header: header.clone(),
                body: ProposalBody::default()
            }),
            Msg::Proposal(_)
        ));
        assert!(matches!(
            Msg::from_message(&Commit {
                header: header.clone(),
                body: CommitBody::default()
            }),
            Msg::Commit(_)
        ));
        assert!(matches!(
            Msg::from_message(&EpochStarted {
                header,
                body: EpochStartedBody::default()
            }),
            Msg::EpochStarted(_)
        ));
        let header = Header::default();
        assert!(matches!(
            Msg::from_message(&RoundSkipVoteMessage {
                header: header.clone(),
                body: RoundSkipVoteBody::default()
            }),
            Msg::RoundSkipVote(_)
        ));
        assert!(matches!(
            Msg::from_message(&RoundSkipCertificateMessage {
                header: header.clone(),
                body: RoundSkipCertificateBody::default()
            }),
            Msg::RoundSkipCertificate(_)
        ));
        assert!(matches!(
            Msg::from_message(&ReconcileAppraisal {
                header: header.clone(),
                body: ReconcileAppraisalBody::default()
            }),
            Msg::ReconcileAppraisal(_)
        ));
        assert!(matches!(
            Msg::from_message(&ReconcileRequest {
                header: header.clone(),
                body: ReconcileRequestBody::default()
            }),
            Msg::ReconcileRequest(_)
        ));
        assert!(matches!(
            Msg::from_message(&ReconcileResponse {
                header: header.clone(),
                body: ReconcileResponseBody::default()
            }),
            Msg::ReconcileResponse(_)
        ));
        assert!(matches!(
            Msg::from_message(&ReconcileCommit {
                header,
                body: ReconcileCommitBody::default()
            }),
            Msg::ReconcileCommit(_)
        ));
    }

    #[test]
    fn message_keys_display_as_wire_names() {
        assert_eq!(MSGKey::Dispatch.to_string(), "DISPATCH");
        assert_eq!(MSGKey::EchoResponse.to_string(), "ECHORESPONSE");
        assert_eq!(MSGKey::EchoRequest.to_string(), "ECHOREQUEST");
        assert_eq!(MSGKey::EchoReDispatch.to_string(), "ECHOREDISPATCH");
        assert_eq!(MSGKey::Verification.to_string(), "VERIFICATION");
        assert_eq!(MSGKey::Proposal.to_string(), "PROPOSAL");
        assert_eq!(MSGKey::Commit.to_string(), "COMMIT");
        assert_eq!(MSGKey::EpochStarted.to_string(), "EPOCHSTARTED");
        assert_eq!(MSGKey::RoundSkipVote.to_string(), "ROUNDSKIPVOTE");
        assert_eq!(
            MSGKey::RoundSkipCertificate.to_string(),
            "ROUNDSKIPCERTIFICATE"
        );
        assert_eq!(MSGKey::ReconcileAppraisal.to_string(), "RECONCILEAPPRAISAL");
        assert_eq!(MSGKey::ReconcileRequest.to_string(), "RECONCILEREQUEST");
        assert_eq!(MSGKey::ReconcileResponse.to_string(), "RECONCILERESPONSE");
        assert_eq!(MSGKey::ReconcileCommit.to_string(), "RECONCILECOMMIT");
    }
}
