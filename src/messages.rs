use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::blossom::{
    BlossomMessage, Commit, Dispatch, EchoReDispatch, EchoRequest, EchoResponse, EpochStarted,
    Proposal, Verification,
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
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MSGKey {
    Dispatch,
    EchoResponse,
    EchoRequest,
    EchoReDispatch,
    Verification,
    Proposal,
    Commit,
    EpochStarted,
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blossom::{
        Commit, CommitBody, Dispatch, DispatchBody, EchoReDispatch, EchoRequest, EchoResponse,
        EchoResponseBody, EpochStarted, EpochStartedBody, Header, Proposal, ProposalBody,
        Verification, VerificationBody,
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
    }
}
