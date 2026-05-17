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
