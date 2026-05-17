use borsh::{BorshDeserialize, BorshSerialize};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::env;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::address_book::Service;
use crate::block::Block;
use crate::blossom::Dispatch;
use crate::error::{BlossomError, Result};
use crate::messages::Msg;
use crate::nonce::Nonce;
use crate::runtime::{AcceptedBlock, EpochTarget, MessageReceipt, NodeStatus};

pub const DEFAULT_MAX_FRAME_SIZE: usize = 32 * 1024 * 1024;
pub const MAX_FRAME_SIZE: usize = DEFAULT_MAX_FRAME_SIZE;
pub const FRAME_PREFIX_BYTES: usize = 4;
pub const MAX_FRAME_SIZE_ENV: &str = "BLOSSOM_MAX_FRAME_SIZE";

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
pub enum WireRequest {
    Health,
    State,
    AddressBook,
    RegisterService(Service),
    NextNonce,
    SubmitBlock(Block),
    Dispatch { round: u8 },
    Message(Msg),
    SendNonce(Nonce),
    BlockNonce(Nonce),
    GetBlock(Nonce),
    SendBlock(Block),
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
pub enum WireResponse {
    Health(NodeHealth),
    State(NodeStatus),
    AddressBook(Vec<Service>),
    AddressBookUpdated(AddressBookUpdate),
    NextNonce(EpochTarget),
    BlockAccepted(AcceptedBlock),
    Dispatch(Dispatch),
    MessageReceipt(MessageReceipt),
    Block(Block),
    Ok,
    Error(String),
}

impl WireResponse {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Health(_) => "health",
            Self::State(_) => "state",
            Self::AddressBook(_) => "address_book",
            Self::AddressBookUpdated(_) => "address_book_updated",
            Self::NextNonce(_) => "next_nonce",
            Self::BlockAccepted(_) => "block_accepted",
            Self::Dispatch(_) => "dispatch",
            Self::MessageReceipt(_) => "message_receipt",
            Self::Block(_) => "block",
            Self::Ok => "ok",
            Self::Error(_) => "error",
        }
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct NodeHealth {
    pub status: String,
    pub public_key: crate::crypto::PubKey,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct AddressBookUpdate {
    pub service: Service,
    pub previous: Option<Service>,
    pub nonce_announced: Option<Nonce>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedFrame {
    bytes: Bytes,
    payload_len: usize,
}

impl EncodedFrame {
    pub fn encode<T>(value: &T) -> Result<Self>
    where
        T: BorshSerialize + ?Sized,
    {
        let payload =
            borsh::to_vec(value).map_err(|err| BlossomError::WireProtocol(err.to_string()))?;
        validate_payload_len(payload.len())?;

        let mut bytes = Vec::with_capacity(FRAME_PREFIX_BYTES + payload.len());
        bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&payload);

        Ok(Self {
            bytes: Bytes::from(bytes),
            payload_len: payload.len(),
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_ref()
    }

    pub fn payload_len(&self) -> usize {
        self.payload_len
    }

    pub fn framed_len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

pub async fn read_frame<T, R>(reader: &mut R) -> Result<T>
where
    T: BorshDeserialize,
    R: AsyncRead + Unpin,
{
    let len = reader
        .read_u32()
        .await
        .map_err(|err| BlossomError::Io(err.to_string()))? as usize;
    if len == 0 || len > configured_max_frame_size() {
        return Err(BlossomError::InvalidFrameSize(len));
    }

    let mut bytes = vec![0; len];
    reader
        .read_exact(&mut bytes)
        .await
        .map_err(|err| BlossomError::Io(err.to_string()))?;
    borsh::from_slice(&bytes).map_err(|err| BlossomError::WireProtocol(err.to_string()))
}

pub async fn write_frame<T, W>(writer: &mut W, value: &T) -> Result<()>
where
    T: BorshSerialize,
    W: AsyncWrite + Unpin,
{
    let bytes = borsh::to_vec(value).map_err(|err| BlossomError::WireProtocol(err.to_string()))?;
    validate_payload_len(bytes.len())?;

    writer
        .write_u32(bytes.len() as u32)
        .await
        .map_err(|err| BlossomError::Io(err.to_string()))?;
    writer
        .write_all(&bytes)
        .await
        .map_err(|err| BlossomError::Io(err.to_string()))?;
    writer
        .flush()
        .await
        .map_err(|err| BlossomError::Io(err.to_string()))
}

pub async fn write_encoded_frame<W>(writer: &mut W, frame: &EncodedFrame) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    validate_payload_len(frame.payload_len)?;
    writer
        .write_all(frame.as_bytes())
        .await
        .map_err(|err| BlossomError::Io(err.to_string()))?;
    writer
        .flush()
        .await
        .map_err(|err| BlossomError::Io(err.to_string()))
}

pub fn configured_max_frame_size() -> usize {
    env::var(MAX_FRAME_SIZE_ENV)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_MAX_FRAME_SIZE)
}

pub fn encoded_len<T>(value: &T) -> Result<usize>
where
    T: BorshSerialize + ?Sized,
{
    borsh::object_length(value).map_err(|err| BlossomError::WireProtocol(err.to_string()))
}

pub fn framed_len<T>(value: &T) -> Result<usize>
where
    T: BorshSerialize + ?Sized,
{
    encoded_len(value)?
        .checked_add(FRAME_PREFIX_BYTES)
        .ok_or_else(|| BlossomError::WireProtocol("frame length overflow".to_string()))
}

fn validate_payload_len(len: usize) -> Result<()> {
    if len == 0 || len > configured_max_frame_size() {
        return Err(BlossomError::InvalidFrameSize(len));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncWriteExt, duplex};

    use super::*;

    #[tokio::test]
    async fn frame_round_trip() {
        let (mut client, mut server) = duplex(1024);
        let request = WireRequest::NextNonce;

        let writer = tokio::spawn(async move { write_frame(&mut client, &request).await });
        let read: WireRequest = read_frame(&mut server).await.unwrap();
        writer.await.unwrap().unwrap();

        assert!(matches!(read, WireRequest::NextNonce));
    }

    #[tokio::test]
    async fn encoded_frame_round_trip() {
        let (mut client, mut server) = duplex(1024);
        let request = WireRequest::NextNonce;
        let frame = EncodedFrame::encode(&request).unwrap();

        assert_eq!(frame.payload_len(), encoded_len(&request).unwrap());
        assert_eq!(frame.framed_len(), framed_len(&request).unwrap());
        assert!(!frame.is_empty());

        let writer = tokio::spawn(async move { write_encoded_frame(&mut client, &frame).await });
        let read: WireRequest = read_frame(&mut server).await.unwrap();
        writer.await.unwrap().unwrap();

        assert!(matches!(read, WireRequest::NextNonce));
    }

    #[tokio::test]
    async fn zero_and_oversized_frames_are_rejected() {
        let (mut client, mut server) = duplex(16);
        let writer = tokio::spawn(async move {
            client.write_u32(0).await.unwrap();
        });

        assert!(matches!(
            read_frame::<WireRequest, _>(&mut server).await,
            Err(BlossomError::InvalidFrameSize(0))
        ));
        writer.await.unwrap();

        let (mut client, mut server) = duplex(16);
        let writer = tokio::spawn(async move {
            client.write_u32((MAX_FRAME_SIZE + 1) as u32).await.unwrap();
        });
        assert!(matches!(
            read_frame::<WireRequest, _>(&mut server).await,
            Err(BlossomError::InvalidFrameSize(size)) if size == MAX_FRAME_SIZE + 1
        ));
        writer.await.unwrap();
    }

    #[test]
    fn response_kind_covers_all_variants() {
        assert_eq!(WireResponse::Ok.kind(), "ok");
        assert_eq!(WireResponse::Error("nope".to_string()).kind(), "error");
        assert_eq!(
            WireResponse::Health(NodeHealth {
                status: "ok".to_string(),
                public_key: crate::PubKey::default()
            })
            .kind(),
            "health"
        );
    }

    #[test]
    fn frame_length_helpers_count_payload_and_prefix() {
        let request = WireRequest::NextNonce;

        assert_eq!(encoded_len(&request).unwrap(), 1);
        assert_eq!(framed_len(&request).unwrap(), FRAME_PREFIX_BYTES + 1);
    }
}
