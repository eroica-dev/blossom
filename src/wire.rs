use borsh::{BorshDeserialize, BorshSerialize};
use bytes::{Bytes, BytesMut};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use std::collections::BTreeMap;
use std::env;
use std::sync::OnceLock;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::address_book::Service;
use crate::block::{Block, BlockApplicationState, BlockBody, Transaction};
use crate::blossom::{Dispatch, DispatchBody, Header, SignatureTree, SignaturesForHash};
use crate::crypto::{PubKey, Signature};
use crate::error::{BlossomError, Result};
use crate::hash::HashType;
use crate::messages::{MSGKey, Msg};
use crate::nonce::Nonce;
use crate::runtime::{AcceptedBlock, EpochTarget, MessageReceipt, NodeStatus};

pub const DEFAULT_MAX_FRAME_SIZE: usize = 32 * 1024 * 1024;
pub const MAX_FRAME_SIZE: usize = DEFAULT_MAX_FRAME_SIZE;
pub const FRAME_PREFIX_BYTES: usize = 4;
pub const MAX_FRAME_SIZE_ENV: &str = "BLOSSOM_MAX_FRAME_SIZE";
pub const HOT_WIRE_CODEC_ENV: &str = "BLOSSOM_HOT_WIRE_CODEC";
const HOT_WIRE_MAGIC: &[u8; 4] = b"BLSM";
const HOT_WIRE_VERSION: u8 = 1;
const HOT_REQUEST_SUBMIT_BLOCK: u8 = 1;
const HOT_REQUEST_MESSAGE_DISPATCH: u8 = 2;
const HOT_REQUEST_SEND_BLOCK: u8 = 3;
const HOT_RESPONSE_DISPATCH: u8 = 64;
const HOT_RESPONSE_BLOCK: u8 = 65;
static CONFIGURED_MAX_FRAME_SIZE: OnceLock<usize> = OnceLock::new();
static CONFIGURED_HOT_WIRE_CODEC_ENABLED: OnceLock<bool> = OnceLock::new();

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

#[derive(Debug, Clone)]
pub struct HotDispatch {
    pub header: Header,
    pub blocks_hash: HashType,
    pub signature_tree_hash: HashType,
    block_count: usize,
    payload: Bytes,
}

impl HotDispatch {
    pub fn block_count(&self) -> usize {
        self.block_count
    }

    pub fn payload_len(&self) -> usize {
        self.payload.len()
    }

    pub fn verify_signature(&self) -> Result<()> {
        let mut body = [0u8; 64];
        body[..32].copy_from_slice(self.blocks_hash.as_ref());
        body[32..].copy_from_slice(self.signature_tree_hash.as_ref());
        self.header.signature.verify(
            Header::signature_hash_for_bytes(
                &self.header.sender,
                &self.header.last_epoch,
                self.header.nonce,
                self.header.round,
                MSGKey::Dispatch,
                &body,
            )
            .as_ref(),
            &self.header.sender,
        )
    }

    pub fn to_dispatch(&self) -> Result<Dispatch> {
        let mut payload = self.payload.as_ref();
        let dispatch = take_dispatch(&mut payload)?;
        ensure_empty(payload, "hot dispatch")?;
        Ok(dispatch)
    }
}

impl Serialize for HotDispatch {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_struct("HotDispatch", 5)?;
        s.serialize_field("header", &self.header)?;
        s.serialize_field("blocks_hash", &self.blocks_hash)?;
        s.serialize_field("signature_tree_hash", &self.signature_tree_hash)?;
        s.serialize_field("block_count", &self.block_count)?;
        s.serialize_field("payload_len", &self.payload.len())?;
        s.end()
    }
}

#[derive(Debug, Clone)]
pub enum WireRequestFrame {
    Request(WireRequest),
    HotDispatch(HotDispatch),
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
        let mut bytes = vec![0; FRAME_PREFIX_BYTES];
        BorshSerialize::serialize(value, &mut bytes)
            .map_err(|err| BlossomError::WireProtocol(err.to_string()))?;

        let payload_len = bytes.len() - FRAME_PREFIX_BYTES;
        validate_payload_len(payload_len)?;
        bytes[..FRAME_PREFIX_BYTES].copy_from_slice(&(payload_len as u32).to_be_bytes());

        Ok(Self {
            bytes: Bytes::from(bytes),
            payload_len,
        })
    }

    pub fn encode_wire_request(value: &WireRequest) -> Result<Self> {
        if hot_wire_codec_enabled()
            && hot_wire_request_is_selected_for_io(value)
            && let Some(frame) = Self::encode_hot_wire_request(value)?
        {
            return Ok(frame);
        }
        Self::encode(value)
    }

    pub fn encode_wire_response(value: &WireResponse) -> Result<Self> {
        if hot_wire_codec_enabled()
            && hot_wire_response_is_selected_for_io(value)
            && let Some(frame) = Self::encode_hot_wire_response(value)?
        {
            return Ok(frame);
        }
        Self::encode(value)
    }

    pub fn encode_hot_wire_request(value: &WireRequest) -> Result<Option<Self>> {
        let Some(payload_len) = hot_wire_request_payload_len(value)? else {
            return Ok(None);
        };
        let mut bytes = frame_buffer(payload_len);
        append_hot_wire_request(value, &mut bytes)?;
        Self::from_framed_payload(bytes).map(Some)
    }

    pub fn encode_hot_wire_response(value: &WireResponse) -> Result<Option<Self>> {
        let Some(payload_len) = hot_wire_response_payload_len(value)? else {
            return Ok(None);
        };
        let mut bytes = frame_buffer(payload_len);
        append_hot_wire_response(value, &mut bytes)?;
        Self::from_framed_payload(bytes).map(Some)
    }

    fn from_framed_payload(mut bytes: Vec<u8>) -> Result<Self> {
        let payload_len = bytes.len() - FRAME_PREFIX_BYTES;
        validate_payload_len(payload_len)?;
        bytes[..FRAME_PREFIX_BYTES].copy_from_slice(&(payload_len as u32).to_be_bytes());

        Ok(Self {
            bytes: Bytes::from(bytes),
            payload_len,
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
    let bytes = read_payload(reader).await?;
    borsh::from_slice(bytes.as_ref()).map_err(|err| BlossomError::WireProtocol(err.to_string()))
}

pub async fn read_wire_request<R>(reader: &mut R) -> Result<WireRequest>
where
    R: AsyncRead + Unpin,
{
    match read_wire_request_frame(reader).await? {
        WireRequestFrame::Request(request) => Ok(request),
        WireRequestFrame::HotDispatch(dispatch) => {
            Ok(WireRequest::Message(Msg::Dispatch(dispatch.to_dispatch()?)))
        }
    }
}

pub async fn read_wire_request_frame<R>(reader: &mut R) -> Result<WireRequestFrame>
where
    R: AsyncRead + Unpin,
{
    let bytes = read_payload(reader).await?.freeze();
    decode_wire_request_frame(bytes)
}

pub async fn read_wire_request_frame_optional<R>(reader: &mut R) -> Result<Option<WireRequestFrame>>
where
    R: AsyncRead + Unpin,
{
    let Some(bytes) = read_payload_optional(reader).await? else {
        return Ok(None);
    };
    decode_wire_request_frame(bytes.freeze()).map(Some)
}

pub async fn read_wire_response<R>(reader: &mut R) -> Result<WireResponse>
where
    R: AsyncRead + Unpin,
{
    let bytes = read_payload(reader).await?;
    decode_wire_response_payload(bytes.as_ref())
}

pub async fn read_encoded_frame<R>(reader: &mut R) -> Result<EncodedFrame>
where
    R: AsyncRead + Unpin,
{
    let payload = read_payload(reader).await?;
    let payload_len = payload.len();
    let mut bytes = Vec::with_capacity(FRAME_PREFIX_BYTES + payload_len);
    bytes.resize(FRAME_PREFIX_BYTES, 0);
    bytes.extend_from_slice(payload.as_ref());
    EncodedFrame::from_framed_payload(bytes)
}

async fn read_payload<R>(reader: &mut R) -> Result<BytesMut>
where
    R: AsyncRead + Unpin,
{
    read_payload_optional(reader)
        .await?
        .ok_or_else(|| BlossomError::Io("connection closed before frame".to_string()))
}

async fn read_payload_optional<R>(reader: &mut R) -> Result<Option<BytesMut>>
where
    R: AsyncRead + Unpin,
{
    let mut prefix = [0u8; FRAME_PREFIX_BYTES];
    let mut read_prefix = 0usize;
    while read_prefix < FRAME_PREFIX_BYTES {
        let read = reader
            .read(&mut prefix[read_prefix..])
            .await
            .map_err(|err| BlossomError::Io(err.to_string()))?;
        if read == 0 {
            if read_prefix == 0 {
                return Ok(None);
            }
            return Err(BlossomError::Io(format!(
                "unexpected EOF while reading frame prefix: read {read_prefix} of {FRAME_PREFIX_BYTES} bytes"
            )));
        }
        read_prefix += read;
    }

    let len = u32::from_be_bytes(prefix) as usize;
    if len == 0 || len > configured_max_frame_size() {
        return Err(BlossomError::InvalidFrameSize(len));
    }

    let mut bytes = BytesMut::with_capacity(len);
    let mut limited = reader.take(len as u64);
    while bytes.len() < len {
        let read = limited
            .read_buf(&mut bytes)
            .await
            .map_err(|err| BlossomError::Io(err.to_string()))?;
        if read == 0 {
            return Err(BlossomError::Io(format!(
                "unexpected EOF while reading frame payload: read {} of {len} bytes",
                bytes.len()
            )));
        }
    }

    Ok(Some(bytes))
}

pub async fn write_frame<T, W>(writer: &mut W, value: &T) -> Result<()>
where
    T: BorshSerialize,
    W: AsyncWrite + Unpin,
{
    let frame = EncodedFrame::encode(value)?;
    write_encoded_frame(writer, &frame).await
}

pub async fn write_wire_request<W>(writer: &mut W, value: &WireRequest) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let frame = EncodedFrame::encode_wire_request(value)?;
    write_encoded_frame(writer, &frame).await
}

pub async fn write_wire_response<W>(writer: &mut W, value: &WireResponse) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let frame = EncodedFrame::encode_wire_response(value)?;
    write_encoded_frame(writer, &frame).await
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
    *CONFIGURED_MAX_FRAME_SIZE.get_or_init(|| {
        env::var(MAX_FRAME_SIZE_ENV)
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(DEFAULT_MAX_FRAME_SIZE)
    })
}

pub fn hot_wire_codec_enabled() -> bool {
    *CONFIGURED_HOT_WIRE_CODEC_ENABLED.get_or_init(|| {
        env::var(HOT_WIRE_CODEC_ENV)
            .ok()
            .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
    })
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

pub fn wire_request_framed_len(value: &WireRequest) -> Result<usize> {
    if !hot_wire_codec_enabled() || !hot_wire_request_is_selected_for_io(value) {
        return framed_len(value);
    }

    match hot_wire_request_framed_len(value)? {
        Some(framed_len) => Ok(framed_len),
        None => framed_len(value),
    }
}

pub fn wire_response_framed_len(value: &WireResponse) -> Result<usize> {
    if !hot_wire_codec_enabled() || !hot_wire_response_is_selected_for_io(value) {
        return framed_len(value);
    }

    match hot_wire_response_framed_len(value)? {
        Some(framed_len) => Ok(framed_len),
        None => framed_len(value),
    }
}

pub fn hot_wire_request_framed_len(value: &WireRequest) -> Result<Option<usize>> {
    hot_wire_request_payload_len(value)?
        .map(|payload_len| {
            payload_len
                .checked_add(FRAME_PREFIX_BYTES)
                .ok_or_else(|| BlossomError::WireProtocol("frame length overflow".to_string()))
        })
        .transpose()
}

pub fn hot_wire_response_framed_len(value: &WireResponse) -> Result<Option<usize>> {
    hot_wire_response_payload_len(value)?
        .map(|payload_len| {
            payload_len
                .checked_add(FRAME_PREFIX_BYTES)
                .ok_or_else(|| BlossomError::WireProtocol("frame length overflow".to_string()))
        })
        .transpose()
}

fn hot_wire_request_is_selected_for_io(value: &WireRequest) -> bool {
    matches!(value, WireRequest::Message(Msg::Dispatch(_)))
}

fn hot_wire_response_is_selected_for_io(value: &WireResponse) -> bool {
    matches!(value, WireResponse::Dispatch(_))
}

pub fn decode_wire_request_frame(bytes: Bytes) -> Result<WireRequestFrame> {
    if let Some((kind, payload)) = hot_wire_payload(bytes.as_ref())?
        && kind == HOT_REQUEST_MESSAGE_DISPATCH
    {
        let payload_start = bytes.len() - payload.len();
        let dispatch = take_hot_dispatch(bytes.slice(payload_start..))?;
        return Ok(WireRequestFrame::HotDispatch(dispatch));
    }

    decode_wire_request_payload(bytes.as_ref()).map(WireRequestFrame::Request)
}

pub fn decode_wire_request_payload(bytes: &[u8]) -> Result<WireRequest> {
    let Some((kind, mut payload)) = hot_wire_payload(bytes)? else {
        return borsh::from_slice(bytes).map_err(|err| BlossomError::WireProtocol(err.to_string()));
    };

    let request = match kind {
        HOT_REQUEST_SUBMIT_BLOCK => WireRequest::SubmitBlock(take_block(&mut payload)?),
        HOT_REQUEST_MESSAGE_DISPATCH => {
            WireRequest::Message(Msg::Dispatch(take_dispatch(&mut payload)?))
        }
        HOT_REQUEST_SEND_BLOCK => WireRequest::SendBlock(take_block(&mut payload)?),
        other => {
            return Err(BlossomError::WireProtocol(format!(
                "unknown blossom hot request kind {other}"
            )));
        }
    };
    ensure_empty(payload, "hot request")?;
    Ok(request)
}

pub fn decode_wire_response_payload(bytes: &[u8]) -> Result<WireResponse> {
    let Some((kind, mut payload)) = hot_wire_payload(bytes)? else {
        return borsh::from_slice(bytes).map_err(|err| BlossomError::WireProtocol(err.to_string()));
    };

    let response = match kind {
        HOT_RESPONSE_DISPATCH => WireResponse::Dispatch(take_dispatch(&mut payload)?),
        HOT_RESPONSE_BLOCK => WireResponse::Block(take_block(&mut payload)?),
        other => {
            return Err(BlossomError::WireProtocol(format!(
                "unknown blossom hot response kind {other}"
            )));
        }
    };
    ensure_empty(payload, "hot response")?;
    Ok(response)
}

pub fn hot_dispatch_response_to_request_frame(
    frame: &EncodedFrame,
) -> Result<Option<(EncodedFrame, usize)>> {
    let payload = &frame.as_bytes()[FRAME_PREFIX_BYTES..];
    let Some((kind, dispatch_payload)) = hot_wire_payload(payload)? else {
        return Ok(None);
    };
    if kind != HOT_RESPONSE_DISPATCH {
        return Ok(None);
    }

    let payload_start = frame.bytes.len() - dispatch_payload.len();
    let dispatch = take_hot_dispatch(frame.bytes.slice(payload_start..))?;
    let mut bytes = frame.as_bytes().to_vec();
    bytes[FRAME_PREFIX_BYTES + HOT_WIRE_MAGIC.len() + 1] = HOT_REQUEST_MESSAGE_DISPATCH;
    let request_frame = EncodedFrame::from_framed_payload(bytes)?;
    Ok(Some((request_frame, dispatch.block_count())))
}

fn append_hot_wire_request(value: &WireRequest, bytes: &mut Vec<u8>) -> Result<bool> {
    match value {
        WireRequest::SubmitBlock(block) => {
            append_hot_prefix(bytes, HOT_REQUEST_SUBMIT_BLOCK);
            append_block(bytes, block);
            Ok(true)
        }
        WireRequest::Message(Msg::Dispatch(dispatch)) => {
            append_hot_prefix(bytes, HOT_REQUEST_MESSAGE_DISPATCH);
            append_dispatch(bytes, dispatch);
            Ok(true)
        }
        WireRequest::SendBlock(block) => {
            append_hot_prefix(bytes, HOT_REQUEST_SEND_BLOCK);
            append_block(bytes, block);
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn hot_wire_request_payload_len(value: &WireRequest) -> Result<Option<usize>> {
    let body_len = match value {
        WireRequest::SubmitBlock(block) | WireRequest::SendBlock(block) => block_wire_len(block)?,
        WireRequest::Message(Msg::Dispatch(dispatch)) => dispatch_wire_len(dispatch)?,
        _ => return Ok(None),
    };
    Ok(Some(hot_payload_len(body_len)?))
}

fn append_hot_wire_response(value: &WireResponse, bytes: &mut Vec<u8>) -> Result<bool> {
    match value {
        WireResponse::Dispatch(dispatch) => {
            append_hot_prefix(bytes, HOT_RESPONSE_DISPATCH);
            append_dispatch(bytes, dispatch);
            Ok(true)
        }
        WireResponse::Block(block) => {
            append_hot_prefix(bytes, HOT_RESPONSE_BLOCK);
            append_block(bytes, block);
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn hot_wire_response_payload_len(value: &WireResponse) -> Result<Option<usize>> {
    let body_len = match value {
        WireResponse::Dispatch(dispatch) => dispatch_wire_len(dispatch)?,
        WireResponse::Block(block) => block_wire_len(block)?,
        _ => return Ok(None),
    };
    Ok(Some(hot_payload_len(body_len)?))
}

fn frame_buffer(payload_len: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(FRAME_PREFIX_BYTES + payload_len);
    bytes.resize(FRAME_PREFIX_BYTES, 0);
    bytes
}

fn hot_payload_len(body_len: usize) -> Result<usize> {
    checked_sum([
        HOT_WIRE_MAGIC.len(),
        1, // version
        1, // kind
        body_len,
    ])
}

fn append_hot_prefix(bytes: &mut Vec<u8>, kind: u8) {
    bytes.extend_from_slice(HOT_WIRE_MAGIC);
    bytes.push(HOT_WIRE_VERSION);
    bytes.push(kind);
}

fn hot_wire_payload(bytes: &[u8]) -> Result<Option<(u8, &[u8])>> {
    if !bytes.starts_with(HOT_WIRE_MAGIC) {
        return Ok(None);
    }
    if bytes.len() < HOT_WIRE_MAGIC.len() + 2 {
        return Err(BlossomError::WireProtocol(
            "truncated blossom hot wire payload".to_string(),
        ));
    }

    let version = bytes[HOT_WIRE_MAGIC.len()];
    if version != HOT_WIRE_VERSION {
        return Err(BlossomError::WireProtocol(format!(
            "unsupported blossom hot wire version {version}"
        )));
    }
    let kind = bytes[HOT_WIRE_MAGIC.len() + 1];
    Ok(Some((kind, &bytes[HOT_WIRE_MAGIC.len() + 2..])))
}

fn dispatch_wire_len(dispatch: &Dispatch) -> Result<usize> {
    let blocks_len = dispatch
        .body
        .blocks
        .values()
        .try_fold(0usize, |sum, block| {
            checked_sum([sum, 32, 4, block_wire_len(block)?])
        })?;

    checked_sum([
        header_wire_len(),
        32, // blocks_hash
        32, // signature_tree_hash
        4,  // block count
        blocks_len,
        signature_tree_wire_len(&dispatch.body.signature_tree)?,
    ])
}

fn append_dispatch(bytes: &mut Vec<u8>, dispatch: &Dispatch) {
    append_header(bytes, &dispatch.header);
    append_hash(bytes, dispatch.body.blocks_hash);
    append_hash(bytes, dispatch.body.signature_tree_hash);
    append_len(bytes, dispatch.body.blocks.len());
    for (hash, block) in &dispatch.body.blocks {
        append_hash(bytes, *hash);
        let block_start = bytes.len();
        append_len(bytes, 0);
        let payload_start = bytes.len();
        append_block(bytes, block);
        let block_len = bytes.len() - payload_start;
        bytes[block_start..block_start + 4].copy_from_slice(&(block_len as u32).to_le_bytes());
    }
    append_signature_tree(bytes, &dispatch.body.signature_tree);
}

fn take_dispatch(input: &mut &[u8]) -> Result<Dispatch> {
    let header = take_header(input)?;
    let blocks_hash = take_hash(input)?;
    let signature_tree_hash = take_hash(input)?;
    let block_count = take_len(input, "dispatch block count")?;
    let mut blocks = BTreeMap::new();
    for _ in 0..block_count {
        let hash = take_hash(input)?;
        let block_len = take_len(input, "dispatch block length")?;
        let mut block_payload = take_exact(input, block_len, "dispatch block")?;
        let block = take_block(&mut block_payload)?;
        ensure_empty(block_payload, "dispatch block")?;
        blocks.insert(hash, block);
    }
    let signature_tree = take_signature_tree(input)?;

    Ok(Dispatch {
        header,
        body: DispatchBody {
            blocks,
            blocks_hash,
            signature_tree,
            signature_tree_hash,
        },
    })
}

fn take_hot_dispatch(payload: Bytes) -> Result<HotDispatch> {
    let mut input = payload.as_ref();
    let header = take_header(&mut input)?;
    let blocks_hash = take_hash(&mut input)?;
    let signature_tree_hash = take_hash(&mut input)?;
    let block_count = take_len(&mut input, "dispatch block count")?;
    for _ in 0..block_count {
        let _hash = take_hash(&mut input)?;
        let block_len = take_len(&mut input, "dispatch block length")?;
        let _block_payload = take_exact(&mut input, block_len, "dispatch block")?;
    }
    scan_signature_tree(&mut input)?;
    ensure_empty(input, "hot dispatch")?;

    Ok(HotDispatch {
        header,
        blocks_hash,
        signature_tree_hash,
        block_count,
        payload,
    })
}

fn header_wire_len() -> usize {
    32 + 32 + 8 + 1 + 64
}

fn append_header(bytes: &mut Vec<u8>, header: &Header) {
    append_pubkey(bytes, header.sender);
    append_hash(bytes, header.last_epoch);
    append_u64(bytes, header.nonce.value());
    bytes.push(header.round);
    append_signature(bytes, header.signature);
}

fn take_header(input: &mut &[u8]) -> Result<Header> {
    Ok(Header {
        sender: take_pubkey(input)?,
        last_epoch: take_hash(input)?,
        nonce: Nonce::new(take_u64(input, "header nonce")?),
        round: take_u8(input, "header round")?,
        signature: take_signature(input)?,
    })
}

fn signature_tree_wire_len(tree: &SignatureTree) -> Result<usize> {
    let entries_len = tree
        .0
        .values()
        .try_fold(0usize, |sum, (signatures, blocks)| {
            checked_sum([
                sum,
                32,
                4,
                checked_mul(signatures.len(), 32 + 64)?,
                4,
                checked_mul(blocks.len(), 32)?,
            ])
        })?;

    checked_sum([4, entries_len])
}

fn append_signature_tree(bytes: &mut Vec<u8>, tree: &SignatureTree) {
    append_len(bytes, tree.0.len());
    for (blocks_hash, (signatures, blocks)) in &tree.0 {
        append_hash(bytes, *blocks_hash);
        append_len(bytes, signatures.len());
        for (pubkey, signature) in signatures {
            append_pubkey(bytes, *pubkey);
            append_signature(bytes, *signature);
        }
        append_len(bytes, blocks.len());
        for hash in blocks.keys() {
            append_hash(bytes, *hash);
        }
    }
}

fn take_signature_tree(input: &mut &[u8]) -> Result<SignatureTree> {
    let entry_count = take_len(input, "signature tree entry count")?;
    let mut tree = SignatureTree::default();
    for _ in 0..entry_count {
        let blocks_hash = take_hash(input)?;
        let signature_count = take_len(input, "signature tree signature count")?;
        let mut signatures = Vec::with_capacity(signature_count.min(1024));
        for _ in 0..signature_count {
            signatures.push((take_pubkey(input)?, take_signature(input)?));
        }

        let block_count = take_len(input, "signature tree block count")?;
        let mut blocks = BTreeMap::new();
        for _ in 0..block_count {
            blocks.insert(take_hash(input)?, ());
        }
        let value: SignaturesForHash = (signatures, blocks);
        tree.0.insert(blocks_hash, value);
    }
    Ok(tree)
}

fn block_wire_len(block: &Block) -> Result<usize> {
    checked_sum([32, 64, block_body_wire_len(&block.body)?])
}

fn block_body_wire_len(body: &BlockBody) -> Result<usize> {
    checked_sum([
        32,
        32,
        8,
        16,
        16,
        32,
        4,
        body.application_state.len(),
        4,
        body.txs
            .iter()
            .try_fold(0usize, |sum, tx| checked_sum([sum, 32, 4, tx.bytes.len()]))?,
    ])
}

fn append_block(bytes: &mut Vec<u8>, block: &Block) {
    append_hash(bytes, block.hash);
    append_signature(bytes, block.signature);
    append_block_body(bytes, &block.body);
}

fn take_block(input: &mut &[u8]) -> Result<Block> {
    Ok(Block {
        hash: take_hash(input)?,
        signature: take_signature(input)?,
        body: take_block_body(input)?,
    })
}

fn append_block_body(bytes: &mut Vec<u8>, body: &BlockBody) {
    append_pubkey(bytes, body.validator);
    append_hash(bytes, body.last_epoch);
    append_u64(bytes, body.nonce.value());
    append_u128(bytes, body.created);
    append_u128(bytes, body.dispatched);
    append_hash(bytes, body.merkle_root);
    append_len(bytes, body.application_state.len());
    bytes.extend_from_slice(body.application_state.as_slice());
    append_len(bytes, body.txs.len());
    for tx in &body.txs {
        append_hash(bytes, tx.hash);
        append_len(bytes, tx.bytes.len());
        bytes.extend_from_slice(&tx.bytes);
    }
}

fn take_block_body(input: &mut &[u8]) -> Result<BlockBody> {
    let validator = take_pubkey(input)?;
    let last_epoch = take_hash(input)?;
    let nonce = Nonce::new(take_u64(input, "block nonce")?);
    let created = take_u128(input, "block created")?;
    let dispatched = take_u128(input, "block dispatched")?;
    let merkle_root = take_hash(input)?;
    let application_state_len = take_len(input, "block application state length")?;
    let application_state = BlockApplicationState::new(
        take_exact(input, application_state_len, "block application state")?.to_vec(),
    )?;
    let tx_count = take_len(input, "transaction count")?;
    let max_possible_txs = input.len() / (32 + 4);
    if tx_count > max_possible_txs {
        return Err(BlossomError::WireProtocol(format!(
            "transaction count {tx_count} exceeds remaining payload capacity {max_possible_txs}"
        )));
    }

    let mut txs = Vec::with_capacity(tx_count);
    for _ in 0..tx_count {
        let hash = take_hash(input)?;
        let tx_len = take_len(input, "transaction length")?;
        let bytes = take_exact(input, tx_len, "transaction bytes")?.to_vec();
        txs.push(Transaction { hash, bytes });
    }
    ensure_empty(input, "block body")?;

    Ok(BlockBody {
        validator,
        last_epoch,
        nonce,
        created,
        dispatched,
        merkle_root,
        application_state,
        txs,
    })
}

fn scan_signature_tree(input: &mut &[u8]) -> Result<()> {
    let entry_count = take_len(input, "signature tree entry count")?;
    for _ in 0..entry_count {
        let _blocks_hash = take_hash(input)?;
        let signature_count = take_len(input, "signature tree signature count")?;
        for _ in 0..signature_count {
            let _pubkey = take_pubkey(input)?;
            let _signature = take_signature(input)?;
        }

        let block_count = take_len(input, "signature tree block count")?;
        for _ in 0..block_count {
            let _hash = take_hash(input)?;
        }
    }
    Ok(())
}

fn append_hash(bytes: &mut Vec<u8>, hash: HashType) {
    bytes.extend_from_slice(hash.as_ref());
}

fn append_pubkey(bytes: &mut Vec<u8>, public_key: PubKey) {
    bytes.extend_from_slice(public_key.as_ref());
}

fn append_signature(bytes: &mut Vec<u8>, signature: Signature) {
    bytes.extend_from_slice(signature.as_ref());
}

fn append_len(bytes: &mut Vec<u8>, len: usize) {
    append_u32(bytes, len as u32);
}

fn append_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn append_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn append_u128(bytes: &mut Vec<u8>, value: u128) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn take_hash(input: &mut &[u8]) -> Result<HashType> {
    HashType::try_from(take_exact(input, 32, "hash")?)
}

fn take_pubkey(input: &mut &[u8]) -> Result<PubKey> {
    PubKey::try_from(take_exact(input, 32, "public key")?)
}

fn take_signature(input: &mut &[u8]) -> Result<Signature> {
    Signature::try_from(take_exact(input, 64, "signature")?)
}

fn take_u8(input: &mut &[u8], field: &str) -> Result<u8> {
    Ok(take_exact(input, 1, field)?[0])
}

fn take_u32(input: &mut &[u8], field: &str) -> Result<u32> {
    let bytes = take_exact(input, 4, field)?;
    Ok(u32::from_le_bytes(bytes.try_into().map_err(|_| {
        BlossomError::WireProtocol(format!("invalid {field}"))
    })?))
}

fn take_u64(input: &mut &[u8], field: &str) -> Result<u64> {
    let bytes = take_exact(input, 8, field)?;
    Ok(u64::from_le_bytes(bytes.try_into().map_err(|_| {
        BlossomError::WireProtocol(format!("invalid {field}"))
    })?))
}

fn take_u128(input: &mut &[u8], field: &str) -> Result<u128> {
    let bytes = take_exact(input, 16, field)?;
    Ok(u128::from_le_bytes(bytes.try_into().map_err(|_| {
        BlossomError::WireProtocol(format!("invalid {field}"))
    })?))
}

fn take_len(input: &mut &[u8], field: &str) -> Result<usize> {
    let len = take_u32(input, field)? as usize;
    if len > configured_max_frame_size() {
        return Err(BlossomError::InvalidFrameSize(len));
    }
    Ok(len)
}

fn take_exact<'a>(input: &mut &'a [u8], len: usize, field: &str) -> Result<&'a [u8]> {
    if input.len() < len {
        return Err(BlossomError::WireProtocol(format!(
            "truncated {field}: need {len} bytes, have {}",
            input.len()
        )));
    }
    let (head, tail) = input.split_at(len);
    *input = tail;
    Ok(head)
}

fn ensure_empty(input: &[u8], field: &str) -> Result<()> {
    if !input.is_empty() {
        return Err(BlossomError::WireProtocol(format!(
            "{field} has {} trailing bytes",
            input.len()
        )));
    }
    Ok(())
}

fn checked_sum(parts: impl IntoIterator<Item = usize>) -> Result<usize> {
    let mut total = 0usize;
    for part in parts {
        total = total
            .checked_add(part)
            .ok_or_else(|| BlossomError::WireProtocol("wire length overflow".to_string()))?;
    }
    Ok(total)
}

fn checked_mul(left: usize, right: usize) -> Result<usize> {
    left.checked_mul(right)
        .ok_or_else(|| BlossomError::WireProtocol("wire length overflow".to_string()))
}

fn validate_payload_len(len: usize) -> Result<()> {
    if len == 0 || len > configured_max_frame_size() || len > u32::MAX as usize {
        return Err(BlossomError::InvalidFrameSize(len));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncWriteExt, duplex};

    use super::*;
    use crate::crypto::Keypair;
    use crate::hash::DoHash;

    fn signed_test_block() -> Block {
        let keypair = Keypair::generate();
        let mut block = Block::default();
        block.body.last_epoch = HashType([1; 32]);
        block.body.nonce = Nonce::new(1);
        block.body.txs.push(Transaction::new("tx-1"));
        block.sign(&keypair.secret);
        block
    }

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

    #[test]
    fn hot_submit_block_request_round_trips() {
        let block = signed_test_block();
        let request = WireRequest::SubmitBlock(block.clone());
        let frame = EncodedFrame::encode_hot_wire_request(&request)
            .unwrap()
            .unwrap();

        assert!(frame.as_bytes()[FRAME_PREFIX_BYTES..].starts_with(HOT_WIRE_MAGIC));
        let decoded = decode_wire_request_payload(&frame.as_bytes()[FRAME_PREFIX_BYTES..]).unwrap();

        match decoded {
            WireRequest::SubmitBlock(decoded_block) => {
                assert_eq!(decoded_block.hash, block.hash);
                assert_eq!(decoded_block.body.txs.len(), 1);
                assert!(decoded_block.verify_integrity().is_ok());
            }
            response => panic!("expected hot submit block, got {response:?}"),
        }
    }

    #[test]
    fn hot_dispatch_response_round_trips() {
        let block = signed_test_block();
        let mut blocks = BTreeMap::new();
        blocks.insert(block.hash, block);
        let signature_tree = SignatureTree::default();
        let dispatch = Dispatch {
            header: Header {
                sender: PubKey([7; 32]),
                ..Default::default()
            },
            body: DispatchBody {
                blocks_hash: blocks.hash(),
                blocks,
                signature_tree_hash: signature_tree.hash(),
                signature_tree,
            },
        };
        let response = WireResponse::Dispatch(dispatch.clone());
        let frame = EncodedFrame::encode_hot_wire_response(&response)
            .unwrap()
            .unwrap();

        assert!(frame.as_bytes()[FRAME_PREFIX_BYTES..].starts_with(HOT_WIRE_MAGIC));
        let decoded =
            decode_wire_response_payload(&frame.as_bytes()[FRAME_PREFIX_BYTES..]).unwrap();

        match decoded {
            WireResponse::Dispatch(decoded_dispatch) => {
                assert_eq!(decoded_dispatch.header.sender, dispatch.header.sender);
                assert_eq!(decoded_dispatch.body.blocks_hash, dispatch.body.blocks_hash);
                assert_eq!(decoded_dispatch.body.blocks.len(), 1);
            }
            response => panic!("expected hot dispatch, got {response:?}"),
        }
    }

    #[test]
    fn hot_dispatch_response_rewrites_to_raw_request_frame() {
        let block = signed_test_block();
        let mut blocks = BTreeMap::new();
        blocks.insert(block.hash, block);
        let signature_tree = SignatureTree::default();
        let dispatch = Dispatch {
            header: Header {
                sender: PubKey([7; 32]),
                ..Default::default()
            },
            body: DispatchBody {
                blocks_hash: blocks.hash(),
                blocks,
                signature_tree_hash: signature_tree.hash(),
                signature_tree,
            },
        };
        let response = WireResponse::Dispatch(dispatch.clone());
        let frame = EncodedFrame::encode_hot_wire_response(&response)
            .unwrap()
            .unwrap();

        let (request_frame, block_count) = hot_dispatch_response_to_request_frame(&frame)
            .unwrap()
            .unwrap();
        assert_eq!(block_count, 1);
        let decoded = decode_wire_request_frame(Bytes::copy_from_slice(
            &request_frame.as_bytes()[FRAME_PREFIX_BYTES..],
        ))
        .unwrap();

        match decoded {
            WireRequestFrame::HotDispatch(raw) => {
                assert_eq!(raw.header.sender, dispatch.header.sender);
                assert_eq!(raw.blocks_hash, dispatch.body.blocks_hash);
                assert_eq!(raw.to_dispatch().unwrap().body.blocks.len(), 1);
            }
            request => panic!("expected raw hot dispatch request, got {request:?}"),
        }
    }

    #[test]
    fn wire_decoders_keep_borsh_fallback() {
        let request = WireRequest::NextNonce;
        let frame = EncodedFrame::encode(&request).unwrap();

        let decoded = decode_wire_request_payload(&frame.as_bytes()[FRAME_PREFIX_BYTES..]).unwrap();

        assert!(matches!(decoded, WireRequest::NextNonce));
    }

    #[test]
    fn hot_block_rejects_impossible_transaction_count_before_allocating() {
        let mut payload = Vec::new();
        append_hot_prefix(&mut payload, HOT_REQUEST_SUBMIT_BLOCK);
        payload.extend_from_slice(&[0; 32]); // block hash
        payload.extend_from_slice(&[0; 64]); // block signature
        payload.extend_from_slice(&[0; 32]); // validator
        payload.extend_from_slice(&[0; 32]); // last epoch
        payload.extend_from_slice(&0u64.to_le_bytes());
        payload.extend_from_slice(&0u128.to_le_bytes());
        payload.extend_from_slice(&0u128.to_le_bytes());
        payload.extend_from_slice(&[0; 32]); // merkle root
        payload.extend_from_slice(&0u32.to_le_bytes()); // application state length
        payload.extend_from_slice(&1u32.to_le_bytes()); // impossible tx count

        let err = decode_wire_request_payload(&payload).unwrap_err();
        assert!(matches!(
            err,
            BlossomError::WireProtocol(message)
                if message.contains("transaction count")
                    && message.contains("remaining payload capacity")
        ));
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
