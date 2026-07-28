//! Wire envelope, frame codec, payload-bound, and compatibility tests.

use tokio::io::{AsyncWriteExt, duplex};

use super::*;
use crate::crypto::{Keypair, SecKey};
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

fn valid_public_key(seed: u8) -> PubKey {
    Keypair::from_secret(SecKey([seed; 32])).public
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

#[tokio::test]
async fn read_encoded_frame_preserves_original_frame_bytes() {
    let (mut client, mut server) = duplex(1024);
    let request = WireRequest::Ping(NodePing::with_payload(7, b"payload"));
    let frame = EncodedFrame::encode_wire_request(&request).unwrap();
    let expected = frame.as_bytes().to_vec();

    let writer = tokio::spawn(async move { write_encoded_frame(&mut client, &frame).await });
    let read = read_encoded_frame(&mut server).await.unwrap();
    writer.await.unwrap().unwrap();

    assert_eq!(read.as_bytes(), expected.as_slice());
    assert_eq!(read.payload_len(), expected.len() - FRAME_PREFIX_BYTES);
}

#[tokio::test]
async fn chunked_encoded_frame_write_preserves_original_frame_bytes() {
    let (mut client, mut server) = duplex(1024);
    let request = WireRequest::Ping(NodePing::with_payload(7, b"payload"));
    let frame = EncodedFrame::encode_wire_request(&request).unwrap();
    let expected = frame.as_bytes().to_vec();

    let writer = tokio::spawn(async move {
        validate_payload_len(frame.payload_len)?;
        write_frame_bytes(&mut client, frame.as_bytes(), Some(3)).await?;
        client
            .flush()
            .await
            .map_err(|err| BlossomError::Io(err.to_string()))
    });
    let read = read_encoded_frame(&mut server).await.unwrap();
    writer.await.unwrap().unwrap();

    assert_eq!(read.as_bytes(), expected.as_slice());
}

#[test]
fn grouped_request_round_trips_through_borsh_frame() {
    let group_id = ConsensusGroupId::named("cache-hotset-a");
    let request = WireRequest::Group {
        group_id,
        request: Box::new(WireRequest::NextNonce),
    };
    let frame = EncodedFrame::encode_wire_request(&request).unwrap();
    let decoded = decode_wire_request_payload(&frame.as_bytes()[FRAME_PREFIX_BYTES..]).unwrap();

    match decoded {
        WireRequest::Group {
            group_id: decoded_group,
            request,
        } => {
            assert_eq!(decoded_group, group_id);
            assert!(matches!(*request, WireRequest::NextNonce));
        }
        response => panic!("expected grouped request, got {response:?}"),
    }
}

#[test]
fn ping_request_and_pong_response_round_trip_through_borsh_frame() {
    let request = WireRequest::Ping(NodePing::with_payload(99, b"are-you-there"));
    let request_frame = EncodedFrame::encode_wire_request(&request).unwrap();
    let decoded_request =
        decode_wire_request_payload(&request_frame.as_bytes()[FRAME_PREFIX_BYTES..]).unwrap();

    match decoded_request {
        WireRequest::Ping(ping) => {
            assert_eq!(ping.nonce, 99);
            assert_eq!(ping.payload, b"are-you-there");
        }
        response => panic!("expected ping request, got {response:?}"),
    }

    let response = WireResponse::Pong(NodePong::new(
        ConsensusGroupId::root(),
        crate::PubKey::default(),
        99,
        b"are-you-there",
    ));
    let response_frame = EncodedFrame::encode(&response).unwrap();
    let decoded_response =
        decode_wire_response_payload(&response_frame.as_bytes()[FRAME_PREFIX_BYTES..]).unwrap();

    match decoded_response {
        WireResponse::Pong(pong) => {
            assert_eq!(pong.group_id, ConsensusGroupId::root());
            assert_eq!(pong.nonce, 99);
            assert_eq!(pong.payload, b"are-you-there");
        }
        response => panic!("expected pong response, got {response:?}"),
    }
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
            assert_eq!(decoded_block.body.txs[0].payload(), b"tx-1");
            assert!(decoded_block.verify_integrity().is_ok());
        }
        response => panic!("expected hot submit block, got {response:?}"),
    }
}

#[cfg(feature = "filtered-transactions")]
#[test]
fn hot_submit_block_preserves_filtered_transaction_metadata() {
    let keypair = Keypair::generate();
    let target = Keypair::generate();
    let tx = Transaction::filtered_full(
        HashType::hash(b"cache-key"),
        3,
        vec![target.public],
        b"target-only-value".to_vec(),
        FilteredDeliveryPolicy::Gossip,
    )
    .unwrap();
    let expected_slot = tx.filtered_slot().unwrap().clone();
    let mut block = Block::default();
    block.body.last_epoch = HashType([1; 32]);
    block.body.nonce = Nonce::new(1);
    block.body.txs.push(tx);
    block.sign(&keypair.secret);

    let request = WireRequest::SubmitBlock(block.clone());
    let frame = EncodedFrame::encode_hot_wire_request(&request)
        .unwrap()
        .unwrap();
    let decoded = decode_wire_request_payload(&frame.as_bytes()[FRAME_PREFIX_BYTES..]).unwrap();

    match decoded {
        WireRequest::SubmitBlock(decoded_block) => {
            assert_eq!(decoded_block.hash, block.hash);
            assert!(decoded_block.verify_integrity().is_ok());
            let decoded_tx = &decoded_block.body.txs[0];
            assert_eq!(decoded_tx.filtered_view, FilteredPayloadView::Full);
            assert_eq!(decoded_tx.filtered_slot(), Some(&expected_slot));
            assert_eq!(decoded_tx.payload(), b"target-only-value");
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
            sender: valid_public_key(7),
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
    let decoded = decode_wire_response_payload(&frame.as_bytes()[FRAME_PREFIX_BYTES..]).unwrap();

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
fn hot_prefill_dispatch_request_round_trips_as_prefill_request() {
    let block = signed_test_block();
    let mut blocks = BTreeMap::new();
    blocks.insert(block.hash, block);
    let signature_tree = SignatureTree::default();
    let dispatch = Dispatch {
        header: Header {
            sender: valid_public_key(7),
            ..Default::default()
        },
        body: DispatchBody {
            blocks_hash: blocks.hash(),
            blocks,
            signature_tree_hash: signature_tree.hash(),
            signature_tree,
        },
    };
    let request = WireRequest::PrefillDispatch(dispatch.clone());
    let frame = EncodedFrame::encode_hot_wire_request(&request)
        .unwrap()
        .unwrap();

    assert!(frame.as_bytes()[FRAME_PREFIX_BYTES..].starts_with(HOT_WIRE_MAGIC));
    let decoded = decode_wire_request_frame(Bytes::copy_from_slice(
        &frame.as_bytes()[FRAME_PREFIX_BYTES..],
    ))
    .unwrap();

    match decoded {
        WireRequestFrame::Request(WireRequest::PrefillDispatch(decoded_dispatch)) => {
            assert_eq!(decoded_dispatch.header.sender, dispatch.header.sender);
            assert_eq!(decoded_dispatch.body.blocks_hash, dispatch.body.blocks_hash);
            assert_eq!(decoded_dispatch.body.blocks.len(), 1);
        }
        request => panic!("expected prefill dispatch request, got {request:?}"),
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
            sender: valid_public_key(7),
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
fn hot_dispatch_response_into_request_frame_rewrites_owned_frame() {
    let block = signed_test_block();
    let mut blocks = BTreeMap::new();
    blocks.insert(block.hash, block);
    let signature_tree = SignatureTree::default();
    let dispatch = Dispatch {
        header: Header {
            sender: valid_public_key(7),
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

    let (request_frame, block_count) = hot_dispatch_response_into_request_frame(frame).unwrap();
    assert_eq!(block_count, Some(1));
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
fn trusted_hot_dispatch_scan_validates_hashes_without_materializing_blocks() {
    let block = signed_test_block();
    let mut blocks = BTreeMap::new();
    blocks.insert(block.hash, block);
    let signature_tree = SignatureTree::default();
    let dispatch = Dispatch {
        header: Header {
            sender: valid_public_key(7),
            last_epoch: HashType([1; 32]),
            nonce: Nonce::new(1),
            ..Default::default()
        },
        body: DispatchBody {
            blocks_hash: blocks.hash(),
            blocks,
            signature_tree_hash: signature_tree.hash(),
            signature_tree,
        },
    };
    let frame =
        EncodedFrame::encode_hot_wire_request(&WireRequest::Message(Msg::Dispatch(dispatch)))
            .unwrap()
            .unwrap();
    let decoded = decode_wire_request_frame(Bytes::copy_from_slice(
        &frame.as_bytes()[FRAME_PREFIX_BYTES..],
    ))
    .unwrap();

    match decoded {
        WireRequestFrame::HotDispatch(raw) => {
            let scan = raw.scan_trusted().unwrap();
            assert_eq!(scan.block_count, 1);
            assert_eq!(scan.transaction_count, 1);
            assert_eq!(scan.block_hashes.hash(), scan.blocks_hash);
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
fn hot_io_selection_includes_large_block_paths() {
    let block = signed_test_block();

    assert!(hot_wire_request_is_selected_for_io(
        &WireRequest::SubmitBlock(block.clone())
    ));
    assert!(hot_wire_request_is_selected_for_io(
        &WireRequest::SendBlock(block)
    ));
    assert!(!hot_wire_request_is_selected_for_io(
        &WireRequest::NextNonce
    ));
}

#[test]
fn hot_block_rejects_impossible_transaction_count_before_allocating() {
    let mut payload = Vec::new();
    append_hot_prefix(&mut payload, HOT_REQUEST_SUBMIT_BLOCK);
    payload.extend_from_slice(&[0; 32]); // block hash
    payload.extend_from_slice(&[0; 64]); // block signature
    payload.extend_from_slice(valid_public_key(7).as_ref()); // validator
    payload.extend_from_slice(&[0; 32]); // last epoch
    payload.extend_from_slice(&0u64.to_le_bytes());
    payload.extend_from_slice(&0u128.to_le_bytes());
    payload.extend_from_slice(&0u128.to_le_bytes());
    payload.extend_from_slice(&[0; 32]); // merkle root
    payload.extend_from_slice(&0u32.to_le_bytes()); // application state length
    payload.extend_from_slice(&0u32.to_le_bytes()); // encounter record count
    payload.extend_from_slice(&0u32.to_le_bytes()); // node admission count
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
        WireResponse::Health(NodeHealth::new("ok", crate::PubKey::default())).kind(),
        "health"
    );
    assert_eq!(
        WireResponse::Pong(NodePong::new(
            ConsensusGroupId::root(),
            crate::PubKey::default(),
            0,
            Vec::new()
        ))
        .kind(),
        "pong"
    );
    assert_eq!(WireResponse::EchoReDispatch(None).kind(), "echo_redispatch");
    #[cfg(feature = "availability-gossip")]
    {
        assert_eq!(
            WireResponse::AvailabilityReceipt(AvailabilityReceipt {
                scope: ConsensusGroupId::root(),
                holder: crate::PubKey::default(),
                entries_accepted: 0,
            })
            .kind(),
            "availability_receipt"
        );
        assert_eq!(
            WireResponse::FilteredPayloadMissing(FilteredPayloadMissing {
                scope: ConsensusGroupId::root(),
                holder: crate::PubKey::default(),
                slot_hash: HashType::default(),
                payload_commitment: HashType::default(),
            })
            .kind(),
            "filtered_payload_missing"
        );

        let slot = FilteredTransactionSlot::for_payload(
            HashType::hash(b"key"),
            1,
            vec![crate::PubKey::default()],
            b"value",
            FilteredDeliveryPolicy::Gossip,
        )
        .unwrap();
        assert_eq!(
            WireResponse::FilteredPayload(
                FilteredPayloadDelivery::trusted(crate::FilteredPayloadDeliveryBody {
                    scope: ConsensusGroupId::root(),
                    holder: crate::PubKey::default(),
                    slot_hash: slot.hash(),
                    slot: slot.clone(),
                    payload: b"value".to_vec(),
                })
                .unwrap()
            )
            .kind(),
            "filtered_payload"
        );
        assert_eq!(
            WireResponse::FilteredPayloadBatch(
                FilteredPayloadBatchDelivery::trusted(crate::FilteredPayloadBatchDeliveryBody {
                    scope: ConsensusGroupId::root(),
                    holder: crate::PubKey::default(),
                    items: vec![crate::FilteredPayloadDeliveryItem {
                        slot_hash: slot.hash(),
                        slot,
                        payload: b"value".to_vec(),
                    }],
                },)
                .unwrap(),
            )
            .kind(),
            "filtered_payload_batch"
        );
    }
}

#[test]
fn frame_length_helpers_count_payload_and_prefix() {
    let request = WireRequest::NextNonce;

    assert_eq!(encoded_len(&request).unwrap(), 1);
    assert_eq!(framed_len(&request).unwrap(), FRAME_PREFIX_BYTES + 1);
}
