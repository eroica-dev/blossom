//! Shared HA fixtures and responsibility-focused test modules.

use super::*;
use crate::address_book::ServiceKind;
use crate::block::Transaction;
use crate::crypto::Keypair;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering as AtomicOrdering};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

const STORAGE_FAULT_NONE: u8 = 0;
const STORAGE_FAULT_FULL: u8 = 1;
const STORAGE_FAULT_SYNC: u8 = 2;
static NEXT_FAULT_STORAGE_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
struct HaFaultStorage {
    path: Arc<std::path::PathBuf>,
    fault: Arc<AtomicU8>,
}

impl HaFaultStorage {
    fn new() -> Self {
        let unique = NEXT_FAULT_STORAGE_ID.fetch_add(1, AtomicOrdering::Relaxed);
        Self {
            path: Arc::new(
                std::env::temp_dir()
                    .join(format!("blossom-ha-fault-{}-{unique}", std::process::id())),
            ),
            fault: Arc::new(AtomicU8::new(STORAGE_FAULT_NONE)),
        }
    }

    fn set_fault(&self, fault: u8) {
        self.fault.store(fault, AtomicOrdering::SeqCst);
    }
}

impl Drop for HaFaultStorage {
    fn drop(&mut self) {
        if Arc::strong_count(&self.path) == 1 {
            let _ = std::fs::remove_dir_all(self.path.as_ref());
        }
    }
}

fn fault_injected_runtime(storage: &HaFaultStorage) -> HighAvailabilityRuntime {
    let identities = (0..3u8).map(member).collect::<Vec<_>>();
    let mut runtime = HighAvailabilityRuntime::open(
        storage.path.as_ref(),
        ConsensusGroupId::named("ha-runtime-test"),
        identities[0].public_key(),
        identities,
        HighAvailabilityParameters::default(),
    )
    .unwrap();
    runtime.store.as_mut().unwrap().test_fault = Some(storage.fault.clone());
    runtime
}

fn spawn_authenticated_ha_worker(path: &Path, port: u16, key: &HaTransportKey) -> Child {
    Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "high_availability::tests::transport::authenticated_ha_process_worker",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("BLOSSOM_HA_PROCESS_WORKER", "1")
        .env("BLOSSOM_HA_PROCESS_PATH", path)
        .env("BLOSSOM_HA_PROCESS_PORT", port.to_string())
        .env("BLOSSOM_HA_PROCESS_KEY", key.to_hex())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

async fn await_authenticated_worker(
    client: &HighAvailabilityTcpClient,
    service: &Service,
    child: &mut Child,
) -> HaNodeStatus {
    let mut last_error = None;
    for _ in 0..200 {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("HA qualification worker exited before readiness: {status}");
        }
        match client.status(service).await {
            Ok(status) => return status,
            Err(error) => last_error = Some(error),
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!(
        "HA qualification worker did not become ready: {}",
        last_error
            .map(|error| error.to_string())
            .unwrap_or_else(|| "no connection attempt".to_string())
    );
}

fn member(index: u8) -> NodeIdentity {
    NodeIdentity::new(
        PubKey([index; 32]),
        None,
        "tcp",
        "127.0.0.1",
        9000 + u16::from(index),
        false,
    )
}

fn durable_store_with_bytes(label: &str, bytes: &[u8]) -> (HaDurableStore, std::path::PathBuf) {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "blossom-ha-upgrade-{label}-{}-{unique}",
        std::process::id()
    ));
    let durable_members = members(3);
    let store = HaDurableStore::open(
        &path,
        ConsensusGroupId::named("ha-runtime-test"),
        member(0).public_key(),
        durable_members.fixed_identity_hash(),
        HighAvailabilityParameters::default().hash(),
    )
    .unwrap();
    store
        .store
        .transaction(|transaction| {
            transaction.insert(
                HA_METADATA_TABLE,
                HA_RUNTIME_STATE_KEY.to_vec(),
                bytes.to_vec(),
            )?;
            Ok(())
        })
        .unwrap();
    (store, path)
}

fn durable_directory_bytes(path: &Path) -> Vec<u8> {
    let mut bytes = Vec::new();
    for entry in std::fs::read_dir(path).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            bytes.extend(durable_directory_bytes(&path));
        } else {
            bytes.extend(std::fs::read(path).unwrap());
        }
    }
    bytes
}

fn members(count: usize) -> HaMemberSlots {
    HaMemberSlots::new((0..count as u8).map(member).collect()).unwrap()
}

fn round_id(active_mask: u8) -> HaRoundId {
    let member_count = (u8::BITS - active_mask.leading_zeros()) as usize;
    HaRoundId {
        group_id: ConsensusGroupId::named("ha-test"),
        fixed_membership_hash: members(member_count).fixed_identity_hash(),
        membership_generation: 1,
        active_mask,
        parameters_hash: HighAvailabilityParameters::default().hash(),
        previous_epoch_hash: HashType([9; 32]),
        previous_epoch_nonce: Nonce::new(4),
        nonce: Nonce::new(5),
        round: 0,
    }
}

fn dispatch(member: &NodeIdentity, slot: u8, target: HaRoundId, label: &str) -> HaDispatch {
    let mut block = Block::default();
    block.body.last_epoch = target.previous_epoch_hash;
    block.body.nonce = target.nonce;
    block.body.txs.push(Transaction::new(label));
    block.seal_unsigned(member.public_key());
    HaDispatch {
        round_id: target,
        sender: HaMemberSlot(slot),
        block_hash: block.hash,
        block,
    }
}

fn install_dispatches(states: &mut [HaRoundState], members: &HaMemberSlots, slots: &[u8]) {
    for slot in slots {
        let message = dispatch(
            members.member(HaMemberSlot(*slot)).unwrap(),
            *slot,
            states[0].round_id,
            &format!("block-{slot}"),
        );
        for state in states.iter_mut() {
            assert_eq!(
                state.receive_dispatch(members, message.clone()).unwrap(),
                HaDispatchOutcome::Accepted
            );
        }
    }
}

fn runtimes(count: usize) -> Vec<HighAvailabilityRuntime> {
    let identities = (0..count as u8).map(member).collect::<Vec<_>>();
    identities
        .iter()
        .map(|identity| {
            HighAvailabilityRuntime::new(
                ConsensusGroupId::named("ha-runtime-test"),
                identity.public_key(),
                identities.clone(),
                HighAvailabilityParameters::default(),
            )
            .unwrap()
        })
        .collect()
}

fn finalize_runtime_epoch(
    runtimes: &mut [HighAvailabilityRuntime],
    participants: &[usize],
    label: &str,
) {
    let transaction_sets = participants
        .iter()
        .map(|index| vec![Transaction::new(format!("{label}-{index}"))])
        .collect::<Vec<_>>();
    finalize_runtime_transactions(runtimes, participants, transaction_sets);
}

fn finalize_runtime_transactions(
    runtimes: &mut [HighAvailabilityRuntime],
    participants: &[usize],
    transaction_sets: Vec<Vec<Transaction>>,
) {
    assert_eq!(participants.len(), transaction_sets.len());
    let mut dispatches = Vec::new();
    for (index, transactions) in participants.iter().zip(transaction_sets) {
        dispatches.push((
            *index,
            runtimes[*index].build_dispatch(transactions).unwrap(),
        ));
    }
    for (sender, dispatch) in &dispatches {
        for receiver in participants {
            if receiver != sender {
                runtimes[*receiver]
                    .receive_dispatch(dispatch.clone())
                    .unwrap();
            }
        }
    }
    let acknowledgements = participants
        .iter()
        .map(|index| (*index, runtimes[*index].acknowledge().unwrap()))
        .collect::<Vec<_>>();
    for (sender, acknowledgement) in &acknowledgements {
        for receiver in participants {
            if receiver != sender {
                runtimes[*receiver]
                    .receive_acknowledgement(acknowledgement.clone())
                    .unwrap();
            }
        }
    }
    let confirmations = participants
        .iter()
        .map(|index| (*index, runtimes[*index].confirm().unwrap().0))
        .collect::<Vec<_>>();
    for (sender, confirmation) in &confirmations {
        for receiver in participants.iter().copied() {
            if receiver != *sender {
                runtimes[receiver]
                    .receive_confirmation(confirmation.clone())
                    .unwrap();
            }
        }
    }
    let head_hash = runtimes[participants[0]].head().hash;
    assert!(
        participants
            .iter()
            .all(|index| runtimes[*index].head().hash == head_hash)
    );
}

#[test]
fn runtime_emits_protocol_and_service_telemetry() {
    let sink = Arc::new(crate::telemetry::InMemoryTelemetrySink::default());
    let telemetry = TelemetryHandle::new(sink.clone() as Arc<dyn crate::telemetry::TelemetrySink>);
    let mut nodes = runtimes(3);
    nodes[0].set_telemetry(telemetry);

    finalize_runtime_epoch(&mut nodes, &[0, 1], "telemetry");
    nodes[0].operational_status().unwrap();
    nodes[0].emit_telemetry_failure(
        "transport",
        "ha_connection_failed",
        &BlossomError::Io("injected".to_string()),
    );

    let events = sink.events();
    assert!(events.iter().any(|event| event.event == "dispatch_built"));
    assert!(
        events
            .iter()
            .any(|event| event.event == "acknowledgement_persisted")
    );
    assert!(
        events
            .iter()
            .any(|event| event.event == "confirmation_persisted")
    );
    assert!(events.iter().any(|event| event.event == "epoch_finalized"));
    assert!(events.iter().any(|event| event.event == "ha_status"));
    assert!(events.iter().any(|event| {
        event.event == "ha_connection_failed"
            && event.outcome.as_deref() == Some("error")
            && event.error.as_deref() == Some("io error: injected")
    }));
}

fn exchange_acknowledgements(states: &mut [HaRoundState], members: &HaMemberSlots) {
    let mut messages = Vec::new();
    for (index, state) in states.iter_mut().enumerate() {
        messages.push(
            state
                .acknowledge(members, HaMemberSlot(index as u8))
                .unwrap(),
        );
    }
    for message in messages {
        for state in states.iter_mut() {
            state
                .receive_acknowledgement(members, message.clone())
                .unwrap();
        }
    }
}

mod durability;
mod membership;
mod protocol;
mod status;
mod transport;
