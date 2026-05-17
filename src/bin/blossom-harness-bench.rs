use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

use clap::{Parser, ValueEnum};

use blossom::{
    BlossomError, EncodedFrame, MockBlockService, Msg, SimulatedCluster, Transaction, WireRequest,
    WireResponse, encoded_len, framed_len, signed_block,
};

type MainResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Parser, Debug)]
#[command(
    name = "blossom-harness-bench",
    about = "Benchmark full Blossom harness scenarios"
)]
struct Args {
    #[arg(long, default_value_t = 6)]
    nodes: usize,
    #[arg(long, default_value_t = 3)]
    transactions: usize,
    #[arg(long, default_value_t = 32)]
    transaction_bytes: usize,
    #[arg(long, default_value_t = 0)]
    application_state_bytes: usize,
    #[arg(long, default_value_t = 10)]
    iterations: usize,
    #[arg(long, default_value_t = 1)]
    warmup: usize,
    #[arg(long, value_enum, default_value = "all-peers")]
    delivery_mode: DeliveryMode,
    #[arg(long)]
    csv: Option<PathBuf>,
    #[arg(long)]
    append: bool,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum DeliveryMode {
    FirstAccepted,
    AllPeers,
}

impl DeliveryMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::FirstAccepted => "first_accepted",
            Self::AllPeers => "all_peers",
        }
    }
}

#[derive(Debug, Clone)]
struct HarnessBenchRow {
    iteration: usize,
    nodes: usize,
    transactions: usize,
    transaction_bytes: usize,
    application_state_bytes: usize,
    delivery_mode: DeliveryMode,
    tx_payload_bytes: usize,
    accepted_application_state_bytes: usize,
    block_bytes: usize,
    register_wire_bytes: usize,
    next_nonce_wire_bytes: usize,
    submit_wire_bytes: usize,
    dispatch_wire_bytes: usize,
    deliver_wire_bytes: usize,
    total_wire_bytes: usize,
    spawn_us: u128,
    tx_build_us: u128,
    block_sign_us: u128,
    register_us: u128,
    next_nonce_us: u128,
    submit_us: u128,
    dispatch_us: u128,
    deliver_us: u128,
    total_us: u128,
    blocks_dispatched: usize,
    deliveries_attempted: usize,
    deliveries_accepted: usize,
    nonce_announced: bool,
    delivered: bool,
}

#[tokio::main]
async fn main() -> MainResult<()> {
    let args = Args::parse();
    let mut rows = Vec::with_capacity(args.iterations);

    for _ in 0..args.warmup {
        run_iteration(
            0,
            args.nodes,
            args.transactions,
            args.transaction_bytes,
            args.application_state_bytes,
            args.delivery_mode,
        )
        .await?;
    }

    for iteration in 0..args.iterations {
        let row = run_iteration(
            iteration,
            args.nodes,
            args.transactions,
            args.transaction_bytes,
            args.application_state_bytes,
            args.delivery_mode,
        )
        .await?;
        println!("{}", row.to_csv());
        rows.push(row);
    }

    if let Some(path) = args.csv {
        write_csv(&path, args.append, &rows)?;
        eprintln!("wrote {}", path.display());
    }

    Ok(())
}

async fn run_iteration(
    iteration: usize,
    nodes: usize,
    transactions: usize,
    transaction_bytes: usize,
    application_state_bytes: usize,
    delivery_mode: DeliveryMode,
) -> MainResult<HarnessBenchRow> {
    let total_start = Instant::now();
    let mut total_wire_bytes = 0usize;

    let spawn_start = Instant::now();
    let cluster = SimulatedCluster::spawn(nodes).await?;
    let block_service = MockBlockService::spawn().await?;
    let spawn_us = spawn_start.elapsed().as_micros();

    let register_start = Instant::now();
    let register_request = WireRequest::RegisterService(block_service.service.clone());
    let register_request_bytes = framed_len(&register_request)?;
    let register_response = cluster.request(0, register_request).await?;
    let register_response_bytes = framed_len(&register_response)?;
    let register_wire_bytes = register_request_bytes + register_response_bytes;
    total_wire_bytes += register_wire_bytes;
    let nonce_announced = match register_response {
        WireResponse::AddressBookUpdated(update) => update.nonce_announced.is_some(),
        WireResponse::Error(message) => return Err(BlossomError::WireProtocol(message).into()),
        response => return Err(unexpected("address-book update", response).into()),
    };
    let register_us = register_start.elapsed().as_micros();

    let next_nonce_start = Instant::now();
    let next_nonce_request = WireRequest::NextNonce;
    let next_nonce_request_bytes = framed_len(&next_nonce_request)?;
    let next_nonce_response = cluster.request(0, next_nonce_request).await?;
    let next_nonce_response_bytes = framed_len(&next_nonce_response)?;
    let next_nonce_wire_bytes = next_nonce_request_bytes + next_nonce_response_bytes;
    total_wire_bytes += next_nonce_wire_bytes;
    let target = match next_nonce_response {
        WireResponse::NextNonce(target) => target,
        WireResponse::Error(message) => return Err(BlossomError::WireProtocol(message).into()),
        response => return Err(unexpected("next nonce", response).into()),
    };
    let next_nonce_us = next_nonce_start.elapsed().as_micros();

    let tx_build_start = Instant::now();
    let txs = build_transactions(iteration, transactions, transaction_bytes);
    let tx_payload_bytes = txs.iter().map(|tx| tx.bytes.len()).sum();
    let tx_build_us = tx_build_start.elapsed().as_micros();

    let block_sign_start = Instant::now();
    let mut block = signed_block(target, block_service.keypair.secret, txs);
    if application_state_bytes > 0 {
        block.set_application_state(application_state_payload(
            iteration,
            application_state_bytes,
        ))?;
        block.sign(&block_service.keypair.secret);
    }
    let block_sign_us = block_sign_start.elapsed().as_micros();
    let application_state_bytes = block.application_state_len();
    let block_bytes = encoded_len(&block)?;

    let submit_start = Instant::now();
    let submit_request = WireRequest::SubmitBlock(block);
    let submit_request_bytes = framed_len(&submit_request)?;
    let submit_response = cluster.request(0, submit_request).await?;
    let submit_response_bytes = framed_len(&submit_response)?;
    let submit_wire_bytes = submit_request_bytes + submit_response_bytes;
    total_wire_bytes += submit_wire_bytes;
    let accepted_application_state_bytes = match submit_response {
        WireResponse::BlockAccepted(accepted) => accepted.application_state_bytes,
        WireResponse::Error(message) => return Err(BlossomError::WireProtocol(message).into()),
        response => return Err(unexpected("block submission", response).into()),
    };
    let submit_us = submit_start.elapsed().as_micros();

    let dispatch_start = Instant::now();
    let dispatch_request = WireRequest::Dispatch { round: 0 };
    let dispatch_request_bytes = framed_len(&dispatch_request)?;
    let dispatch_response = cluster.request(0, dispatch_request).await?;
    let dispatch_response_bytes = framed_len(&dispatch_response)?;
    let dispatch_wire_bytes = dispatch_request_bytes + dispatch_response_bytes;
    total_wire_bytes += dispatch_wire_bytes;
    let dispatch = match dispatch_response {
        WireResponse::Dispatch(dispatch) => dispatch,
        WireResponse::Error(message) => return Err(BlossomError::WireProtocol(message).into()),
        response => return Err(unexpected("dispatch", response).into()),
    };
    let dispatch_us = dispatch_start.elapsed().as_micros();
    let blocks_dispatched = dispatch.body.blocks.len();

    let deliver_start = Instant::now();
    let mut deliver_wire_bytes = 0usize;
    let mut deliveries_attempted = 0usize;
    let mut deliveries_accepted = 0usize;
    let delivered = if nodes > 1 {
        let deliver_request = WireRequest::Message(Msg::Dispatch(dispatch));
        let deliver_frame = EncodedFrame::encode(&deliver_request)?;
        let deliver_request_bytes = deliver_frame.framed_len();
        for recipient in 1..nodes {
            let deliver_response = cluster.request_frame(recipient, &deliver_frame).await?;
            let deliver_response_bytes = framed_len(&deliver_response)?;
            deliver_wire_bytes += deliver_request_bytes + deliver_response_bytes;
            deliveries_attempted += 1;

            match deliver_response {
                WireResponse::MessageReceipt(receipt) => {
                    if receipt.accepted {
                        deliveries_accepted += 1;
                    }
                    if receipt.accepted && delivery_mode == DeliveryMode::FirstAccepted {
                        break;
                    }
                }
                WireResponse::Error(_) => {}
                response => return Err(unexpected("dispatch delivery", response).into()),
            }
        }
        match delivery_mode {
            DeliveryMode::FirstAccepted => deliveries_accepted > 0,
            DeliveryMode::AllPeers => deliveries_accepted == nodes - 1,
        }
    } else {
        false
    };
    let deliver_us = deliver_start.elapsed().as_micros();
    total_wire_bytes += deliver_wire_bytes;

    Ok(HarnessBenchRow {
        iteration,
        nodes,
        transactions,
        transaction_bytes,
        application_state_bytes,
        delivery_mode,
        tx_payload_bytes,
        accepted_application_state_bytes,
        block_bytes,
        register_wire_bytes,
        next_nonce_wire_bytes,
        submit_wire_bytes,
        dispatch_wire_bytes,
        deliver_wire_bytes,
        total_wire_bytes,
        spawn_us,
        tx_build_us,
        block_sign_us,
        register_us,
        next_nonce_us,
        submit_us,
        dispatch_us,
        deliver_us,
        total_us: total_start.elapsed().as_micros(),
        blocks_dispatched,
        deliveries_attempted,
        deliveries_accepted,
        nonce_announced,
        delivered,
    })
}

fn build_transactions(
    iteration: usize,
    transactions: usize,
    transaction_bytes: usize,
) -> Vec<Transaction> {
    (0..transactions)
        .map(|index| Transaction::new(transaction_payload(iteration, index, transaction_bytes)))
        .collect()
}

fn transaction_payload(iteration: usize, index: usize, len: usize) -> Vec<u8> {
    let mut bytes = vec![0; len];
    let mut seed = (iteration as u64)
        .wrapping_mul(0x9e37_79b9_7f4a_7c15)
        .wrapping_add(index as u64);

    for chunk in bytes.chunks_mut(8) {
        seed = splitmix64(seed);
        let seed_bytes = seed.to_le_bytes();
        let take = chunk.len();
        chunk.copy_from_slice(&seed_bytes[..take]);
    }

    bytes
}

fn application_state_payload(iteration: usize, len: usize) -> Vec<u8> {
    let mut bytes = vec![0; len];
    let mut seed = (iteration as u64) ^ 0xa076_1d64_78bd_642f;

    for chunk in bytes.chunks_mut(8) {
        seed = splitmix64(seed);
        let seed_bytes = seed.to_le_bytes();
        let take = chunk.len();
        chunk.copy_from_slice(&seed_bytes[..take]);
    }

    bytes
}

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = value;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn unexpected(context: &str, response: WireResponse) -> BlossomError {
    BlossomError::WireProtocol(format!(
        "{context}: unexpected response {}",
        response.kind()
    ))
}

fn write_csv(path: &PathBuf, append: bool, rows: &[HarnessBenchRow]) -> MainResult<()> {
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }

    let write_header = !append || !path.exists() || path.metadata()?.len() == 0;
    let mut file = OpenOptions::new()
        .create(true)
        .append(append)
        .write(true)
        .truncate(!append)
        .open(path)?;

    if write_header {
        writeln!(
            file,
            "iteration,nodes,transactions,transaction_bytes,application_state_bytes,delivery_mode,tx_payload_bytes,accepted_application_state_bytes,block_bytes,register_wire_bytes,next_nonce_wire_bytes,submit_wire_bytes,dispatch_wire_bytes,deliver_wire_bytes,total_wire_bytes,spawn_us,tx_build_us,block_sign_us,register_us,next_nonce_us,submit_us,dispatch_us,deliver_us,total_us,blocks_dispatched,deliveries_attempted,deliveries_accepted,nonce_announced,delivered"
        )?;
    }
    for row in rows {
        writeln!(file, "{}", row.to_csv())?;
    }
    Ok(())
}

impl HarnessBenchRow {
    fn to_csv(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            self.iteration,
            self.nodes,
            self.transactions,
            self.transaction_bytes,
            self.application_state_bytes,
            self.delivery_mode.as_str(),
            self.tx_payload_bytes,
            self.accepted_application_state_bytes,
            self.block_bytes,
            self.register_wire_bytes,
            self.next_nonce_wire_bytes,
            self.submit_wire_bytes,
            self.dispatch_wire_bytes,
            self.deliver_wire_bytes,
            self.total_wire_bytes,
            self.spawn_us,
            self.tx_build_us,
            self.block_sign_us,
            self.register_us,
            self.next_nonce_us,
            self.submit_us,
            self.dispatch_us,
            self.deliver_us,
            self.total_us,
            self.blocks_dispatched,
            self.deliveries_attempted,
            self.deliveries_accepted,
            self.nonce_announced,
            self.delivered
        )
    }
}
