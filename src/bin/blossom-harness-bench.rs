use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

use clap::Parser;

use blossom::{
    BlossomError, MockBlockService, Msg, SimulatedCluster, Transaction, WireRequest, WireResponse,
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
    #[arg(long, default_value_t = 10)]
    iterations: usize,
    #[arg(long, default_value_t = 1)]
    warmup: usize,
    #[arg(long)]
    csv: Option<PathBuf>,
    #[arg(long)]
    append: bool,
}

#[derive(Debug, Clone)]
struct HarnessBenchRow {
    iteration: usize,
    nodes: usize,
    transactions: usize,
    spawn_us: u128,
    register_us: u128,
    submit_us: u128,
    dispatch_us: u128,
    deliver_us: u128,
    total_us: u128,
    blocks_dispatched: usize,
    nonce_announced: bool,
    delivered: bool,
}

#[tokio::main]
async fn main() -> MainResult<()> {
    let args = Args::parse();
    let mut rows = Vec::with_capacity(args.iterations);

    for _ in 0..args.warmup {
        run_iteration(0, args.nodes, args.transactions).await?;
    }

    for iteration in 0..args.iterations {
        let row = run_iteration(iteration, args.nodes, args.transactions).await?;
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
) -> MainResult<HarnessBenchRow> {
    let total_start = Instant::now();

    let spawn_start = Instant::now();
    let cluster = SimulatedCluster::spawn(nodes).await?;
    let block_service = MockBlockService::spawn().await?;
    let spawn_us = spawn_start.elapsed().as_micros();

    let register_start = Instant::now();
    let nonce_announced = match cluster
        .request(
            0,
            WireRequest::RegisterService(block_service.service.clone()),
        )
        .await?
    {
        WireResponse::AddressBookUpdated(update) => update.nonce_announced.is_some(),
        WireResponse::Error(message) => return Err(BlossomError::WireProtocol(message).into()),
        response => return Err(unexpected("address-book update", response).into()),
    };
    let register_us = register_start.elapsed().as_micros();

    let target = cluster.next_target(0).await?;
    let txs = (0..transactions)
        .map(|index| Transaction::new(format!("bench-{iteration}-tx-{index}")))
        .collect::<Vec<_>>();
    let block = block_service.signed_block(target, txs);

    let submit_start = Instant::now();
    match cluster.request(0, WireRequest::SubmitBlock(block)).await? {
        WireResponse::BlockAccepted(_) => {}
        WireResponse::Error(message) => return Err(BlossomError::WireProtocol(message).into()),
        response => return Err(unexpected("block submission", response).into()),
    }
    let submit_us = submit_start.elapsed().as_micros();

    let dispatch_start = Instant::now();
    let dispatch = match cluster
        .request(0, WireRequest::Dispatch { round: 0 })
        .await?
    {
        WireResponse::Dispatch(dispatch) => dispatch,
        WireResponse::Error(message) => return Err(BlossomError::WireProtocol(message).into()),
        response => return Err(unexpected("dispatch", response).into()),
    };
    let dispatch_us = dispatch_start.elapsed().as_micros();
    let blocks_dispatched = dispatch.body.blocks.len();

    let deliver_start = Instant::now();
    let delivered = if nodes > 1 {
        let mut accepted = false;
        for recipient in 1..nodes {
            match cluster
                .request(
                    recipient,
                    WireRequest::Message(Msg::Dispatch(dispatch.clone())),
                )
                .await?
            {
                WireResponse::MessageReceipt(receipt) => {
                    accepted = receipt.accepted;
                    if accepted {
                        break;
                    }
                }
                WireResponse::Error(_) => {}
                response => return Err(unexpected("dispatch delivery", response).into()),
            }
        }
        accepted
    } else {
        false
    };
    let deliver_us = deliver_start.elapsed().as_micros();

    Ok(HarnessBenchRow {
        iteration,
        nodes,
        transactions,
        spawn_us,
        register_us,
        submit_us,
        dispatch_us,
        deliver_us,
        total_us: total_start.elapsed().as_micros(),
        blocks_dispatched,
        nonce_announced,
        delivered,
    })
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
            "iteration,nodes,transactions,spawn_us,register_us,submit_us,dispatch_us,deliver_us,total_us,blocks_dispatched,nonce_announced,delivered"
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
            "{},{},{},{},{},{},{},{},{},{},{},{}",
            self.iteration,
            self.nodes,
            self.transactions,
            self.spawn_us,
            self.register_us,
            self.submit_us,
            self.dispatch_us,
            self.deliver_us,
            self.total_us,
            self.blocks_dispatched,
            self.nonce_announced,
            self.delivered
        )
    }
}
