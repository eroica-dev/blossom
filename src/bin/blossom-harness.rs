use clap::Parser;

use blossom::{
    BlossomError, MockBlockService, Msg, SimulatedCluster, Transaction, WireRequest, WireResponse,
};

type MainResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Parser, Debug)]
#[command(
    name = "blossom-harness",
    about = "Run a local Blossom node-behavior simulation"
)]
struct Args {
    #[arg(long, default_value_t = 6)]
    nodes: usize,
    #[arg(long, default_value_t = 3)]
    transactions: usize,
}

#[tokio::main]
async fn main() -> MainResult<()> {
    let args = Args::parse();
    let cluster = SimulatedCluster::spawn(args.nodes).await?;
    let block_service = MockBlockService::spawn().await?;

    println!("started {} simulated node(s)", cluster.len());
    for (index, node) in cluster.nodes().iter().enumerate() {
        println!(
            "node {index}: tcp://{} {}",
            node.addr(),
            node.identity.public_key()
        );
    }
    println!(
        "block service: tcp://{} {}",
        block_service.service.socket_addr(),
        block_service.service.public_key
    );

    expect(
        cluster
            .request(
                0,
                WireRequest::RegisterService(
                    block_service
                        .signed_record(
                            cluster.node(0).runtime.group_id(),
                            &cluster.node(0).keypair,
                            1,
                        )?
                        .into(),
                ),
            )
            .await?,
        "address-book update",
    )?;

    let target = cluster.next_target(0).await?;
    let txs = (0..args.transactions)
        .map(|index| Transaction::new(format!("harness-tx-{index}")))
        .collect::<Vec<_>>();
    let block = block_service.signed_block(target, txs);

    expect(
        cluster.request(0, WireRequest::SubmitBlock(block)).await?,
        "block submission",
    )?;
    let dispatch = match cluster
        .request(0, WireRequest::Dispatch { round: 0 })
        .await?
    {
        WireResponse::Dispatch(dispatch) => dispatch,
        response => {
            return Err(BlossomError::WireProtocol(format!(
                "expected dispatch, got {}",
                response.kind()
            ))
            .into());
        }
    };
    println!(
        "node 0 dispatched {} block(s) for nonce {}",
        dispatch.body.blocks.len(),
        dispatch.header.nonce
    );

    if cluster.len() > 1 {
        expect(
            cluster
                .request(1, WireRequest::Message(Msg::Dispatch(dispatch)))
                .await?,
            "dispatch delivery",
        )?;
        println!("delivered dispatch from node 0 to node 1");
    }

    println!(
        "block service received nonce announcements: {:?}",
        block_service.received_nonces()
    );
    Ok(())
}

fn expect(response: WireResponse, label: &str) -> MainResult<()> {
    match response {
        WireResponse::AddressBookUpdated(update) => {
            println!(
                "{label}: registered {} service, nonce {:?}",
                update.service.kind, update.nonce_announced
            );
            Ok(())
        }
        WireResponse::BlockAccepted(block) => {
            println!(
                "{label}: accepted block {} application_state_bytes={}",
                block.hash, block.application_state_bytes
            );
            Ok(())
        }
        WireResponse::MessageReceipt(receipt) => {
            println!("{label}: {} accepted={}", receipt.kind, receipt.accepted);
            Ok(())
        }
        WireResponse::Ok => {
            println!("{label}: ok");
            Ok(())
        }
        WireResponse::Error(message) => Err(BlossomError::WireProtocol(message).into()),
        response => Err(BlossomError::WireProtocol(format!(
            "{label}: unexpected response {}",
            response.kind()
        ))
        .into()),
    }
}
