#[cfg(not(feature = "availability-gossip"))]
fn main() {
    eprintln!("blossom-subset-gossip-bench requires --features availability-gossip");
    std::process::exit(1);
}

#[cfg(feature = "availability-gossip")]
mod bench {
    use std::fs::{OpenOptions, create_dir_all};
    use std::io::Write;
    use std::path::PathBuf;

    use blossom::{
        SubsetGossipConfig, SubsetGossipEpochRow, SubsetLatencyDistribution, SubsetLatencyProfile,
        run_subset_gossip,
    };
    use clap::{Parser, ValueEnum};

    pub type MainResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

    #[derive(Parser, Debug)]
    #[command(
        name = "blossom-subset-gossip-bench",
        about = "Model recipient-filtered subset block gossip against full block replication"
    )]
    struct Args {
        #[arg(long, default_value = "subset")]
        scenario: String,
        #[arg(long, default_value_t = 1)]
        repeat: usize,
        #[arg(long, default_value_t = 36)]
        nodes: usize,
        #[arg(long, default_value_t = 6)]
        quorum_size: usize,
        #[arg(long, default_value_t = 100, alias = "epochs")]
        epoch_depth: usize,
        #[arg(long, default_value_t = 256)]
        commands_per_node: usize,
        #[arg(long, default_value_t = 1024)]
        command_bytes: usize,
        #[arg(long, default_value_t = 3)]
        targets_per_command: usize,
        #[arg(long, default_value_t = false)]
        trusted: bool,
        #[arg(long, default_value_t = false)]
        shuffle: bool,
        #[arg(long, default_value_t = true)]
        repair_missing: bool,
        #[arg(long, value_enum, default_value_t = LatencyDistributionArg::Even)]
        latency_distribution: LatencyDistributionArg,
        #[arg(long, default_value_t = 150)]
        latency_ms: u64,
        #[arg(long, default_value_t = 1)]
        latency_min_ms: u64,
        #[arg(long, default_value_t = 300)]
        latency_max_ms: u64,
        #[arg(long, default_value_t = 0x7375_6273_6574_31)]
        latency_seed: u64,
        #[arg(long, default_value_t = 0x626c_6f73_736f_6d31)]
        seed: u64,
        #[arg(long)]
        csv: Option<PathBuf>,
        #[arg(long)]
        append: bool,
        #[arg(long, default_value_t = false)]
        expect_complete: bool,
    }

    #[derive(Debug, Clone, Copy, ValueEnum)]
    enum LatencyDistributionArg {
        Even,
        Random,
    }

    impl From<LatencyDistributionArg> for SubsetLatencyDistribution {
        fn from(value: LatencyDistributionArg) -> Self {
            match value {
                LatencyDistributionArg::Even => Self::Even,
                LatencyDistributionArg::Random => Self::Random,
            }
        }
    }

    pub fn main() -> MainResult<()> {
        let args = Args::parse();
        let config = SubsetGossipConfig {
            seed: args.seed,
            nodes: args.nodes,
            epochs: args.epoch_depth,
            quorum_size: args.quorum_size,
            commands_per_node: args.commands_per_node,
            command_bytes: args.command_bytes,
            targets_per_command: args.targets_per_command,
            trusted: args.trusted,
            shuffle: args.shuffle,
            repair_missing: args.repair_missing,
            latency: SubsetLatencyProfile {
                distribution: args.latency_distribution.into(),
                latency_ms: args.latency_ms,
                min_ms: args.latency_min_ms,
                max_ms: args.latency_max_ms,
                seed: args.latency_seed,
            },
        };

        let report = run_subset_gossip(config)?;
        if args.expect_complete {
            validate_complete(&report.rows)?;
        }

        for row in &report.rows {
            println!("{}", row_to_csv(&args.scenario, args.repeat, row));
        }

        if let Some(path) = args.csv.as_ref() {
            write_csv(path, args.append, &args.scenario, args.repeat, &report.rows)?;
            eprintln!("wrote {}", path.display());
        }

        Ok(())
    }

    fn validate_complete(rows: &[SubsetGossipEpochRow]) -> MainResult<()> {
        for row in rows {
            if !row.metadata_converged {
                return Err(format!(
                    "epoch {} metadata converged on {}/{} nodes",
                    row.epoch, row.metadata_converged_nodes, row.nodes
                )
                .into());
            }
            if !row.subset_payloads_complete_after_repair {
                return Err(format!(
                    "epoch {} missing {} target payloads after repair",
                    row.epoch, row.subset_missing_payloads_after_repair
                )
                .into());
            }
        }
        Ok(())
    }

    fn write_csv(
        path: &PathBuf,
        append: bool,
        scenario: &str,
        repeat: usize,
        rows: &[SubsetGossipEpochRow],
    ) -> MainResult<()> {
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
                "scenario,repeat,epoch,epoch_depth,nodes,quorum_size,rounds,quorums,trusted,shuffle,repair_missing,latency_distribution,latency_ms,latency_min_ms,latency_max_ms,commands_per_node,command_bytes,targets_per_command,total_commands,target_payload_deliveries,metadata_converged_nodes,metadata_converged,subset_payloads_complete_before_repair,subset_payloads_complete_after_repair,subset_missing_payloads_before_repair,subset_missing_payloads_after_repair,subset_delivered_payloads_before_repair,subset_delivered_payloads_after_repair,subset_repair_batches,subset_repair_bytes,subset_repair_latency_ms,modeled_finality_latency_ms,modeled_dispatch_latency_ms,modeled_control_latency_ms,subset_payload_ready_latency_ms,full_block_bytes,full_dispatch_bytes,subset_dispatch_bytes,control_bytes,full_wire_bytes,subset_wire_bytes,full_amplification,subset_amplification,subset_savings_pct,full_tps,subset_payload_ready_tps,full_total_gbps,subset_total_gbps,full_per_node_gbps,subset_per_node_gbps"
            )?;
        }
        for row in rows {
            writeln!(file, "{}", row_to_csv(scenario, repeat, row))?;
        }
        Ok(())
    }

    fn row_to_csv(scenario: &str, repeat: usize, row: &SubsetGossipEpochRow) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6}",
            scenario,
            repeat,
            row.epoch,
            row.epoch_depth,
            row.nodes,
            row.quorum_size,
            row.rounds,
            row.quorums,
            row.trusted,
            row.shuffle,
            row.repair_missing,
            row.latency_distribution.as_str(),
            row.latency_ms,
            row.latency_min_ms,
            row.latency_max_ms,
            row.commands_per_node,
            row.command_bytes,
            row.targets_per_command,
            row.total_commands,
            row.target_payload_deliveries,
            row.metadata_converged_nodes,
            row.metadata_converged,
            row.subset_payloads_complete_before_repair,
            row.subset_payloads_complete_after_repair,
            row.subset_missing_payloads_before_repair,
            row.subset_missing_payloads_after_repair,
            row.subset_delivered_payloads_before_repair,
            row.subset_delivered_payloads_after_repair,
            row.subset_repair_batches,
            row.subset_repair_bytes,
            row.subset_repair_latency_ms,
            row.modeled_finality_latency_ms,
            row.modeled_dispatch_latency_ms,
            row.modeled_control_latency_ms,
            row.subset_payload_ready_latency_ms,
            row.full_block_bytes,
            row.full_dispatch_bytes,
            row.subset_dispatch_bytes,
            row.control_bytes,
            row.full_wire_bytes,
            row.subset_wire_bytes,
            row.full_amplification,
            row.subset_amplification,
            row.subset_savings_pct,
            row.full_tps,
            row.subset_payload_ready_tps,
            row.full_total_gbps,
            row.subset_total_gbps,
            row.full_per_node_gbps,
            row.subset_per_node_gbps
        )
    }
}

#[cfg(feature = "availability-gossip")]
fn main() -> bench::MainResult<()> {
    bench::main()
}
