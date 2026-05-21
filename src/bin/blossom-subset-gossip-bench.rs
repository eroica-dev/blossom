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
        SubsetPrefillMode, run_subset_gossip,
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
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        repair_missing: bool,
        #[arg(long, value_enum, default_value_t = PrefillModeArg::None)]
        prefill_mode: PrefillModeArg,
        #[arg(long, default_value_t = 0)]
        prefill_fanout: usize,
        #[arg(long, default_value_t = false)]
        hash_advertise: bool,
        #[arg(long, default_value_t = false)]
        drop_round0_dispatch: bool,
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

    #[derive(Debug, Clone, Copy, ValueEnum)]
    enum PrefillModeArg {
        None,
        Random,
        Scheduled,
    }

    impl From<LatencyDistributionArg> for SubsetLatencyDistribution {
        fn from(value: LatencyDistributionArg) -> Self {
            match value {
                LatencyDistributionArg::Even => Self::Even,
                LatencyDistributionArg::Random => Self::Random,
            }
        }
    }

    impl From<PrefillModeArg> for SubsetPrefillMode {
        fn from(value: PrefillModeArg) -> Self {
            match value {
                PrefillModeArg::None => Self::None,
                PrefillModeArg::Random => Self::Random,
                PrefillModeArg::Scheduled => Self::Scheduled,
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
            prefill_mode: args.prefill_mode.into(),
            prefill_fanout: args.prefill_fanout,
            hash_advertise: args.hash_advertise,
            drop_round0_dispatch: args.drop_round0_dispatch,
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
                "scenario,repeat,epoch,epoch_depth,nodes,quorum_size,rounds,quorums,trusted,shuffle,repair_missing,prefill_mode,prefill_fanout,hash_advertise,drop_round0_dispatch,latency_distribution,latency_ms,latency_min_ms,latency_max_ms,commands_per_node,command_bytes,targets_per_command,total_commands,target_payload_deliveries,metadata_converged_nodes,metadata_converged,subset_payloads_complete_before_repair,subset_payloads_complete_after_repair,subset_missing_payloads_before_repair,subset_missing_payloads_after_repair,subset_delivered_payloads_before_repair,subset_delivered_payloads_after_repair,subset_repair_batches,subset_repair_bytes,subset_repair_latency_ms,prefill_recipients,prefill_expected_hashes,prefill_bytes,hash_advertise_messages,hash_advertise_bytes,duplicate_suppressed_blocks,modeled_prefill_latency_ms,modeled_hash_advertise_latency_ms,modeled_finality_latency_ms,modeled_dispatch_latency_ms,modeled_control_latency_ms,subset_payload_ready_latency_ms,full_block_bytes,full_dispatch_bytes,subset_dispatch_bytes,control_bytes,full_wire_bytes,subset_wire_bytes,full_amplification,subset_amplification,subset_savings_pct,full_tps,subset_payload_ready_tps,full_total_gbps,subset_total_gbps,full_per_node_gbps,subset_per_node_gbps"
            )?;
        }
        for row in rows {
            writeln!(file, "{}", row_to_csv(scenario, repeat, row))?;
        }
        Ok(())
    }

    fn row_to_csv(scenario: &str, repeat: usize, row: &SubsetGossipEpochRow) -> String {
        [
            scenario.to_string(),
            repeat.to_string(),
            row.epoch.to_string(),
            row.epoch_depth.to_string(),
            row.nodes.to_string(),
            row.quorum_size.to_string(),
            row.rounds.to_string(),
            row.quorums.to_string(),
            row.trusted.to_string(),
            row.shuffle.to_string(),
            row.repair_missing.to_string(),
            row.prefill_mode.as_str().to_string(),
            row.prefill_fanout.to_string(),
            row.hash_advertise.to_string(),
            row.drop_round0_dispatch.to_string(),
            row.latency_distribution.as_str().to_string(),
            row.latency_ms.to_string(),
            row.latency_min_ms.to_string(),
            row.latency_max_ms.to_string(),
            row.commands_per_node.to_string(),
            row.command_bytes.to_string(),
            row.targets_per_command.to_string(),
            row.total_commands.to_string(),
            row.target_payload_deliveries.to_string(),
            row.metadata_converged_nodes.to_string(),
            row.metadata_converged.to_string(),
            row.subset_payloads_complete_before_repair.to_string(),
            row.subset_payloads_complete_after_repair.to_string(),
            row.subset_missing_payloads_before_repair.to_string(),
            row.subset_missing_payloads_after_repair.to_string(),
            row.subset_delivered_payloads_before_repair.to_string(),
            row.subset_delivered_payloads_after_repair.to_string(),
            row.subset_repair_batches.to_string(),
            row.subset_repair_bytes.to_string(),
            row.subset_repair_latency_ms.to_string(),
            row.prefill_recipients.to_string(),
            row.prefill_expected_hashes.to_string(),
            row.prefill_bytes.to_string(),
            row.hash_advertise_messages.to_string(),
            row.hash_advertise_bytes.to_string(),
            row.duplicate_suppressed_blocks.to_string(),
            row.modeled_prefill_latency_ms.to_string(),
            row.modeled_hash_advertise_latency_ms.to_string(),
            row.modeled_finality_latency_ms.to_string(),
            row.modeled_dispatch_latency_ms.to_string(),
            row.modeled_control_latency_ms.to_string(),
            row.subset_payload_ready_latency_ms.to_string(),
            row.full_block_bytes.to_string(),
            row.full_dispatch_bytes.to_string(),
            row.subset_dispatch_bytes.to_string(),
            row.control_bytes.to_string(),
            row.full_wire_bytes.to_string(),
            row.subset_wire_bytes.to_string(),
            format!("{:.6}", row.full_amplification),
            format!("{:.6}", row.subset_amplification),
            format!("{:.6}", row.subset_savings_pct),
            format!("{:.6}", row.full_tps),
            format!("{:.6}", row.subset_payload_ready_tps),
            format!("{:.6}", row.full_total_gbps),
            format!("{:.6}", row.subset_total_gbps),
            format!("{:.6}", row.full_per_node_gbps),
            format!("{:.6}", row.subset_per_node_gbps),
        ]
        .join(",")
    }
}

#[cfg(feature = "availability-gossip")]
fn main() -> bench::MainResult<()> {
    bench::main()
}
