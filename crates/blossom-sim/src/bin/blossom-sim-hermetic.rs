use std::collections::BTreeMap;
use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use std::path::PathBuf;

use blossom::{BlossomError, NodePing, TrustMode, WireRequest};
use blossom_sim::{
    DataPattern, DeterministicData, HermeticActionRecord, HermeticEventLog, HermeticOutcome,
    HermeticPlan, HermeticSimConfig, run_plan,
};
use clap::Parser;

type MainResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Parser, Debug)]
#[command(
    name = "blossom-sim-hermetic",
    about = "Run a socket-free deterministic Blossom simulation with logical time and replayable faults"
)]
struct Args {
    #[arg(long, default_value_t = 6)]
    nodes: usize,
    #[arg(long, default_value_t = 100)]
    requests: usize,
    #[arg(long, default_value_t = 0)]
    payload_bytes: usize,
    #[arg(long, default_value_t = DataPattern::SplitMix)]
    data_pattern: DataPattern,
    #[arg(long, default_value_t = 0)]
    default_latency_ms: u64,
    #[arg(long, default_value_t = 0)]
    jitter_ms: u64,
    #[arg(long, default_value_t = 0)]
    drop_ppm: u32,
    #[arg(long, default_value_t = 0x7369_6d5f_626c_6f31)]
    seed: u64,
    #[arg(long, default_value_t = false)]
    trusted: bool,
    #[arg(long, value_delimiter = ',')]
    slow_nodes: Vec<usize>,
    #[arg(long, default_value_t = 0)]
    slow_at_ms: u64,
    #[arg(long, default_value_t = 0)]
    slow_latency_ms: u64,
    #[arg(long, value_delimiter = ',')]
    down_nodes: Vec<usize>,
    #[arg(long, default_value_t = 0)]
    down_at_ms: u64,
    #[arg(long)]
    up_at_ms: Option<u64>,
    #[arg(long)]
    restart_after_ms: Option<u64>,
    #[arg(long)]
    csv: Option<PathBuf>,
    #[arg(long)]
    event_log: Option<PathBuf>,
    #[arg(long)]
    bug_log: Option<PathBuf>,
    #[arg(long)]
    bug_latency_budget_ms: Option<u64>,
}

#[tokio::main]
async fn main() -> MainResult<()> {
    let args = Args::parse();
    if args.nodes == 0 {
        return Err(BlossomError::WireProtocol(
            "hermetic simulation requires at least one node".to_string(),
        )
        .into());
    }

    let plan = build_plan(&args)?;
    let log = run_plan(&plan).await?;
    let summary = SimSummary::from_log(&args, &log);
    println!("{}", summary.to_csv());

    if let Some(path) = args.csv.as_ref() {
        write_summary(path, &summary)?;
        eprintln!("wrote {}", path.display());
    }
    if let Some(path) = args.event_log.as_ref() {
        write_event_log(path, &log)?;
        eprintln!("wrote {}", path.display());
    }
    if let Some(path) = args.bug_log.as_ref() {
        write_bug_log(path, &args, &summary, &log)?;
        eprintln!("wrote {}", path.display());
    }

    Ok(())
}

fn build_plan(args: &Args) -> MainResult<HermeticPlan> {
    let mut plan = HermeticPlan::new(
        args.nodes,
        if args.trusted {
            TrustMode::Trusted
        } else {
            TrustMode::Verified
        },
        HermeticSimConfig {
            seed: args.seed,
            default_latency_ms: args.default_latency_ms,
            jitter_ms: args.jitter_ms,
            drop_ppm: args.drop_ppm,
        },
    );

    if !args.slow_nodes.is_empty() {
        plan.set_latency(
            args.slow_at_ms,
            args.slow_nodes.iter().copied(),
            args.slow_latency_ms,
        );
    }

    for node in &args.down_nodes {
        plan.node_down(args.down_at_ms, *node);
        if let Some(up_at_ms) = args.up_at_ms.or_else(|| {
            args.restart_after_ms
                .map(|restart_after_ms| args.down_at_ms.saturating_add(restart_after_ms))
        }) {
            plan.node_up(up_at_ms, *node);
        }
    }

    let data = DeterministicData::new(args.seed, args.data_pattern);
    for request_index in 0..args.requests {
        let source = 0usize;
        let target = (request_index % args.nodes.saturating_sub(1).max(1)) + 1;
        let target = target.min(args.nodes - 1);
        let payload = data.bytes(args.payload_bytes, target as u64, request_index as u64);
        plan.request(
            request_index as u64,
            source,
            target,
            WireRequest::Ping(NodePing::with_payload(request_index as u64, payload)),
        );
    }

    Ok(plan)
}

#[derive(Debug, Clone)]
struct SimSummary {
    nodes: usize,
    requests: usize,
    payload_bytes: usize,
    data_pattern: DataPattern,
    seed: u64,
    default_latency_ms: u64,
    jitter_ms: u64,
    drop_ppm: u32,
    records: usize,
    responses: usize,
    dropped: usize,
    unavailable: usize,
    errors: usize,
    applied_faults: usize,
    final_time_ms: u64,
}

impl SimSummary {
    fn from_log(args: &Args, log: &HermeticEventLog) -> Self {
        let mut errors = 0usize;
        let mut applied_faults = 0usize;
        for record in &log.records {
            match record.outcome {
                HermeticOutcome::Error { .. } => errors += 1,
                HermeticOutcome::Applied => applied_faults += 1,
                _ => {}
            }
        }

        Self {
            nodes: args.nodes,
            requests: args.requests,
            payload_bytes: args.payload_bytes,
            data_pattern: args.data_pattern,
            seed: args.seed,
            default_latency_ms: args.default_latency_ms,
            jitter_ms: args.jitter_ms,
            drop_ppm: args.drop_ppm,
            records: log.records.len(),
            responses: log.response_count(),
            dropped: log.dropped_count(),
            unavailable: log.unavailable_count(),
            errors,
            applied_faults,
            final_time_ms: log
                .records
                .iter()
                .map(|record| record.delivered_at_ms)
                .max()
                .unwrap_or(0),
        }
    }

    fn to_csv(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            self.nodes,
            self.requests,
            self.payload_bytes,
            self.data_pattern,
            self.seed,
            self.default_latency_ms,
            self.jitter_ms,
            self.drop_ppm,
            self.records,
            self.responses,
            self.dropped,
            self.unavailable,
            self.errors,
            self.applied_faults,
            self.final_time_ms,
        )
    }
}

fn write_summary(path: &PathBuf, summary: &SimSummary) -> MainResult<()> {
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    writeln!(
        file,
        "nodes,requests,payload_bytes,data_pattern,seed,default_latency_ms,jitter_ms,drop_ppm,records,responses,dropped,unavailable,errors,applied_faults,final_time_ms"
    )?;
    writeln!(file, "{}", summary.to_csv())?;
    Ok(())
}

fn write_event_log(path: &PathBuf, log: &HermeticEventLog) -> MainResult<()> {
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    writeln!(
        file,
        "event_id,planned_at_ms,delivered_at_ms,action,source,target,node,nodes,latency_ms,request_kind,outcome,response_kind,message"
    )?;
    for record in &log.records {
        writeln!(file, "{}", event_record_csv(record))?;
    }
    Ok(())
}

fn write_bug_log(
    path: &PathBuf,
    args: &Args,
    summary: &SimSummary,
    log: &HermeticEventLog,
) -> MainResult<()> {
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }

    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;

    let incidents = collect_incidents(args, log);
    let event_log = args
        .event_log
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "(not written)".to_string());

    writeln!(file, "# Blossom Simulation Bug Log")?;
    writeln!(file)?;
    writeln!(file, "## Reproduce")?;
    writeln!(file)?;
    writeln!(file, "```bash")?;
    writeln!(file, "{}", replay_command(args))?;
    writeln!(file, "```")?;
    writeln!(file)?;
    writeln!(
        file,
        "- summary_csv: {}",
        display_optional(args.csv.as_ref())
    )?;
    writeln!(file, "- event_log_csv: {event_log}")?;
    writeln!(file)?;
    writeln!(file, "## Scenario")?;
    writeln!(file)?;
    writeln!(file, "- nodes: {}", args.nodes)?;
    writeln!(file, "- requests: {}", args.requests)?;
    writeln!(file, "- payload_bytes: {}", args.payload_bytes)?;
    writeln!(file, "- data_pattern: {}", args.data_pattern)?;
    writeln!(file, "- seed: {}", args.seed)?;
    writeln!(
        file,
        "- trust_mode: {}",
        if args.trusted { "trusted" } else { "verified" }
    )?;
    writeln!(file, "- default_latency_ms: {}", args.default_latency_ms)?;
    writeln!(file, "- jitter_ms: {}", args.jitter_ms)?;
    writeln!(file, "- drop_ppm: {}", args.drop_ppm)?;
    writeln!(file, "- slow_nodes: {}", format_node_list(&args.slow_nodes))?;
    writeln!(file, "- slow_at_ms: {}", args.slow_at_ms)?;
    writeln!(file, "- slow_latency_ms: {}", args.slow_latency_ms)?;
    writeln!(file, "- down_nodes: {}", format_node_list(&args.down_nodes))?;
    writeln!(file, "- down_at_ms: {}", args.down_at_ms)?;
    writeln!(
        file,
        "- up_at_ms: {}",
        args.up_at_ms
            .map(|value| value.to_string())
            .unwrap_or_else(|| "never".to_string())
    )?;
    writeln!(
        file,
        "- restart_after_ms: {}",
        args.restart_after_ms
            .map(|value| value.to_string())
            .unwrap_or_else(|| "disabled".to_string())
    )?;
    writeln!(
        file,
        "- bug_latency_budget_ms: {}",
        args.bug_latency_budget_ms
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unset".to_string())
    )?;
    writeln!(file)?;
    writeln!(file, "## Summary")?;
    writeln!(file)?;
    writeln!(file, "- records: {}", summary.records)?;
    writeln!(file, "- responses: {}", summary.responses)?;
    writeln!(file, "- dropped: {}", summary.dropped)?;
    writeln!(file, "- unavailable: {}", summary.unavailable)?;
    writeln!(file, "- errors: {}", summary.errors)?;
    writeln!(file, "- applied_faults: {}", summary.applied_faults)?;
    writeln!(file, "- final_time_ms: {}", summary.final_time_ms)?;
    writeln!(file)?;
    writeln!(file, "## Bug Candidates")?;
    writeln!(file)?;

    if incidents.is_empty() {
        writeln!(file, "No bug candidates were detected.")?;
    } else {
        for incident in incidents {
            writeln!(file, "### {}", incident.title)?;
            writeln!(file)?;
            writeln!(file, "- severity: {}", incident.severity)?;
            writeln!(file, "- count: {}", incident.count)?;
            writeln!(
                file,
                "- expected_under_faults: {}",
                incident.expected_under_faults
            )?;
            writeln!(file, "- event_ids: {}", incident.event_ids)?;
            writeln!(file, "- note: {}", incident.note)?;
            writeln!(file)?;
        }
    }

    Ok(())
}

fn event_record_csv(record: &blossom_sim::HermeticEventRecord) -> String {
    let (action, source, target, node, nodes, latency_ms, request_kind) = match &record.action {
        HermeticActionRecord::Request {
            source,
            target,
            request_kind,
        } => (
            "request",
            source.to_string(),
            target.to_string(),
            String::new(),
            String::new(),
            String::new(),
            (*request_kind).to_string(),
        ),
        HermeticActionRecord::NodeDown { node } => (
            "node_down",
            String::new(),
            String::new(),
            node.to_string(),
            String::new(),
            String::new(),
            String::new(),
        ),
        HermeticActionRecord::NodeUp { node } => (
            "node_up",
            String::new(),
            String::new(),
            node.to_string(),
            String::new(),
            String::new(),
            String::new(),
        ),
        HermeticActionRecord::SetLatency { nodes, latency_ms } => (
            "set_latency",
            String::new(),
            String::new(),
            String::new(),
            nodes
                .iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join("|"),
            latency_ms.to_string(),
            String::new(),
        ),
    };
    let (outcome, response_kind, message) = match &record.outcome {
        HermeticOutcome::Response { response_kind } => {
            ("response", (*response_kind).to_string(), String::new())
        }
        HermeticOutcome::Error { message } => ("error", String::new(), sanitize_csv(message)),
        HermeticOutcome::Dropped => ("dropped", String::new(), String::new()),
        HermeticOutcome::NodeUnavailable => ("node_unavailable", String::new(), String::new()),
        HermeticOutcome::Applied => ("applied", String::new(), String::new()),
    };

    format!(
        "{},{},{},{},{},{},{},{},{},{},{},{},{}",
        record.event_id,
        record.planned_at_ms,
        record.delivered_at_ms,
        action,
        source,
        target,
        node,
        nodes,
        latency_ms,
        request_kind,
        outcome,
        response_kind,
        message,
    )
}

fn sanitize_csv(value: &str) -> String {
    value.replace(',', ";").replace('\n', " ")
}

#[derive(Debug, Clone)]
struct BugIncident {
    severity: &'static str,
    title: String,
    count: usize,
    expected_under_faults: bool,
    event_ids: String,
    note: String,
}

fn collect_incidents(args: &Args, log: &HermeticEventLog) -> Vec<BugIncident> {
    let mut incidents = Vec::new();

    let error_records = records_with(log, |record| {
        matches!(record.outcome, HermeticOutcome::Error { .. })
    });
    if !error_records.is_empty() {
        incidents.push(BugIncident {
            severity: "high",
            title: "Protocol or handler errors".to_string(),
            count: error_records.len(),
            expected_under_faults: false,
            event_ids: sample_event_ids(&error_records),
            note: "Any simulator error is treated as actionable unless the test intentionally asserts that error.".to_string(),
        });
    }

    let dropped_records = records_with(log, |record| {
        matches!(record.outcome, HermeticOutcome::Dropped)
    });
    if !dropped_records.is_empty() {
        incidents.push(BugIncident {
            severity: if args.drop_ppm == 0 { "high" } else { "info" },
            title: "Dropped requests".to_string(),
            count: dropped_records.len(),
            expected_under_faults: args.drop_ppm > 0,
            event_ids: sample_event_ids(&dropped_records),
            note: if args.drop_ppm == 0 {
                "Drops occurred even though the scenario configured drop_ppm=0.".to_string()
            } else {
                "Drops came from the deterministic fault injector. Re-run with the same seed to reproduce the exact events.".to_string()
            },
        });
    }

    let unavailable_by_node = unavailable_by_target(log);
    for (node, records) in unavailable_by_node {
        incidents.push(BugIncident {
            severity: if args.down_nodes.contains(&node) { "info" } else { "high" },
            title: format!("Node {node} unavailable"),
            count: records.len(),
            expected_under_faults: args.down_nodes.contains(&node),
            event_ids: sample_event_ids(&records),
            note: if args.down_nodes.contains(&node) {
                "Unavailable responses match an injected node-down interval. Check the event log around down_at_ms/up_at_ms if the window is surprising.".to_string()
            } else {
                "The node was not configured as a down node, so this is a bug candidate.".to_string()
            },
        });
    }

    if let Some(budget_ms) = args.bug_latency_budget_ms {
        let slow_records = records_with(log, |record| {
            matches!(record.action, HermeticActionRecord::Request { .. })
                && matches!(record.outcome, HermeticOutcome::Response { .. })
                && record.delivered_at_ms.saturating_sub(record.planned_at_ms) > budget_ms
        });
        if !slow_records.is_empty() {
            incidents.push(BugIncident {
                severity: "medium",
                title: format!("Requests exceeded {budget_ms}ms latency budget"),
                count: slow_records.len(),
                expected_under_faults: !args.slow_nodes.is_empty(),
                event_ids: sample_event_ids(&slow_records),
                note: "Latency budget is caller-defined. Use the event log to inspect the target nodes and injected latency rules.".to_string(),
            });
        }
    }

    let request_records = log
        .records
        .iter()
        .filter(|record| matches!(record.action, HermeticActionRecord::Request { .. }))
        .count();
    if request_records != args.requests {
        incidents.push(BugIncident {
            severity: "high",
            title: "Request accounting mismatch".to_string(),
            count: request_records.abs_diff(args.requests),
            expected_under_faults: false,
            event_ids: "(aggregate)".to_string(),
            note: format!(
                "Plan requested {} requests, but the event log contains {request_records} request records.",
                args.requests
            ),
        });
    }

    incidents
}

fn records_with(
    log: &HermeticEventLog,
    predicate: impl Fn(&blossom_sim::HermeticEventRecord) -> bool,
) -> Vec<&blossom_sim::HermeticEventRecord> {
    log.records
        .iter()
        .filter(|record| predicate(record))
        .collect()
}

fn unavailable_by_target(
    log: &HermeticEventLog,
) -> BTreeMap<usize, Vec<&blossom_sim::HermeticEventRecord>> {
    let mut by_target = BTreeMap::new();
    for record in &log.records {
        if !matches!(record.outcome, HermeticOutcome::NodeUnavailable) {
            continue;
        }
        let HermeticActionRecord::Request { target, .. } = record.action else {
            continue;
        };
        by_target
            .entry(target)
            .or_insert_with(Vec::new)
            .push(record);
    }
    by_target
}

fn sample_event_ids(records: &[&blossom_sim::HermeticEventRecord]) -> String {
    let mut values = records
        .iter()
        .take(12)
        .map(|record| record.event_id.to_string())
        .collect::<Vec<_>>();
    if records.len() > values.len() {
        values.push(format!("...+{}", records.len() - values.len()));
    }
    values.join(",")
}

fn display_optional(path: Option<&PathBuf>) -> String {
    path.map(|path| path.display().to_string())
        .unwrap_or_else(|| "(not written)".to_string())
}

fn replay_command(args: &Args) -> String {
    let mut parts = vec![
        "cargo".to_string(),
        "run".to_string(),
        "--release".to_string(),
        "-p".to_string(),
        "blossom-sim".to_string(),
        "--bin".to_string(),
        "blossom-sim-hermetic".to_string(),
        "--".to_string(),
    ];
    push_arg_value(&mut parts, "--nodes", args.nodes);
    push_arg_value(&mut parts, "--requests", args.requests);
    push_arg_value(&mut parts, "--payload-bytes", args.payload_bytes);
    push_arg_value(&mut parts, "--data-pattern", args.data_pattern);
    push_arg_value(&mut parts, "--default-latency-ms", args.default_latency_ms);
    push_arg_value(&mut parts, "--jitter-ms", args.jitter_ms);
    push_arg_value(&mut parts, "--drop-ppm", args.drop_ppm);
    push_arg_value(&mut parts, "--seed", args.seed);
    if args.trusted {
        parts.push("--trusted".to_string());
    }
    if !args.slow_nodes.is_empty() {
        push_arg_value(&mut parts, "--slow-nodes", join_nodes(&args.slow_nodes));
        push_arg_value(&mut parts, "--slow-at-ms", args.slow_at_ms);
        push_arg_value(&mut parts, "--slow-latency-ms", args.slow_latency_ms);
    }
    if !args.down_nodes.is_empty() {
        push_arg_value(&mut parts, "--down-nodes", join_nodes(&args.down_nodes));
        push_arg_value(&mut parts, "--down-at-ms", args.down_at_ms);
        if let Some(up_at_ms) = args.up_at_ms {
            push_arg_value(&mut parts, "--up-at-ms", up_at_ms);
        } else if let Some(restart_after_ms) = args.restart_after_ms {
            push_arg_value(&mut parts, "--restart-after-ms", restart_after_ms);
        }
    }
    if let Some(budget_ms) = args.bug_latency_budget_ms {
        push_arg_value(&mut parts, "--bug-latency-budget-ms", budget_ms);
    }
    parts.join(" ")
}

fn push_arg_value(parts: &mut Vec<String>, name: &str, value: impl ToString) {
    parts.push(name.to_string());
    parts.push(shell_quote(&value.to_string()));
}

fn shell_quote(value: &str) -> String {
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | ',' | '/' | ':'))
    {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn format_node_list(nodes: &[usize]) -> String {
    if nodes.is_empty() {
        "none".to_string()
    } else {
        join_nodes(nodes)
    }
}

fn join_nodes(nodes: &[usize]) -> String {
    nodes
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(",")
}
