use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{Duration, Instant};

use blossom_sim::{
    DeterministicCampaignArtifact, DeterministicCampaignProfile, run_deterministic_campaign,
};
use clap::Parser;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, Parser)]
#[command(
    name = "blossom-deterministic-campaign",
    about = "Run replayable HA and trusted Blossom deterministic fault campaigns"
)]
struct Args {
    #[arg(long, default_value = "pr")]
    profile: ProfileArgument,
    #[arg(long, default_value_t = 0x6473_745f_626c_6f73)]
    seed: u64,
    /// Continue novelty runs until this wall-clock budget is reached.
    #[arg(long, default_value_t = 0)]
    budget_seconds: u64,
    #[arg(
        long,
        default_value = "target/deterministic-sandbox/latest/report.json"
    )]
    output: PathBuf,
}

#[derive(Debug, Clone, Copy)]
struct ProfileArgument(DeterministicCampaignProfile);

impl FromStr for ProfileArgument {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "pr" => Ok(Self(DeterministicCampaignProfile::Pr)),
            "nightly" => Ok(Self(DeterministicCampaignProfile::Nightly)),
            "release" => Ok(Self(DeterministicCampaignProfile::Release)),
            _ => Err(format!(
                "unsupported deterministic profile {value:?}; expected pr, nightly, or release"
            )),
        }
    }
}

fn main() -> Result<(), BoxError> {
    let args = Args::parse();
    let started = Instant::now();
    let mut report = run_deterministic_campaign(args.profile.0, args.seed)?;
    let budget = Duration::from_secs(args.budget_seconds);
    let mut iteration = 1u64;
    while !budget.is_zero() && started.elapsed() < budget {
        let novelty = run_deterministic_campaign(
            DeterministicCampaignProfile::Pr,
            args.seed ^ iteration.wrapping_mul(0x9e37_79b9_7f4a_7c15),
        )?;
        report.total_events = report.total_events.saturating_add(novelty.total_events);
        report.total_schedules = report
            .total_schedules
            .saturating_add(novelty.total_schedules);
        report.safety_passed &= novelty.safety_passed;
        report.cells.extend(novelty.cells);
        iteration = iteration.saturating_add(1);
    }
    let git_revision = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let artifact = DeterministicCampaignArtifact {
        schema_version: 1,
        git_revision,
        report,
    };
    let output_dir = args
        .output
        .parent()
        .ok_or("deterministic output must have a parent directory")?;
    fs::create_dir_all(output_dir)?;
    write_cell_artifacts(output_dir, &artifact)?;
    let mut summary = artifact.clone();
    for cell in &mut summary.report.cells {
        cell.scenario = None;
        cell.minimized = None;
        cell.trace = None;
    }
    fs::write(&args.output, serde_json::to_vec_pretty(&summary)?)?;
    println!("{}", args.output.display());
    if !artifact.report.safety_passed {
        return Err("deterministic campaign failed one or more safety cells".into());
    }
    Ok(())
}

fn write_cell_artifacts(
    output_dir: &std::path::Path,
    artifact: &DeterministicCampaignArtifact,
) -> Result<(), BoxError> {
    for (index, cell) in artifact.report.cells.iter().enumerate() {
        let cell_dir = output_dir.join(format!("cell-{index:04}-{}", sanitize(&cell.topology)));
        fs::create_dir_all(&cell_dir)?;
        let mut cell_summary = cell.clone();
        cell_summary.scenario = None;
        cell_summary.minimized = None;
        cell_summary.trace = None;
        fs::write(
            cell_dir.join("summary.json"),
            serde_json::to_vec_pretty(&cell_summary)?,
        )?;
        if let Some(scenario) = &cell.scenario {
            fs::write(
                cell_dir.join("scenario.json"),
                serde_json::to_vec_pretty(scenario)?,
            )?;
        }
        if let Some(trace) = &cell.trace {
            if !cell.safety_passed || !cell.replay_passed {
                fs::write(
                    cell_dir.join("failing-trace.json"),
                    serde_json::to_vec_pretty(trace)?,
                )?;
            }
            fs::write(
                cell_dir.join("trace-choices.json"),
                serde_json::to_vec_pretty(&trace.choices)?,
            )?;
            let compact_events = trace
                .events
                .iter()
                .map(|event| {
                    serde_json::json!({
                        "sequence": event.sequence,
                        "at_micros": event.at.0,
                        "key": &event.event.key,
                        "disposition": &event.disposition,
                        "state_digest": &event.state_digest,
                    })
                })
                .collect::<Vec<_>>();
            fs::write(
                cell_dir.join("state-digests.json"),
                serde_json::to_vec_pretty(&compact_events)?,
            )?;
            fs::write(
                cell_dir.join("client-history.json"),
                serde_json::to_vec_pretty(&trace.client_history)?,
            )?;
            let unknown_outcomes = trace
                .client_history
                .iter()
                .filter(|event| {
                    matches!(
                        event,
                        deterministic_test_env::ClientHistoryEvent::Complete {
                            outcome: deterministic_test_env::ClientOutcome::Unknown,
                            ..
                        }
                    )
                })
                .count();
            fs::write(
                cell_dir.join("linearizability-report.json"),
                serde_json::to_vec_pretty(&serde_json::json!({
                    "applicable": false,
                    "passed": true,
                    "unknown_outcomes": unknown_outcomes,
                    "reason": "This cell drives protocol stages; conflicting application histories are checked by the shared HA/OpenRaft benchmark harness.",
                }))?,
            )?;
            fs::write(
                cell_dir.join("properties.json"),
                serde_json::to_vec_pretty(&serde_json::json!({
                    "statuses": &trace.properties.statuses,
                    "failures": trace.properties.failures().collect::<Vec<_>>(),
                }))?,
            )?;
            fs::write(
                cell_dir.join("fault-coverage.json"),
                serde_json::to_vec_pretty(&trace.fault_coverage)?,
            )?;
        }
        if let Some(manifest) = &cell.replay_manifest {
            let mut manifest = manifest.clone();
            manifest.git_revision = artifact.git_revision.clone();
            fs::write(
                cell_dir.join("replay-manifest.json"),
                serde_json::to_vec_pretty(&manifest)?,
            )?;
        }
        if let Some(minimized) = &cell.minimized {
            fs::write(
                cell_dir.join("minimized-scenario.json"),
                serde_json::to_vec_pretty(&minimized.scenario)?,
            )?;
            fs::write(
                cell_dir.join("minimized-trace.json"),
                serde_json::to_vec_pretty(&minimized.trace)?,
            )?;
        }
    }
    Ok(())
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}
