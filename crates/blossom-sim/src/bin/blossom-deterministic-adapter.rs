//! Product-owned deterministic-simulation protocol adapter for Blossom.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use deterministic_sim_engine::{
    ADAPTER_PROTOCOL_VERSION, AdapterCapabilities, AdapterDescriptor, AdapterRunRequest,
    AdapterRunResult, CampaignAdapter, EngineError, serve_adapter_once,
};
use deterministic_test_env::{ExplorationMode, PropertyStatus, RunMode};
use serde::Deserialize;

struct BlossomAdapter;

#[derive(Debug, Deserialize)]
struct BlossomArtifact {
    report: BlossomReport,
}

#[derive(Debug, Deserialize)]
struct BlossomReport {
    cells: Vec<BlossomCell>,
    total_events: usize,
    total_schedules: usize,
    safety_passed: bool,
}

#[derive(Debug, Deserialize)]
struct BlossomCell {
    protocol: String,
    topology: String,
    epochs: usize,
    unique_states: usize,
    safety_passed: bool,
    replay_passed: bool,
    property_failures: Vec<String>,
    final_state_digest: String,
}

impl CampaignAdapter for BlossomAdapter {
    fn descriptor(&self) -> Result<AdapterDescriptor, EngineError> {
        Ok(AdapterDescriptor {
            adapter: "blossom/protocol-v1".to_string(),
            implementation: "Blossom HA and trusted deterministic campaigns".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            capabilities: AdapterCapabilities {
                multi_node_topology: true,
                fault_injection: true,
                regional_faults: true,
                // Protocol-mode replacement is an abstract fault. Actual
                // volume replacement is admitted only by the VM profile.
                disk_replacement: false,
                exact_replay: false,
                internal_replay_verification: true,
                reduction: false,
                causality: false,
                ambiguous_outcomes: true,
                exploration_modes: vec![
                    ExplorationMode::Random,
                    ExplorationMode::Systematic,
                    ExplorationMode::NoveltyGuided,
                ],
                property_evaluators: property_evaluators(),
            },
        })
    }

    fn execute(&self, request: &AdapterRunRequest) -> Result<AdapterRunResult, EngineError> {
        if request.schema_version != ADAPTER_PROTOCOL_VERSION {
            return Err(EngineError::Adapter(format!(
                "unsupported request schema {}",
                request.schema_version
            )));
        }
        if request.scenario.is_some()
            || matches!(
                request.mode,
                RunMode::Replay { .. } | RunMode::ReplayThenRandom { .. }
            )
        {
            return Err(EngineError::Adapter(
                "Blossom protocol-v1 executes versioned whole-campaign cells; exact cell replay uses each emitted Blossom replay manifest"
                    .to_string(),
            ));
        }

        let executable = std::env::var_os("BLOSSOM_DETERMINISTIC_CAMPAIGN")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("blossom-deterministic-campaign"));
        let profile = std::env::var("BLOSSOM_CAMPAIGN_PROFILE")
            .unwrap_or_else(|_| inferred_profile(request).to_string());
        let artifact_root = std::env::var_os("BLOSSOM_SIMULATION_ARTIFACT_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("target/deterministic-sandbox/framework"));
        let run_directory = artifact_root.join(format!(
            "{}-{}",
            sanitize(&request.manifest.name),
            request.seed
        ));
        let report_path = run_directory.join("report.json");
        let campaign_stdout_path = run_directory.join("campaign.stdout.log");
        let campaign_stderr_path = run_directory.join("campaign.stderr.log");
        std::fs::create_dir_all(&run_directory)?;
        let status = run_campaign_process(
            &executable,
            &profile,
            request.seed,
            &report_path,
            &campaign_stdout_path,
            &campaign_stderr_path,
        )?;
        if !report_path.is_file() {
            return Err(EngineError::Adapter(format!(
                "Blossom campaign exited with {status} without writing {}",
                report_path.display()
            )));
        }
        let artifact = serde_json::from_slice::<BlossomArtifact>(&std::fs::read(&report_path)?)?;
        let replay_verified = artifact.report.cells.iter().all(|cell| cell.replay_passed);
        let all_failures = artifact
            .report
            .cells
            .iter()
            .flat_map(|cell| cell.property_failures.iter())
            .cloned()
            .collect::<Vec<_>>();
        let properties = request
            .manifest
            .properties
            .iter()
            .map(|property| {
                let failed = all_failures.iter().any(|failure| {
                    failure.starts_with(&property.evaluator)
                        || failure.starts_with(property.id.trim_start_matches("blossom/"))
                });
                (
                    property.id.clone(),
                    if failed {
                        PropertyStatus::Failing
                    } else {
                        PropertyStatus::Passing
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let passed = status.success()
            && artifact.report.safety_passed
            && replay_verified
            && artifact.report.cells.iter().all(|cell| cell.safety_passed)
            && properties
                .values()
                .all(|status| *status == PropertyStatus::Passing);
        let cell_digests = artifact
            .report
            .cells
            .iter()
            .map(|cell| {
                format!(
                    "{}:{}:{}",
                    cell.protocol, cell.topology, cell.final_state_digest
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        Ok(AdapterRunResult {
            schema_version: ADAPTER_PROTOCOL_VERSION,
            adapter: "blossom/protocol-v1".to_string(),
            interactions: artifact.report.cells.iter().map(|cell| cell.epochs).sum(),
            schedules: artifact.report.total_schedules,
            unique_states: artifact
                .report
                .cells
                .iter()
                .map(|cell| cell.unique_states)
                .sum(),
            differential_mismatches: usize::from(!passed),
            internal_replay_verified: replay_verified,
            properties,
            details: BTreeMap::from([
                ("artifact".to_string(), report_path.display().to_string()),
                (
                    "campaign_stderr".to_string(),
                    campaign_stderr_path.display().to_string(),
                ),
                (
                    "campaign_stdout".to_string(),
                    campaign_stdout_path.display().to_string(),
                ),
                ("cell_failures".to_string(), all_failures.join(" | ")),
                ("cell_state_digests".to_string(), cell_digests),
                (
                    "events".to_string(),
                    artifact.report.total_events.to_string(),
                ),
                ("profile".to_string(), profile),
            ]),
            scenario: None,
            trace: None,
        })
    }
}

fn run_campaign_process(
    executable: &Path,
    profile: &str,
    seed: u64,
    report_path: &Path,
    stdout_path: &Path,
    stderr_path: &Path,
) -> Result<ExitStatus, EngineError> {
    let campaign_stdout = File::create(stdout_path)?;
    let campaign_stderr = File::create(stderr_path)?;
    Command::new(executable)
        .args([
            "--profile",
            profile,
            "--seed",
            &seed.to_string(),
            "--output",
        ])
        .arg(report_path)
        // Adapter stdout is reserved for exactly one JSON protocol response.
        // Persist child output as evidence instead of allowing human-readable
        // product logs to corrupt the response stream.
        .stdout(Stdio::from(campaign_stdout))
        .stderr(Stdio::from(campaign_stderr))
        .status()
        .map_err(|error| {
            EngineError::Adapter(format!(
                "failed to start Blossom campaign {}: {error}",
                executable.display()
            ))
        })
}

fn property_evaluators() -> BTreeSet<String> {
    [
        "ha_unique_finality",
        "ha_historical_finality_is_stable",
        "ha_local_chain_is_contiguous",
        "ha_confirmation_has_majority",
        "ha_sealed_prefix_is_immutable",
        "ha_consensus_parameters_agree",
        "ha_application_is_exact_once",
        "ha_application_hashes_agree_at_equal_heads",
        "ha_service_status_is_actionable",
        "ha_unknown_client_outcomes_resolved",
        "ha_converged_after_quiescence",
        "trusted_unique_checkpoint",
        "trusted_stable_prefix",
        "parallel_network_independence",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn inferred_profile(request: &AdapterRunRequest) -> &'static str {
    let exploration = &request.manifest.profile.exploration;
    if exploration.maximum_schedules <= 250
        && request.manifest.profile.workload.maximum_interactions <= 5_000
    {
        "pr"
    } else if exploration.maximum_schedules <= 2_000 {
        "novelty"
    } else if exploration.maximum_schedules <= 20_000 {
        "nightly"
    } else {
        "release"
    }
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

fn main() -> Result<(), EngineError> {
    serve_adapter_once(&BlossomAdapter)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_is_conservative_and_matches_the_product_contract() {
        let descriptor = BlossomAdapter.descriptor().unwrap();
        assert_eq!(descriptor.adapter, "blossom/protocol-v1");
        assert!(descriptor.capabilities.multi_node_topology);
        assert!(descriptor.capabilities.regional_faults);
        assert!(!descriptor.capabilities.disk_replacement);
        assert!(!descriptor.capabilities.exact_replay);
        assert!(descriptor.capabilities.internal_replay_verification);
        assert!(
            descriptor
                .capabilities
                .property_evaluators
                .contains("ha_application_is_exact_once")
        );
    }

    #[cfg(unix)]
    #[test]
    fn campaign_output_isolated_from_adapter_protocol_stdout() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "blossom-deterministic-adapter-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let executable = root.join("campaign.sh");
        std::fs::write(
            &executable,
            "#!/bin/sh\nprintf 'human-readable stdout\\n'\nprintf 'diagnostic stderr\\n' >&2\n",
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let stdout = root.join("campaign.stdout.log");
        let stderr = root.join("campaign.stderr.log");
        let status = run_campaign_process(
            &executable,
            "pr",
            7,
            &root.join("report.json"),
            &stdout,
            &stderr,
        )
        .unwrap();

        assert!(status.success());
        assert_eq!(
            std::fs::read_to_string(stdout).unwrap(),
            "human-readable stdout\n"
        );
        assert_eq!(
            std::fs::read_to_string(stderr).unwrap(),
            "diagnostic stderr\n"
        );
        std::fs::remove_dir_all(root).ok();
    }
}
