//! Correctness-gated benchmark runner used by release validation.

use std::fs;
use std::path::{Path, PathBuf};

use blossom_bench_harness::PerformanceArtifact;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "blossom-benchmark-gate",
    about = "Reject incomplete or correctness-failing benchmark artifacts"
)]
struct Args {
    #[arg(long)]
    artifact: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();
    let bytes = fs::read(&args.artifact)?;
    let artifact: PerformanceArtifact = serde_json::from_slice(&bytes)?;
    let mut failures = artifact.validate_for_publication().unwrap_err_or_default();
    let base = args.artifact.parent().unwrap_or_else(|| Path::new("."));
    for (name, path) in [
        ("milestone events", &artifact.artifacts.milestone_events),
        ("histories", &artifact.artifacts.histories),
        (
            "environment snapshot",
            &artifact.artifacts.environment_snapshot,
        ),
        (
            "configuration snapshot",
            &artifact.artifacts.configuration_snapshot,
        ),
        ("safety manifest", &artifact.artifacts.safety_manifest),
        ("fault trace", &artifact.artifacts.fault_trace),
        (
            "dependency versions",
            &artifact.artifacts.dependency_versions,
        ),
        ("summary report", &artifact.artifacts.summary_report),
    ] {
        let path = base.join(path);
        if !path.is_file() || fs::metadata(&path)?.len() == 0 {
            failures.push(format!(
                "{name} artifact is missing or empty: {}",
                path.display()
            ));
        }
    }
    if !failures.is_empty() {
        for failure in failures {
            eprintln!("gate failed: {failure}");
        }
        return Err("benchmark artifact is not publishable".into());
    }
    println!("publishable: {}", args.artifact.display());
    Ok(())
}

trait ResultExt {
    fn unwrap_err_or_default(self) -> Vec<String>;
}

impl ResultExt for Result<(), Vec<String>> {
    fn unwrap_err_or_default(self) -> Vec<String> {
        match self {
            Ok(()) => Vec::new(),
            Err(errors) => errors,
        }
    }
}
