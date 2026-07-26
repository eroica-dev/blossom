//! Host durability boundary for deterministic product-adapter runs.
//!
//! The protocol scheduler itself must not call the host filesystem. Durable
//! campaigns deliberately exercise the production redb implementation, so
//! disk replacement is isolated here as a reviewed, non-replayable host
//! boundary. Logical replay remains verified inside the Blossom adapter.

use std::path::Path;

pub(crate) fn replace_store(path: &Path) -> blossom::Result<()> {
    if path.exists() {
        std::fs::remove_file(path).map_err(|error| blossom::BlossomError::Io(error.to_string()))?;
    }
    Ok(())
}
