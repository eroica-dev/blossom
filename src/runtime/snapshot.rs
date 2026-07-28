//! Versioned runtime snapshot decoding and node-identity validation.

use super::*;

impl RuntimeSnapshotV1 {
    /// Supported JSON snapshot format version.
    pub const VERSION: u16 = 1;

    /// Reads and fully validates a JSON snapshot from disk.
    pub fn read_json(path: impl AsRef<Path>) -> Result<Self> {
        let bytes = fs::read(path.as_ref()).map_err(|err| BlossomError::Io(err.to_string()))?;
        let snapshot: Self = serde_json::from_slice(&bytes).map_err(|err| {
            BlossomError::WireProtocol(format!("invalid runtime snapshot: {err}"))
        })?;
        snapshot.validate()?;
        Ok(snapshot)
    }

    /// Durably replaces a JSON snapshot using file and directory synchronization.
    pub fn write_json_atomic(&self, path: impl AsRef<Path>) -> Result<()> {
        self.validate()?;
        let path = path.as_ref();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).map_err(|err| BlossomError::Io(err.to_string()))?;
        }
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("runtime-snapshot.json");
        let tmp = path.with_file_name(format!("{file_name}.tmp"));
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|err| BlossomError::WireProtocol(format!("encode runtime snapshot: {err}")))?;
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp)
            .map_err(|err| BlossomError::Io(err.to_string()))?;
        file.write_all(&bytes)
            .map_err(|err| BlossomError::Io(err.to_string()))?;
        file.sync_all()
            .map_err(|err| BlossomError::Io(err.to_string()))?;
        drop(file);
        fs::rename(&tmp, path).map_err(|err| BlossomError::Io(err.to_string()))?;
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|err| BlossomError::Io(err.to_string()))?;
        }
        Ok(())
    }

    /// Validates format, genesis, chain linkage, certificates, and membership.
    pub fn validate(&self) -> Result<()> {
        if self.version != Self::VERSION {
            return Err(BlossomError::WireProtocol(format!(
                "unsupported runtime snapshot version {}",
                self.version
            )));
        }
        if self.epochchain.epochchain.is_empty() {
            return Err(BlossomError::EmptyEpochChain);
        }
        self.consensus_parameters.validate()?;
        validate_genesis_anchor(
            self.epochchain
                .epochchain
                .first()
                .ok_or(BlossomError::EmptyEpochChain)?,
            self.group_id,
        )?;
        for (index, epoch) in self.epochchain.epochchain.iter().enumerate() {
            if epoch.body.group_id != self.group_id {
                return Err(BlossomError::WireProtocol(
                    "snapshot epoch group id mismatch".to_string(),
                ));
            }
            let epoch_parameters = epoch.body.effective_consensus_parameters();
            epoch_parameters.validate()?;
            if epoch_parameters != self.consensus_parameters {
                return Err(BlossomError::ConsensusParametersMismatch {
                    configured: self.consensus_parameters.quorum_size.get(),
                    committed: epoch_parameters.quorum_size.get(),
                });
            }
            let expected_hash = HashType::hash(&epoch.body.to_bytes());
            if epoch.hash != expected_hash {
                return Err(BlossomError::WireProtocol(
                    "snapshot epoch hash mismatch".to_string(),
                ));
            }
            if index > 0 {
                let previous = &self.epochchain.epochchain[index - 1];
                if epoch.body.last_epoch != previous.hash {
                    return Err(BlossomError::WireProtocol(
                        "snapshot epoch chain linkage mismatch".to_string(),
                    ));
                }
                if epoch.body.nonce != previous.body.nonce.new_next() {
                    return Err(BlossomError::InvalidEpochNonce);
                }
                if let Some(previous_nonce) = epoch.body.previous_nonce
                    && previous_nonce != previous.body.nonce
                {
                    return Err(BlossomError::InvalidEpochNonce);
                }
                if self.trust_mode == TrustMode::Verified {
                    validate_certified_extension(
                        previous,
                        epoch,
                        self.consensus_node_removal_policy,
                    )?;
                }
            } else if epoch.body.previous_nonce.is_some() {
                return Err(BlossomError::WireProtocol(
                    "genesis epoch must not claim a previous nonce".to_string(),
                ));
            }
        }
        let latest = self
            .epochchain
            .epochchain
            .last()
            .ok_or(BlossomError::EmptyEpochChain)?;
        if !latest.body.verifiers.contains_key(&self.self_public_key) {
            return Err(BlossomError::WireProtocol(
                "snapshot self public key is not in latest verifier set".to_string(),
            ));
        }
        Ok(())
    }

    /// Validates the snapshot and binds it to the supplied local public identity.
    pub fn validate_for_node(&self, self_node: &NodeIdentity) -> Result<()> {
        self.validate()?;
        if self.self_public_key != self_node.public_key() {
            return Err(BlossomError::KeyMismatch);
        }
        Ok(())
    }
}
