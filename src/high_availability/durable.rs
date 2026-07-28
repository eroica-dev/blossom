//! Validation, recovery, and delta persistence for durable HA state.

use super::*;

impl HighAvailabilityRuntimeState {
    pub(super) fn validate(&self) -> Result<()> {
        self.parameters.validate()?;
        self.members.validate()?;
        if self.members.member(self.self_slot).is_none() {
            return Err(BlossomError::UnknownSender);
        }
        if self.epochs.is_empty() {
            return Err(BlossomError::EmptyEpochChain);
        }
        let mut genesis_members = self.members.clone();
        genesis_members.active_mask = low_bits(genesis_members.member_count);
        if let Some(checkpoint) = &self.checkpoint {
            checkpoint.validate(&self.members, self.parameters)?;
            let stored_anchor = borsh::to_vec(&self.epochs[0]).map_err(|error| {
                BlossomError::WireProtocol(format!("encode stored HA checkpoint anchor: {error}"))
            })?;
            let certified_anchor = borsh::to_vec(&checkpoint.through_epoch).map_err(|error| {
                BlossomError::WireProtocol(format!(
                    "encode certified HA checkpoint anchor: {error}"
                ))
            })?;
            if stored_anchor != certified_anchor {
                return Err(BlossomError::WireProtocol(
                    "HA retained history does not begin at its certified checkpoint".to_string(),
                ));
            }
        } else {
            let expected_genesis =
                HaEpoch::genesis(self.group_id, &genesis_members, self.parameters);
            let stored_genesis = borsh::to_vec(&self.epochs[0]).map_err(|error| {
                BlossomError::WireProtocol(format!("encode stored HA genesis: {error}"))
            })?;
            let canonical_genesis = borsh::to_vec(&expected_genesis).map_err(|error| {
                BlossomError::WireProtocol(format!("encode canonical HA genesis: {error}"))
            })?;
            if stored_genesis != canonical_genesis {
                return Err(BlossomError::WireProtocol(
                    "HA genesis does not match the committed fixed membership".to_string(),
                ));
            }
        }
        for (index, epoch) in self.epochs.iter().enumerate() {
            if epoch.group_id != self.group_id
                || epoch.fixed_membership_hash != self.members.fixed_identity_hash()
                || epoch.parameters != self.parameters
                || epoch.parameters_hash != self.parameters.hash()
            {
                return Err(BlossomError::InvalidConfiguration(
                    "HA epoch parameters or group mismatch".to_string(),
                ));
            }
            if epoch.hash != epoch.compute_hash() {
                return Err(BlossomError::WireProtocol(
                    "HA epoch hash mismatch".to_string(),
                ));
            }
            if index > 0 {
                let previous = &self.epochs[index - 1];
                if epoch.previous_epoch_hash != previous.hash
                    || epoch.previous_epoch_nonce != Some(previous.nonce)
                    || epoch.nonce != previous.nonce.new_next()
                {
                    return Err(BlossomError::WireProtocol(
                        "HA epoch chain linkage mismatch".to_string(),
                    ));
                }
                epoch.validate(&self.members)?;
            }
        }
        let tip = self.epochs.last().expect("non-empty checked above");
        if self.checkpoint.as_ref().is_some_and(|checkpoint| {
            checkpoint.through_epoch.nonce
                > Nonce::new(
                    tip.nonce
                        .value()
                        .saturating_sub(u64::from(self.parameters.mutable_epoch_depth)),
                )
        }) {
            return Err(BlossomError::WireProtocol(
                "HA checkpoint is newer than the sealed watermark".to_string(),
            ));
        }
        if self.round.round_id.group_id != self.group_id
            || self.round.round_id.fixed_membership_hash != self.members.fixed_identity_hash()
            || self.round.round_id.membership_generation != self.membership_generation
            || self.round.round_id.active_mask != self.members.active_mask()
            || self.round.round_id.parameters_hash != self.parameters.hash()
            || self.round.round_id.previous_epoch_hash != tip.hash
            || self.round.round_id.previous_epoch_nonce != tip.nonce
            || self.round.round_id.nonce != tip.nonce.new_next()
        {
            return Err(BlossomError::WireProtocol(
                "HA current round does not extend the epoch tip".to_string(),
            ));
        }
        for index in self.members.member_count()..MAX_HA_NODES {
            if self.membership_votes[index].is_some() {
                return Err(BlossomError::WireProtocol(
                    "HA membership vote references an unassigned slot".to_string(),
                ));
            }
        }
        if let Some(locked) = self.membership_vote_lock
            && self.membership_votes[self.self_slot.index()] != Some(locked)
        {
            return Err(BlossomError::WireProtocol(
                "HA durable membership vote lock is missing its local vote".to_string(),
            ));
        }
        let mut expected_generation = self
            .checkpoint
            .as_ref()
            .map_or(0, |checkpoint| checkpoint.membership_generation);
        let mut expected_active_mask = self
            .checkpoint
            .as_ref()
            .map_or(low_bits(self.members.member_count), |checkpoint| {
                checkpoint.active_mask
            });
        for certificate in &self.membership_changes {
            let proposal = certificate.proposal;
            if proposal.digest != proposal.compute_digest()
                || proposal.group_id != self.group_id
                || proposal.membership_generation != expected_generation
                || proposal.active_mask != expected_active_mask
                || proposal.parameters_hash != self.parameters.hash()
                || certificate.approval_mask & !expected_active_mask != 0
                || (certificate.approval_mask.count_ones() as usize)
                    < high_availability_majority(expected_active_mask.count_ones() as usize)
            {
                return Err(BlossomError::WireProtocol(
                    "invalid durable HA membership certificate chain".to_string(),
                ));
            }
            let bit = proposal.slot.bit()?;
            match proposal.action {
                HaMembershipAction::Suspend => {
                    if expected_active_mask & bit == 0
                        || (expected_active_mask & !bit).count_ones() < MIN_HA_NODES as u32
                    {
                        return Err(BlossomError::WireProtocol(
                            "invalid durable HA suspension certificate".to_string(),
                        ));
                    }
                    expected_active_mask &= !bit;
                }
                HaMembershipAction::Reactivate { .. } => {
                    if expected_active_mask & bit != 0 {
                        return Err(BlossomError::WireProtocol(
                            "invalid durable HA reactivation certificate".to_string(),
                        ));
                    }
                    expected_active_mask |= bit;
                }
            }
            expected_generation = expected_generation.checked_add(1).ok_or_else(|| {
                BlossomError::InvalidConfiguration("HA membership generation overflow".to_string())
            })?;
        }
        if expected_generation != self.membership_generation
            || expected_active_mask != self.members.active_mask()
        {
            return Err(BlossomError::WireProtocol(
                "HA membership certificates do not reconstruct current membership".to_string(),
            ));
        }

        let mut replay_members = if let Some(checkpoint) = &self.checkpoint {
            let mut members = self.members.clone();
            members.active_mask = checkpoint.active_mask;
            members
        } else {
            genesis_members
        };
        let mut replay_generation = self
            .checkpoint
            .as_ref()
            .map_or(0, |checkpoint| checkpoint.membership_generation);
        let mut replay_presence = self
            .checkpoint
            .as_ref()
            .map_or_else(HaPresenceTracker::default, |checkpoint| {
                checkpoint.presence.clone()
            });
        let mut change_index = 0usize;
        for epoch in self.epochs.iter().skip(1) {
            while self
                .membership_changes
                .get(change_index)
                .is_some_and(|certificate| certificate.proposal.effective_nonce == epoch.nonce)
            {
                let certificate = self.membership_changes[change_index];
                Self::replay_membership_change(
                    &mut replay_members,
                    &mut replay_presence,
                    certificate,
                )?;
                replay_generation = replay_generation.checked_add(1).ok_or_else(|| {
                    BlossomError::InvalidConfiguration(
                        "HA membership generation overflow".to_string(),
                    )
                })?;
                change_index += 1;
            }
            if self
                .membership_changes
                .get(change_index)
                .is_some_and(|certificate| certificate.proposal.effective_nonce < epoch.nonce)
                || epoch.membership_generation != replay_generation
                || epoch.active_mask != replay_members.active_mask()
            {
                return Err(BlossomError::WireProtocol(
                    "HA epoch membership generation does not match its certificate chain"
                        .to_string(),
                ));
            }
            replay_presence.observe_epoch(
                &replay_members,
                epoch.presence_mask,
                epoch.nonce,
                self.parameters,
            );
        }
        let pending_nonce = tip.nonce.new_next();
        while let Some(certificate) = self.membership_changes.get(change_index).copied() {
            if certificate.proposal.effective_nonce != pending_nonce {
                return Err(BlossomError::WireProtocol(
                    "HA membership certificate is not effective at an epoch boundary".to_string(),
                ));
            }
            Self::replay_membership_change(&mut replay_members, &mut replay_presence, certificate)?;
            replay_generation = replay_generation.checked_add(1).ok_or_else(|| {
                BlossomError::InvalidConfiguration("HA membership generation overflow".to_string())
            })?;
            change_index += 1;
        }
        if replay_generation != self.membership_generation
            || replay_members.active_mask() != self.members.active_mask()
            || replay_presence != self.presence
        {
            return Err(BlossomError::WireProtocol(
                "HA recovered presence or membership state is not deterministic".to_string(),
            ));
        }
        for amendment in &self.amendments {
            self.validate_amendment_structure(amendment)?;
        }
        Ok(())
    }

    pub(super) fn validate_persist_tip(&self) -> Result<()> {
        self.parameters.validate()?;
        self.members.validate()?;
        if self.members.member(self.self_slot).is_none() {
            return Err(BlossomError::UnknownSender);
        }
        let tip = self.epochs.last().ok_or(BlossomError::EmptyEpochChain)?;
        if tip.group_id != self.group_id
            || tip.fixed_membership_hash != self.members.fixed_identity_hash()
            || tip.parameters != self.parameters
            || tip.parameters_hash != self.parameters.hash()
            || tip.hash != tip.compute_hash()
        {
            return Err(BlossomError::InvalidConfiguration(
                "HA durable tip does not match its runtime envelope".to_string(),
            ));
        }
        if self.epochs.len() > 1 {
            tip.validate(&self.members)?;
        }
        if self.round.round_id.group_id != self.group_id
            || self.round.round_id.fixed_membership_hash != self.members.fixed_identity_hash()
            || self.round.round_id.membership_generation != self.membership_generation
            || self.round.round_id.active_mask != self.members.active_mask()
            || self.round.round_id.parameters_hash != self.parameters.hash()
            || self.round.round_id.previous_epoch_hash != tip.hash
            || self.round.round_id.previous_epoch_nonce != tip.nonce
            || self.round.round_id.nonce != tip.nonce.new_next()
        {
            return Err(BlossomError::WireProtocol(
                "HA current round does not extend the durable epoch tip".to_string(),
            ));
        }
        for index in self.members.member_count()..MAX_HA_NODES {
            if self.membership_votes[index].is_some() {
                return Err(BlossomError::WireProtocol(
                    "HA membership vote references an unassigned slot".to_string(),
                ));
            }
        }
        if let Some(locked) = self.membership_vote_lock
            && self.membership_votes[self.self_slot.index()] != Some(locked)
        {
            return Err(BlossomError::WireProtocol(
                "HA durable membership vote lock is missing its local vote".to_string(),
            ));
        }
        Ok(())
    }

    pub(super) fn replay_membership_change(
        members: &mut HaMemberSlots,
        presence: &mut HaPresenceTracker,
        certificate: HaMembershipCertificate,
    ) -> Result<()> {
        let proposal = certificate.proposal;
        *members = match proposal.action {
            HaMembershipAction::Suspend => {
                presence.mark_suspended(proposal.slot, proposal.effective_nonce);
                members.with_suspended(proposal.slot)?
            }
            HaMembershipAction::Reactivate { .. } => {
                presence.mark_reactivated(proposal.slot);
                members.with_reactivated(proposal.slot)?
            }
        };
        Ok(())
    }

    pub(super) fn head(&self) -> &HaEpoch {
        self.epochs.last().expect("HA runtime always has genesis")
    }

    pub(super) fn sealed_nonce(&self) -> Nonce {
        Nonce::new(
            self.head()
                .nonce
                .value()
                .saturating_sub(u64::from(self.parameters.mutable_epoch_depth)),
        )
    }

    pub(super) fn validate_amendment_structure(&self, amendment: &AmendmentRecord) -> Result<()> {
        if self.members.member(amendment.origin_slot).is_none() {
            return Err(BlossomError::UnknownSender);
        }
        let target = self
            .epochs
            .iter()
            .find(|epoch| epoch.nonce == amendment.target_epoch_nonce)
            .ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "HA amendment target epoch is not in the local chain".to_string(),
                )
            })?;
        if target.hash != amendment.target_epoch_hash {
            return Err(BlossomError::WireProtocol(
                "HA amendment target hash mismatch".to_string(),
            ));
        }
        let containing_exists = self
            .epochs
            .iter()
            .any(|epoch| epoch.nonce == amendment.containing_epoch_nonce);
        if !containing_exists || amendment.containing_epoch_nonce <= amendment.target_epoch_nonce {
            return Err(BlossomError::InvalidConfiguration(
                "HA amendment must be carried by a later committed epoch".to_string(),
            ));
        }
        Ok(())
    }

    pub(super) fn validate_new_amendment(&self, amendment: &AmendmentRecord) -> Result<()> {
        self.validate_amendment_structure(amendment)?;
        if matches!(
            epoch_lifecycle(
                amendment.target_epoch_nonce,
                self.head().nonce,
                self.parameters.mutable_epoch_depth,
            ),
            EpochLifecycle::Sealed
        ) {
            return Err(BlossomError::EpochSealed {
                target: amendment.target_epoch_nonce,
                sealed: self.sealed_nonce(),
                writable: self.round.round_id.nonce,
            });
        }
        Ok(())
    }
}

impl HaDurableCache {
    pub(super) fn from_state(state: &HighAvailabilityRuntimeState) -> Result<Self> {
        Ok(Self {
            metadata: HaDurableMetadata::from(state),
            checkpoint_bytes: borsh::to_vec(&state.checkpoint).map_err(ha_persist_encode)?,
            epochs: ha_epoch_summary(&state.epochs),
            membership_changes: ha_record_summary(&state.membership_changes)?,
            amendments: ha_record_summary(&state.amendments)?,
        })
    }
}

impl HaDurableStore {
    pub(super) fn open(
        path: impl AsRef<Path>,
        group_id: ConsensusGroupId,
        self_key: PubKey,
        fixed_membership_hash: HashType,
        parameters_hash: HashType,
    ) -> Result<Self> {
        let public_scope =
            borsh::to_vec(&(group_id, self_key, fixed_membership_hash, parameters_hash)).map_err(
                |error| BlossomError::WireProtocol(format!("encode HA durable identity: {error}")),
            )?;
        let identity = BlossomLogStoreIdentity::new("ha-runtime", public_scope, 1)?;
        Ok(Self {
            store: BlossomLogStore::open(BlossomLogStoreConfig::new(path.as_ref()), identity)?,
            cached: Arc::new(StdMutex::new(None)),
            #[cfg(test)]
            test_fault: None,
        })
    }

    pub(super) fn load(&self) -> Result<Option<HighAvailabilityRuntimeState>> {
        let Some(value) = self.store.get(HA_METADATA_TABLE, HA_RUNTIME_STATE_KEY)? else {
            return Ok(None);
        };
        let metadata = borsh::from_slice::<HaDurableMetadata>(&value).map_err(|_| {
            BlossomError::InvalidConfiguration(
                "durable HA runtime state predates the v1 LogStore format; create a new store directory or recover from a certified snapshot"
                    .to_string(),
            )
        })?;
        if metadata.format_version != HA_RUNTIME_STATE_FORMAT_VERSION {
            return Err(BlossomError::InvalidConfiguration(format!(
                "unsupported durable HA runtime state format version {}",
                metadata.format_version
            )));
        }
        let state = HighAvailabilityRuntimeState {
            group_id: metadata.group_id,
            self_slot: metadata.self_slot,
            members: metadata.members,
            membership_generation: metadata.membership_generation,
            parameters: metadata.parameters,
            checkpoint: metadata.checkpoint,
            epochs: load_ha_records(&self.store, HA_EPOCHS_TABLE)?,
            round: metadata.round,
            presence: metadata.presence,
            membership_vote_lock: metadata.membership_vote_lock,
            membership_votes: metadata.membership_votes,
            membership_changes: load_ha_records(&self.store, HA_MEMBERSHIP_CHANGES_TABLE)?,
            amendments: load_ha_records(&self.store, HA_AMENDMENTS_TABLE)?,
        };
        state.validate()?;
        *self.cached.lock().map_err(ha_cache_error)? = Some(HaDurableCache::from_state(&state)?);
        Ok(Some(state))
    }

    pub(super) fn persist(&self, state: &HighAvailabilityRuntimeState) -> Result<()> {
        #[cfg(test)]
        if let Some(fault) = self
            .test_fault
            .as_ref()
            .map(|fault| fault.load(std::sync::atomic::Ordering::SeqCst))
            .filter(|fault| *fault != 0)
        {
            let message = if fault == 1 {
                "injected HA ENOSPC"
            } else {
                "injected HA fsync failure"
            };
            return Err(BlossomError::Io(format!("HA durable store: {message}")));
        }
        let mut cached = self.cached.lock().map_err(ha_cache_error)?;
        let previous = cached.as_ref();
        validate_ha_persist_transition(previous, state)?;
        let next_cache = HaDurableCache::from_state(state)?;
        let metadata = borsh::to_vec(&HaDurableMetadata::from(state)).map_err(|error| {
            BlossomError::WireProtocol(format!("encode durable HA runtime state: {error}"))
        })?;
        self.store.transaction(|transaction| {
            transaction.insert(HA_METADATA_TABLE, HA_RUNTIME_STATE_KEY.to_vec(), metadata)?;
            sync_ha_epochs(
                transaction,
                previous.map(|cache| cache.epochs),
                &state.epochs,
            )?;
            sync_ha_records(
                transaction,
                HA_MEMBERSHIP_CHANGES_TABLE,
                previous.map(|cache| cache.membership_changes),
                &state.membership_changes,
            )?;
            sync_ha_records(
                transaction,
                HA_AMENDMENTS_TABLE,
                previous.map(|cache| cache.amendments),
                &state.amendments,
            )?;
            Ok(())
        })?;
        *cached = Some(next_cache);
        Ok(())
    }
}

fn validate_ha_persist_transition(
    previous: Option<&HaDurableCache>,
    next: &HighAvailabilityRuntimeState,
) -> Result<()> {
    let Some(previous) = previous else {
        return next.validate();
    };
    let checkpoint_bytes = borsh::to_vec(&next.checkpoint).map_err(ha_persist_encode)?;
    let membership_changes = ha_record_summary(&next.membership_changes)?;
    let amendments = ha_record_summary(&next.amendments)?;
    let static_envelope_unchanged = previous.metadata.group_id == next.group_id
        && previous.metadata.self_slot == next.self_slot
        && previous.metadata.members == next.members
        && previous.metadata.membership_generation == next.membership_generation
        && previous.metadata.parameters == next.parameters
        && previous.checkpoint_bytes == checkpoint_bytes
        && previous.membership_changes == membership_changes
        && previous.amendments == amendments;
    if !static_envelope_unchanged {
        return next.validate();
    }
    let next_epochs = ha_epoch_summary(&next.epochs);
    let history_is_unchanged = previous.epochs == next_epochs;
    let history_appended_once = next.epochs.len() == previous.epochs.len.saturating_add(1)
        && previous.epochs.first_hash == next_epochs.first_hash
        && previous.epochs.last_hash.is_some_and(|previous_tip| {
            next.epochs
                .get(previous.epochs.len.saturating_sub(1))
                .is_some_and(|retained_tip| retained_tip.hash == previous_tip)
        });
    if !history_is_unchanged && !history_appended_once {
        return next.validate();
    }
    next.validate_persist_tip()
}

fn ha_epoch_summary(epochs: &[HaEpoch]) -> HaSequenceSummary {
    HaSequenceSummary {
        len: epochs.len(),
        first_hash: epochs.first().map(|epoch| epoch.hash),
        last_hash: epochs.last().map(|epoch| epoch.hash),
    }
}

fn ha_record_summary<T: BorshSerialize>(records: &[T]) -> Result<HaSequenceSummary> {
    Ok(HaSequenceSummary {
        len: records.len(),
        first_hash: records.first().map(hash_ha_record).transpose()?,
        last_hash: records.last().map(hash_ha_record).transpose()?,
    })
}

fn hash_ha_record<T: BorshSerialize>(record: &T) -> Result<HashType> {
    borsh::to_vec(record)
        .map(|bytes| HashType::hash(&bytes))
        .map_err(ha_persist_encode)
}

fn ha_persist_encode(error: impl std::fmt::Display) -> BlossomError {
    BlossomError::WireProtocol(format!("encode HA persistence transition: {error}"))
}

fn load_ha_records<T: BorshDeserialize>(store: &BlossomLogStore, table: &str) -> Result<Vec<T>> {
    store
        .scan(table)?
        .into_iter()
        .enumerate()
        .map(|(expected, (key, value))| {
            let index = decode_ha_index(&key)?;
            let expected = u64::try_from(expected).map_err(|_| {
                BlossomError::InvalidConfiguration(format!(
                    "HA durable table {table} index exceeds u64"
                ))
            })?;
            if index != expected {
                return Err(BlossomError::InvalidConfiguration(format!(
                    "HA durable table {table} contains an index gap"
                )));
            }
            borsh::from_slice(&value).map_err(|error| {
                BlossomError::WireProtocol(format!("decode HA durable table {table}: {error}"))
            })
        })
        .collect()
}

fn sync_ha_epochs(
    transaction: &mut BlossomLogTransaction<'_>,
    previous: Option<HaSequenceSummary>,
    next: &[HaEpoch],
) -> Result<()> {
    let next_summary = ha_epoch_summary(next);
    if previous == Some(next_summary) {
        return Ok(());
    }
    if previous.is_some_and(|previous| {
        next.len() == previous.len.saturating_add(1)
            && previous.first_hash == next_summary.first_hash
            && previous.last_hash.is_some_and(|previous_tip| {
                next.get(previous.len.saturating_sub(1))
                    .is_some_and(|retained_tip| retained_tip.hash == previous_tip)
            })
    }) {
        let previous_len = previous.expect("checked previous summary").len;
        let index = u64::try_from(previous_len).map_err(|_| {
            BlossomError::InvalidConfiguration("HA durable epoch index overflow".to_string())
        })?;
        transaction.insert(
            HA_EPOCHS_TABLE,
            index.to_be_bytes().to_vec(),
            borsh::to_vec(next.last().expect("one epoch appended")).map_err(|error| {
                BlossomError::WireProtocol(format!(
                    "encode HA durable table {HA_EPOCHS_TABLE}: {error}"
                ))
            })?,
        )?;
        return Ok(());
    }
    let previous: Vec<HaEpoch> = load_ha_transaction_records(transaction, HA_EPOCHS_TABLE)?;
    let common = previous
        .iter()
        .zip(next)
        .take_while(|(old, new)| old.nonce == new.nonce && old.hash == new.hash)
        .count();
    sync_ha_suffix(
        transaction,
        HA_EPOCHS_TABLE,
        previous.len(),
        &next[common..],
        common,
    )
}

fn sync_ha_records<T: BorshSerialize + BorshDeserialize + PartialEq>(
    transaction: &mut BlossomLogTransaction<'_>,
    table: &str,
    previous: Option<HaSequenceSummary>,
    next: &[T],
) -> Result<()> {
    let next_summary = ha_record_summary(next)?;
    if previous == Some(next_summary) {
        return Ok(());
    }
    let is_single_append = if let Some(previous) = previous {
        let retained_tail_hash = next
            .get(previous.len.saturating_sub(1))
            .map(hash_ha_record)
            .transpose()?;
        next.len() == previous.len.saturating_add(1)
            && previous.first_hash == next_summary.first_hash
            && previous.last_hash == retained_tail_hash
    } else {
        false
    };
    if is_single_append {
        let previous_len = previous.expect("checked previous summary").len;
        let index = u64::try_from(previous_len).map_err(|_| {
            BlossomError::InvalidConfiguration("HA durable record index overflow".to_string())
        })?;
        transaction.insert(
            table,
            index.to_be_bytes().to_vec(),
            borsh::to_vec(next.last().expect("one HA record appended")).map_err(|error| {
                BlossomError::WireProtocol(format!("encode HA durable table {table}: {error}"))
            })?,
        )?;
        return Ok(());
    }
    let previous: Vec<T> = load_ha_transaction_records(transaction, table)?;
    let common = previous
        .iter()
        .zip(next)
        .take_while(|(old, new)| old == new)
        .count();
    sync_ha_suffix(transaction, table, previous.len(), &next[common..], common)
}

fn load_ha_transaction_records<T: BorshDeserialize>(
    transaction: &BlossomLogTransaction<'_>,
    table: &str,
) -> Result<Vec<T>> {
    transaction
        .scan(table)?
        .into_iter()
        .enumerate()
        .map(|(expected, (key, value))| {
            let index = decode_ha_index(&key)?;
            let expected = u64::try_from(expected).map_err(|_| {
                BlossomError::InvalidConfiguration(format!(
                    "HA durable table {table} index exceeds u64"
                ))
            })?;
            if index != expected {
                return Err(BlossomError::InvalidConfiguration(format!(
                    "HA durable table {table} contains an index gap"
                )));
            }
            borsh::from_slice(&value).map_err(|error| {
                BlossomError::WireProtocol(format!("decode HA durable table {table}: {error}"))
            })
        })
        .collect()
}

fn sync_ha_suffix<T: BorshSerialize>(
    transaction: &mut BlossomLogTransaction<'_>,
    table: &str,
    previous_len: usize,
    suffix: &[T],
    start: usize,
) -> Result<()> {
    for index in start..previous_len {
        let index = u64::try_from(index).map_err(|_| {
            BlossomError::InvalidConfiguration("HA durable index overflow".to_string())
        })?;
        transaction.remove(table, index.to_be_bytes().to_vec())?;
    }
    for (offset, value) in suffix.iter().enumerate() {
        let index = start.checked_add(offset).ok_or_else(|| {
            BlossomError::InvalidConfiguration("HA durable index overflow".to_string())
        })?;
        let index = u64::try_from(index).map_err(|_| {
            BlossomError::InvalidConfiguration("HA durable index overflow".to_string())
        })?;
        transaction.insert(
            table,
            index.to_be_bytes().to_vec(),
            borsh::to_vec(value).map_err(|error| {
                BlossomError::WireProtocol(format!("encode HA durable table {table}: {error}"))
            })?,
        )?;
    }
    Ok(())
}

fn decode_ha_index(key: &[u8]) -> Result<u64> {
    let key: [u8; 8] = key.try_into().map_err(|_| {
        BlossomError::InvalidConfiguration("HA durable table key has invalid length".to_string())
    })?;
    Ok(u64::from_be_bytes(key))
}

fn ha_cache_error<T>(error: std::sync::PoisonError<T>) -> BlossomError {
    BlossomError::Io(format!("HA durable cache lock poisoned: {error}"))
}
