//! Service-level active-active orchestration over the fixed-slot HA runtime.
//!
//! The HA runtime owns consensus and membership safety. This layer keeps the
//! application routing contract and locally accepted-write disposition
//! explicit across catch-up and membership cutovers.

use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::active_active::{
    ActiveActiveCommand, CommandIdentity, CommandSpecVersion, RouteGeneration,
};
use crate::block::Transaction;
use crate::error::{BlossomError, Result};
use crate::hash::HashType;
use crate::high_availability::{
    HaMemberSlot, HaMembershipCertificate, HaMembershipVote, HaOperationalStatus,
    HaRecoverySnapshot, HaRuntimeEvent, HighAvailabilityRuntime, NodeAvailabilityStatus,
    StateRevision,
};
use crate::nonce::Nonce;

const ACTIVE_ACTIVE_HA_RECOVERY_MANIFEST_DOMAIN: &[u8] =
    b"blossom/active-active/ha-recovery-manifest/v1";
const ACTIVE_ACTIVE_HA_CUTOVER_MANIFEST_DOMAIN: &[u8] =
    b"blossom/active-active/ha-cutover-manifest/v1";
pub const ACTIVE_ACTIVE_HA_RECOVERY_MANIFEST_VERSION: u16 = 1;
pub const ACTIVE_ACTIVE_HA_CUTOVER_MANIFEST_VERSION: u16 = 1;
pub const MAX_ACCEPTED_WRITE_ABORT_REASON_BYTES: usize = 1 << 10;

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum AcceptedWriteDisposition {
    Pending,
    Recertified {
        from: RouteGeneration,
        to: RouteGeneration,
        from_command_spec_version: CommandSpecVersion,
        to_command_spec_version: CommandSpecVersion,
        command: ActiveActiveCommand,
        command_hash: HashType,
    },
    Aborted {
        route_generation: RouteGeneration,
        command_spec_version: CommandSpecVersion,
        reason: String,
    },
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct AcceptedWriteRecord {
    pub command: ActiveActiveCommand,
    pub command_hash: HashType,
    pub command_spec_version: CommandSpecVersion,
    pub accepted_route_generation: RouteGeneration,
    pub disposition: AcceptedWriteDisposition,
}

impl AcceptedWriteRecord {
    fn validate(&self) -> Result<()> {
        self.command.validate()?;
        self.command_spec_version.validate()?;
        self.accepted_route_generation.validate()?;
        if self.command.hash()? != self.command_hash {
            return Err(BlossomError::InvalidConfiguration(
                "accepted-write record hash does not match its command".to_string(),
            ));
        }
        match &self.disposition {
            AcceptedWriteDisposition::Pending => {}
            AcceptedWriteDisposition::Recertified {
                from,
                to,
                from_command_spec_version,
                to_command_spec_version,
                command,
                command_hash,
            } => {
                from.validate()?;
                to.validate()?;
                from_command_spec_version.validate()?;
                to_command_spec_version.validate()?;
                command.validate()?;
                if *from != self.accepted_route_generation
                    || *from_command_spec_version != self.command_spec_version
                    || to.0 <= from.0
                    || to_command_spec_version.0 < from_command_spec_version.0
                    || command.identity != self.command.identity
                    || command.hash()? != *command_hash
                {
                    return Err(BlossomError::InvalidConfiguration(
                        "accepted-write recertification has an invalid target application contract"
                            .to_string(),
                    ));
                }
            }
            AcceptedWriteDisposition::Aborted {
                route_generation,
                command_spec_version,
                reason,
            } => {
                route_generation.validate()?;
                command_spec_version.validate()?;
                if *route_generation != self.accepted_route_generation
                    || *command_spec_version != self.command_spec_version
                    || reason.is_empty()
                    || reason.len() > MAX_ACCEPTED_WRITE_ABORT_REASON_BYTES
                {
                    return Err(BlossomError::InvalidConfiguration(
                        "accepted-write abort record is invalid".to_string(),
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub struct ActiveActiveCutover {
    pub from: RouteGeneration,
    pub to: RouteGeneration,
    pub from_command_spec_version: CommandSpecVersion,
    pub to_command_spec_version: CommandSpecVersion,
    pub membership_generation: u64,
    pub active_mask: u8,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct ActiveActiveHaRecoveryManifest {
    pub format_version: u16,
    pub route_generation: RouteGeneration,
    pub command_spec_version: CommandSpecVersion,
    pub runtime: HaRecoverySnapshot,
    pub accepted_writes: Vec<AcceptedWriteRecord>,
    pub cutover: Option<ActiveActiveCutover>,
    pub manifest_hash: HashType,
}

impl ActiveActiveHaRecoveryManifest {
    pub fn validate(&self) -> Result<()> {
        if self.format_version != ACTIVE_ACTIVE_HA_RECOVERY_MANIFEST_VERSION {
            return Err(BlossomError::InvalidConfiguration(
                "unsupported active-active HA recovery manifest version".to_string(),
            ));
        }
        self.route_generation.validate()?;
        self.command_spec_version.validate()?;
        let mut previous = None;
        for accepted in &self.accepted_writes {
            accepted.validate()?;
            if accepted.command_spec_version != self.command_spec_version
                || accepted.accepted_route_generation != self.route_generation
                || previous.is_some_and(|identity| identity >= accepted.command.identity)
            {
                return Err(BlossomError::InvalidConfiguration(
                    "HA recovery manifest accepted writes are not canonical".to_string(),
                ));
            }
            previous = Some(accepted.command.identity);
        }
        if let Some(cutover) = self.cutover {
            cutover.from.validate()?;
            cutover.to.validate()?;
            cutover.from_command_spec_version.validate()?;
            cutover.to_command_spec_version.validate()?;
            if cutover.from != self.route_generation
                || cutover.from_command_spec_version != self.command_spec_version
                || cutover.to.0 <= cutover.from.0
                || cutover.to_command_spec_version.0 < cutover.from_command_spec_version.0
            {
                return Err(BlossomError::InvalidConfiguration(
                    "HA recovery manifest cutover is invalid".to_string(),
                ));
            }
            for accepted in &self.accepted_writes {
                validate_cutover_disposition(cutover, &accepted.disposition)?;
            }
        } else if self
            .accepted_writes
            .iter()
            .any(|accepted| !matches!(accepted.disposition, AcceptedWriteDisposition::Pending))
        {
            return Err(BlossomError::InvalidConfiguration(
                "resolved accepted writes require an active cutover".to_string(),
            ));
        }
        if self.compute_hash()? != self.manifest_hash {
            return Err(BlossomError::InvalidConfiguration(
                "HA recovery manifest hash mismatch".to_string(),
            ));
        }
        Ok(())
    }

    fn compute_hash(&self) -> Result<HashType> {
        let mut unhashed = self.clone();
        unhashed.manifest_hash = HashType::default();
        manifest_hash(ACTIVE_ACTIVE_HA_RECOVERY_MANIFEST_DOMAIN, &unhashed)
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct AcceptedWriteResolution {
    pub command_identity: CommandIdentity,
    pub command_hash: HashType,
    pub disposition: AcceptedWriteDisposition,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct ActiveActiveHaCutoverManifest {
    pub format_version: u16,
    pub cutover: ActiveActiveCutover,
    pub command_spec_version: CommandSpecVersion,
    pub accepted_write_resolutions: Vec<AcceptedWriteResolution>,
    pub manifest_hash: HashType,
}

impl ActiveActiveHaCutoverManifest {
    pub fn validate(&self) -> Result<()> {
        if self.format_version != ACTIVE_ACTIVE_HA_CUTOVER_MANIFEST_VERSION {
            return Err(BlossomError::InvalidConfiguration(
                "unsupported active-active HA cutover manifest version".to_string(),
            ));
        }
        self.cutover.from.validate()?;
        self.cutover.to.validate()?;
        self.command_spec_version.validate()?;
        self.cutover.from_command_spec_version.validate()?;
        self.cutover.to_command_spec_version.validate()?;
        if self.command_spec_version != self.cutover.from_command_spec_version
            || self.cutover.to.0 <= self.cutover.from.0
            || self.cutover.to_command_spec_version.0 < self.cutover.from_command_spec_version.0
        {
            return Err(BlossomError::InvalidConfiguration(
                "active-active cutover must advance a valid application contract".to_string(),
            ));
        }
        let mut previous = None;
        for resolution in &self.accepted_write_resolutions {
            if matches!(resolution.disposition, AcceptedWriteDisposition::Pending)
                || previous.is_some_and(|identity| identity >= resolution.command_identity)
            {
                return Err(BlossomError::InvalidConfiguration(
                    "cutover manifest has pending or non-canonical accepted-write resolutions"
                        .to_string(),
                ));
            }
            validate_cutover_disposition(self.cutover, &resolution.disposition)?;
            previous = Some(resolution.command_identity);
        }
        if self.compute_hash()? != self.manifest_hash {
            return Err(BlossomError::InvalidConfiguration(
                "active-active HA cutover manifest hash mismatch".to_string(),
            ));
        }
        Ok(())
    }

    fn compute_hash(&self) -> Result<HashType> {
        let mut unhashed = self.clone();
        unhashed.manifest_hash = HashType::default();
        manifest_hash(ACTIVE_ACTIVE_HA_CUTOVER_MANIFEST_DOMAIN, &unhashed)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ActiveActiveHaRecoveryStatus {
    pub operational: HaOperationalStatus,
    pub route_generation: RouteGeneration,
    pub command_spec_version: CommandSpecVersion,
    pub accepted_writes: usize,
    pub unresolved_accepted_writes: usize,
    pub cutover: Option<ActiveActiveCutover>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct LearnerCatchUp {
    pub installed_revision: StateRevision,
    pub caught_up_through: Nonce,
    pub eligible_for_activation: bool,
}

/// Active-active service facade for HA catch-up and route cutover operations.
pub struct ActiveActiveHaEngine {
    runtime: HighAvailabilityRuntime,
    route_generation: RouteGeneration,
    command_spec_version: CommandSpecVersion,
    accepted_writes: BTreeMap<CommandIdentity, AcceptedWriteRecord>,
    cutover: Option<ActiveActiveCutover>,
}

impl ActiveActiveHaEngine {
    pub fn new(
        runtime: HighAvailabilityRuntime,
        route_generation: RouteGeneration,
        command_spec_version: CommandSpecVersion,
    ) -> Result<Self> {
        route_generation.validate()?;
        command_spec_version.validate()?;
        Ok(Self {
            runtime,
            route_generation,
            command_spec_version,
            accepted_writes: BTreeMap::new(),
            cutover: None,
        })
    }

    pub fn runtime(&self) -> &HighAvailabilityRuntime {
        &self.runtime
    }

    pub fn runtime_mut(&mut self) -> &mut HighAvailabilityRuntime {
        &mut self.runtime
    }

    pub fn accept_local(&mut self, command: ActiveActiveCommand) -> Result<HashType> {
        command.validate()?;
        let command_hash = command.hash()?;
        if let Some(existing) = self.accepted_writes.get(&command.identity) {
            if existing.command_hash != command_hash {
                return Err(BlossomError::InvalidConfiguration(
                    "conflicting bytes for one accepted command identity".to_string(),
                ));
            }
            return Ok(command_hash);
        }
        self.accepted_writes.insert(
            command.identity,
            AcceptedWriteRecord {
                command,
                command_hash,
                command_spec_version: self.command_spec_version,
                accepted_route_generation: self.route_generation,
                disposition: AcceptedWriteDisposition::Pending,
            },
        );
        Ok(command_hash)
    }

    pub fn accepted_transaction(&self, identity: CommandIdentity) -> Result<Transaction> {
        let accepted = self.accepted_writes.get(&identity).ok_or_else(|| {
            BlossomError::InvalidConfiguration("unknown accepted write".to_string())
        })?;
        Transaction::from_borsh(&accepted.command)
    }

    pub fn begin_cutover(&mut self, next_route_generation: RouteGeneration) -> Result<()> {
        self.begin_application_cutover(next_route_generation, self.command_spec_version)
    }

    /// Begins one atomic route and command-spec cutover.
    ///
    /// A command-spec upgrade must also advance the route generation. Every
    /// accepted source-spec command must then be translated and rehashed with
    /// [`Self::recertify_accepted_as`] or explicitly aborted.
    pub fn begin_application_cutover(
        &mut self,
        next_route_generation: RouteGeneration,
        next_command_spec_version: CommandSpecVersion,
    ) -> Result<()> {
        next_route_generation.validate()?;
        next_command_spec_version.validate()?;
        if self.cutover.is_some()
            || next_route_generation.0 <= self.route_generation.0
            || next_command_spec_version.0 < self.command_spec_version.0
        {
            return Err(BlossomError::InvalidConfiguration(
                "active-active application cutover is already active, regresses the command spec, or does not advance the route"
                    .to_string(),
            ));
        }
        let status = self.runtime.status()?;
        self.cutover = Some(ActiveActiveCutover {
            from: self.route_generation,
            to: next_route_generation,
            from_command_spec_version: self.command_spec_version,
            to_command_spec_version: next_command_spec_version,
            membership_generation: status.membership_generation,
            active_mask: status.active_mask,
        });
        Ok(())
    }

    pub fn recertify_accepted(&mut self, identity: CommandIdentity) -> Result<()> {
        let command = self
            .accepted_writes
            .get(&identity)
            .ok_or_else(|| {
                BlossomError::InvalidConfiguration("unknown accepted write".to_string())
            })?
            .command
            .clone();
        let cutover = self.cutover.ok_or_else(|| {
            BlossomError::InvalidConfiguration(
                "accepted-write recertification requires an active cutover".to_string(),
            )
        })?;
        if cutover.to_command_spec_version != cutover.from_command_spec_version {
            return Err(BlossomError::InvalidConfiguration(
                "command-spec upgrades require recertify_accepted_as with translated command bytes, or an explicit abort"
                    .to_string(),
            ));
        }
        self.recertify_accepted_as(identity, command)
    }

    pub fn recertify_accepted_as(
        &mut self,
        identity: CommandIdentity,
        translated_command: ActiveActiveCommand,
    ) -> Result<()> {
        let cutover = self.cutover.ok_or_else(|| {
            BlossomError::InvalidConfiguration(
                "accepted-write recertification requires an active cutover".to_string(),
            )
        })?;
        translated_command.validate()?;
        if translated_command.identity != identity {
            return Err(BlossomError::InvalidConfiguration(
                "translated accepted write must preserve its command identity".to_string(),
            ));
        }
        let translated_command_hash = translated_command.hash()?;
        let accepted = self.accepted_writes.get_mut(&identity).ok_or_else(|| {
            BlossomError::InvalidConfiguration("unknown accepted write".to_string())
        })?;
        if accepted.accepted_route_generation != cutover.from
            || accepted.command_spec_version != cutover.from_command_spec_version
        {
            return Err(BlossomError::InvalidConfiguration(
                "accepted write does not belong to the cutover source application contract"
                    .to_string(),
            ));
        }
        let disposition = AcceptedWriteDisposition::Recertified {
            from: cutover.from,
            to: cutover.to,
            from_command_spec_version: cutover.from_command_spec_version,
            to_command_spec_version: cutover.to_command_spec_version,
            command: translated_command,
            command_hash: translated_command_hash,
        };
        if accepted.disposition == disposition {
            return Ok(());
        }
        if !matches!(accepted.disposition, AcceptedWriteDisposition::Pending) {
            return Err(BlossomError::InvalidConfiguration(
                "accepted write already has a different cutover resolution".to_string(),
            ));
        }
        accepted.disposition = disposition;
        Ok(())
    }

    pub fn abort_accepted(
        &mut self,
        identity: CommandIdentity,
        reason: impl Into<String>,
    ) -> Result<()> {
        let cutover = self.cutover.ok_or_else(|| {
            BlossomError::InvalidConfiguration(
                "accepted-write abort requires an active cutover".to_string(),
            )
        })?;
        let reason = reason.into();
        if reason.is_empty() || reason.len() > MAX_ACCEPTED_WRITE_ABORT_REASON_BYTES {
            return Err(BlossomError::InvalidConfiguration(
                "accepted-write abort reason is empty or too large".to_string(),
            ));
        }
        let accepted = self.accepted_writes.get_mut(&identity).ok_or_else(|| {
            BlossomError::InvalidConfiguration("unknown accepted write".to_string())
        })?;
        if accepted.accepted_route_generation != cutover.from
            || accepted.command_spec_version != cutover.from_command_spec_version
        {
            return Err(BlossomError::InvalidConfiguration(
                "accepted write does not belong to the cutover source application contract"
                    .to_string(),
            ));
        }
        let disposition = AcceptedWriteDisposition::Aborted {
            route_generation: accepted.accepted_route_generation,
            command_spec_version: accepted.command_spec_version,
            reason,
        };
        if accepted.disposition == disposition {
            return Ok(());
        }
        if !matches!(accepted.disposition, AcceptedWriteDisposition::Pending) {
            return Err(BlossomError::InvalidConfiguration(
                "accepted write already has a different cutover resolution".to_string(),
            ));
        }
        accepted.disposition = disposition;
        Ok(())
    }

    pub fn cutover_manifest(&self) -> Result<ActiveActiveHaCutoverManifest> {
        let cutover = self.cutover.ok_or_else(|| {
            BlossomError::InvalidConfiguration("no active route cutover".to_string())
        })?;
        let accepted_write_resolutions = self
            .accepted_writes
            .values()
            .filter(|accepted| accepted.accepted_route_generation == cutover.from)
            .map(|accepted| {
                if matches!(accepted.disposition, AcceptedWriteDisposition::Pending) {
                    return Err(BlossomError::InvalidConfiguration(
                        "every accepted write must be recertified or explicitly aborted before cutover"
                            .to_string(),
                    ));
                }
                Ok(AcceptedWriteResolution {
                    command_identity: accepted.command.identity,
                    command_hash: accepted.command_hash,
                    disposition: accepted.disposition.clone(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let mut manifest = ActiveActiveHaCutoverManifest {
            format_version: ACTIVE_ACTIVE_HA_CUTOVER_MANIFEST_VERSION,
            cutover,
            command_spec_version: self.command_spec_version,
            accepted_write_resolutions,
            manifest_hash: HashType::default(),
        };
        manifest.manifest_hash = manifest.compute_hash()?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn activate_cutover(&mut self, manifest: &ActiveActiveHaCutoverManifest) -> Result<()> {
        manifest.validate()?;
        let current = self.runtime.status()?;
        if self.cutover != Some(manifest.cutover)
            || self.route_generation != manifest.cutover.from
            || self.command_spec_version != manifest.cutover.from_command_spec_version
            || self.command_spec_version != manifest.command_spec_version
            || current.membership_generation != manifest.cutover.membership_generation
            || current.active_mask != manifest.cutover.active_mask
        {
            return Err(BlossomError::InvalidConfiguration(
                "cutover manifest does not match current routing or HA membership".to_string(),
            ));
        }
        let expected_resolutions = self
            .accepted_writes
            .values()
            .filter(|accepted| accepted.accepted_route_generation == manifest.cutover.from)
            .count();
        if manifest.accepted_write_resolutions.len() != expected_resolutions {
            return Err(BlossomError::InvalidConfiguration(
                "cutover manifest does not resolve every accepted source-generation write"
                    .to_string(),
            ));
        }
        for resolution in &manifest.accepted_write_resolutions {
            let accepted = self
                .accepted_writes
                .get(&resolution.command_identity)
                .ok_or_else(|| {
                    BlossomError::InvalidConfiguration(
                        "cutover manifest references an unknown accepted write".to_string(),
                    )
                })?;
            if accepted.command_hash != resolution.command_hash
                || accepted.disposition != resolution.disposition
            {
                return Err(BlossomError::InvalidConfiguration(
                    "cutover accepted-write resolution mismatch".to_string(),
                ));
            }
        }
        for resolution in &manifest.accepted_write_resolutions {
            match &resolution.disposition {
                AcceptedWriteDisposition::Recertified {
                    to,
                    to_command_spec_version,
                    command,
                    command_hash,
                    ..
                } => {
                    let accepted = self
                        .accepted_writes
                        .get_mut(&resolution.command_identity)
                        .expect("validated above");
                    accepted.command = command.clone();
                    accepted.command_hash = *command_hash;
                    accepted.command_spec_version = *to_command_spec_version;
                    accepted.accepted_route_generation = *to;
                    accepted.disposition = AcceptedWriteDisposition::Pending;
                }
                AcceptedWriteDisposition::Aborted { .. } => {
                    self.accepted_writes.remove(&resolution.command_identity);
                }
                AcceptedWriteDisposition::Pending => unreachable!("manifest validation rejects"),
            }
        }
        self.route_generation = manifest.cutover.to;
        self.command_spec_version = manifest.cutover.to_command_spec_version;
        self.cutover = None;
        Ok(())
    }

    pub fn complete_accepted(
        &mut self,
        identity: CommandIdentity,
        command_hash: HashType,
    ) -> Result<()> {
        let accepted = self.accepted_writes.get(&identity).ok_or_else(|| {
            BlossomError::InvalidConfiguration("unknown accepted write".to_string())
        })?;
        if accepted.command_hash != command_hash {
            return Err(BlossomError::InvalidConfiguration(
                "accepted-write completion hash mismatch".to_string(),
            ));
        }
        if !matches!(accepted.disposition, AcceptedWriteDisposition::Pending) {
            return Err(BlossomError::InvalidConfiguration(
                "resolved cutover write must remain in its manifest until activation".to_string(),
            ));
        }
        self.accepted_writes.remove(&identity);
        Ok(())
    }

    pub fn recovery_status(&self) -> Result<ActiveActiveHaRecoveryStatus> {
        Ok(ActiveActiveHaRecoveryStatus {
            operational: self.runtime.operational_status()?,
            route_generation: self.route_generation,
            command_spec_version: self.command_spec_version,
            accepted_writes: self.accepted_writes.len(),
            unresolved_accepted_writes: self
                .accepted_writes
                .values()
                .filter(|accepted| {
                    matches!(accepted.disposition, AcceptedWriteDisposition::Pending)
                })
                .count(),
            cutover: self.cutover,
        })
    }

    pub fn recovery_manifest(&self) -> Result<ActiveActiveHaRecoveryManifest> {
        let mut manifest = ActiveActiveHaRecoveryManifest {
            format_version: ACTIVE_ACTIVE_HA_RECOVERY_MANIFEST_VERSION,
            route_generation: self.route_generation,
            command_spec_version: self.command_spec_version,
            runtime: self.runtime.recovery_snapshot(),
            accepted_writes: self.accepted_writes.values().cloned().collect(),
            cutover: self.cutover,
            manifest_hash: HashType::default(),
        };
        manifest.manifest_hash = manifest.compute_hash()?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn install_recovery_manifest(
        &mut self,
        manifest: ActiveActiveHaRecoveryManifest,
    ) -> Result<LearnerCatchUp> {
        manifest.validate()?;
        if manifest.route_generation != self.route_generation
            || manifest.command_spec_version != self.command_spec_version
            || self
                .cutover
                .is_some_and(|cutover| Some(cutover) != manifest.cutover)
        {
            return Err(BlossomError::InvalidConfiguration(
                "recovery manifest application contract mismatch".to_string(),
            ));
        }
        for incoming in &manifest.accepted_writes {
            if let Some(existing) = self.accepted_writes.get(&incoming.command.identity)
                && existing != incoming
            {
                return Err(BlossomError::InvalidConfiguration(
                    "recovery manifest conflicts with a local accepted write".to_string(),
                ));
            }
        }
        let caught_up_through = manifest
            .runtime
            .epochs
            .last()
            .ok_or(BlossomError::EmptyEpochChain)?
            .nonce;
        let revision = self.runtime.install_recovery_snapshot(manifest.runtime)?;
        for incoming in manifest.accepted_writes {
            self.accepted_writes
                .entry(incoming.command.identity)
                .or_insert(incoming);
        }
        self.cutover = manifest.cutover;
        let eligible_for_activation = matches!(
            self.runtime.node_status(self.runtime.self_slot()),
            NodeAvailabilityStatus::Suspended { .. }
        ) && self.runtime.head().nonce >= caught_up_through;
        Ok(LearnerCatchUp {
            installed_revision: revision,
            caught_up_through,
            eligible_for_activation,
        })
    }

    pub fn activate_learner(
        &mut self,
        slot: HaMemberSlot,
    ) -> Result<(HaMembershipVote, Option<HaMembershipCertificate>)> {
        self.runtime
            .vote_to_reactivate(slot, self.runtime.head().nonce)
    }

    pub fn suspend_member(
        &mut self,
        slot: HaMemberSlot,
    ) -> Result<(HaMembershipVote, Option<HaMembershipCertificate>)> {
        self.runtime.vote_to_suspend(slot)
    }

    pub fn receive_activation_vote(&mut self, vote: HaMembershipVote) -> Result<HaRuntimeEvent> {
        self.runtime.receive_membership_vote(vote)
    }
}

fn validate_cutover_disposition(
    cutover: ActiveActiveCutover,
    disposition: &AcceptedWriteDisposition,
) -> Result<()> {
    let matches_cutover = match disposition {
        AcceptedWriteDisposition::Pending => true,
        AcceptedWriteDisposition::Recertified {
            from,
            to,
            from_command_spec_version,
            to_command_spec_version,
            ..
        } => {
            *from == cutover.from
                && *to == cutover.to
                && *from_command_spec_version == cutover.from_command_spec_version
                && *to_command_spec_version == cutover.to_command_spec_version
        }
        AcceptedWriteDisposition::Aborted {
            route_generation,
            command_spec_version,
            ..
        } => {
            *route_generation == cutover.from
                && *command_spec_version == cutover.from_command_spec_version
        }
    };
    if !matches_cutover {
        return Err(BlossomError::InvalidConfiguration(
            "accepted-write disposition does not match the active cutover".to_string(),
        ));
    }
    Ok(())
}

fn manifest_hash<T: BorshSerialize>(domain: &[u8], value: &T) -> Result<HashType> {
    let encoded = borsh::to_vec(value).map_err(|error| {
        BlossomError::WireProtocol(format!("encode active-active HA manifest: {error}"))
    })?;
    Ok(HashType::hash_slices([domain, encoded.as_slice()]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::active_active::{ApplicationCommand, ClientEpoch, ClientId, CommandIdentity};
    use crate::crypto::PubKey;
    use crate::group::ConsensusGroupId;
    use crate::high_availability::HighAvailabilityParameters;
    use crate::node::NodeIdentity;

    fn members() -> Vec<NodeIdentity> {
        (0..3)
            .map(|index| {
                NodeIdentity::new(
                    PubKey([index; 32]),
                    None,
                    "tcp",
                    "127.0.0.1",
                    19_000 + u16::from(index),
                    false,
                )
            })
            .collect()
    }

    fn command(sequence: u64) -> ActiveActiveCommand {
        ActiveActiveCommand {
            identity: CommandIdentity {
                client_id: ClientId([7; 16]),
                client_epoch: ClientEpoch(1),
                sequence,
            },
            command: ApplicationCommand::new(sequence.to_le_bytes().to_vec()).unwrap(),
        }
    }

    fn engine() -> ActiveActiveHaEngine {
        let members = members();
        let runtime = HighAvailabilityRuntime::new(
            ConsensusGroupId::named("active-active-ha-facade"),
            members[0].public_key(),
            members,
            HighAvailabilityParameters::default(),
        )
        .unwrap();
        ActiveActiveHaEngine::new(runtime, RouteGeneration(1), CommandSpecVersion(1)).unwrap()
    }

    #[test]
    fn cutover_requires_every_accepted_write_to_be_resolved() {
        let mut engine = engine();
        let recertified = command(1);
        let aborted = command(2);
        engine.accept_local(recertified.clone()).unwrap();
        engine.accept_local(aborted.clone()).unwrap();
        engine.begin_cutover(RouteGeneration(2)).unwrap();
        assert!(engine.cutover_manifest().is_err());

        engine.recertify_accepted(recertified.identity).unwrap();
        engine
            .abort_accepted(aborted.identity, "operator-confirmed abort")
            .unwrap();
        let manifest = engine.cutover_manifest().unwrap();
        engine.activate_cutover(&manifest).unwrap();

        let status = engine.recovery_status().unwrap();
        assert_eq!(status.route_generation, RouteGeneration(2));
        assert_eq!(status.command_spec_version, CommandSpecVersion(1));
        assert_eq!(status.accepted_writes, 1);
        assert_eq!(status.unresolved_accepted_writes, 1);
    }

    #[test]
    fn command_spec_cutover_requires_translation_or_abort() {
        let mut engine = engine();
        let original = command(1);
        engine.accept_local(original.clone()).unwrap();
        engine
            .begin_application_cutover(RouteGeneration(2), CommandSpecVersion(2))
            .unwrap();
        assert!(engine.recertify_accepted(original.identity).is_err());

        let translated = ActiveActiveCommand {
            identity: original.identity,
            command: ApplicationCommand::new(b"translated-command-spec-v2".to_vec()).unwrap(),
        };
        let translated_hash = translated.hash().unwrap();
        engine
            .recertify_accepted_as(original.identity, translated.clone())
            .unwrap();
        let manifest = engine.cutover_manifest().unwrap();
        assert_eq!(
            manifest.cutover.from_command_spec_version,
            CommandSpecVersion(1)
        );
        assert_eq!(
            manifest.cutover.to_command_spec_version,
            CommandSpecVersion(2)
        );
        engine.activate_cutover(&manifest).unwrap();

        let status = engine.recovery_status().unwrap();
        assert_eq!(status.route_generation, RouteGeneration(2));
        assert_eq!(status.command_spec_version, CommandSpecVersion(2));
        assert_eq!(
            engine
                .accepted_transaction(original.identity)
                .unwrap()
                .payload_as_borsh::<ActiveActiveCommand>()
                .unwrap(),
            translated
        );
        assert!(
            engine
                .complete_accepted(original.identity, original.hash().unwrap())
                .is_err()
        );
        engine
            .complete_accepted(original.identity, translated_hash)
            .unwrap();
    }

    #[test]
    fn recovery_manifest_carries_runtime_and_accepted_write_state() {
        let mut source = engine();
        let command = command(1);
        source.accept_local(command.clone()).unwrap();
        let manifest = source.recovery_manifest().unwrap();

        let mut learner = engine();
        let catch_up = learner.install_recovery_manifest(manifest).unwrap();
        assert_eq!(catch_up.caught_up_through, learner.runtime().head().nonce);
        assert_eq!(learner.recovery_status().unwrap().accepted_writes, 1);
        assert_eq!(
            learner
                .accepted_transaction(command.identity)
                .unwrap()
                .payload_as_borsh::<ActiveActiveCommand>()
                .unwrap(),
            command
        );
    }
}
