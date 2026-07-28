//! Committed HA parameters and stable public-key-to-slot assignment.

use super::*;

/// Returns the strict-majority threshold for an HA active membership.
pub const fn high_availability_majority(member_count: usize) -> usize {
    (member_count / 2) + 1
}

/// Number of crash/inactive members tolerated without reconfiguration.
pub const fn high_availability_fault_tolerance(member_count: usize) -> usize {
    member_count.saturating_sub(high_availability_majority(member_count))
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
/// Consensus-committed HA lifecycle depths.
pub struct HighAvailabilityParameters {
    /// Parameter codec version.
    pub version: u16,
    /// Successors required before an epoch is sealed.
    pub mutable_epoch_depth: u32,
    /// Consecutive missed epochs before a member is unresponsive.
    pub unresponsive_epoch_depth: u32,
}

impl HighAvailabilityParameters {
    /// Creates versioned parameters with explicit positive depths.
    pub const fn new(mutable_epoch_depth: u32, unresponsive_epoch_depth: u32) -> Self {
        Self {
            version: HIGH_AVAILABILITY_PARAMETERS_VERSION,
            mutable_epoch_depth,
            unresponsive_epoch_depth,
        }
    }

    /// Validates the version and positive depth bounds.
    pub fn validate(self) -> Result<()> {
        if self.version != HIGH_AVAILABILITY_PARAMETERS_VERSION {
            return Err(BlossomError::InvalidConfiguration(format!(
                "unsupported high-availability parameters version {}",
                self.version
            )));
        }
        if self.mutable_epoch_depth == 0 {
            return Err(BlossomError::InvalidConfiguration(
                "mutable epoch depth must be positive".to_string(),
            ));
        }
        if self.unresponsive_epoch_depth == 0 {
            return Err(BlossomError::InvalidConfiguration(
                "unresponsive epoch depth must be positive".to_string(),
            ));
        }
        Ok(())
    }

    /// Resolves CLI-over-environment-over-default startup values.
    pub fn resolve_startup(
        mutable_cli: Option<&str>,
        mutable_environment: Option<&str>,
        unresponsive_cli: Option<&str>,
        unresponsive_environment: Option<&str>,
    ) -> Result<Self> {
        let mutable_epoch_depth = parse_depth(
            BLOSSOM_MUTABLE_EPOCH_DEPTH_ENV,
            mutable_cli.or(mutable_environment),
            DEFAULT_MUTABLE_EPOCH_DEPTH,
        )?;
        let unresponsive_epoch_depth = parse_depth(
            BLOSSOM_UNRESPONSIVE_EPOCH_DEPTH_ENV,
            unresponsive_cli.or(unresponsive_environment),
            DEFAULT_UNRESPONSIVE_EPOCH_DEPTH,
        )?;
        let parameters = Self::new(mutable_epoch_depth, unresponsive_epoch_depth);
        parameters.validate()?;
        Ok(parameters)
    }

    /// Resolves both depths from their environment variables.
    pub fn from_environment() -> Result<Self> {
        Self::resolve_startup(
            None,
            optional_environment(BLOSSOM_MUTABLE_EPOCH_DEPTH_ENV)?.as_deref(),
            None,
            optional_environment(BLOSSOM_UNRESPONSIVE_EPOCH_DEPTH_ENV)?.as_deref(),
        )
    }

    /// Computes the consensus-committed parameter hash.
    pub fn hash(self) -> HashType {
        let mut hasher = ProtocolHasher::new();
        hasher.update(HA_PARAMETERS_HASH_DOMAIN);
        hasher.update(self.version.to_le_bytes());
        hasher.update(self.mutable_epoch_depth.to_le_bytes());
        hasher.update(self.unresponsive_epoch_depth.to_le_bytes());
        hasher.finalize()
    }
}

impl Default for HighAvailabilityParameters {
    fn default() -> Self {
        Self::new(
            DEFAULT_MUTABLE_EPOCH_DEPTH,
            DEFAULT_UNRESPONSIVE_EPOCH_DEPTH,
        )
    }
}

fn optional_environment(name: &str) -> Result<Option<String>> {
    match env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(BlossomError::InvalidConfiguration(format!(
            "read {name}: {error}"
        ))),
    }
}

fn parse_depth(name: &str, value: Option<&str>, default: u32) -> Result<u32> {
    let value = match value {
        Some(value) => value.parse::<u32>().map_err(|_| {
            BlossomError::InvalidConfiguration(format!(
                "{name} must be a positive u32, got {value:?}"
            ))
        })?,
        None => default,
    };
    if value == 0 {
        return Err(BlossomError::InvalidConfiguration(format!(
            "{name} must be positive"
        )));
    }
    Ok(value)
}

#[derive(
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
/// Stable index of one fixed HA public identity.
pub struct HaMemberSlot(pub u8);

impl HaMemberSlot {
    /// Returns the slot as an array index.
    pub fn index(self) -> usize {
        usize::from(self.0)
    }

    pub(super) fn bit(self) -> Result<u8> {
        if self.index() >= MAX_HA_NODES {
            return Err(BlossomError::InvalidConfiguration(format!(
                "HA member slot {} exceeds maximum slot {}",
                self.0,
                MAX_HA_NODES - 1
            )));
        }
        Ok(1u8 << self.0)
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// Sorted fixed identities and the current active-slot mask.
///
/// Serialized member identities contain public material only.
pub struct HaMemberSlots {
    pub(super) member_count: u8,
    pub(super) active_mask: u8,
    fixed_identity_hash: HashType,
    members: [Option<NodeIdentity>; MAX_HA_NODES],
}

impl HaMemberSlots {
    /// Sorts two through seven unique identities into stable slots.
    pub fn new(mut members: Vec<NodeIdentity>) -> Result<Self> {
        if !(MIN_HA_NODES..=MAX_HA_NODES).contains(&members.len()) {
            return Err(BlossomError::InvalidHighAvailabilityNodeCount(
                members.len(),
            ));
        }
        members.sort_by_key(NodeIdentity::public_key);
        if members
            .windows(2)
            .any(|pair| pair[0].public_key() == pair[1].public_key())
        {
            return Err(BlossomError::InvalidConfiguration(
                "high-availability membership contains duplicate public keys".to_string(),
            ));
        }
        let member_count = u8::try_from(members.len()).expect("HA membership is at most seven");
        let active_mask = low_bits(member_count);
        let mut slots = array::from_fn(|_| None);
        for (index, member) in members.into_iter().enumerate() {
            slots[index] = Some(member.public_only());
        }
        let result = Self {
            member_count,
            active_mask,
            fixed_identity_hash: Self::compute_fixed_identity_hash(member_count, &slots),
            members: slots,
        };
        result.validate()?;
        Ok(result)
    }

    /// Validates dense ordering, public identity hash, and active bounds.
    pub fn validate(&self) -> Result<()> {
        let member_count = usize::from(self.member_count);
        if !(MIN_HA_NODES..=MAX_HA_NODES).contains(&member_count) {
            return Err(BlossomError::InvalidHighAvailabilityNodeCount(member_count));
        }
        if self.active_mask & !low_bits(self.member_count) != 0 {
            return Err(BlossomError::InvalidConfiguration(
                "HA active mask references an unassigned slot".to_string(),
            ));
        }
        if self.fixed_identity_hash
            != Self::compute_fixed_identity_hash(self.member_count, &self.members)
        {
            return Err(BlossomError::InvalidConfiguration(
                "HA fixed membership hash does not match its public-key slots".to_string(),
            ));
        }
        if self.active_count() < MIN_HA_NODES {
            return Err(BlossomError::InvalidConfiguration(
                "HA requires at least two active members".to_string(),
            ));
        }
        for index in 0..MAX_HA_NODES {
            let should_exist = index < member_count;
            if self.members[index].is_some() != should_exist {
                return Err(BlossomError::InvalidConfiguration(
                    "HA membership slots must be densely assigned".to_string(),
                ));
            }
            if index > 0
                && index < member_count
                && self.members[index - 1]
                    .as_ref()
                    .expect("validated dense member")
                    .public_key()
                    >= self.members[index]
                        .as_ref()
                        .expect("validated dense member")
                        .public_key()
            {
                return Err(BlossomError::InvalidConfiguration(
                    "HA membership slots must be ordered by public key".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Returns the fixed genesis identity count.
    pub fn member_count(&self) -> usize {
        usize::from(self.member_count)
    }

    /// Returns the bit mask of currently active fixed slots.
    pub fn active_mask(&self) -> u8 {
        self.active_mask
    }

    /// Returns the number of currently active slots.
    pub fn active_count(&self) -> usize {
        (self.active_mask & low_bits(self.member_count)).count_ones() as usize
    }

    /// Returns the strict majority of the active slots.
    pub fn majority(&self) -> usize {
        high_availability_majority(self.active_count())
    }

    /// Returns the hash of sorted fixed public identities.
    pub fn fixed_identity_hash(&self) -> HashType {
        self.fixed_identity_hash
    }

    fn compute_fixed_identity_hash(
        member_count: u8,
        members: &[Option<NodeIdentity>; MAX_HA_NODES],
    ) -> HashType {
        let mut hasher = ProtocolHasher::new();
        hasher.update(HA_MEMBERSHIP_HASH_DOMAIN);
        hasher.update([member_count]);
        for member in members.iter().take(usize::from(member_count)) {
            hasher.update(
                member
                    .as_ref()
                    .expect("validated HA membership is densely assigned")
                    .public_key()
                    .as_ref(),
            );
        }
        hasher.finalize()
    }

    /// Returns the public identity assigned to `slot`.
    pub fn member(&self, slot: HaMemberSlot) -> Option<&NodeIdentity> {
        self.members.get(slot.index()).and_then(Option::as_ref)
    }

    /// Finds the stable slot assigned to a public key.
    pub fn slot_for(&self, public_key: &PubKey) -> Option<HaMemberSlot> {
        self.members
            .iter()
            .take(self.member_count())
            .position(|member| {
                member
                    .as_ref()
                    .is_some_and(|member| member.public_key() == *public_key)
            })
            .map(|index| HaMemberSlot(index as u8))
    }

    pub(super) fn same_fixed_identities(&self, other: &Self) -> bool {
        self.member_count == other.member_count
            && (0..self.member_count()).all(|index| {
                self.members[index]
                    .as_ref()
                    .zip(other.members[index].as_ref())
                    .is_some_and(|(left, right)| left.public_key() == right.public_key())
            })
    }

    pub(super) fn public_only(&self) -> Self {
        self.clone()
    }

    /// Returns whether a fixed slot is currently active.
    pub fn is_active(&self, slot: HaMemberSlot) -> bool {
        slot.bit()
            .is_ok_and(|bit| self.active_mask & bit != 0 && self.member(slot).is_some())
    }

    /// Returns a validated copy with one active slot suspended.
    pub fn with_suspended(&self, slot: HaMemberSlot) -> Result<Self> {
        if !self.is_active(slot) {
            return Err(BlossomError::InvalidConfiguration(
                "cannot suspend an inactive HA member".to_string(),
            ));
        }
        let next_mask = self.active_mask & !slot.bit()?;
        if next_mask.count_ones() < MIN_HA_NODES as u32 {
            return Err(BlossomError::InvalidConfiguration(
                "cannot suspend enough HA members to leave fewer than two active".to_string(),
            ));
        }
        let mut next = self.clone();
        next.active_mask = next_mask;
        next.validate()?;
        Ok(next)
    }

    /// Returns a validated copy with one assigned slot reactivated.
    pub fn with_reactivated(&self, slot: HaMemberSlot) -> Result<Self> {
        if self.member(slot).is_none() {
            return Err(BlossomError::UnknownSender);
        }
        let mut next = self.clone();
        next.active_mask |= slot.bit()?;
        next.validate()?;
        Ok(next)
    }
}

pub(super) fn low_bits(count: u8) -> u8 {
    ((1u16 << count) - 1) as u8
}
