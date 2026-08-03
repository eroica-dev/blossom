//! Admission, availability, ordering, read-barrier, and completion evidence.

use super::*;

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// Signed statement that one holder durably admitted a command.
pub struct AdmissionReceiptBody {
    /// Stable command identity admitted by the holder.
    pub command_identity: CommandIdentity,
    /// Domain-separated hash of the opaque command envelope.
    pub command_hash: HashType,
    /// Writer-local sequence assigned to the command.
    pub origin_sequence: u64,
    /// Public key of the durable holder.
    pub holder: PubKey,
    /// Site containing the holder.
    pub site: SiteId,
    /// Frozen holder membership generation.
    pub membership_epoch: ReplicaMembershipEpoch,
    /// Durable store incarnation used for admission.
    pub durable_store_generation: StoreGeneration,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// Holder-authenticated durable admission receipt.
pub struct AdmissionReceipt {
    /// Signed admission statement.
    pub body: AdmissionReceiptBody,
    /// Holder signature over the domain-separated statement.
    pub signature: Signature,
}

impl AdmissionReceipt {
    /// Signs an admission statement with the named holder.
    pub fn signed(body: AdmissionReceiptBody, signer: &SecretSigner) -> Result<Self> {
        if signer.public_key() != body.holder {
            return Err(BlossomError::KeyMismatch);
        }
        let message = signed_body_bytes(ADMISSION_RECEIPT_DOMAIN, &body)?;
        Ok(Self {
            body,
            signature: signer.sign(&message),
        })
    }

    /// Verifies the holder signature.
    pub fn verify(&self) -> Result<()> {
        let message = signed_body_bytes(ADMISSION_RECEIPT_DOMAIN, &self.body)?;
        self.signature.verify(&message, &self.body.holder)
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// Holder attestation for one complete canonical command batch.
pub struct AdmissionBatchReceiptBody {
    /// Application shard whose lane admitted the batch.
    pub shard: Vec<u8>,
    /// Domain-separated hash of the complete canonical batch.
    pub command_batch_hash: HashType,
    /// First writer-local sequence in the batch.
    pub first_origin_sequence: u64,
    /// Last writer-local sequence in the batch.
    pub last_origin_sequence: u64,
    /// Number of commands in the batch.
    pub command_count: u32,
    /// Public key of the durable holder.
    pub holder: PubKey,
    /// Site containing the holder.
    pub site: SiteId,
    /// Frozen holder membership generation.
    pub membership_epoch: ReplicaMembershipEpoch,
    /// Durable store incarnation used for admission.
    pub durable_store_generation: StoreGeneration,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// Holder-authenticated durable admission receipt for a complete batch.
pub struct AdmissionBatchReceipt {
    /// Signed batch admission statement.
    pub body: AdmissionBatchReceiptBody,
    /// Holder signature over the domain-separated statement.
    pub signature: Signature,
}

impl AdmissionBatchReceipt {
    /// Signs a batch admission statement with the named holder.
    pub fn signed(body: AdmissionBatchReceiptBody, signer: &SecretSigner) -> Result<Self> {
        if signer.public_key() != body.holder {
            return Err(BlossomError::KeyMismatch);
        }
        validate_shard_id(&body.shard)?;
        let message = signed_body_bytes(ADMISSION_BATCH_RECEIPT_DOMAIN, &body)?;
        Ok(Self {
            body,
            signature: signer.sign(&message),
        })
    }

    /// Verifies the holder signature and shard bound.
    pub fn verify(&self) -> Result<()> {
        validate_shard_id(&self.body.shard)?;
        let message = signed_body_bytes(ADMISSION_BATCH_RECEIPT_DOMAIN, &self.body)?;
        self.signature.verify(&message, &self.body.holder)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
/// Frozen site-local policy for command admission.
pub struct LocalAdmissionPolicy {
    /// Site whose holders issue the receipts.
    pub site: SiteId,
    /// Membership generation frozen for admission.
    pub membership_epoch: ReplicaMembershipEpoch,
    /// Eligible holder public keys.
    pub members: BTreeSet<PubKey>,
    /// Required durable store incarnation for every holder.
    pub store_generations: BTreeMap<PubKey, StoreGeneration>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
/// Supermajority site-local proof that one command was durably admitted.
pub struct LocalAdmissionCertificate {
    /// Frozen admission policy.
    pub policy: LocalAdmissionPolicy,
    /// Command identity shared by every receipt.
    pub command_identity: CommandIdentity,
    /// Command hash shared by every receipt.
    pub command_hash: HashType,
    /// Origin sequence shared by every receipt.
    pub origin_sequence: u64,
    /// Distinct authenticated holder receipts.
    pub receipts: Vec<AdmissionReceipt>,
}

impl LocalAdmissionCertificate {
    /// Validates policy membership, store generations, and receipt quorum.
    pub fn verify(&self) -> Result<()> {
        validate_local_admission_policy(&self.policy)?;
        let mut holders = BTreeSet::new();
        for receipt in &self.receipts {
            receipt.verify()?;
            if receipt.body.command_identity != self.command_identity
                || receipt.body.command_hash != self.command_hash
                || receipt.body.origin_sequence != self.origin_sequence
                || receipt.body.site != self.policy.site
                || receipt.body.membership_epoch != self.policy.membership_epoch
                || !self.policy.members.contains(&receipt.body.holder)
                || self.policy.store_generations.get(&receipt.body.holder)
                    != Some(&receipt.body.durable_store_generation)
            {
                return Err(BlossomError::InvalidConfiguration(
                    "admission receipt does not match its frozen policy".to_string(),
                ));
            }
            holders.insert(receipt.body.holder);
        }
        if holders.len() < supermajority_count(self.policy.members.len()) {
            return Err(BlossomError::FailedConsensus);
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
/// Site-local durability quorum certificate for one canonical command batch.
pub struct LocalAdmissionBatchCertificate {
    /// Frozen admission policy.
    pub policy: LocalAdmissionPolicy,
    /// Application shard whose lane admitted the batch.
    pub shard: Vec<u8>,
    /// Domain-separated hash of the complete batch.
    pub command_batch_hash: HashType,
    /// First writer-local sequence in the batch.
    pub first_origin_sequence: u64,
    /// Last writer-local sequence in the batch.
    pub last_origin_sequence: u64,
    /// Number of commands in the batch.
    pub command_count: u32,
    /// Distinct authenticated holder receipts.
    pub receipts: Vec<AdmissionBatchReceipt>,
}

/// In-process proof that a command batch matched a valid local admission
/// quorum certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedLocalAdmissionBatch {
    pub(super) policy: LocalAdmissionPolicy,
    shard: Vec<u8>,
    pub(super) command_batch_hash: HashType,
}

impl VerifiedLocalAdmissionBatch {
    /// Borrows the validated shard identifier.
    pub fn shard(&self) -> &[u8] {
        &self.shard
    }

    /// Returns the validated canonical command-batch hash.
    pub fn command_batch_hash(&self) -> HashType {
        self.command_batch_hash
    }
}

impl LocalAdmissionBatchCertificate {
    /// Verifies that this certificate commits the supplied complete batch.
    pub fn verify_batch(&self, batch: &CommandBatch) -> Result<()> {
        self.verify_and_bind(batch).map(|_| ())
    }

    /// Verifies the batch and returns an unforgeable in-process proof.
    pub fn verify_and_bind(&self, batch: &CommandBatch) -> Result<VerifiedLocalAdmissionBatch> {
        validate_local_admission_policy(&self.policy)?;
        validate_shard_id(&self.shard)?;
        batch.validate()?;
        let first = batch
            .commands
            .first()
            .expect("validated command batch is non-empty")
            .origin_sequence;
        let last = batch
            .commands
            .last()
            .expect("validated command batch is non-empty")
            .origin_sequence;
        let command_count = u32::try_from(batch.commands.len()).map_err(|_| {
            BlossomError::InvalidConfiguration(
                "local admission batch command count exceeds u32".to_string(),
            )
        })?;
        if self.command_batch_hash != batch.hash()?
            || self.first_origin_sequence != first
            || self.last_origin_sequence != last
            || self.command_count != command_count
        {
            return Err(BlossomError::InvalidConfiguration(
                "local admission batch certificate does not match its command batch".to_string(),
            ));
        }
        let mut holders = BTreeSet::new();
        for receipt in &self.receipts {
            receipt.verify()?;
            if receipt.body.command_batch_hash != self.command_batch_hash
                || receipt.body.shard != self.shard
                || receipt.body.first_origin_sequence != self.first_origin_sequence
                || receipt.body.last_origin_sequence != self.last_origin_sequence
                || receipt.body.command_count != self.command_count
                || receipt.body.site != self.policy.site
                || receipt.body.membership_epoch != self.policy.membership_epoch
                || !self.policy.members.contains(&receipt.body.holder)
                || self.policy.store_generations.get(&receipt.body.holder)
                    != Some(&receipt.body.durable_store_generation)
                || !holders.insert(receipt.body.holder)
            {
                return Err(BlossomError::InvalidConfiguration(
                    "admission batch receipt does not match its frozen policy".to_string(),
                ));
            }
        }
        if holders.len() < supermajority_count(self.policy.members.len()) {
            return Err(BlossomError::FailedConsensus);
        }
        Ok(VerifiedLocalAdmissionBatch {
            policy: self.policy.clone(),
            shard: self.shard.clone(),
            command_batch_hash: self.command_batch_hash,
        })
    }
}

fn validate_local_admission_policy(policy: &LocalAdmissionPolicy) -> Result<()> {
    if policy.members.is_empty()
        || policy
            .store_generations
            .keys()
            .copied()
            .collect::<BTreeSet<_>>()
            != policy.members
    {
        return Err(BlossomError::InvalidConfiguration(
            "admission policy must bind one store generation per member".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn validate_local_admission_policy_against_membership(
    policy: &LocalAdmissionPolicy,
    membership: &HolderMembership,
) -> Result<()> {
    validate_local_admission_policy(policy)?;
    membership.validate()?;
    let expected_members = membership
        .members_by_site
        .get(&policy.site)
        .ok_or_else(|| {
            BlossomError::InvalidConfiguration(
                "local admission policy site is not in holder membership".to_string(),
            )
        })?;
    let expected_store_generations = expected_members
        .iter()
        .map(|member| {
            membership
                .store_generations
                .get(member)
                .copied()
                .map(|generation| (*member, generation))
                .ok_or_else(|| {
                    BlossomError::InvalidConfiguration(
                        "holder membership is missing a local store generation".to_string(),
                    )
                })
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    if policy.membership_epoch != membership.epoch
        || &policy.members != expected_members
        || policy.store_generations != expected_store_generations
    {
        return Err(BlossomError::InvalidConfiguration(
            "local admission policy does not match configured holder membership".to_string(),
        ));
    }
    Ok(())
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// Signed statement that one holder retains a complete batch reference.
pub struct AvailabilityReceiptBody {
    /// Hash of the complete batch reference.
    pub reference_hash: HashType,
    /// Public key of the holder retaining the bytes.
    pub holder: PubKey,
    /// Site containing the holder.
    pub site: SiteId,
    /// Frozen holder membership generation.
    pub membership_epoch: ReplicaMembershipEpoch,
    /// Durable store incarnation retaining the bytes.
    pub durable_store_generation: StoreGeneration,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// Holder-authenticated claim that a complete batch is durable.
pub struct AuthenticatedAvailabilityReceipt {
    /// Signed availability statement.
    pub body: AvailabilityReceiptBody,
    /// Holder signature over the domain-separated statement.
    pub signature: Signature,
}

impl AuthenticatedAvailabilityReceipt {
    /// Signs an availability statement with the named holder.
    pub fn signed(body: AvailabilityReceiptBody, signer: &SecretSigner) -> Result<Self> {
        if signer.public_key() != body.holder {
            return Err(BlossomError::KeyMismatch);
        }
        let message = signed_body_bytes(AVAILABILITY_RECEIPT_DOMAIN, &body)?;
        Ok(Self {
            body,
            signature: signer.sign(&message),
        })
    }

    /// Verifies the holder signature.
    pub fn verify(&self) -> Result<()> {
        let message = signed_body_bytes(AVAILABILITY_RECEIPT_DOMAIN, &self.body)?;
        self.signature.verify(&message, &self.body.holder)
    }
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
/// Fault model used to interpret holder availability claims.
pub enum AvailabilityTrust {
    /// Known crash-fault holders using site-local supermajorities.
    Trusted,
    /// Authenticated claims sized for the configured Byzantine holder bound.
    VerifiedClaims,
}

impl AvailabilityTrust {
    /// Returns a stable operator-facing description.
    pub fn result_label(self) -> &'static str {
        match self {
            Self::Trusted => "trusted durable availability",
            Self::VerifiedClaims => "Byzantine finality with authenticated availability claims",
        }
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// Frozen three-site holder membership and durable store generations.
pub struct HolderMembership {
    /// Holder membership generation.
    pub epoch: ReplicaMembershipEpoch,
    /// Eligible holders grouped by non-empty site.
    pub members_by_site: BTreeMap<SiteId, BTreeSet<PubKey>>,
    /// Required durable store incarnation for each holder.
    pub store_generations: BTreeMap<PubKey, StoreGeneration>,
    /// Byzantine holder failures tolerated per site.
    pub holder_fault_bound: usize,
}

impl HolderMembership {
    /// Validates three-site uniqueness and complete store-generation binding.
    pub fn validate(&self) -> Result<()> {
        if self.members_by_site.len() != 3 || self.members_by_site.values().any(BTreeSet::is_empty)
        {
            return Err(BlossomError::InvalidConfiguration(
                "availability membership requires three non-empty sites".to_string(),
            ));
        }
        let mut all_members = BTreeSet::new();
        for members in self.members_by_site.values() {
            for member in members {
                if !all_members.insert(*member) {
                    return Err(BlossomError::InvalidConfiguration(
                        "one availability holder cannot belong to multiple sites".to_string(),
                    ));
                }
            }
        }
        if self
            .store_generations
            .keys()
            .copied()
            .collect::<BTreeSet<_>>()
            != all_members
        {
            return Err(BlossomError::InvalidConfiguration(
                "holder membership must bind one store generation per member".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// Old-committee-authorized replacement of holders and ordering validators.
pub struct CommitteeTransitionStatement {
    /// Application cluster whose ordered stream changes committee.
    pub cluster_id: HashType,
    /// Blossom consensus group whose ordered stream changes committee.
    pub consensus_group_id: ConsensusGroupId,
    /// Holder membership epoch authorizing the transition.
    pub previous_holder_membership_epoch: ReplicaMembershipEpoch,
    /// Validator generation whose signatures authorize the transition.
    pub previous_validator_generation: ValidatorGeneration,
    /// Complete next holder membership.
    pub next_holder_membership: HolderMembership,
    /// Next validator generation.
    pub next_validator_generation: ValidatorGeneration,
    /// Complete next validator keys.
    pub next_validators: BTreeSet<PubKey>,
    /// Globally applied boundary at which activation is safe.
    pub activated_at: Watermark,
    /// Order-certificate hash at the activation boundary.
    pub order_certificate_hash: HashType,
}

impl CommitteeTransitionStatement {
    /// Validates monotonic generations, bounded validators, and holder shape.
    pub fn validate(&self) -> Result<()> {
        self.next_holder_membership.validate()?;
        if self.cluster_id == HashType::default()
            || self.next_holder_membership.epoch.0
                != self
                    .previous_holder_membership_epoch
                    .0
                    .checked_add(1)
                    .ok_or_else(|| {
                        BlossomError::InvalidConfiguration(
                            "holder membership epoch overflow".to_string(),
                        )
                    })?
            || self.next_validator_generation.0
                != self
                    .previous_validator_generation
                    .0
                    .checked_add(1)
                    .ok_or_else(|| {
                        BlossomError::InvalidConfiguration(
                            "validator generation overflow".to_string(),
                        )
                    })?
            || self.next_validators.is_empty()
            || self.next_validators.len() > MAX_REFERENCES_PER_ORDERING_WINDOW
            || (self.activated_at == Watermark::default())
                != (self.order_certificate_hash == HashType::default())
        {
            return Err(BlossomError::InvalidConfiguration(
                "committee transition generations, scope, boundary, or validators are invalid"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// One old validator's signature authorizing an exact committee transition.
pub struct CommitteeTransitionVote {
    /// Transition statement shared by every signer.
    pub statement: CommitteeTransitionStatement,
    /// Current validator signing the replacement.
    pub validator: PubKey,
    /// Domain-separated signature.
    pub signature: Signature,
}

impl CommitteeTransitionVote {
    /// Signs an exact transition with one current validator.
    pub(super) fn signed(
        statement: CommitteeTransitionStatement,
        signer: &SecretSigner,
    ) -> Result<Self> {
        statement.validate()?;
        let validator = signer.public_key();
        let signature = signer.sign(&CommitteeTransitionCertificate::signing_bytes(&statement)?);
        Ok(Self {
            statement,
            validator,
            signature,
        })
    }

    /// Verifies the vote's signature and statement shape.
    pub fn verify(&self) -> Result<()> {
        self.statement.validate()?;
        self.signature.verify(
            &CommitteeTransitionCertificate::signing_bytes(&self.statement)?,
            &self.validator,
        )
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// Current-validator supermajority certificate for one committee replacement.
pub struct CommitteeTransitionCertificate {
    /// Exact replacement statement.
    pub statement: CommitteeTransitionStatement,
    /// Distinct signatures from the old validator committee.
    pub signatures: BTreeMap<PubKey, Signature>,
}

impl CommitteeTransitionCertificate {
    /// Returns the domain-separated bytes validators sign.
    pub fn signing_bytes(statement: &CommitteeTransitionStatement) -> Result<Vec<u8>> {
        signed_body_bytes(COMMITTEE_TRANSITION_STATEMENT_DOMAIN, statement)
    }

    /// Builds a certificate from distinct votes over identical bytes.
    pub fn from_votes(
        statement: CommitteeTransitionStatement,
        votes: impl IntoIterator<Item = CommitteeTransitionVote>,
    ) -> Result<Self> {
        statement.validate()?;
        let mut signatures = BTreeMap::new();
        for vote in votes {
            if vote.statement != statement {
                return Err(BlossomError::InvalidConfiguration(
                    "committee transition vote does not match the certificate statement"
                        .to_string(),
                ));
            }
            vote.verify()?;
            if signatures.insert(vote.validator, vote.signature).is_some() {
                return Err(BlossomError::InvalidConfiguration(
                    "duplicate committee transition signer".to_string(),
                ));
            }
        }
        Ok(Self {
            statement,
            signatures,
        })
    }

    /// Verifies scope, exact old generations, and an old-validator supermajority.
    pub fn verify(
        &self,
        cluster_id: HashType,
        consensus_group_id: ConsensusGroupId,
        holder_membership: &HolderMembership,
        validator_generation: ValidatorGeneration,
        validators: &BTreeSet<PubKey>,
    ) -> Result<()> {
        self.statement.validate()?;
        if self.statement.cluster_id != cluster_id
            || self.statement.consensus_group_id != consensus_group_id
            || self.statement.previous_holder_membership_epoch != holder_membership.epoch
            || self.statement.previous_validator_generation != validator_generation
            || self.signatures.len() > validators.len()
        {
            return Err(BlossomError::FailedConsensus);
        }
        let message = Self::signing_bytes(&self.statement)?;
        let mut valid = 0usize;
        for (validator, signature) in &self.signatures {
            if !validators.contains(validator) {
                return Err(BlossomError::UnknownSender);
            }
            signature.verify(&message, validator)?;
            valid += 1;
        }
        if !has_supermajority(validators.len(), valid) {
            return Err(BlossomError::FailedConsensus);
        }
        Ok(())
    }

    /// Computes the durable chain identity of this replacement.
    pub fn hash(&self) -> Result<HashType> {
        hash_borsh(COMMITTEE_TRANSITION_CERTIFICATE_DOMAIN, self)
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// Multi-site proof that the bytes addressed by a reference are recoverable.
pub struct AvailabilityCertificate {
    /// Complete hash-committed batch reference.
    pub reference: BatchReference,
    /// Fault model used for availability thresholds.
    pub trust: AvailabilityTrust,
    /// Distinct authenticated holder receipts.
    pub receipts: Vec<AuthenticatedAvailabilityReceipt>,
}

impl AvailabilityCertificate {
    /// Verifies reference scope, holder eligibility, and site thresholds.
    pub fn verify(&self, membership: &HolderMembership) -> Result<()> {
        membership.validate()?;
        self.reference.validate()?;
        if membership.epoch != self.reference.data_holder_membership_epoch {
            return Err(BlossomError::InvalidConfiguration(
                "holder membership generation mismatch".to_string(),
            ));
        }
        let reference_hash = self.reference.hash()?;
        let mut holders_by_site = BTreeMap::<SiteId, BTreeSet<PubKey>>::new();
        let mut all_holders = BTreeSet::new();
        for receipt in &self.receipts {
            receipt.verify()?;
            if receipt.body.reference_hash != reference_hash
                || receipt.body.membership_epoch != membership.epoch
            {
                return Err(BlossomError::InvalidConfiguration(
                    "availability receipt does not bind the complete reference".to_string(),
                ));
            }
            let Some(site_members) = membership.members_by_site.get(&receipt.body.site) else {
                return Err(BlossomError::UnknownSender);
            };
            if !site_members.contains(&receipt.body.holder)
                || membership.store_generations.get(&receipt.body.holder)
                    != Some(&receipt.body.durable_store_generation)
                || !all_holders.insert(receipt.body.holder)
            {
                return Err(BlossomError::InvalidConfiguration(
                    "duplicate or ineligible availability holder".to_string(),
                ));
            }
            holders_by_site
                .entry(receipt.body.site.clone())
                .or_default()
                .insert(receipt.body.holder);
        }

        let certified_sites = membership
            .members_by_site
            .iter()
            .filter(|(site, members)| {
                let count = holders_by_site.get(*site).map_or(0, BTreeSet::len);
                let required = match self.trust {
                    AvailabilityTrust::Trusted => supermajority_count(members.len()),
                    AvailabilityTrust::VerifiedClaims => membership
                        .holder_fault_bound
                        .checked_mul(2)
                        .and_then(|value| value.checked_add(1))
                        .unwrap_or(usize::MAX),
                };
                count >= required
            })
            .count();
        if certified_sites < 2 {
            return Err(BlossomError::FailedConsensus);
        }
        Ok(())
    }

    /// Returns the distinct holders represented by the certificate.
    pub fn holders(&self) -> BTreeSet<PubKey> {
        self.receipts
            .iter()
            .map(|receipt| receipt.body.holder)
            .collect()
    }

    /// Selects eligible missing holders needed to restore per-site thresholds.
    pub fn repair_targets(&self, membership: &HolderMembership) -> Result<BTreeSet<PubKey>> {
        membership.validate()?;
        if membership.epoch != self.reference.data_holder_membership_epoch {
            return Err(BlossomError::InvalidConfiguration(
                "holder membership generation mismatch".to_string(),
            ));
        }
        let holders = self.holders();
        let mut repair_targets = BTreeSet::new();
        for members in membership.members_by_site.values() {
            let required = match self.trust {
                AvailabilityTrust::Trusted => supermajority_count(members.len()),
                AvailabilityTrust::VerifiedClaims => membership
                    .holder_fault_bound
                    .checked_mul(2)
                    .and_then(|value| value.checked_add(1))
                    .ok_or_else(|| {
                        BlossomError::InvalidConfiguration(
                            "holder repair threshold overflow".to_string(),
                        )
                    })?,
            };
            let present = members.intersection(&holders).count();
            repair_targets.extend(
                members
                    .difference(&holders)
                    .take(required.saturating_sub(present))
                    .copied(),
            );
        }
        Ok(repair_targets)
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// Validator statement assigning one reference to the global order chain.
pub struct OrderStatement {
    /// Consensus group authorizing the order.
    pub consensus_group_id: ConsensusGroupId,
    /// Hash of the Blossom epoch that fixed this reference's immutable order.
    pub blossom_epoch_hash: HashType,
    /// One-based global position.
    pub position: Watermark,
    /// Hash of the batch reference assigned to the position.
    pub reference_hash: HashType,
    /// Previous certificate hash in the global order chain.
    pub previous_order_certificate_hash: HashType,
    /// Validator generation authorized to sign.
    pub validator_generation: ValidatorGeneration,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// Supermajority certificate for one immutable global position.
pub struct OrderCertificate {
    /// Statement shared by all signatures.
    pub statement: OrderStatement,
    /// Distinct current-validator signatures.
    pub signatures: BTreeMap<PubKey, Signature>,
}

impl OrderCertificate {
    /// Returns the domain-separated bytes validators sign.
    pub fn signing_bytes(statement: &OrderStatement) -> Result<Vec<u8>> {
        signed_body_bytes(ORDER_STATEMENT_DOMAIN, statement)
    }

    /// Verifies statement scope and a distinct current-validator supermajority.
    pub fn verify(
        &self,
        validator_generation: ValidatorGeneration,
        validators: &BTreeSet<PubKey>,
    ) -> Result<()> {
        if self.statement.validator_generation != validator_generation
            || self.statement.position.position == 0
            || self.statement.blossom_epoch_hash == HashType::default()
            || self.signatures.len() > validators.len()
        {
            return Err(BlossomError::FailedConsensus);
        }
        let message = Self::signing_bytes(&self.statement)?;
        let mut valid = 0usize;
        for (validator, signature) in &self.signatures {
            if !validators.contains(validator) {
                return Err(BlossomError::UnknownSender);
            }
            signature.verify(&message, validator)?;
            valid += 1;
        }
        if !has_supermajority(validators.len(), valid) {
            return Err(BlossomError::FailedConsensus);
        }
        Ok(())
    }

    pub(super) fn trusted(statement: OrderStatement) -> Self {
        Self {
            statement,
            signatures: BTreeMap::new(),
        }
    }

    pub(super) fn verify_trusted(&self, validator_generation: ValidatorGeneration) -> Result<()> {
        if self.statement.validator_generation != validator_generation
            || self.statement.position.position == 0
            || self.statement.blossom_epoch_hash == HashType::default()
            || !self.signatures.is_empty()
        {
            return Err(BlossomError::FailedConsensus);
        }
        Ok(())
    }

    /// Builds a certificate from distinct votes over the identical statement.
    pub fn from_votes(
        statement: OrderStatement,
        votes: impl IntoIterator<Item = OrderVote>,
    ) -> Result<Self> {
        let mut signatures = BTreeMap::new();
        for vote in votes {
            if vote.statement != statement {
                return Err(BlossomError::InvalidConfiguration(
                    "order vote does not match the certificate statement".to_string(),
                ));
            }
            if signatures.insert(vote.validator, vote.signature).is_some() {
                return Err(BlossomError::InvalidConfiguration(
                    "duplicate validator order vote".to_string(),
                ));
            }
        }
        Ok(Self {
            statement,
            signatures,
        })
    }

    /// Computes the domain-separated certificate hash used for chain linkage.
    pub fn hash(&self) -> Result<HashType> {
        hash_borsh(ORDER_CERTIFICATE_DOMAIN, self)
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// One validator's signature over an order statement.
pub struct OrderVote {
    /// Proposed global position and chain linkage.
    pub statement: OrderStatement,
    /// Signing validator.
    pub validator: PubKey,
    /// Validator signature.
    pub signature: Signature,
}

impl OrderVote {
    /// Verifies this vote against its validator key.
    pub fn verify(&self) -> Result<()> {
        self.signature.verify(
            &OrderCertificate::signing_bytes(&self.statement)?,
            &self.validator,
        )
    }
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
/// Caller-generated nonce that makes a read-barrier observation fresh.
pub struct ReadBarrierChallenge(pub [u8; 32]);

impl ReadBarrierChallenge {
    /// Generates a cryptographically random challenge.
    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
/// Local request used to gather one fresh read-barrier certificate.
pub struct ReadBarrierRequest {
    /// Unique challenge that every vote must commit.
    pub challenge: ReadBarrierChallenge,
}

impl ReadBarrierRequest {
    /// Creates a request with a fresh random challenge.
    pub fn fresh() -> Self {
        Self {
            challenge: ReadBarrierChallenge::random(),
        }
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// Exact global-order tail observed by validators for a read challenge.
pub struct ReadBarrierStatement {
    /// Application cluster identifier.
    pub cluster_id: HashType,
    /// Blossom consensus group authorizing the barrier.
    pub consensus_group_id: ConsensusGroupId,
    /// Validator generation authorized to vote.
    pub validator_generation: ValidatorGeneration,
    /// Active application routing generation.
    pub route_generation: RouteGeneration,
    /// Active application command schema.
    pub command_spec_version: CommandSpecVersion,
    /// Caller-generated freshness nonce.
    pub challenge: ReadBarrierChallenge,
    /// Certified global order position.
    pub position: Watermark,
    /// Certificate hash at the certified tail.
    pub order_certificate_hash: HashType,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// One validator's signature over a read-barrier statement.
pub struct ReadBarrierVote {
    /// Fresh tail observation being signed.
    pub statement: ReadBarrierStatement,
    /// Signing validator.
    pub validator: PubKey,
    /// Validator signature.
    pub signature: Signature,
}

impl ReadBarrierVote {
    /// Verifies this vote against its validator key.
    pub fn verify(&self) -> Result<()> {
        self.signature.verify(
            &ReadBarrierCertificate::signing_bytes(&self.statement)?,
            &self.validator,
        )
    }
}

/// A fresh quorum observation of the global order head.
///
/// Freshness is relative to the caller-generated challenge. Reusing a
/// challenge intentionally permits replay, so callers must generate a new
/// challenge for every linearizable read attempt.
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct ReadBarrierCertificate {
    /// Fresh tail statement shared by all signatures.
    pub statement: ReadBarrierStatement,
    /// Distinct current-validator signatures.
    pub signatures: BTreeMap<PubKey, Signature>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
/// Read request paired with the certificate that answers its exact challenge.
pub struct CertifiedReadBarrier {
    /// Original caller request.
    pub request: ReadBarrierRequest,
    /// Quorum certificate over the request challenge and order tail.
    pub certificate: ReadBarrierCertificate,
}

impl ReadBarrierCertificate {
    /// Returns the domain-separated bytes validators sign.
    pub fn signing_bytes(statement: &ReadBarrierStatement) -> Result<Vec<u8>> {
        signed_body_bytes(READ_BARRIER_STATEMENT_DOMAIN, statement)
    }

    /// Builds a certificate from distinct valid votes over one statement.
    pub fn from_votes(
        statement: ReadBarrierStatement,
        votes: impl IntoIterator<Item = ReadBarrierVote>,
    ) -> Result<Self> {
        let mut signatures = BTreeMap::new();
        for vote in votes {
            if vote.statement != statement {
                return Err(BlossomError::InvalidConfiguration(
                    "read-barrier vote does not match the certificate statement".to_string(),
                ));
            }
            vote.verify()?;
            if signatures.insert(vote.validator, vote.signature).is_some() {
                return Err(BlossomError::InvalidConfiguration(
                    "duplicate validator read-barrier vote".to_string(),
                ));
            }
        }
        Ok(Self {
            statement,
            signatures,
        })
    }

    /// Verifies freshness, application generations, and validator quorum.
    pub fn verify(
        &self,
        expected_challenge: ReadBarrierChallenge,
        validator_generation: ValidatorGeneration,
        validators: &BTreeSet<PubKey>,
    ) -> Result<()> {
        if self.statement.challenge != expected_challenge
            || self.statement.validator_generation != validator_generation
            || self.signatures.len() > validators.len()
        {
            return Err(BlossomError::FailedConsensus);
        }
        self.statement.route_generation.validate()?;
        self.statement.command_spec_version.validate()?;
        if (self.statement.position == Watermark::default())
            != (self.statement.order_certificate_hash == HashType::default())
        {
            return Err(BlossomError::FailedConsensus);
        }
        let message = Self::signing_bytes(&self.statement)?;
        let mut valid = 0usize;
        for (validator, signature) in &self.signatures {
            if !validators.contains(validator) {
                return Err(BlossomError::UnknownSender);
            }
            signature.verify(&message, validator)?;
            valid += 1;
        }
        if !has_supermajority(validators.len(), valid) {
            return Err(BlossomError::FailedConsensus);
        }
        Ok(())
    }

    /// Computes the domain-separated certificate hash.
    pub fn hash(&self) -> Result<HashType> {
        hash_borsh(READ_BARRIER_CERTIFICATE_DOMAIN, self)
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// Terminal durable result of applying one ordered reference.
pub struct AppliedCompletion {
    /// Hash of the applied batch reference.
    pub reference_hash: HashType,
    /// Global position applied by the application.
    pub watermark: Watermark,
    /// Opaque results in command order.
    pub results: Vec<ApplicationResult>,
}

impl AppliedCompletion {
    pub(super) fn validate(&self, expected_command_count: Option<usize>) -> Result<()> {
        if self.watermark.position == 0
            || expected_command_count.is_some_and(|count| count != self.results.len())
        {
            return Err(BlossomError::InvalidConfiguration(
                "applied completion watermark or result count is invalid".to_string(),
            ));
        }
        let mut total_bytes = 0usize;
        for result in &self.results {
            result.validate()?;
            total_bytes = total_bytes
                .checked_add(result.as_bytes().len())
                .ok_or_else(|| {
                    BlossomError::InvalidConfiguration(
                        "application completion result size overflow".to_string(),
                    )
                })?;
        }
        if total_bytes > MAX_APPLICATION_RESULT_BYTES {
            return Err(BlossomError::InvalidConfiguration(format!(
                "application completion results exceed {MAX_APPLICATION_RESULT_BYTES} bytes"
            )));
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
/// Indexed durable status of one batch reference.
pub enum ReferenceStatus {
    /// No local admission or ordered state is known.
    Unknown,
    /// The reference reached a non-terminal milestone.
    Pending(MilestoneEvent),
    /// Ordered application completed durably.
    Applied(AppliedCompletion),
}

impl ReferenceStatus {
    /// Returns whether this status satisfies `target`.
    pub fn reached(&self, target: Milestone) -> bool {
        match self {
            Self::Unknown => false,
            Self::Pending(event) => event.milestone.reaches(target),
            Self::Applied(_) => true,
        }
    }

    /// Returns whether no later lifecycle transition exists.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Applied(_))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
/// Result of a bounded wait for a reference milestone.
pub enum WaitForOutcome {
    /// The requested milestone was observed before the deadline.
    Reached(ReferenceStatus),
    /// The deadline elapsed; carries the latest observed status.
    TimedOut(ReferenceStatus),
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
/// Durable record of an atomic route and command-schema cutover.
pub struct ApplicationContractActivation {
    /// Routing generation active before cutover.
    pub previous_route_generation: RouteGeneration,
    /// Routing generation active after cutover.
    pub route_generation: RouteGeneration,
    /// Command schema active before cutover.
    pub previous_command_spec_version: CommandSpecVersion,
    /// Command schema active after cutover.
    pub command_spec_version: CommandSpecVersion,
    /// Applied boundary at which both generations changed.
    pub activated_at: Watermark,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
/// Durable result of one certified holder and validator replacement.
pub struct CommitteeTransitionActivation {
    /// Holder generation active before replacement.
    pub previous_holder_membership_epoch: ReplicaMembershipEpoch,
    /// Holder generation active after replacement.
    pub holder_membership_epoch: ReplicaMembershipEpoch,
    /// Validator generation active before replacement.
    pub previous_validator_generation: ValidatorGeneration,
    /// Validator generation active after replacement.
    pub validator_generation: ValidatorGeneration,
    /// Globally applied boundary at which the replacement became active.
    pub activated_at: Watermark,
    /// Hash of the durably installed transition certificate.
    pub transition_hash: HashType,
}
