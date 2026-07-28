//! Trusted direct-ordering benchmark cluster implementation.

use super::*;

impl BlossomTrustedDirectCluster {
    pub async fn start(
        participant_count: usize,
        quorum_size: QuorumSize,
    ) -> Result<Self, BoxError> {
        Ok(Self {
            order_cluster: BlossomTcpOrderCluster::start(participant_count, quorum_size).await?,
            state_machine: SharedStateMachine::new(4096)?,
        })
    }

    /// Places one command directly in each active writer's unsigned block and
    /// waits through local state-machine application.
    pub async fn client_write_universal(
        &mut self,
        commands: Vec<ActiveActiveCommand>,
    ) -> Result<BlossomTrustedDirectSample, BoxError> {
        let active_writers = commands.len();
        if active_writers == 0 || active_writers > self.order_cluster.participant_count() {
            return Err(format!(
                "active writer count must be in 1..={}, got {active_writers}",
                self.order_cluster.participant_count()
            )
            .into());
        }
        let started = Instant::now();
        let phase_started = Instant::now();
        let mut member_transactions = Vec::with_capacity(active_writers);
        for command in commands {
            command.validate()?;
            let encoded = borsh::to_vec(&command)?;
            let mut payload =
                Vec::with_capacity(TRUSTED_DIRECT_COMMAND_DOMAIN.len() + encoded.len());
            payload.extend_from_slice(TRUSTED_DIRECT_COMMAND_DOMAIN);
            payload.extend_from_slice(&encoded);
            member_transactions.push(vec![Transaction::new(payload)]);
        }
        let command_prepare_nanos = elapsed_nanos(phase_started);

        let (epoch, mut finality, _) = self
            .order_cluster
            .finalize_transactions(&member_transactions)
            .await?;
        let finalized_returned = Instant::now();
        let finalized_nanos = elapsed_nanos(started);
        let block_submission_nanos = finality.blocks_submitted_nanos;
        let receipt_and_order_nanos = finality
            .finalized_nanos
            .saturating_sub(finality.blocks_submitted_nanos);

        let phase_started = Instant::now();
        let ordered = epoch.trusted_ordered_transactions()?;
        if ordered.len() != active_writers {
            return Err("trusted epoch did not contain every direct writer command".into());
        }
        finality.reference_hashes = ordered
            .iter()
            .map(|ordered| ordered.transaction.hash)
            .collect();
        finality.reference_hash = finality
            .reference_hashes
            .first()
            .copied()
            .unwrap_or_default();
        let mut results = Vec::with_capacity(ordered.len());
        for ordered_transaction in ordered {
            let payload = ordered_transaction.transaction.payload.into_bytes();
            let encoded = payload
                .strip_prefix(TRUSTED_DIRECT_COMMAND_DOMAIN)
                .ok_or("trusted direct epoch contains an unknown transaction domain")?;
            let command = borsh::from_slice::<ActiveActiveCommand>(encoded)?;
            results.push(self.state_machine.apply(&command)?);
        }
        let apply_nanos = elapsed_nanos(phase_started);
        let applied_nanos = elapsed_nanos(started);

        let phase_started = Instant::now();
        self.order_cluster
            .wait_for_converged_epoch(finality.nonce, finality.epoch_hash)
            .await?;
        let convergence_nanos = elapsed_nanos(phase_started);
        finality.converged_nanos = Some(
            finality
                .finalized_nanos
                .saturating_add(elapsed_nanos(finalized_returned)),
        );
        finality.converged_nodes = self.order_cluster.participant_count();
        Ok(BlossomTrustedDirectSample {
            active_writers,
            finalized_nanos,
            applied_nanos,
            converged_nanos: elapsed_nanos(started),
            command_prepare_nanos,
            block_submission_nanos,
            receipt_and_order_nanos,
            apply_nanos,
            convergence_nanos,
            results,
            finality,
        })
    }

    pub fn read_local(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.state_machine.get(key).map(<[u8]>::to_vec)
    }
}
