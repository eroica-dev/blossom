use crate::{
    ManifestAuthentication, PropagationPlan, PropagationStrategy, RedundancyPlan, TrustBoundary,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PushEstimate {
    pub recipients: usize,
    pub messages: usize,
    pub payload_bytes: usize,
    pub duplicate_bytes: usize,
    pub latency_steps: usize,
}

pub fn plan(trust_boundary: TrustBoundary) -> PropagationPlan {
    PropagationPlan {
        strategy: PropagationStrategy::PushFullBlocks,
        trust_boundary,
        manifest_authentication: ManifestAuthentication::None,
        redundancy: RedundancyPlan::new(1, 0),
        during_consensus: true,
    }
}

pub fn estimate_push(
    recipient_count: usize,
    known_recipient_count: usize,
    payload_bytes: usize,
    frame_overhead_bytes: usize,
) -> PushEstimate {
    let recipients = recipient_count.saturating_sub(known_recipient_count);
    let per_message = payload_bytes.saturating_add(frame_overhead_bytes);
    PushEstimate {
        recipients,
        messages: recipients,
        payload_bytes: per_message.saturating_mul(recipients),
        duplicate_bytes: per_message.saturating_mul(known_recipient_count.min(recipient_count)),
        latency_steps: usize::from(recipients > 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_push_is_valid_for_trustless_consensus_rounds() {
        plan(TrustBoundary::Trustless {
            quorum_size: 6,
            tolerated_byzantine: 1,
        })
        .validate()
        .unwrap();
    }

    #[test]
    fn push_estimate_uses_one_latency_step_and_skips_known_recipients() {
        let estimate = estimate_push(6, 2, 1_024, 64);

        assert_eq!(estimate.recipients, 4);
        assert_eq!(estimate.messages, 4);
        assert_eq!(estimate.payload_bytes, 4_352);
        assert_eq!(estimate.duplicate_bytes, 2_176);
        assert_eq!(estimate.latency_steps, 1);
    }
}
