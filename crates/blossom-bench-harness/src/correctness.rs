//! Cross-engine correctness checks and canonical workload results.

use std::collections::{BTreeMap, BTreeSet};

use blossom::{ActiveActiveCommand, HashType};
use serde::{Deserialize, Serialize};

use crate::{CommandResult, SharedStateMachine};
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct HistoryOperation {
    pub operation_id: u64,
    pub invocation_nanos: u128,
    pub response_nanos: u128,
    pub command: ActiveActiveCommand,
    pub result: CommandResult,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct LinearizabilityReport {
    pub linearizable: bool,
    pub checked_operations: usize,
    pub witness_order: Vec<u64>,
    pub reason: String,
}

pub fn compare_non_conflicting_final_states(
    states: impl IntoIterator<Item = BTreeMap<Vec<u8>, Vec<u8>>>,
) -> bool {
    let mut states = states.into_iter();
    let Some(first) = states.next() else {
        return true;
    };
    states.all(|state| state == first)
}

/// Exact bounded linearizability checker for conflicting histories.
///
/// Benchmark drivers split long histories at quiescent points and feed each
/// segment here. A segment is capped at 63 operations so the explored set can
/// be represented without approximation.
pub fn check_linearizable_history(
    history: &[HistoryOperation],
    max_reorder: u64,
) -> LinearizabilityReport {
    if history.len() > 63 {
        return LinearizabilityReport {
            linearizable: false,
            checked_operations: 0,
            witness_order: Vec::new(),
            reason: "history segment exceeds the exact checker limit of 63 operations".to_string(),
        };
    }
    if history
        .iter()
        .any(|operation| operation.response_nanos < operation.invocation_nanos)
    {
        return LinearizabilityReport {
            linearizable: false,
            checked_operations: 0,
            witness_order: Vec::new(),
            reason: "history contains a response before its invocation".to_string(),
        };
    }
    let machine = match SharedStateMachine::new(max_reorder) {
        Ok(machine) => machine,
        Err(error) => {
            return LinearizabilityReport {
                linearizable: false,
                checked_operations: 0,
                witness_order: Vec::new(),
                reason: error.to_string(),
            };
        }
    };
    let mut seen = BTreeSet::new();
    let mut witness = Vec::with_capacity(history.len());
    let complete_mask = if history.is_empty() {
        0
    } else {
        (1u64 << history.len()) - 1
    };
    let linearizable = search(history, machine, 0, complete_mask, &mut seen, &mut witness);
    LinearizabilityReport {
        linearizable,
        checked_operations: history.len(),
        witness_order: if linearizable { witness } else { Vec::new() },
        reason: if linearizable {
            "history has a legal sequential witness respecting real-time order".to_string()
        } else {
            "no legal sequential witness respects results and real-time order".to_string()
        },
    }
}

fn search(
    history: &[HistoryOperation],
    machine: SharedStateMachine,
    applied_mask: u64,
    complete_mask: u64,
    seen: &mut BTreeSet<(u64, HashType)>,
    witness: &mut Vec<u64>,
) -> bool {
    if applied_mask == complete_mask {
        return true;
    }
    let state_hash = match machine.canonical_hash() {
        Ok(hash) => hash,
        Err(_) => return false,
    };
    if !seen.insert((applied_mask, state_hash)) {
        return false;
    }

    for (index, candidate) in history.iter().enumerate() {
        let bit = 1u64 << index;
        if applied_mask & bit != 0 {
            continue;
        }
        let blocked_by_real_time = history.iter().enumerate().any(|(other_index, other)| {
            let other_bit = 1u64 << other_index;
            applied_mask & other_bit == 0
                && other_index != index
                && other.response_nanos <= candidate.invocation_nanos
        });
        if blocked_by_real_time {
            continue;
        }

        let mut next_machine = machine.clone();
        let Ok(result) = next_machine.apply(&candidate.command) else {
            continue;
        };
        if result != candidate.result {
            continue;
        }
        witness.push(candidate.operation_id);
        if search(
            history,
            next_machine,
            applied_mask | bit,
            complete_mask,
            seen,
            witness,
        ) {
            return true;
        }
        witness.pop();
    }
    false
}

pub fn check_certified_application_order(
    certified_reference_order: &[HashType],
    applied_reference_order: &[HashType],
) -> bool {
    applied_reference_order.len() <= certified_reference_order.len()
        && applied_reference_order == &certified_reference_order[..applied_reference_order.len()]
}

#[cfg(test)]
mod tests {
    use blossom::{ClientEpoch, ClientId, CommandIdentity};

    use super::*;
    use crate::{CommandOperation, active_active_command};

    fn write(id: u64, value: &[u8]) -> ActiveActiveCommand {
        active_active_command(
            CommandIdentity {
                client_id: ClientId([id as u8; 16]),
                client_epoch: ClientEpoch(1),
                sequence: 1,
            },
            CommandOperation::BlindWrite {
                key: b"k".to_vec(),
                value: value.to_vec(),
            },
        )
        .unwrap()
    }

    #[test]
    fn checker_accepts_one_of_multiple_valid_consensus_orders() {
        let history = vec![
            HistoryOperation {
                operation_id: 1,
                invocation_nanos: 0,
                response_nanos: 10,
                command: write(1, b"a"),
                result: CommandResult::Written,
            },
            HistoryOperation {
                operation_id: 2,
                invocation_nanos: 1,
                response_nanos: 9,
                command: write(2, b"b"),
                result: CommandResult::Written,
            },
        ];
        assert!(check_linearizable_history(&history, 64).linearizable);
    }

    #[test]
    fn certified_application_order_must_be_a_stable_prefix() {
        let a = HashType([1; 32]);
        let b = HashType([2; 32]);
        assert!(check_certified_application_order(&[a, b], &[a]));
        assert!(!check_certified_application_order(&[a, b], &[b]));
    }

    #[test]
    fn response_equal_to_next_invocation_establishes_real_time_order() {
        let append = |id| {
            active_active_command(
                CommandIdentity {
                    client_id: ClientId([id; 16]),
                    client_epoch: ClientEpoch(1),
                    sequence: 1,
                },
                CommandOperation::Append {
                    key: b"k".to_vec(),
                    value: vec![id],
                },
            )
            .unwrap()
        };
        let history = vec![
            HistoryOperation {
                operation_id: 1,
                invocation_nanos: 0,
                response_nanos: 10,
                command: append(1),
                result: CommandResult::Appended { new_length: 2 },
            },
            HistoryOperation {
                operation_id: 2,
                invocation_nanos: 10,
                response_nanos: 20,
                command: append(2),
                result: CommandResult::Appended { new_length: 1 },
            },
        ];

        assert!(!check_linearizable_history(&history, 64).linearizable);
    }
}
