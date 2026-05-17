use serde::{Deserialize, Serialize};

use crate::algorithm::supermajority_count;
use crate::crypto::PubKey;
use crate::messages::Msg;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum Status {
    DispatchReceived,
    DispatchPending,
    DispatchVoid,
    EchoReceived,
    EchoVoid,
    NodePassed,
    NodePending,
    NodeVoid,
    NodeSelf,
    Void,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct QuorumQueue {
    pub queue: Vec<MessageMatrix>,
    pub length: usize,
    pub position: usize,
}

impl QuorumQueue {
    pub fn new(quorum_peers: Vec<Vec<PubKey>>, self_key: &PubKey) -> Self {
        let queue = quorum_peers
            .iter()
            .map(|quorum| MessageMatrix::new(quorum, self_key))
            .collect::<Vec<_>>();
        Self {
            length: queue.len(),
            queue,
            position: 0,
        }
    }

    pub fn next_matrix(&mut self) {
        if self.position + 1 < self.length {
            self.position += 1;
        }
    }

    pub fn update_matrix(&mut self, is_valid: bool, msg: Msg) -> bool {
        match self.queue.get_mut(self.position) {
            Some(matrix) => matrix.update(is_valid, msg),
            None => false,
        }
    }

    pub fn get_current_matrix(&self) -> Option<&MessageMatrix> {
        self.queue.get(self.position)
    }

    pub fn get_status(&self, index: usize) -> bool {
        self.queue
            .get(index)
            .map(MessageMatrix::status)
            .unwrap_or(false)
    }

    pub fn get_current_matrix_status(&self) -> bool {
        self.get_current_matrix()
            .map(MessageMatrix::status)
            .unwrap_or(false)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct MessageMatrix {
    pub matrix: Vec<Vec<Status>>,
    pub message_matrix: Vec<Vec<Option<Msg>>>,
    pub quorum_nodes: Vec<PubKey>,
    pub node_status: Vec<Status>,
    pub self_key: PubKey,
    pub self_index: usize,
}

impl MessageMatrix {
    pub fn new(quorum: &[PubKey], self_key: &PubKey) -> Self {
        let self_index = quorum
            .iter()
            .position(|pubkey| pubkey == self_key)
            .unwrap_or_default();

        let mut matrix = Vec::with_capacity(quorum.len());
        for receiver_index in 0..quorum.len() {
            let mut row = Vec::with_capacity(quorum.len());
            for sender_index in 0..quorum.len() {
                if sender_index == receiver_index {
                    row.push(Status::NodeSelf);
                } else if receiver_index == self_index {
                    row.push(Status::DispatchVoid);
                } else {
                    row.push(Status::EchoVoid);
                }
            }
            matrix.push(row);
        }

        let message_matrix = vec![vec![None; quorum.len()]; quorum.len()];
        let node_status = vec![Status::NodeVoid; quorum.len()];

        Self {
            matrix,
            message_matrix,
            quorum_nodes: quorum.to_vec(),
            node_status,
            self_key: *self_key,
            self_index,
        }
    }

    pub fn update(&mut self, is_valid: bool, msg: Msg) -> bool {
        let response = match &msg {
            Msg::Dispatch(msg) => {
                Some((msg.header.sender, self.self_key, Status::DispatchReceived))
            }
            Msg::EchoReDispatch(msg) => {
                Some((msg.header.sender, self.self_key, Status::DispatchReceived))
            }
            Msg::EchoResponse(msg) => {
                Some((msg.body.sender, msg.header.sender, Status::EchoReceived))
            }
            _ => None,
        };

        let Some((sender, receiver, status)) = response else {
            return false;
        };

        let Some(sender_index) = self.find_key_index(&sender) else {
            return false;
        };
        let Some(receiver_index) = self.find_key_index(&receiver) else {
            return false;
        };

        self.matrix[receiver_index][sender_index] = if is_valid { status } else { Status::Void };
        self.message_matrix[sender_index][receiver_index] = Some(msg);

        self.update_status(sender_index, receiver_index);
        self.status()
    }

    pub fn status(&self) -> bool {
        let count_for_supermajority = supermajority_count(self.quorum_nodes.len());
        let passed_node_count = self
            .node_status
            .iter()
            .filter(|status| matches!(status, Status::NodePassed))
            .count();
        passed_node_count >= count_for_supermajority
    }

    pub fn update_status(&mut self, sender: usize, receiver: usize) {
        let count_for_supermajority = supermajority_count(self.quorum_nodes.len());

        for index in [sender, receiver] {
            let mut dispatch_received = false;
            let mut column_count = 0;
            for (row_index, row) in self.matrix.iter().enumerate() {
                if row_index == self.self_index && index == self.self_index {
                    dispatch_received = true;
                }

                match row[index] {
                    Status::DispatchReceived => {
                        dispatch_received = true;
                        column_count += 1;
                    }
                    Status::EchoReceived | Status::NodeSelf => column_count += 1,
                    _ => {}
                }
            }

            let column_status =
                matrix_axis_status(column_count, dispatch_received, count_for_supermajority);

            let mut row_count = 0;
            for item in &self.matrix[index] {
                match item {
                    Status::DispatchReceived => {
                        dispatch_received = true;
                        row_count += 1;
                    }
                    Status::EchoReceived | Status::NodeSelf => row_count += 1,
                    _ => {}
                }
            }

            let row_status =
                matrix_axis_status(row_count, dispatch_received, count_for_supermajority);

            self.node_status[index] = if column_status == Status::NodePassed
                && row_status == Status::NodePassed
            {
                Status::NodePassed
            } else if column_status == Status::NodePending || row_status == Status::NodePending {
                Status::NodePending
            } else {
                Status::NodeVoid
            };
        }
    }

    pub fn find_key_index(&self, pubkey: &PubKey) -> Option<usize> {
        self.quorum_nodes.iter().position(|key| key == pubkey)
    }
}

fn matrix_axis_status(
    count: usize,
    dispatch_received: bool,
    count_for_supermajority: usize,
) -> Status {
    if count >= count_for_supermajority {
        if dispatch_received {
            Status::NodePassed
        } else {
            Status::NodePending
        }
    } else if dispatch_received {
        Status::NodePending
    } else {
        Status::NodeVoid
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blossom::{Dispatch, DispatchBody, EchoResponse, EchoResponseBody, Header};

    fn key_vec() -> Vec<PubKey> {
        (0..6).map(|index| PubKey([index; 32])).collect()
    }

    #[test]
    fn new_matrix_marks_self_axis() {
        let quorum = key_vec();
        let matrix = MessageMatrix::new(&quorum, &quorum[0]);

        for (receiver_index, row) in matrix.matrix.iter().enumerate() {
            for (sender_index, item) in row.iter().enumerate() {
                if receiver_index == sender_index {
                    assert_eq!(item, &Status::NodeSelf);
                } else if receiver_index == matrix.self_index {
                    assert_eq!(item, &Status::DispatchVoid);
                } else {
                    assert_eq!(item, &Status::EchoVoid);
                }
            }
        }
    }

    #[test]
    fn all_echoes_pass_matrix() {
        let quorum = key_vec();
        let mut matrix = MessageMatrix::new(&quorum, &quorum[0]);

        for pk in &quorum[1..] {
            matrix.update(
                true,
                Msg::Dispatch(Dispatch {
                    header: Header {
                        sender: *pk,
                        ..Default::default()
                    },
                    body: DispatchBody::default(),
                }),
            );
        }

        for receiver in 0..quorum.len() {
            for sender in 1..quorum.len() {
                if receiver == sender {
                    continue;
                }
                matrix.update(
                    true,
                    Msg::EchoResponse(EchoResponse {
                        header: Header {
                            sender: quorum[sender],
                            ..Default::default()
                        },
                        body: EchoResponseBody {
                            sender: quorum[receiver],
                            ..Default::default()
                        },
                    }),
                );
            }
        }

        assert!(matrix.status());
    }
}
