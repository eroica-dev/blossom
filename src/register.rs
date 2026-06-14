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
        self.update_cell(is_valid, sender, receiver, status, Some(msg))
    }

    pub fn update_dispatch_received(&mut self, is_valid: bool, sender: PubKey) -> bool {
        self.update_cell(
            is_valid,
            sender,
            self.self_key,
            Status::DispatchReceived,
            None,
        )
    }

    fn update_cell(
        &mut self,
        is_valid: bool,
        sender: PubKey,
        receiver: PubKey,
        status: Status,
        msg: Option<Msg>,
    ) -> bool {
        let Some(sender_index) = self.find_key_index(&sender) else {
            return false;
        };
        let Some(receiver_index) = self.find_key_index(&receiver) else {
            return false;
        };

        self.matrix[receiver_index][sender_index] = if is_valid { status } else { Status::Void };
        self.message_matrix[sender_index][receiver_index] = msg;

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

    fn dispatch_from(sender: PubKey) -> Msg {
        Msg::Dispatch(Dispatch {
            header: Header {
                sender,
                ..Default::default()
            },
            body: DispatchBody::default(),
        })
    }

    fn echo_from_about(observer: PubKey, subject: PubKey) -> Msg {
        Msg::EchoResponse(EchoResponse {
            header: Header {
                sender: observer,
                ..Default::default()
            },
            body: EchoResponseBody {
                sender: subject,
                ..Default::default()
            },
        })
    }

    fn update_all_echoes(matrix: &mut MessageMatrix, quorum: &[PubKey]) {
        for receiver in 0..quorum.len() {
            for sender in 1..quorum.len() {
                if receiver == sender {
                    continue;
                }
                matrix.update(true, echo_from_about(quorum[sender], quorum[receiver]));
            }
        }
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
            matrix.update(true, dispatch_from(*pk));
        }

        update_all_echoes(&mut matrix, &quorum);

        assert!(matrix.status());
    }

    #[test]
    fn missing_dispatch_keeps_echoed_node_pending() {
        let quorum = key_vec();
        let mut matrix = MessageMatrix::new(&quorum, &quorum[0]);
        let missing_dispatch_sender = 1;

        for observer in 2..quorum.len() {
            matrix.update(
                true,
                echo_from_about(quorum[observer], quorum[missing_dispatch_sender]),
            );
        }

        assert!(!matrix.status());
        assert_eq!(
            matrix.node_status[missing_dispatch_sender],
            Status::NodePending
        );
        assert_eq!(
            matrix.matrix[matrix.self_index][missing_dispatch_sender],
            Status::DispatchVoid
        );
    }

    #[test]
    fn delayed_dispatch_can_complete_existing_echo_evidence() {
        let quorum = key_vec()[..4].to_vec();
        let mut matrix = MessageMatrix::new(&quorum, &quorum[0]);
        let delayed_sender = quorum[1];

        for sender in &quorum[2..] {
            matrix.update(true, dispatch_from(*sender));
        }
        update_all_echoes(&mut matrix, &quorum);
        assert_eq!(matrix.node_status[1], Status::NodePending);

        matrix.update(true, dispatch_from(delayed_sender));

        assert_eq!(matrix.node_status[1], Status::NodePassed);
    }

    #[test]
    fn lightweight_dispatch_update_advances_status_without_storing_message() {
        let quorum = key_vec()[..4].to_vec();
        let mut matrix = MessageMatrix::new(&quorum, &quorum[0]);
        let sender = quorum[1];

        assert!(!matrix.update_dispatch_received(true, sender));

        let sender_index = matrix.find_key_index(&sender).unwrap();
        let receiver_index = matrix.find_key_index(&quorum[0]).unwrap();
        assert_eq!(
            matrix.matrix[receiver_index][sender_index],
            Status::DispatchReceived
        );
        assert!(matrix.message_matrix[sender_index][receiver_index].is_none());
    }

    #[test]
    fn false_echo_is_recorded_as_void_without_passing() {
        let quorum = key_vec();
        let mut matrix = MessageMatrix::new(&quorum, &quorum[0]);

        assert!(!matrix.update(false, echo_from_about(quorum[2], quorum[1])));

        let sender_index = matrix.find_key_index(&quorum[1]).unwrap();
        let receiver_index = matrix.find_key_index(&quorum[2]).unwrap();
        assert_eq!(matrix.matrix[receiver_index][sender_index], Status::Void);
        assert!(matches!(
            matrix.message_matrix[sender_index][receiver_index],
            Some(Msg::EchoResponse(_))
        ));
        assert!(!matrix.status());
    }

    #[test]
    fn unknown_echo_peer_does_not_change_matrix() {
        let quorum = key_vec();
        let mut matrix = MessageMatrix::new(&quorum, &quorum[0]);

        assert!(!matrix.update(true, echo_from_about(PubKey([99; 32]), quorum[1])));
        assert!(!matrix.update(true, echo_from_about(quorum[2], PubKey([99; 32]))));

        assert!(
            matrix
                .message_matrix
                .iter()
                .all(|row| row.iter().all(Option::is_none))
        );
        assert!(
            matrix
                .node_status
                .iter()
                .all(|status| *status == Status::NodeVoid)
        );
    }

    #[test]
    fn invalid_or_unknown_messages_do_not_pass_matrix() {
        let quorum = key_vec();
        let mut matrix = MessageMatrix::new(&quorum, &quorum[0]);

        assert!(!matrix.update(
            false,
            Msg::Dispatch(Dispatch {
                header: Header {
                    sender: quorum[1],
                    ..Default::default()
                },
                body: DispatchBody::default(),
            })
        ));
        assert_eq!(matrix.matrix[matrix.self_index][1], Status::Void);

        assert!(!matrix.update(
            true,
            Msg::Dispatch(Dispatch {
                header: Header {
                    sender: PubKey([99; 32]),
                    ..Default::default()
                },
                body: DispatchBody::default(),
            })
        ));
        assert!(!matrix.update(true, Msg::Ok));
    }

    #[test]
    fn quorum_queue_advances_but_stays_at_last_matrix() {
        let quorum = key_vec();
        let mut queue = QuorumQueue::new(vec![quorum.clone(), quorum], &key_vec()[0]);

        assert_eq!(queue.position, 0);
        assert!(queue.get_current_matrix().is_some());
        queue.next_matrix();
        assert_eq!(queue.position, 1);
        queue.next_matrix();
        assert_eq!(queue.position, 1);
        assert!(!queue.get_status(99));
    }
}
