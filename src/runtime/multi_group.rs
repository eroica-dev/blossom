//! Routing facade for independent consensus groups in one process.

use super::*;

#[derive(Clone)]
/// Thread-safe registry that routes work to independent group runtimes.
pub struct MultiGroupRuntime {
    inner: Arc<MultiGroupRuntimeInner>,
}

struct MultiGroupRuntimeInner {
    root_group: ConsensusGroupId,
    groups: RwLock<BTreeMap<ConsensusGroupId, NodeRuntime>>,
}

impl MultiGroupRuntime {
    /// Creates a registry containing its required root runtime.
    pub fn new(root_runtime: NodeRuntime) -> Self {
        let root_group = root_runtime.group_id();
        let mut groups = BTreeMap::new();
        groups.insert(root_group, root_runtime);

        Self {
            inner: Arc::new(MultiGroupRuntimeInner {
                root_group,
                groups: RwLock::new(groups),
            }),
        }
    }

    /// Creates a registry from a root runtime and additional independent groups.
    pub fn with_groups(
        root_runtime: NodeRuntime,
        groups: impl IntoIterator<Item = NodeRuntime>,
    ) -> Self {
        let runtime = Self::new(root_runtime);
        for group in groups {
            runtime.insert_group(group);
        }
        runtime
    }

    /// Returns the identifier of the required root consensus group.
    pub fn root_group(&self) -> ConsensusGroupId {
        self.inner.root_group
    }

    /// Returns a clone of the required root runtime handle.
    pub fn root_runtime(&self) -> NodeRuntime {
        self.group(&self.inner.root_group)
            .expect("root runtime should always be present")
    }

    /// Inserts or replaces the runtime for its consensus group.
    pub fn insert_group(&self, runtime: NodeRuntime) -> Option<NodeRuntime> {
        let group_id = runtime.group_id();
        self.inner
            .groups
            .write()
            .expect("group runtime lock poisoned")
            .insert(group_id, runtime)
    }

    /// Returns the runtime registered for `group_id`.
    pub fn group(&self, group_id: &ConsensusGroupId) -> Option<NodeRuntime> {
        self.inner
            .groups
            .read()
            .expect("group runtime lock poisoned")
            .get(group_id)
            .cloned()
    }

    /// Finds the runtime whose verified or durable chain contains `epoch_hash`.
    pub fn group_for_epoch(&self, epoch_hash: &HashType) -> Option<NodeRuntime> {
        self.inner
            .groups
            .read()
            .expect("group runtime lock poisoned")
            .values()
            .find(|runtime| runtime.contains_epoch_hash(epoch_hash))
            .cloned()
    }

    /// Returns all registered group identifiers in deterministic order.
    pub fn group_ids(&self) -> Vec<ConsensusGroupId> {
        self.inner
            .groups
            .read()
            .expect("group runtime lock poisoned")
            .keys()
            .copied()
            .collect()
    }

    /// Returns the number of registered group runtimes.
    pub fn len(&self) -> usize {
        self.inner
            .groups
            .read()
            .expect("group runtime lock poisoned")
            .len()
    }

    /// Reports whether the registry contains no runtimes.
    ///
    /// A normally constructed registry is never empty because it retains its
    /// root runtime.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
