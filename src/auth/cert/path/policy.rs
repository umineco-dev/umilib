use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use crate::auth::cert::x509::{CertificatePolicies, PolicyMappings};
use crate::codec::asn1::ObjectIdentifier;

/// A node of the [`PolicyGraph`]: a valid policy, the policies that would
/// satisfy it in the next certificate, and its parents at the depth above.
/// Qualifiers are not kept, as RFC 9618 §5.2 allows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyNode {
    pub policy: ObjectIdentifier<'static>,
    pub expected: Vec<ObjectIdentifier<'static>>,
    /// Indices of the parents in the level above.
    pub parents: Vec<usize>,
    /// Whether the node is still in the graph (pruning removes nodes without children).
    pub alive: bool,
}

/// The `valid_policy_graph` of RFC 9618 §5, which replaces the
/// `valid_policy_tree` of RFC 5280 §6.1 and grows linearly with the
/// policies and mappings of the path instead of exponentially. A NULL
/// graph is the absence of a `PolicyGraph`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyGraph {
    /// The nodes of each depth, depth 0 first.
    pub levels: Vec<Vec<PolicyNode>>,
}

impl Default for PolicyGraph {
    fn default() -> PolicyGraph {
        PolicyGraph::new()
    }
}

impl PolicyGraph {
    /// The initial graph: one node of anyPolicy expecting anyPolicy, at depth 0.
    pub fn new() -> PolicyGraph {
        let any = CertificatePolicies::ANY_POLICY;
        PolicyGraph {
            levels: vec![vec![PolicyNode {
                policy: any.clone(),
                expected: vec![any],
                parents: Vec::new(),
                alive: true,
            }]],
        }
    }

    /// The deepest depth.
    pub fn depth(&self) -> usize {
        self.levels.len() - 1
    }

    /// Whether the deepest level has no node left, which makes the graph NULL.
    pub fn is_empty(&self) -> bool {
        self.levels.last().is_none_or(|level| !level.iter().any(|node| node.alive))
    }

    /// The index of the live node of `policy` at `depth`.
    pub fn find(&self, depth: usize, policy: &ObjectIdentifier<'_>) -> Option<usize> {
        self.levels[depth].iter().position(|node| node.alive && node.policy == *policy)
    }

    /// For each policy expected at `depth`, the live nodes there that expect it.
    pub fn expecting(&self, depth: usize) -> BTreeMap<ObjectIdentifier<'static>, Vec<usize>> {
        let mut map: BTreeMap<ObjectIdentifier<'static>, Vec<usize>> = BTreeMap::new();
        for (index, node) in self.levels[depth].iter().enumerate().filter(|(_, node)| node.alive) {
            for policy in &node.expected {
                map.entry(policy.clone()).or_default().push(index);
            }
        }
        map
    }

    /// Adds the level of certificate `i` from its certificate policies (RFC
    /// 9618 §5.3, step (d)): `any_policy` is whether its anyPolicy counts
    /// (inhibit_anyPolicy greater than 0, or a self-issued intermediate).
    pub fn process(&mut self, policies: &CertificatePolicies<'_>, any_policy: bool) {
        let any = CertificatePolicies::ANY_POLICY;
        let above = self.depth();
        let expecting = self.expecting(above);
        let any_above = self.find(above, &any);
        let mut level: Vec<PolicyNode> = Vec::new();
        for information in policies.policies.iter().filter(|information| information.identifier != any) {
            let policy = information.identifier.clone().into_owned();
            let parents = match expecting.get(&policy) {
                Some(parents) => parents.clone(),
                None => match any_above {
                    Some(any_node) => vec![any_node],
                    None => continue,
                },
            };
            level.push(PolicyNode { expected: vec![policy.clone()], policy, parents, alive: true });
        }
        if any_policy && policies.policies.iter().any(|information| information.identifier == any) {
            for (policy, parents) in &expecting {
                if !level.iter().any(|node| node.policy == *policy) {
                    let node = PolicyNode {
                        policy: policy.clone(),
                        expected: vec![policy.clone()],
                        parents: parents.clone(),
                        alive: true,
                    };
                    level.push(node);
                }
            }
        }
        self.levels.push(level);
        self.prune();
    }

    /// Removes the nodes above the deepest level that have no live child,
    /// repeatedly (RFC 9618 §5.3, step (d)(3)).
    pub fn prune(&mut self) {
        for depth in (0..self.depth()).rev() {
            let mut has_child = vec![false; self.levels[depth].len()];
            for node in self.levels[depth + 1].iter().filter(|node| node.alive) {
                node.parents.iter().for_each(|&parent| has_child[parent] = true);
            }
            for (node, has_child) in self.levels[depth].iter_mut().zip(has_child) {
                node.alive &= has_child;
            }
        }
    }

    /// Applies the policy mappings of the deepest certificate (RFC 9618
    /// §5.4, step (b)): with `allowed` (policy_mapping greater than 0), each
    /// mapped policy expects the policies it maps to; otherwise the mapped
    /// policies are deleted. The caller refuses mappings of anyPolicy first.
    pub fn map(&mut self, mappings: &PolicyMappings<'_>, allowed: bool) {
        let depth = self.depth();
        let any = CertificatePolicies::ANY_POLICY;
        let mut issuer_policies: Vec<&ObjectIdentifier<'_>> =
            mappings.mappings.iter().map(|mapping| &mapping.issuer_domain_policy).collect();
        issuer_policies.sort_unstable();
        issuer_policies.dedup();
        for issuer_policy in issuer_policies {
            let found = self.find(depth, issuer_policy);
            if !allowed {
                if let Some(index) = found {
                    self.levels[depth][index].alive = false;
                }
                continue;
            }
            let mut subjects: Vec<ObjectIdentifier<'static>> = mappings
                .mappings
                .iter()
                .filter(|mapping| mapping.issuer_domain_policy == *issuer_policy)
                .map(|mapping| mapping.subject_domain_policy.clone().into_owned())
                .collect();
            subjects.sort_unstable();
            subjects.dedup();
            match found {
                Some(index) => self.levels[depth][index].expected = subjects,
                None => {
                    let Some(any_node) = self.find(depth, &any) else { continue };
                    let parents = self.levels[depth][any_node].parents.clone();
                    let node = PolicyNode {
                        policy: issuer_policy.clone().into_owned(),
                        expected: subjects,
                        parents,
                        alive: true,
                    };
                    self.levels[depth].push(node);
                }
            }
        }
        if !allowed {
            self.prune();
        }
    }

    /// The `user_constrained_policy_set` of RFC 9618 §5.5, step (g), for
    /// `initial` (`None` for any-policy). It contains anyPolicy when every
    /// policy is valid.
    pub fn user_constrained_policies(
        &self,
        initial: Option<&[ObjectIdentifier<'static>]>,
    ) -> Vec<ObjectIdentifier<'static>> {
        let any = CertificatePolicies::ANY_POLICY;
        let mut authority: Vec<ObjectIdentifier<'static>> = Vec::new();
        for depth in 1..self.levels.len() {
            for node in self.levels[depth].iter().filter(|node| node.alive && node.policy != any) {
                let below_any = node.parents.len() == 1 && self.levels[depth - 1][node.parents[0]].policy == any;
                if below_any {
                    authority.push(node.policy.clone());
                }
            }
        }
        if self.find(self.depth(), &any).is_some() {
            authority.push(any.clone());
        }
        authority.sort_unstable();
        authority.dedup();
        let Some(initial) = initial else { return authority };
        let mut user: Vec<ObjectIdentifier<'static>> =
            authority.iter().filter(|policy| initial.contains(policy)).cloned().collect();
        if authority.contains(&any) {
            for policy in initial {
                if !user.contains(policy) {
                    user.push(policy.clone());
                }
            }
        }
        user.sort_unstable();
        user.dedup();
        user
    }
}
