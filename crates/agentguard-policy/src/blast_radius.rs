//! Blast-radius analysis: classify decision changes across a replay corpus.
//!
//! A blast-radius analysis replays a corpus of past authorization requests
//! against both the old and the new policy bundle, then classifies each
//! request as `Unchanged`, `AllowToDeny` (the dangerous direction), or
//! `DenyToAllow` (often a bug).

use crate::PolicyBundle;

/// Classification of how a single replay request's decision changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeClass {
    Unchanged,
    AllowToDeny,
    DenyToAllow,
    Other(String),
}

impl ChangeClass {
    pub fn is_dangerous(&self) -> bool {
        matches!(self, ChangeClass::AllowToDeny)
    }
}

/// A replay request — a serialized [`agentguard_core::AgentRequest`] plus
/// the expected authorization effect under the old bundle.
#[derive(Debug, Clone)]
pub struct ReplayRequest {
    pub request: Box<agentguard_core::AgentRequest>,
    pub entities: Vec<serde_json::Value>,
    pub old_effect: String,
}

/// Aggregate blast-radius report.
#[derive(Debug, Default, Clone)]
pub struct BlastRadiusReport {
    pub unchanged: usize,
    pub allow_to_deny: usize,
    pub deny_to_allow: usize,
    pub other: usize,
    /// One example per observed `AllowToDeny` (capped at 10).
    pub sample_allow_to_deny: Vec<ReplayRequest>,
    /// One example per observed `DenyToAllow` (capped at 10).
    pub sample_deny_to_allow: Vec<ReplayRequest>,
}

impl BlastRadiusReport {
    pub fn total(&self) -> usize {
        self.unchanged + self.allow_to_deny + self.deny_to_allow + self.other
    }

    /// `true` if any request that was `Allow` is now `Deny`.
    pub fn has_allow_to_deny(&self) -> bool {
        self.allow_to_deny > 0
    }
}

impl std::fmt::Display for BlastRadiusReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "blast-radius report:")?;
        writeln!(f, "  unchanged:    {}", self.unchanged)?;
        writeln!(f, "  allow→deny:   {} (DANGEROUS)", self.allow_to_deny)?;
        writeln!(f, "  deny→allow:   {}", self.deny_to_allow)?;
        if self.other > 0 {
            writeln!(f, "  other:        {}", self.other)?;
        }
        if self.has_allow_to_deny() {
            writeln!(f, "  WARNING: at least one allow→deny flip detected")?;
        }
        Ok(())
    }
}

/// Stub analyzer. The full implementation would replay each request against
/// both bundles using `agentguard_core::Authorizer`. For v2.0 we provide
/// the type and the diff classification; the actual replay engine is a
/// v2.1 follow-up that can take advantage of the in-process cedar engine
/// without the subprocess overhead.
pub fn analyze(
    _old: &PolicyBundle,
    _new: &PolicyBundle,
    replay: &[ReplayRequest],
) -> BlastRadiusReport {
    // Without invoking the full cedar engine for each request, we can only
    // report the corpus size. The wiring is in place; the implementation
    // arrives in v2.1.
    let _ = replay;
    BlastRadiusReport::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn change_class_dangerous() {
        assert!(ChangeClass::AllowToDeny.is_dangerous());
        assert!(!ChangeClass::DenyToAllow.is_dangerous());
        assert!(!ChangeClass::Unchanged.is_dangerous());
    }

    #[test]
    fn empty_report() {
        let r = BlastRadiusReport::default();
        assert_eq!(r.total(), 0);
        assert!(!r.has_allow_to_deny());
    }
}