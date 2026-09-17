//! What to call an identity (§5.2).
//!
//! Three tiers, and they are not interchangeable:
//!
//! | tier | who vouches | forgeable by |
//! |---|---|---|
//! | local label | you, privately | nobody — it never leaves this machine |
//! | self-asserted | the identity itself | the identity, freely |
//! | bound name | an identity *and* a directory | neither alone (M8, not built) |
//!
//! A self-asserted name is authenticated — it sits inside a signed object, so no
//! relay can alter it — but it is not *verified*. It is worth about what an email
//! `From:` header is worth, and must never be displayed as though someone else
//! agreed to it.

use pigeonnet_core::{IdentityId, Timestamp};

use crate::{Node, NodeError};

/// Longest local label.
pub const MAX_LABEL: usize = 64;

/// What is known about what to call an identity.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Naming {
    /// What this operator calls them. Unforgeable, because private.
    pub local: Option<String>,
    /// What they call themselves. Authenticated, but vouched for by nobody else.
    pub asserted: Option<String>,
}

impl Naming {
    /// The best available label, if any.
    ///
    /// A local label always wins. Your own opinion about who someone is should
    /// not be overridden by their opinion about who they are.
    #[must_use]
    pub fn best(&self) -> Option<&str> {
        self.local.as_deref().or(self.asserted.as_deref())
    }

    /// Whether [`Naming::best`] came from the identity rather than from here.
    ///
    /// Callers use this to decide whether the label needs a caveat attached.
    #[must_use]
    pub const fn best_is_asserted(&self) -> bool {
        self.local.is_none() && self.asserted.is_some()
    }
}

impl Node {
    /// Label an identity locally.
    pub fn set_local_name(
        &self,
        identity: IdentityId,
        label: &str,
        now: i64,
    ) -> Result<(), NodeError> {
        let label = label.trim();
        if label.is_empty() || label.len() > MAX_LABEL {
            return Err(NodeError::BadLabel);
        }
        Ok(self.store().name_set(identity, label, now)?)
    }

    /// Forget a local label.
    pub fn remove_local_name(&self, identity: IdentityId) -> Result<bool, NodeError> {
        Ok(self.store().name_remove(identity)?)
    }

    /// Every local label.
    pub fn local_names(&self) -> Result<Vec<(IdentityId, String)>, NodeError> {
        Ok(self.store().names()?)
    }

    /// What to call an identity, from both available sources.
    ///
    /// The self-asserted half comes from a snapshot this node already holds, so
    /// this performs no network work and returns nothing rather than failing for
    /// an identity nobody has heard of.
    pub fn naming(&self, identity: IdentityId, now: i64) -> Result<Naming, NodeError> {
        let local = self.store().name_of(identity)?;

        let asserted = match self.snapshot(identity, now)? {
            Some(snapshot) => snapshot
                .verify(Timestamp::from_millis(now))
                .ok()
                .and_then(|resolved| resolved.profile)
                .and_then(|profile| profile.display_name),
            None => None,
        };

        Ok(Naming { local, asserted })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_local_label_beats_what_someone_calls_themselves() {
        // Your opinion about who somebody is should not be overridden by their
        // opinion about who they are.
        let naming = Naming {
            local: Some("jaytaph".into()),
            asserted: Some("Joshua".into()),
        };
        assert_eq!(naming.best(), Some("jaytaph"));
        assert!(!naming.best_is_asserted(), "needs no caveat");
    }

    #[test]
    fn a_self_asserted_name_is_flagged() {
        let naming = Naming {
            local: None,
            asserted: Some("Joshua".into()),
        };
        assert_eq!(naming.best(), Some("Joshua"));
        assert!(naming.best_is_asserted(), "must be shown with a caveat");
    }

    #[test]
    fn with_neither_there_is_no_name() {
        assert_eq!(Naming::default().best(), None);
        assert!(!Naming::default().best_is_asserted());
    }
}
