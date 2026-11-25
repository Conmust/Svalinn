//! Single source of truth for the patron-tier ordering and which tiers
//! unlock which gated features. Mirrors the pattern in `crate::badges`.

/// Tiers in ascending order of privilege. An unrecognized value (including a
/// user who predates this enum, or a typo) ranks the same as `free`.
const TIER_ORDER: &[&str] = &["free", "patron", "guild", "enterprise"];

/// The lowest tier that is allowed to create a server.
const SERVER_CREATION_MIN_TIER: &str = "guild";

pub(crate) fn tier_rank(tier: &str) -> usize {
    TIER_ORDER.iter().position(|t| *t == tier).unwrap_or(0)
}

/// Whether an account at `patron_tier` may create a server. The site owner
/// always may, regardless of tier -- consistent with the owner bypass in
/// `crate::badges::allowed_emblems`.
pub fn can_create_server(patron_tier: &str, is_site_owner: bool) -> bool {
    is_site_owner || tier_rank(patron_tier) >= tier_rank(SERVER_CREATION_MIN_TIER)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_and_patron_cannot_create_a_server() {
        assert!(!can_create_server("free", false));
        assert!(!can_create_server("patron", false));
    }

    #[test]
    fn guild_and_enterprise_can_create_a_server() {
        assert!(can_create_server("guild", false));
        assert!(can_create_server("enterprise", false));
    }

    #[test]
    fn site_owner_can_always_create_a_server_regardless_of_tier() {
        assert!(can_create_server("free", true));
        assert!(can_create_server("patron", true));
    }

    #[test]
    fn an_unrecognized_tier_is_treated_as_the_lowest_rank() {
        assert!(!can_create_server("not-a-real-tier", false));
    }
}
