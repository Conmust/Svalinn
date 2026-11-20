//! Which badge emblems each patron tier -- and the site owner -- may pick.
//!
//! A tier badge used to be one fixed icon per `patron_tier`. This lets each
//! member choose among a small set of alternate emblems for their own tier.
//! The chosen id is just stored on `users.badge_emblem` (see
//! `migrations/0034_badge_emblems.sql`); this module is the single source of
//! truth for which ids are valid for whom, so the write path (`PATCH
//! /api/v1/users/me/badge-emblem`) and any future read-side validation agree.
//!
//! Tiers don't inherit each other's emblems: a `patron` can only pick from
//! `PATRON_EMBLEMS`, a `guild` only from `GUILD_EMBLEMS`. `enterprise` and
//! `free` have no picker (enterprise keeps its single fixed badge; free has
//! none at all). The site owner is the one exception -- they may pick *any*
//! emblem from either set, plus the owner-exclusive rune, regardless of
//! their own `patron_tier`, because site ownership is a separate flag
//! (`users.site_role`) orthogonal to the patron tier system.

/// The 5 emblems selectable by the `patron` tier.
pub const PATRON_EMBLEMS: &[&str] = &["crown", "starlight", "ember", "wayfinder", "laurel"];

/// The 10 emblems selectable by the `guild` tier.
pub const GUILD_EMBLEMS: &[&str] = &[
    "aegis", "blade", "warbrand", "bastion", "anchor", "storm", "reaper", "wolf", "ruby",
    "conqueror",
];

/// Shown only on the site owner, never selectable by anyone else.
pub const OWNER_EMBLEM: &str = "fehu_rune";

/// The emblem ids `user_id` may set for themselves, given their `patron_tier`
/// and whether they're the site owner. Empty means that account has no
/// emblem picker at all (its badge, if any, is fixed).
pub fn allowed_emblems(patron_tier: &str, is_site_owner: bool) -> Vec<&'static str> {
    if is_site_owner {
        return PATRON_EMBLEMS
            .iter()
            .chain(GUILD_EMBLEMS.iter())
            .copied()
            .chain(std::iter::once(OWNER_EMBLEM))
            .collect();
    }
    match patron_tier {
        "patron" => PATRON_EMBLEMS.to_vec(),
        "guild" => GUILD_EMBLEMS.to_vec(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patron_only_gets_patron_emblems() {
        let allowed = allowed_emblems("patron", false);
        assert_eq!(allowed, PATRON_EMBLEMS.to_vec());
    }

    #[test]
    fn guild_only_gets_guild_emblems() {
        let allowed = allowed_emblems("guild", false);
        assert_eq!(allowed, GUILD_EMBLEMS.to_vec());
    }

    #[test]
    fn enterprise_and_free_get_nothing() {
        assert!(allowed_emblems("enterprise", false).is_empty());
        assert!(allowed_emblems("free", false).is_empty());
    }

    #[test]
    fn site_owner_gets_everything_including_the_rune_regardless_of_tier() {
        let allowed = allowed_emblems("free", true);
        assert!(allowed.contains(&"crown"));
        assert!(allowed.contains(&"ruby"));
        assert!(allowed.contains(&OWNER_EMBLEM));
        assert_eq!(allowed.len(), PATRON_EMBLEMS.len() + GUILD_EMBLEMS.len() + 1);
    }

    #[test]
    fn non_owner_never_gets_the_rune() {
        assert!(!allowed_emblems("patron", false).contains(&OWNER_EMBLEM));
        assert!(!allowed_emblems("guild", false).contains(&OWNER_EMBLEM));
    }
}
