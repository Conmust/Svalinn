//! Blocks signups from known disposable/temp-mail providers (Mailinator,
//! Guerrilla Mail, 10 Minute Mail, and the like). This doesn't verify an
//! email is "real" on its own -- that's what the verification-link flow in
//! `routes::auth` does -- but it stops the cheapest form of ban evasion:
//! burning a fresh throwaway address for every new account, with no real
//! mailbox behind it to lose.
//!
//! The list (`disposable_email_domains.txt`) is vendored from the
//! community-maintained disposable-email-domains project
//! (<https://github.com/disposable-email-domains/disposable-email-domains>)
//! at build time via `include_str!`, so there's no runtime fetch and no
//! network dependency to go stale silently -- updating it means re-pulling
//! that file and rebuilding. It's necessarily incomplete (new disposable
//! services appear constantly); treat it as raising the cost of evasion,
//! not eliminating it.

use std::collections::HashSet;

const DOMAINS_TXT: &str = include_str!("disposable_email_domains.txt");

static DOMAINS: std::sync::OnceLock<HashSet<&'static str>> = std::sync::OnceLock::new();

fn domains() -> &'static HashSet<&'static str> {
    DOMAINS.get_or_init(|| {
        DOMAINS_TXT
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect()
    })
}

/// True if `email`'s domain is a known disposable/temp-mail provider.
/// Matches the domain itself and any subdomain of it (so
/// `foo.mailinator.com` is caught by a `mailinator.com` entry), since
/// throwaway services routinely spin up subdomains to dodge domain-level
/// blocklists.
pub fn is_disposable(email: &str) -> bool {
    let Some((_, domain)) = email.rsplit_once('@') else { return false };
    let domain = domain.trim().to_lowercase();
    let set = domains();

    domain
        .char_indices()
        .filter(|&(i, c)| i == 0 || c == '.')
        .any(|(i, c)| {
            let suffix = if c == '.' { &domain[i + 1..] } else { &domain[i..] };
            set.contains(suffix)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catches_a_known_disposable_domain() {
        assert!(is_disposable("someone@mailinator.com"));
    }

    #[test]
    fn catches_a_subdomain_of_a_known_disposable_domain() {
        assert!(is_disposable("someone@sub.mailinator.com"));
    }

    #[test]
    fn allows_an_ordinary_domain() {
        assert!(!is_disposable("someone@gmail.com"));
        assert!(!is_disposable("someone@example.com"));
    }

    #[test]
    fn is_case_insensitive() {
        assert!(is_disposable("someone@MAILINATOR.COM"));
    }

    #[test]
    fn handles_malformed_input_without_panicking() {
        assert!(!is_disposable("not-an-email"));
        assert!(!is_disposable(""));
    }
}
