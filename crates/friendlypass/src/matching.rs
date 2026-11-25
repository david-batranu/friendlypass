//! URL and Android-app matching, shared by the browser integration and the
//! mobile vault.
//!
//! This is the single implementation of "does this entry belong to the site or
//! app the user is logging in to". The browser server and the Android vault
//! both call [`score`]; keeping it here means a fix (a wildcard edge case, a
//! scheme rule) lands in both places at once.
//!
//! Web scoring is exactly the browser's historical `entry_match_score`
//! (`crates/friendlypass-browser/src/service.rs` before this module existed):
//! same host, path and subdomain rules, and the same +8 penalty for a match on
//! an additional URL. Android scoring is the KeePassDX/KP2A convention:
//! `AndroidApp` / `AndroidApp_1` fields and `androidapp://<package>` URLs.

/// What the caller is trying to log in to.
///
/// Either or both may be set. When both produce a match the lower (better)
/// score wins; when neither matches the result is `None`.
#[derive(Debug, Default, Clone, Copy)]
pub struct MatchTarget<'a> {
    /// The URL of the page the user is on (or the form's submit URL).
    pub web_url: Option<&'a str>,
    /// The Android package name for an app login.
    pub android_package: Option<&'a str>,
}

/// One entry's matching inputs.
///
/// * `url` — the entry's main URL (`URL`).
/// * `additional_urls` — `KP2A_URL`, `KP2A_URL_1`, … and any field whose value
///   is an `androidapp://…` URL.
/// * `android_apps` — the values of `AndroidApp`, `AndroidApp_1`, … fields.
#[derive(Debug, Default, Clone, Copy)]
pub struct MatchCandidate<'a> {
    pub url: &'a str,
    pub additional_urls: &'a [String],
    pub android_apps: &'a [String],
}

/// Score one candidate against a target. Lower is better; `None` = no match.
///
/// Web matches keep the browser's historical scoring:
///
/// | score | meaning |
/// |-------|---------|
/// | 0 | full URL matches |
/// | 1 | entry is the site root, target has a path |
/// | 2 | same host and path |
/// | 3 | target path continues the entry path |
/// | 4 | different host, but parent/subdomain or wildcard |
/// | 6 | same host, different path |
/// | +8 | matched on an additional URL |
///
/// An exact Android package match (against an `AndroidApp*` field, the main
/// URL, or an `androidapp://<package>` URL) scores 0.
pub fn score(candidate: &MatchCandidate<'_>, target: &MatchTarget<'_>) -> Option<u16> {
    let mut best = target.web_url.and_then(|url| {
        let parsed = UrlParts::parse(url);
        entry_match_score(candidate, &parsed)
    });

    if let Some(package) = target.android_package {
        if android_score(candidate, package.trim()).is_some() {
            best = Some(best.map_or(0, |current| current.min(0)));
        }
    }

    best
}

/// The UUID named by a `keepassxc://by-uuid/<uuid>` diagnostic URL, normalized
/// to dashless lowercase hex. `Some("")` when the path has the prefix but the
/// UUID is malformed (matching the browser's historical behavior: no entry
/// matches).
///
/// This scheme is used by the browser extension's diagnostics and is not part
/// of ordinary URL matching, which is why [`score`] does not handle it.
pub fn by_uuid_target(raw: &str) -> Option<String> {
    let target = UrlParts::parse(raw);
    // The extension's URL is `keepassxc://by-uuid/<uuid>` (the UUID is the
    // path, `by-uuid` the authority). Keep accepting the historical
    // `/by-uuid/<uuid>` path form as well.
    let rest = if target.scheme == "keepassxc" && target.host == "by-uuid" {
        target.path.trim_start_matches('/')
    } else {
        target.path.strip_prefix("/by-uuid/")?
    };
    Some(normalize_uuid(rest).unwrap_or_default())
}

/// Keep a UUID in dashless lowercase hex. Returns `None` for anything that is
/// not 32 hex digits (with optional dashes).
fn normalize_uuid(text: &str) -> Option<String> {
    let mut out = String::with_capacity(32);
    for ch in text.chars() {
        if ch == '-' {
            continue;
        }
        if ch.is_ascii_hexdigit() {
            out.push(ch.to_ascii_lowercase());
        } else {
            return None;
        }
    }
    (out.len() == 32).then_some(out)
}

/// A parsed URL, reduced to the parts credential matching needs.
#[derive(Debug, Default, Clone)]
struct UrlParts {
    scheme: String,
    host: String,
    path: String,
}

impl UrlParts {
    fn parse(raw: &str) -> UrlParts {
        let raw = raw.trim();
        let (scheme, rest) = match raw.split_once("://") {
            Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest),
            None => (String::new(), raw),
        };
        let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..authority_end];
        let host = authority
            .rsplit_once('@')
            .map(|(_, host)| host)
            .unwrap_or(authority)
            .split(':')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let host = host.strip_prefix("www.").unwrap_or(&host).to_owned();
        let mut path = rest[authority_end..].to_owned();
        if let Some(cut) = path.find(['?', '#']) {
            path.truncate(cut);
        }
        if path.is_empty() {
            path.push('/');
        }
        UrlParts { scheme, host, path }
    }

    fn full(&self) -> String {
        format!("{}://{}{}", self.scheme, self.host, self.path)
    }
}

/// Lower is better; `None` means no match.
fn entry_match_score(candidate: &MatchCandidate<'_>, target: &UrlParts) -> Option<u16> {
    let mut best = single_url_score(candidate.url, target);
    for extra in candidate.additional_urls {
        if let Some(score) = single_url_score(extra, target) {
            best = Some(best.map_or(score + 8, |current: u16| current.min(score + 8)));
        }
    }
    best
}

fn single_url_score(raw: &str, target: &UrlParts) -> Option<u16> {
    if raw.is_empty() {
        return None;
    }
    let entry = UrlParts::parse(raw);
    if entry.host != target.host {
        // Wildcards: `*.example.com` matches any subdomain; `*` matches any
        // host. Otherwise allow a parent/subdomain relationship, like
        // KeePassXC's `handleURL`.
        let subdomain = target.host.ends_with(&format!(".{}", entry.host))
            || entry.host.ends_with(&format!(".{}", target.host));
        let wildcard_match = entry.host == "*"
            || match entry.host.strip_prefix("*.") {
                Some("") => true,
                Some(suffix) => {
                    target.host == suffix || target.host.ends_with(&format!(".{suffix}"))
                }
                None => false,
            };
        if !subdomain && !wildcard_match {
            return None;
        }
    }
    if !entry.scheme.is_empty() && !target.scheme.is_empty() && entry.scheme != target.scheme {
        // http vs https is allowed; other schemes are not.
        if !(entry.scheme == "http" && target.scheme == "https")
            && !(entry.scheme == "https" && target.scheme == "http")
        {
            return None;
        }
    }
    let same_host = entry.host == target.host;
    if same_host && entry.full() == target.full() {
        return Some(0);
    }
    if same_host && (entry.path == "/" || entry.path.is_empty()) {
        return Some(1);
    }
    if same_host && entry.path == target.path {
        return Some(2);
    }
    if same_host && target.path.starts_with(entry.path.trim_end_matches('/')) {
        return Some(3);
    }
    Some(if same_host { 6 } else { 4 })
}

/// Exact Android package match against an `AndroidApp*` value or an
/// `androidapp://<package>` URL (main or additional).
fn android_score(candidate: &MatchCandidate<'_>, package: &str) -> Option<u16> {
    if package.is_empty() {
        return None;
    }
    let matches_package = |value: &str| {
        let value = value.trim().trim_end_matches('/');
        let value = value.strip_prefix("androidapp://").unwrap_or(value);
        value == package
    };
    if candidate
        .android_apps
        .iter()
        .any(|app| matches_package(app))
    {
        return Some(0);
    }
    if matches_package(candidate.url) {
        return Some(0);
    }
    candidate
        .additional_urls
        .iter()
        .any(|url| matches_package(url))
        .then_some(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate<'a>(
        url: &'a str,
        additional: &'a [String],
        apps: &'a [String],
    ) -> MatchCandidate<'a> {
        MatchCandidate {
            url,
            additional_urls: additional,
            android_apps: apps,
        }
    }

    fn web(url: &str) -> MatchTarget<'_> {
        MatchTarget {
            web_url: Some(url),
            android_package: None,
        }
    }

    fn no_extras<'a>() -> &'a [String] {
        &[]
    }

    #[test]
    fn exact_url_is_the_best_score() {
        let c = candidate("https://example.com/login", no_extras(), no_extras());
        assert_eq!(score(&c, &web("https://example.com/login")), Some(0));
    }

    #[test]
    fn site_root_scores_better_than_other_paths() {
        let root = candidate("https://example.com", no_extras(), no_extras());
        assert_eq!(score(&root, &web("https://example.com/login")), Some(1));

        let other = candidate("https://example.com/elsewhere", no_extras(), no_extras());
        assert_eq!(score(&other, &web("https://example.com/login")), Some(6));
    }

    #[test]
    fn matching_and_extending_paths_are_distinguished() {
        let same = candidate("https://example.com/login", no_extras(), no_extras());
        assert_eq!(score(&same, &web("https://example.com/login")), Some(0));
        assert_eq!(
            score(&same, &web("https://example.com/login/more")),
            Some(3)
        );
    }

    #[test]
    fn subdomains_and_wildcards_match() {
        let parent = candidate("https://example.com", no_extras(), no_extras());
        assert_eq!(score(&parent, &web("https://login.example.com")), Some(4));

        let wildcard = candidate("https://*.example.com", no_extras(), no_extras());
        assert_eq!(score(&wildcard, &web("https://login.example.com")), Some(4));

        let any = candidate("*", no_extras(), no_extras());
        assert!(score(&any, &web("https://anything.test/x")).is_some());
    }

    #[test]
    fn different_hosts_and_schemes_do_not_match() {
        let c = candidate("https://example.com", no_extras(), no_extras());
        assert_eq!(score(&c, &web("https://other.example.org")), None);
        assert_eq!(score(&c, &web("ftp://example.com")), None);
        assert!(score(&c, &web("http://example.com")).is_some());
    }

    #[test]
    fn additional_urls_match_with_a_penalty() {
        let extras = vec!["https://extra.example.net/login".to_owned()];
        let c = candidate("https://example.com", &extras, no_extras());
        assert_eq!(score(&c, &web("https://extra.example.net/login")), Some(8));
    }

    #[test]
    fn by_uuid_target_is_normalized() {
        assert_eq!(
            by_uuid_target("keepassxc://by-uuid/D5EC68C3-5705-B72F-DE38-0BD469AA149F").as_deref(),
            Some("d5ec68c35705b72fde380bd469aa149f")
        );
        assert_eq!(
            by_uuid_target("https://example.com/by-uuid/d5ec68c35705b72fde380bd469aa149f")
                .as_deref(),
            Some("d5ec68c35705b72fde380bd469aa149f")
        );
        assert_eq!(
            by_uuid_target("keepassxc://by-uuid/not-a-uuid").as_deref(),
            Some("")
        );
        assert_eq!(
            by_uuid_target("https://example.com/by-uuid/x"),
            Some("".to_owned())
        );
    }

    #[test]
    fn android_package_fields_match_exactly() {
        let apps = vec!["com.example.app".to_owned(), "com.example.other".to_owned()];
        let c = candidate("", no_extras(), &apps);
        let target = MatchTarget {
            web_url: None,
            android_package: Some("com.example.app"),
        };
        assert_eq!(score(&c, &target), Some(0));

        let mismatch = MatchTarget {
            web_url: None,
            android_package: Some("com.example"),
        };
        assert_eq!(score(&c, &mismatch), None);
    }

    #[test]
    fn androidapp_urls_match_in_main_and_additional_urls() {
        let extras = vec!["androidapp://com.example.chat".to_owned()];
        let c = candidate("", &extras, no_extras());
        let target = MatchTarget {
            web_url: None,
            android_package: Some("com.example.chat"),
        };
        assert_eq!(score(&c, &target), Some(0));

        let main = candidate("androidapp://com.example.mail", no_extras(), no_extras());
        let mail = MatchTarget {
            web_url: None,
            android_package: Some("com.example.mail"),
        };
        assert_eq!(score(&main, &mail), Some(0));
    }

    #[test]
    fn android_package_wins_when_the_web_url_also_matches() {
        let apps = vec!["com.example.app".to_owned()];
        let c = candidate("https://example.com/login", no_extras(), &apps);
        let target = MatchTarget {
            web_url: Some("https://example.com/login"),
            android_package: Some("com.example.app"),
        };
        assert_eq!(score(&c, &target), Some(0));
    }

    #[test]
    fn an_empty_android_package_never_matches() {
        let c = candidate("", no_extras(), no_extras());
        let target = MatchTarget {
            web_url: None,
            android_package: Some(""),
        };
        assert_eq!(score(&c, &target), None);
    }
}
