// Copyright 2026 OpenObserve Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Pure scope logic for the Logto integration: normalization, the
//! feature-area registry, scope→permission matching, coarse role derivation,
//! and the feature-permission view consumed by the frontend.
//!
//! The KV-backed store and cache live alongside (`cache_get`/`store_scopes`)
//! and are added in a later task. This file deliberately has no I/O so the
//! matching logic can be unit-tested in isolation.

use std::collections::HashMap;
use std::sync::LazyLock;

/// OIDC standard scopes that carry no business meaning for OpenObserve and are
/// stripped during normalization.
const OIDC_STANDARD_SCOPES: &[&str] = &[
    "openid",
    "profile",
    "email",
    "address",
    "phone",
    "offline_access",
    "roles",
    "groups",
    "urn:loggto",
];

/// The 10 feature areas OpenObserve groups its resources into. Each maps to a
/// Logto API resource; each area × action becomes a scope (`<area>:<action>`).
/// This registry is the single source of truth for `o2_type` → feature mapping.
static FEATURE_REGISTRY: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    let mut m = HashMap::new();
    for rt in ["dashboard", "dfolder"] {
        m.insert(rt, "dashboards");
    }
    for rt in ["alert", "destinations", "destination", "templates", "template", "afolder"] {
        m.insert(rt, "alerts");
    }
    m.insert("stream", "streams");
    for rt in ["search", "query"] {
        m.insert(rt, "search");
    }
    m.insert("pipeline", "pipelines");
    m.insert("function", "functions");
    for rt in ["logs", "metrics", "traces"] {
        m.insert(rt, "ingestion");
    }
    m.insert("report", "reports");
    for rt in ["user", "role", "group", "organization", "org"] {
        m.insert(rt, "iam");
    }
    for rt in ["settings", "sysinfo", "config"] {
        m.insert(rt, "settings");
    }
    m
});

/// Normalize the `scope` field from a token response: split on whitespace,
/// drop OIDC standard scopes, trim, and de-duplicate while preserving order.
pub fn normalize_scopes(raw: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    raw.split_whitespace()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && !OIDC_STANDARD_SCOPES.contains(&s.as_str()))
        .filter(|s| seen.insert(s.clone()))
        .collect()
}

/// Map a scope action to the HTTP methods it authorizes.
fn action_methods(action: &str) -> Vec<String> {
    match action {
        "read" => vec!["GET"],
        "create" => vec!["POST"],
        "update" => vec!["PUT", "PATCH"],
        "delete" => vec!["DELETE"],
        _ => vec![],
    }
    .into_iter()
    .map(String::from)
    .collect()
}

/// Resolve an `AuthExtractor.o2_type` (e.g. `dashboard:<id>`) to its feature
/// area. Takes the resource type before the first `:`. Returns `None` for
/// unmapped types — callers apply the configured unmapped-route policy.
pub fn resolve_feature(o2_type: &str) -> Option<&'static str> {
    let resource_type = o2_type.split(':').next().unwrap_or(o2_type);
    FEATURE_REGISTRY.get(resource_type).copied()
}

/// Does a single scope authorize `(feature, method)`?
///
/// Scope grammar:
/// - `*`                     → everything (built-in admin)
/// - `<area>`                → all methods on that area
/// - `<area>:*`              → all methods on that area
/// - `<area>:<action>`       → the methods that action covers
///
/// `method` is matched case-insensitively.
pub fn scope_authorizes(scope: &str, feature: &str, method: &str) -> bool {
    if scope == "*" {
        return true;
    }
    let (scope_feature, scope_action) = match scope.split_once(':') {
        Some((f, a)) => (f, Some(a)),
        None => (scope, None),
    };
    if scope_feature != feature {
        return false;
    }
    match scope_action {
        None | Some("*") => true,
        Some(action) => {
            let method = method.to_uppercase();
            action_methods(action).into_iter().any(|m| m == method)
        }
    }
}

/// True if any scope in `scopes` authorizes `(feature, method)`.
pub fn any_scope_authorizes(scopes: &[String], feature: &str, method: &str) -> bool {
    scopes.iter().any(|s| scope_authorizes(s, feature, method))
}

/// Pure authorization decision used by the community `check_permissions`. All
/// runtime state (root check, logto-enabled flag, public-endpoint match, the
/// user's cached scopes, unmapped policy) is resolved by the caller and passed
/// in, so this function is trivially unit-testable.
///
/// Decision order:
/// 1. root user → allow (always)
/// 2. logto disabled → allow (community backward-compat)
/// 3. public/self-service endpoint → allow
/// 4. mapped feature + scopes present → scope match
/// 5. mapped feature + scope cache miss (`scopes == None`) → deny (fail-closed)
/// 6. unmapped route → configured unmapped policy
pub fn evaluate_permission(
    is_root: bool,
    logto_enabled: bool,
    is_public_or_self_service: bool,
    o2_type: &str,
    method: &str,
    scopes: Option<&[String]>,
    unmapped_policy_allow: bool,
) -> bool {
    if is_root {
        return true;
    }
    if !logto_enabled {
        return true;
    }
    if is_public_or_self_service {
        return true;
    }
    match resolve_feature(o2_type) {
        Some(feature) => match scopes {
            Some(s) => any_scope_authorizes(s, feature, method),
            None => false, // cache miss → fail-closed
        },
        None => unmapped_policy_allow,
    }
}

/// Derive a coarse OpenObserve role from scopes, for backward compatibility
/// with the frontend's existing `role === "admin"` gating. Users holding any
/// management-level scope (`iam:*`, `settings:*`, or global `*`) are `admin`;
/// everyone else is `member`. Fine-grained control is layered on top via
/// [`feature_permissions`].
pub fn derive_role(scopes: &[String]) -> &'static str {
    let is_admin = scopes.iter().any(|s| {
        s == "*"
            || s == "iam"
            || s == "settings"
            || s.starts_with("iam:")
            || s.starts_with("settings:")
    });
    if is_admin {
        "admin"
    } else {
        "member"
    }
}

/// Build the `{ feature: [actions] }` view the frontend consumes for
/// `hasFeature(area, action?)`. Actions are normalized to `read`/`create`/
/// `update`/`delete`; a whole-area scope (`<area>` / `<area>:*`) expands to all
/// four. Unrecognized scopes (no matching feature area) are dropped.
pub fn feature_permissions(scopes: &[String]) -> HashMap<String, Vec<String>> {
    let all = vec![
        "read".to_string(),
        "create".to_string(),
        "update".to_string(),
        "delete".to_string(),
    ];
    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    for scope in scopes {
        let (area, action) = match scope.split_once(':') {
            Some((a, act)) => (a, Some(act)),
            None => (scope.as_str(), None),
        };
        // Validate the area is a known feature (reverse-lookup against registry
        // values). If it isn't, skip silently — unknown scopes are ignored.
        let known = FEATURE_REGISTRY.values().any(|v| *v == area);
        if !known {
            continue;
        }
        let actions = match action {
            None | Some("*") => all.clone(),
            Some(a) if ["read", "create", "update", "delete"].contains(&a) => vec![a.to_string()],
            Some(_) => continue, // unknown action on a known area → skip
        };
        let entry = out.entry(area.to_string()).or_default();
        for a in actions {
            if !entry.contains(&a) {
                entry.push(a);
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// KV-backed scope store + in-memory cache (Task 4).
//
// Scopes are snapshotted from the token response at login, persisted to the
// `logto_scopes` KV table, and mirrored into the `LOGTO_USER_SCOPES` cache.
// `check_permissions` reads only the cache (hot path, no I/O); a cache miss is
// treated as deny (fail-closed). On startup the cache is rebuilt from KV so a
// restart does not force users to re-login.
// ---------------------------------------------------------------------------

use crate::common::infra::config::LOGTO_USER_SCOPES;

/// KV "table" (org_id namespace) for per-user scopes, keyed by lowercased email.
const KV_SCOPES_TABLE: &str = "logto_scopes";

/// Read a user's scopes from the in-memory cache. `None` on miss → caller
/// treats the request as deny (fail-closed).
pub fn cache_get(email: &str) -> Option<Vec<String>> {
    LOGTO_USER_SCOPES
        .get(&email.to_lowercase())
        .map(|v| v.clone())
}

fn cache_put(email: &str, scopes: Vec<String>) {
    LOGTO_USER_SCOPES.insert(email.to_lowercase(), scopes);
}

/// Persist scopes to KV and refresh the in-memory cache. Called after a
/// successful Logto login. Email is normalized to lowercase.
pub async fn store_scopes(email: &str, scopes: Vec<String>) -> Result<(), anyhow::Error> {
    let payload = serde_json::to_vec(&scopes)?;
    crate::service::kv::set(KV_SCOPES_TABLE, &email.to_lowercase(), payload.into()).await?;
    cache_put(email, scopes);
    Ok(())
}

/// Rebuild the in-memory cache from the KV table. Call once on startup (when
/// Logto is enabled) so a restart does not strip users of their permissions.
pub async fn load_cache_from_kv() -> Result<(), anyhow::Error> {
    let emails = crate::service::kv::list(KV_SCOPES_TABLE, "").await?;
    for email in emails {
        if let Ok(payload) = crate::service::kv::get(KV_SCOPES_TABLE, &email).await {
            if let Ok(scopes) = serde_json::from_slice::<Vec<String>>(&payload) {
                cache_put(&email, scopes);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- normalize_scopes (Task 3) ---

    #[test]
    fn strips_oidc_standard_scopes() {
        let raw = "openid profile email dashboards:write alerts:read";
        assert_eq!(
            normalize_scopes(raw),
            vec!["dashboards:write", "alerts:read"]
        );
    }

    #[test]
    fn trims_and_dedups() {
        assert_eq!(
            normalize_scopes("  dashboards:read   dashboards:read "),
            vec!["dashboards:read"]
        );
    }

    #[test]
    fn empty_or_standard_only() {
        assert!(normalize_scopes("").is_empty());
        assert!(normalize_scopes("openid profile email").is_empty());
    }

    // --- resolve_feature (Task 6) ---

    #[test]
    fn test_resolve_feature() {
        assert_eq!(resolve_feature("dashboard:abc123"), Some("dashboards"));
        assert_eq!(resolve_feature("dfolder:xyz"), Some("dashboards"));
        assert_eq!(resolve_feature("alert:id"), Some("alerts"));
        assert_eq!(resolve_feature("destinations:id"), Some("alerts"));
        assert_eq!(resolve_feature("stream:org_id"), Some("streams"));
        assert_eq!(resolve_feature("pipeline:id"), Some("pipelines"));
        assert_eq!(resolve_feature("function:id"), Some("functions"));
        assert_eq!(resolve_feature("user:id"), Some("iam"));
        assert_eq!(resolve_feature("org:id"), Some("iam"));
        assert_eq!(resolve_feature("settings:org"), Some("settings"));
        assert_eq!(resolve_feature("search:id"), Some("search"));
        assert_eq!(resolve_feature("logs:id"), Some("ingestion"));
        // unmapped
        assert_eq!(resolve_feature("unknown_thing:id"), None);
        // no colon
        assert_eq!(resolve_feature("dashboard"), Some("dashboards"));
    }

    // --- action_methods (Task 5) ---

    #[test]
    fn test_action_methods() {
        assert_eq!(action_methods("read"), vec!["GET"]);
        assert_eq!(action_methods("create"), vec!["POST"]);
        assert!(action_methods("update").contains(&"PUT".to_string()));
        assert!(action_methods("update").contains(&"PATCH".to_string()));
        assert_eq!(action_methods("delete"), vec!["DELETE"]);
        assert!(action_methods("foobar").is_empty());
    }

    // --- scope_authorizes (Task 7) ---

    #[test]
    fn test_scope_authorizes() {
        // specific action
        assert!(scope_authorizes("dashboards:read", "dashboards", "GET"));
        assert!(!scope_authorizes("dashboards:read", "dashboards", "POST"));
        // whole area (action omitted)
        assert!(scope_authorizes("alerts", "alerts", "GET"));
        assert!(scope_authorizes("alerts", "alerts", "DELETE"));
        // explicit wildcard
        assert!(scope_authorizes("alerts:*", "alerts", "POST"));
        // global wildcard
        assert!(scope_authorizes("*", "dashboards", "POST"));
        assert!(scope_authorizes("*", "iam", "DELETE"));
        // mismatched area
        assert!(!scope_authorizes("dashboards:read", "alerts", "GET"));
        // malformed scope
        assert!(!scope_authorizes("garbage", "dashboards", "GET"));
        // case-insensitive method
        assert!(scope_authorizes("dashboards:read", "dashboards", "get"));
    }

    #[test]
    fn test_any_scope_authorizes() {
        let scopes = vec![
            "dashboards:read".to_string(),
            "alerts:*".to_string(),
        ];
        assert!(any_scope_authorizes(&scopes, "dashboards", "GET"));
        assert!(!any_scope_authorizes(&scopes, "dashboards", "POST"));
        assert!(any_scope_authorizes(&scopes, "alerts", "DELETE"));
        assert!(!any_scope_authorizes(&scopes, "iam", "GET"));
    }

    // --- derive_role (Task 8) ---

    #[test]
    fn test_derive_role() {
        assert_eq!(
            derive_role(&["iam:*".into(), "dashboards:read".into()]),
            "admin"
        );
        assert_eq!(derive_role(&["settings:*".into()]), "admin");
        assert_eq!(derive_role(&["*".into()]), "admin");
        assert_eq!(
            derive_role(&["dashboards:read".into(), "alerts:*".into()]),
            "member"
        );
        assert_eq!(derive_role(&[]), "member");
    }

    // --- feature_permissions (Task 15 helper) ---

    #[test]
    fn test_feature_permissions() {
        let fp = feature_permissions(&[
            "dashboards:read".into(),
            "alerts:*".into(),
            "bogus:read".into(), // unknown area → dropped
        ]);
        assert_eq!(fp.get("dashboards"), Some(&vec!["read".to_string()]));
        assert_eq!(
            fp.get("alerts"),
            Some(&vec![
                "read".to_string(),
                "create".to_string(),
                "update".to_string(),
                "delete".to_string()
            ])
        );
        assert!(fp.get("bogus").is_none());
    }

    // --- evaluate_permission (Task 9 glue) ---

    #[test]
    fn test_evaluate_permission_root_bypasses() {
        // root always allowed, even with no scopes / unmapped / cache miss
        assert!(evaluate_permission(true, true, false, "iam:admin", "DELETE", None, false));
        assert!(evaluate_permission(true, true, false, "unknown:id", "GET", None, false));
    }

    #[test]
    fn test_evaluate_permission_disabled_is_allow() {
        // logto off → community backward-compat: allow everything
        assert!(evaluate_permission(false, false, false, "dashboard:x", "POST", None, false));
    }

    #[test]
    fn test_evaluate_permission_public_allowed() {
        assert!(evaluate_permission(false, true, true, "config", "GET", None, false));
    }

    #[test]
    fn test_evaluate_permission_scope_match() {
        let scopes = vec!["dashboards:read".to_string()];
        assert!(evaluate_permission(
            false, true, false, "dashboard:x", "GET", Some(&scopes), false
        ));
        assert!(!evaluate_permission(
            false, true, false, "dashboard:x", "POST", Some(&scopes), false
        ));
    }

    #[test]
    fn test_evaluate_permission_cache_miss_is_deny() {
        // mapped feature but scope cache miss → fail-closed
        assert!(!evaluate_permission(
            false, true, false, "dashboard:x", "GET", None, false
        ));
    }

    #[test]
    fn test_evaluate_permission_unmapped_policy() {
        // unmapped route with deny policy → false
        assert!(!evaluate_permission(
            false, true, false, "unknown:id", "GET", Some(&[]), false
        ));
        // unmapped route with allow policy → true
        assert!(evaluate_permission(
            false, true, false, "unknown:id", "GET", Some(&[]), true
        ));
    }
}
