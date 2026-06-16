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

//! Logto (OIDC) integration data structures. Used by the community-edition
//! Logto login flow and scope-based authorization. See
//! `docs/superpowers/specs/2026-06-15-logto-integration-design.md`.

use serde::{Deserialize, Serialize};

/// Subset of the OIDC discovery document
/// (`{issuer}/.well-known/openid-configuration`) that the Logto flow needs.
/// Cached after the first fetch.
#[derive(Debug, Clone, Deserialize)]
pub struct OidcDiscovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    /// Standard OIDC single sign-out endpoint. May be absent on some IdPs.
    #[serde(default)]
    pub end_session_endpoint: Option<String>,
}

/// Response from the token endpoint on a successful authorization-code
/// exchange. `scope` is the authoritative list of granted scopes — it is the
/// source of truth for what the user may do in OpenObserve.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub id_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_in: Option<i64>,
    /// Space-separated granted scopes. Empty if the IdP omits it.
    #[serde(default)]
    pub scope: Option<String>,
}

/// Claims extracted from the verified ID token. Only the fields OpenObserve
/// uses are decoded; `aud` is kept as a JSON value because OIDC allows either a
/// string or an array.
#[derive(Debug, Clone, Deserialize)]
pub struct IdTokenClaims {
    pub sub: String,
    pub email: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub given_name: Option<String>,
    #[serde(default)]
    pub family_name: Option<String>,
    /// Audience: per OIDC this is either a string or an array of strings.
    #[serde(default)]
    pub aud: serde_json::Value,
    pub exp: i64,
    pub iss: String,
}

/// A pending authorization: the PKCE `code_verifier` paired with the opaque
/// `state` we sent to Logto. Stored in the `logto_auth_state` KV table until
/// the callback consumes (and deletes) it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSession {
    pub code_verifier: String,
    pub created_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discovery_parse() {
        let raw = r#"{
            "issuer":"https://logto.example.com",
            "authorization_endpoint":"https://logto.example.com/auth",
            "token_endpoint":"https://logto.example.com/token",
            "jwks_uri":"https://logto.example.com/jwks",
            "end_session_endpoint":"https://logto.example.com/oidc/logout"
        }"#;
        let d: OidcDiscovery = serde_json::from_str(raw).unwrap();
        assert_eq!(d.issuer, "https://logto.example.com");
        assert_eq!(d.jwks_uri, "https://logto.example.com/jwks");
        assert_eq!(
            d.end_session_endpoint.as_deref(),
            Some("https://logto.example.com/oidc/logout")
        );
    }

    #[test]
    fn test_discovery_without_end_session() {
        let raw = r#"{
            "issuer":"https://logto.example.com",
            "authorization_endpoint":"/auth",
            "token_endpoint":"/token",
            "jwks_uri":"/jwks"
        }"#;
        let d: OidcDiscovery = serde_json::from_str(raw).unwrap();
        assert!(d.end_session_endpoint.is_none());
    }

    #[test]
    fn test_token_response_parse() {
        let raw = r#"{
            "access_token":"a",
            "id_token":"i",
            "refresh_token":"r",
            "expires_in":3600,
            "scope":"openid dashboards:read"
        }"#;
        let t: TokenResponse = serde_json::from_str(raw).unwrap();
        assert_eq!(t.access_token, "a");
        assert_eq!(t.id_token, "i");
        assert_eq!(t.refresh_token.as_deref(), Some("r"));
        assert_eq!(t.expires_in, Some(3600));
        assert_eq!(t.scope.as_deref(), Some("openid dashboards:read"));
    }

    #[test]
    fn test_token_response_minimal() {
        let raw = r#"{"access_token":"a","id_token":"i"}"#;
        let t: TokenResponse = serde_json::from_str(raw).unwrap();
        assert!(t.refresh_token.is_none());
        assert!(t.expires_in.is_none());
        assert!(t.scope.is_none());
    }
}
