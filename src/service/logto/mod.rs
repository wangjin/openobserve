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

//! Logto (OIDC) integration orchestration for OpenObserve community edition.
//!
//! Flow: [`login`] (build authz URL + PKCE + state) → Logto authenticates the
//! user → [`callback`] (exchange code, verify ID token, JIT-provision the
//! user, snapshot scopes, issue an OpenObserve session cookie) → subsequent
//! requests are authenticated by the existing community validator and
//! authorized by [`scopes`]. [`logout`] clears the session and redirects to
//! Logto's end-session endpoint.

pub mod jwks;
pub mod scopes;

use crate::common::meta::logto::{AuthSession, IdTokenClaims, OidcDiscovery, TokenResponse};
use crate::common::meta::organization::DEFAULT_ORG;
use crate::common::meta::user::AuthTokens;
use crate::common::utils::auth::get_hash;
use base64::Engine as _;
use config::meta::user::{DBUser, UserOrg, UserRole};

/// KV "table" for the short-lived `{state -> PKCE verifier}` pairs created by
/// [`login`] and consumed (and deleted) by [`callback`].
const KV_STATE_TABLE: &str = "logto_auth_state";

/// Fetch (and the caller caches) the OIDC discovery document.
pub async fn fetch_discovery(issuer: &str) -> Result<OidcDiscovery, anyhow::Error> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    Ok(reqwest::get(&url).await?.json().await?)
}

/// Generate a high-entropy PKCE pair. Returns `(code_verifier, code_challenge)`
/// where `code_challenge = BASE64URL_NOPAD(SHA256(verifier))`.
pub fn generate_pkce_pair() -> (String, String) {
    // Two uuids concatenated (with hyphens, all PKCE-unreserved) → 72 chars,
    // within the 43..=128 range.
    let verifier = format!("{}{}", config::ider::uuid(), config::ider::uuid());
    let digest_hex = sha256::digest(verifier.as_bytes());
    let raw = hex::decode(digest_hex).expect("sha256 hex is always 64 chars");
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
    (verifier, challenge)
}

/// Opaque CSRF `state` value.
pub fn generate_state() -> String {
    config::ider::uuid()
}

/// Build the Logto authorization URL (Authorization Code + PKCE).
pub fn build_authz_url(
    discovery: &OidcDiscovery,
    client_id: &str,
    redirect_uri: &str,
    api_indicator: &str,
    state: &str,
    challenge: &str,
) -> String {
    let scope = format!(
        "openid profile email {}",
        urlencoding::encode(api_indicator)
    );
    format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&state={}&scope={}&code_challenge={}&code_challenge_method=S256",
        discovery.authorization_endpoint,
        urlencoding::encode(client_id),
        urlencoding::encode(redirect_uri),
        urlencoding::encode(state),
        scope,
        urlencoding::encode(challenge),
    )
}

/// Persist `{state -> verifier}` to KV (TTL handled by the callback consuming
/// and deleting it; long-stale entries are benign).
pub async fn save_state(state: &str, verifier: &str) -> Result<(), anyhow::Error> {
    let item = AuthSession {
        code_verifier: verifier.to_string(),
        created_at: config::utils::time::now_micros(),
    };
    let payload = serde_json::to_vec(&item)?;
    crate::service::kv::set(KV_STATE_TABLE, state, payload.into()).await?;
    Ok(())
}

/// Consume a `state`: return its verifier and delete the KV entry. `None` if
/// the state is unknown/expired (→ callback rejects).
pub async fn take_state(state: &str) -> Option<AuthSession> {
    let bytes = crate::service::kv::get(KV_STATE_TABLE, state).await.ok()?;
    let item: AuthSession = serde_json::from_slice(&bytes).ok()?;
    let _ = crate::service::kv::delete(KV_STATE_TABLE, state).await;
    Some(item)
}

/// Exchange an authorization code for tokens at Logto's token endpoint.
pub async fn exchange_code(
    token_endpoint: &str,
    client_id: &str,
    client_secret: &str,
    redirect_uri: &str,
    code: &str,
    code_verifier: &str,
) -> Result<TokenResponse, anyhow::Error> {
    let resp = reqwest::Client::new()
        .post(token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("code_verifier", code_verifier),
        ])
        .send()
        .await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("token endpoint returned {status}: {body}");
    }
    Ok(resp.json().await?)
}

/// Verify the Logto ID token (signature via JWKS, issuer, audience, expiry
/// with a 60s leeway for clock skew) and return its claims.
pub async fn verify_id_token(
    id_token: &str,
    discovery: &OidcDiscovery,
    client_id: &str,
) -> Result<IdTokenClaims, anyhow::Error> {
    use jsonwebtoken::{decode, decode_header, Algorithm, Validation};

    let header = decode_header(id_token)?;
    let kid = header.kid;

    if jwks::LOGTO_JWKS.is_stale() {
        jwks::LOGTO_JWKS.refresh(&discovery.jwks_uri).await?;
    }
    let key = jwks::LOGTO_JWKS
        .decoding_key(kid.as_deref())
        .ok_or_else(|| anyhow::anyhow!("no JWKS key matching kid {kid:?}"))?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[client_id]);
    validation.set_issuer(&[&discovery.issuer]);
    validation.leeway = 60;
    let data = decode::<IdTokenClaims>(id_token, &key, &validation)?;
    Ok(data.claims)
}

/// JIT-provision (or refresh) the OpenObserve user for a Logto login. External
/// users have no password they know, so we mint a random one (rotated each
/// login) purely to act as the OpenObserve session credential. Returns the
/// plaintext credential for building the session cookie.
///
/// The DB org role only matters for root identification in community (authz is
/// scope-driven via [`scopes`]); non-root users are stored as `UserRole::User`.
pub async fn upsert_external_user(
    email: &str,
    first_name: &str,
    last_name: &str,
    is_root: bool,
) -> Result<String, anyhow::Error> {
    // Random per-login session credential (the user never sees it).
    let credential = format!("{}{}", config::ider::uuid(), config::ider::uuid());

    match crate::service::db::user::get_user_by_email(email).await {
        Some(existing) => {
            // Rotate the credential; reuse the existing salt (validator uses it).
            let hashed = get_hash(&credential, &existing.salt);
            crate::service::db::user::update(
                email,
                &existing.first_name,
                &existing.last_name,
                &hashed,
                existing.password_ext.clone(),
            )
            .await?;
        }
        None => {
            let salt = config::ider::uuid();
            let hashed = get_hash(&credential, &salt);
            let role = if is_root {
                UserRole::Root
            } else {
                UserRole::User
            };
            let user = DBUser {
                email: email.to_string(),
                first_name: first_name.to_string(),
                last_name: last_name.to_string(),
                password: hashed,
                salt,
                organizations: vec![UserOrg {
                    name: DEFAULT_ORG.to_string(),
                    org_name: DEFAULT_ORG.to_string(),
                    token: String::new(),
                    rum_token: None,
                    role,
                }],
                is_external: true,
                password_ext: None,
            };
            crate::service::db::user::add(&user).await?;
        }
    }
    Ok(credential)
}

/// Build the OpenObserve session value (the `auth_tokens` cookie contents),
/// matching the community login format: `Basic base64(email:credential)`.
pub fn build_auth_tokens(email: &str, credential: &str) -> AuthTokens {
    let raw = base64::engine::general_purpose::STANDARD.encode(format!("{email}:{credential}"));
    AuthTokens {
        access_token: format!("Basic {raw}"),
        refresh_token: String::new(),
    }
}

/// Serialize the session into the base64 cookie payload the community validator
/// reads back (mirrors `_prepare_cookie` in `users/mod.rs`).
pub fn encode_session_cookie(tokens: &AuthTokens) -> String {
    let json = serde_json::to_string(tokens).unwrap_or_default();
    base64::engine::general_purpose::STANDARD.encode(json)
}
