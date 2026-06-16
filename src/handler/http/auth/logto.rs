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

//! HTTP handlers for the Logto (OIDC) login flow:
//! - [`login`]  → redirect to Logto `/auth` with PKCE + state
//! - [`callback`] → exchange code, verify ID token, JIT user, snapshot scopes,
//!   set the OpenObserve session cookie, redirect to the web app
//! - [`logout`] → clear the session cookie and redirect to Logto end-session
//!
//! Orchestration lives in `crate::service::logto`.

use std::collections::HashMap;

use axum::body::Body;
use axum::extract::Query;
use axum::response::Response;
use axum_extra::extract::cookie::{Cookie, SameSite};
use http::{header, StatusCode};

use crate::service::logto;

/// `GET /api/logto/login` — start the OIDC Authorization Code + PKCE flow.
pub async fn login() -> Response {
    let cfg = config::get_config();
    let logto_cfg = &cfg.auth.logto;
    if !logto_cfg.enabled {
        return plain(StatusCode::NOT_FOUND, "logto disabled");
    }

    let discovery = match logto::fetch_discovery(&logto_cfg.issuer).await {
        Ok(d) => d,
        Err(e) => {
            log::error!("logto discovery failed: {e}");
            return plain(StatusCode::BAD_GATEWAY, "logto discovery failed");
        }
    };

    let (verifier, challenge) = logto::generate_pkce_pair();
    let state = logto::generate_state();
    if let Err(e) = logto::save_state(&state, &verifier).await {
        log::error!("logto save_state failed: {e}");
        return plain(StatusCode::INTERNAL_SERVER_ERROR, "state store failed");
    }

    let url = logto::build_authz_url(
        &discovery,
        &logto_cfg.client_id,
        &logto_cfg.redirect_uri,
        &logto_cfg.api_indicator,
        &state,
        &challenge,
    );
    redirect(&url)
}

/// `GET /api/logto/callback?code=…&state=…` — complete the OIDC flow.
pub async fn callback(Query(q): Query<HashMap<String, String>>) -> Response {
    let cfg = config::get_config();
    let logto_cfg = &cfg.auth.logto;

    let code = match q.get("code") {
        Some(c) => c.as_str(),
        None => return plain(StatusCode::BAD_REQUEST, "missing code"),
    };
    let state = match q.get("state") {
        Some(s) => s.as_str(),
        None => return plain(StatusCode::BAD_REQUEST, "missing state"),
    };
    let session = match logto::take_state(state).await {
        Some(s) => s,
        None => return plain(StatusCode::BAD_REQUEST, "invalid or expired state"),
    };

    let discovery = match logto::fetch_discovery(&logto_cfg.issuer).await {
        Ok(d) => d,
        Err(_) => return plain(StatusCode::BAD_GATEWAY, "logto discovery failed"),
    };

    let token = match logto::exchange_code(
        &discovery.token_endpoint,
        &logto_cfg.client_id,
        &logto_cfg.client_secret,
        &logto_cfg.redirect_uri,
        code,
        &session.code_verifier,
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            log::error!("logto token exchange failed: {e}");
            return plain(StatusCode::BAD_GATEWAY, "token exchange failed");
        }
    };

    let claims =
        match logto::verify_id_token(&token.id_token, &discovery, &logto_cfg.client_id).await {
            Ok(c) => c,
            Err(e) => {
                log::error!("logto id_token verify failed: {e}");
                return plain(StatusCode::UNAUTHORIZED, "invalid id_token");
            }
        };

    let email = claims.email.trim().to_lowercase();
    if email.is_empty() {
        return plain(StatusCode::BAD_REQUEST, "id_token missing email claim");
    }
    let is_root = !cfg.auth.root_user_email.is_empty()
        && email == cfg.auth.root_user_email.trim().to_lowercase();
    let first = claims
        .given_name
        .clone()
        .or_else(|| claims.name.clone())
        .unwrap_or_default();
    let last = claims.family_name.clone().unwrap_or_default();

    let credential = match logto::upsert_external_user(&email, &first, &last, is_root).await {
        Ok(c) => c,
        Err(e) => {
            log::error!("logto JIT user provisioning failed: {e}");
            return plain(StatusCode::INTERNAL_SERVER_ERROR, "user provisioning failed");
        }
    };

    // Snapshot the granted scopes for this user (authz reads them on every
    // request). Non-fatal if it fails — re-login will retry.
    let scopes = logto::scopes::normalize_scopes(token.scope.as_deref().unwrap_or(""));
    if let Err(e) = logto::scopes::store_scopes(&email, scopes).await {
        log::warn!("logto store_scopes failed for {email} (non-fatal): {e}");
    }

    // Issue the OpenObserve session cookie (community format).
    let tokens = logto::build_auth_tokens(&email, &credential);
    let cookie = build_session_cookie("auth_tokens", &logto::encode_session_cookie(&tokens));

    let url = format!("{}{}/web/", cfg.common.web_url, cfg.common.base_uri);
    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, url)
        .header(header::SET_COOKIE, cookie.to_string())
        .body(Body::empty())
        .unwrap()
}

/// `GET /api/logto/logout` — clear the OO session and redirect through Logto's
/// end-session endpoint back to the configured post-logout URI.
pub async fn logout() -> Response {
    let cfg = config::get_config();
    let logto_cfg = &cfg.auth.logto;
    let cleared = build_clear_cookie("auth_tokens");

    let end_session = logto::fetch_discovery(&logto_cfg.issuer)
        .await
        .ok()
        .and_then(|d| d.end_session_endpoint);

    let target = match end_session {
        Some(ep) => format!(
            "{}?post_logout_redirect_uri={}",
            ep,
            urlencoding::encode(&logto_cfg.post_logout_uri)
        ),
        None => format!("{}{}/login", cfg.common.web_url, cfg.common.base_uri),
    };

    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, target)
        .header(header::SET_COOKIE, cleared.to_string())
        .body(Body::empty())
        .unwrap()
}

// --- helpers ---

fn plain(status: StatusCode, msg: &str) -> Response {
    Response::builder()
        .status(status)
        .body(Body::from(msg.to_string()))
        .unwrap()
}

fn redirect(url: &str) -> Response {
    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, url)
        .body(Body::empty())
        .unwrap()
}

/// Build the `auth_tokens` cookie with the same attributes the community login
/// uses (http_only, path "/", secure/samesite from config, max-age from config).
fn build_session_cookie(name: &str, value: &str) -> Cookie<'static> {
    let cfg = config::get_config();
    let mut c = Cookie::new(name.to_string(), value.to_string());
    c.set_http_only(true);
    c.set_secure(cfg.auth.cookie_secure_only);
    c.set_path("/");
    if cfg.auth.cookie_same_site_lax {
        c.set_same_site(SameSite::Lax);
    } else {
        c.set_same_site(SameSite::None);
    }
    let expiry =
        time::OffsetDateTime::now_utc() + time::Duration::seconds(cfg.auth.cookie_max_age);
    c.set_expires(expiry);
    c
}

/// Build a cookie that immediately expires, to clear the session.
fn build_clear_cookie(name: &str) -> Cookie<'static> {
    let cfg = config::get_config();
    let mut c = Cookie::new(name.to_string(), String::new());
    c.set_http_only(true);
    c.set_secure(cfg.auth.cookie_secure_only);
    c.set_path("/");
    c.set_max_age(time::Duration::seconds(0));
    c
}
