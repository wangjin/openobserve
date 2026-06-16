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

//! Logto JWKS fetch + cache. Logto signs ID tokens with a key from its JWKS
//! endpoint; keys rotate, so we cache with a TTL and refresh on stale/miss.

use std::sync::{LazyLock, RwLock};
use std::time::{Duration, Instant};

use jsonwebtoken::DecodingKey;

/// How long a fetched JWKS is considered fresh before we re-fetch.
const TTL: Duration = Duration::from_secs(3600);

struct JwksInner {
    keys: Vec<serde_json::Value>,
    fetched_at: Option<Instant>,
}

impl Default for JwksInner {
    fn default() -> Self {
        Self {
            keys: Vec::new(),
            fetched_at: None,
        }
    }
}

/// In-memory JWKS cache. Cheap to read (sync); refresh is async and rare.
pub struct JwksCache {
    inner: RwLock<JwksInner>,
}

impl JwksCache {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(JwksInner::default()),
        }
    }

    /// True when no JWKS has been fetched yet, or the cache is past its TTL.
    pub fn is_stale(&self) -> bool {
        match self.inner.read() {
            Ok(inner) => inner.fetched_at.map_or(true, |t| t.elapsed() > TTL),
            Err(_) => true, // poisoned → treat as stale so we re-fetch
        }
    }

    /// Fetch `{ jwks_uri }` and replace the cached key set.
    pub async fn refresh(&self, jwks_uri: &str) -> Result<(), anyhow::Error> {
        let value: serde_json::Value = reqwest::get(jwks_uri).await?.json().await?;
        let keys = value
            .get("keys")
            .and_then(|k| k.as_array())
            .cloned()
            .unwrap_or_default();
        if let Ok(mut inner) = self.inner.write() {
            inner.keys = keys;
            inner.fetched_at = Some(Instant::now());
        }
        Ok(())
    }

    /// Return a `DecodingKey` for the given `kid`. When `kid` is `None`, falls
    /// back to the single key in the set (common for small deployments).
    pub fn decoding_key(&self, kid: Option<&str>) -> Option<DecodingKey> {
        let inner = self.inner.read().ok()?;
        for key in &inner.keys {
            let this_kid = key.get("kid").and_then(|v| v.as_str());
            let matches = match (kid, this_kid) {
                (Some(want), Some(have)) => want == have,
                (None, _) => inner.keys.len() == 1,
                _ => false,
            };
            if matches {
                let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(key.clone()).ok()?;
                return DecodingKey::from_jwk(&jwk).ok();
            }
        }
        None
    }
}

/// Process-wide Logto JWKS cache.
pub static LOGTO_JWKS: LazyLock<JwksCache> = LazyLock::new(JwksCache::new);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_cache_is_stale() {
        let cache = JwksCache::new();
        assert!(cache.is_stale());
        assert!(cache.decoding_key(Some("anything")).is_none());
    }
}
