//! OIDC federation for `AssumeRoleWithWebIdentity`: trusted identity providers, JWT
//! verification (RS256/384/512, PS256/384/512, ES256/384) and JWKS fetching with caching and
//! `kid` rotation.
//!
//! Build an [`OidcVerifier`] from [`OidcProviderConfig`]s and hand it to
//! [`crate::sts::StsState::with_oidc`]. Tokens are never logged; error messages never echo
//! token contents.

use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet, KeyAlgorithm, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Largest accepted web identity token (bytes).
pub const MAX_TOKEN_BYTES: usize = 16 * 1024;
/// Largest accepted JWKS document (bytes).
pub const MAX_JWKS_BYTES: usize = 1024 * 1024;
/// Clock skew tolerated on `exp` / `nbf` / `iat` (seconds).
pub const LEEWAY_SECS: u64 = 60;

/// One trusted OIDC identity provider (config: `[[sts.oidc_providers]]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcProviderConfig {
    /// Issuer URL, compared exactly (modulo a trailing `/`) with the token's `iss`.
    pub issuer: String,
    /// Accepted `aud` values; at least one is required.
    pub audiences: Vec<String>,
    /// JWKS endpoint (`https://`, or `http://` on a loopback address for tests/dev).
    #[serde(default)]
    pub jwks_url: Option<String>,
    /// Inline JWKS document (JSON); used instead of `jwks_url` when set.
    #[serde(default)]
    pub jwks: Option<Value>,
    /// Claim name → session tag key; scalar claims become `aws:PrincipalTag/<key>`.
    #[serde(default)]
    pub claim_tags: BTreeMap<String, String>,
}

impl OidcProviderConfig {
    /// Provider id: the issuer without scheme and trailing `/` (AWS style, e.g.
    /// `token.actions.githubusercontent.com`). Used as the condition-key prefix
    /// (`<id>:sub`, `<id>:aud`) and in `Federated` principals.
    pub fn provider_id(&self) -> String {
        provider_id(&self.issuer)
    }
}

fn provider_id(issuer: &str) -> String {
    let s = issuer.trim_end_matches('/');
    s.strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .unwrap_or(s)
        .to_string()
}

/// Why a web identity token was rejected.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum OidcError {
    /// No OIDC provider is configured on this server.
    #[error("web identity federation is not configured")]
    NotConfigured,
    /// Invalid provider configuration.
    #[error("invalid OIDC provider configuration: {0}")]
    Config(String),
    /// Not a well-formed JWT.
    #[error("malformed web identity token")]
    Malformed,
    /// `iss` is not a configured provider.
    #[error("token issuer is not trusted")]
    UnknownIssuer,
    /// `alg` is not an accepted asymmetric algorithm.
    #[error("unsupported token algorithm")]
    UnsupportedAlgorithm,
    /// No JWKS key matches the token's `kid` (after a refresh).
    #[error("no signing key matches the token")]
    UnknownKey,
    /// Signature does not verify.
    #[error("invalid token signature")]
    InvalidSignature,
    /// `exp` is in the past.
    #[error("token has expired")]
    Expired,
    /// `aud` does not contain an accepted audience.
    #[error("token audience is not accepted")]
    InvalidAudience,
    /// Some other claim check failed (nbf, missing sub/exp, ...).
    #[error("invalid token: {0}")]
    InvalidClaims(String),
    /// The JWKS endpoint could not be fetched or parsed.
    #[error("could not fetch the identity provider's keys: {0}")]
    Jwks(String),
}

/// A verified web identity.
#[derive(Debug, Clone, PartialEq)]
pub struct WebIdentity {
    /// Provider id (issuer without scheme).
    pub provider: String,
    /// Issuer as configured.
    pub issuer: String,
    /// `sub`.
    pub subject: String,
    /// `aud` values.
    pub audience: Vec<String>,
    /// All claims.
    pub claims: Map<String, Value>,
    /// Session tags from `claim_tags`.
    pub tags: BTreeMap<String, String>,
}

impl WebIdentity {
    /// The audience that matched the provider configuration (first accepted value).
    pub fn primary_audience(&self) -> &str {
        self.audience.first().map(String::as_str).unwrap_or("")
    }
}

struct Cached {
    set: Arc<JwkSet>,
    fetched: Instant,
}

struct Provider {
    cfg: OidcProviderConfig,
    id: String,
    issuer_norm: String,
    inline: Option<Arc<JwkSet>>,
    cache: tokio::sync::Mutex<Option<Cached>>,
}

/// Verifies web identity tokens against the configured providers.
pub struct OidcVerifier {
    providers: Vec<Provider>,
    http: reqwest::Client,
    ttl: Duration,
    min_refetch: Duration,
}

impl std::fmt::Debug for OidcVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcVerifier")
            .field(
                "providers",
                &self.providers.iter().map(|p| &p.id).collect::<Vec<_>>(),
            )
            .finish()
    }
}

fn is_loopback_http(u: &url::Url) -> bool {
    u.scheme() == "http"
        && match u.host() {
            Some(url::Host::Ipv4(a)) => a.is_loopback(),
            Some(url::Host::Ipv6(a)) => a.is_loopback(),
            Some(url::Host::Domain(d)) => d == "localhost",
            None => false,
        }
}

impl OidcVerifier {
    /// Validate the provider list and build the verifier. JWKS caches refresh after 1 h, and
    /// an unknown `kid` triggers at most one refetch per provider every 10 s.
    pub fn new(configs: Vec<OidcProviderConfig>) -> Result<Self, OidcError> {
        let mut providers = Vec::new();
        for cfg in configs {
            let bad = |m: &str| OidcError::Config(format!("{}: {m}", cfg.issuer));
            let iu = url::Url::parse(&cfg.issuer).map_err(|_| bad("issuer is not a URL"))?;
            if iu.scheme() != "https" && !is_loopback_http(&iu) {
                return Err(bad("issuer must be https"));
            }
            if cfg.audiences.is_empty() || cfg.audiences.iter().any(String::is_empty) {
                return Err(bad("at least one non-empty audience is required"));
            }
            let inline = match &cfg.jwks {
                Some(v) => Some(Arc::new(
                    serde_json::from_value::<JwkSet>(v.clone())
                        .map_err(|e| bad(&format!("inline jwks: {e}")))?,
                )),
                None => None,
            };
            match (&cfg.jwks_url, &inline) {
                (None, None) => return Err(bad("jwks_url or jwks is required")),
                (Some(u), _) => {
                    let u = url::Url::parse(u).map_err(|_| bad("jwks_url is not a URL"))?;
                    if u.scheme() != "https" && !is_loopback_http(&u) {
                        return Err(bad("jwks_url must be https"));
                    }
                }
                _ => {}
            }
            for (claim, tag) in &cfg.claim_tags {
                if claim.is_empty() || !valid_tag_key(tag) {
                    return Err(bad(
                        "claim_tags: tag keys are 1..=128 chars of [\\w.:/=+@-]",
                    ));
                }
            }
            if providers
                .iter()
                .any(|p: &Provider| p.id == cfg.provider_id())
            {
                return Err(bad("duplicate provider"));
            }
            providers.push(Provider {
                id: cfg.provider_id(),
                issuer_norm: cfg.issuer.trim_end_matches('/').to_string(),
                inline,
                cache: tokio::sync::Mutex::new(None),
                cfg,
            });
        }
        let http = reqwest::Client::builder()
            .use_rustls_tls()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| OidcError::Config(format!("http client: {e}")))?;
        Ok(Self {
            providers,
            http,
            ttl: Duration::from_secs(3600),
            min_refetch: Duration::from_secs(10),
        })
    }

    /// Override cache TTL and minimum refetch interval (tests).
    pub fn with_cache_policy(mut self, ttl: Duration, min_refetch: Duration) -> Self {
        self.ttl = ttl;
        self.min_refetch = min_refetch;
        self
    }

    /// Configured provider ids.
    pub fn provider_ids(&self) -> Vec<String> {
        self.providers.iter().map(|p| p.id.clone()).collect()
    }

    /// Verify `token`: issuer is configured, `alg` is asymmetric, signature verifies with the
    /// provider's key for `kid`, `exp`/`nbf` hold (±60 s), `aud` is accepted, `sub` present.
    pub async fn verify(&self, token: &str) -> Result<WebIdentity, OidcError> {
        if self.providers.is_empty() {
            return Err(OidcError::NotConfigured);
        }
        if token.len() > MAX_TOKEN_BYTES || token.split('.').count() != 3 {
            return Err(OidcError::Malformed);
        }
        let header = jsonwebtoken::decode_header(token).map_err(|_| OidcError::Malformed)?;
        if !matches!(
            header.alg,
            Algorithm::RS256
                | Algorithm::RS384
                | Algorithm::RS512
                | Algorithm::PS256
                | Algorithm::PS384
                | Algorithm::PS512
                | Algorithm::ES256
                | Algorithm::ES384
        ) {
            return Err(OidcError::UnsupportedAlgorithm);
        }
        let unverified: Map<String, Value> = jsonwebtoken::dangerous::insecure_decode_claims(token)
            .map_err(|_| OidcError::Malformed)?;
        let iss = unverified
            .get("iss")
            .and_then(Value::as_str)
            .ok_or(OidcError::UnknownIssuer)?;
        let p = self
            .providers
            .iter()
            .find(|p| p.issuer_norm == iss.trim_end_matches('/'))
            .ok_or(OidcError::UnknownIssuer)?;
        let jwk = self.key_for(p, header.kid.as_deref(), header.alg).await?;
        let key = DecodingKey::from_jwk(&jwk).map_err(|_| OidcError::UnknownKey)?;
        let mut v = Validation::new(header.alg);
        v.leeway = LEEWAY_SECS;
        v.validate_nbf = true;
        v.set_issuer(&[iss]);
        v.set_audience(&p.cfg.audiences);
        v.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        let data = jsonwebtoken::decode::<Map<String, Value>>(token, &key, &v).map_err(|e| {
            use jsonwebtoken::errors::ErrorKind as K;
            match e.kind() {
                K::ExpiredSignature => OidcError::Expired,
                K::InvalidAudience => OidcError::InvalidAudience,
                K::InvalidIssuer => OidcError::UnknownIssuer,
                K::InvalidSignature => OidcError::InvalidSignature,
                K::InvalidAlgorithm | K::InvalidKeyFormat | K::InvalidRsaKey(_) => {
                    OidcError::UnknownKey
                }
                K::ImmatureSignature => OidcError::InvalidClaims("token is not yet valid".into()),
                K::MissingRequiredClaim(c) => OidcError::InvalidClaims(format!("missing {c}")),
                K::InvalidClaimFormat(c) => {
                    OidcError::InvalidClaims(format!("bad claim format: {c}"))
                }
                _ => OidcError::Malformed,
            }
        })?;
        let claims = data.claims;
        let subject = match claims.get("sub") {
            Some(Value::String(s)) if !s.is_empty() && s.len() <= 255 => s.clone(),
            _ => {
                return Err(OidcError::InvalidClaims(
                    "sub must be a 1..=255 char string".into(),
                ));
            }
        };
        let mut audience: Vec<String> = match claims.get("aud") {
            Some(Value::String(s)) => vec![s.clone()],
            Some(Value::Array(a)) => a
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect(),
            _ => Vec::new(),
        };
        audience.sort_by_key(|a| !p.cfg.audiences.contains(a));
        let mut tags = BTreeMap::new();
        for (claim, tag) in &p.cfg.claim_tags {
            let val = match claims.get(claim) {
                Some(Value::String(s)) => s.clone(),
                Some(Value::Bool(b)) => b.to_string(),
                Some(Value::Number(n)) => n.to_string(),
                _ => continue,
            };
            if val.chars().count() <= 256 {
                tags.insert(tag.clone(), val);
            }
        }
        Ok(WebIdentity {
            provider: p.id.clone(),
            issuer: p.cfg.issuer.clone(),
            subject,
            audience,
            claims,
            tags,
        })
    }

    async fn key_for(
        &self,
        p: &Provider,
        kid: Option<&str>,
        alg: Algorithm,
    ) -> Result<Jwk, OidcError> {
        if let Some(set) = &p.inline {
            return pick(set, kid, alg).ok_or(OidcError::UnknownKey);
        }
        let url = p.cfg.jwks_url.as_deref().ok_or(OidcError::UnknownKey)?;
        let mut cache = p.cache.lock().await;
        let fresh = cache
            .as_ref()
            .is_some_and(|c| c.fetched.elapsed() < self.ttl);
        if fresh && let Some(k) = cache.as_ref().and_then(|c| pick(&c.set, kid, alg)) {
            return Ok(k);
        }
        let may_refetch = cache
            .as_ref()
            .is_none_or(|c| !fresh || c.fetched.elapsed() >= self.min_refetch);
        if !may_refetch {
            return Err(OidcError::UnknownKey);
        }
        match self.fetch(url).await {
            Ok(set) => {
                let set = Arc::new(set);
                *cache = Some(Cached {
                    set: set.clone(),
                    fetched: Instant::now(),
                });
                pick(&set, kid, alg).ok_or(OidcError::UnknownKey)
            }
            Err(e) => {
                tracing::warn!(provider = %p.id, error = %e, "jwks fetch failed");
                match cache.as_ref().and_then(|c| pick(&c.set, kid, alg)) {
                    Some(k) => Ok(k),
                    None => Err(e),
                }
            }
        }
    }

    async fn fetch(&self, url: &str) -> Result<JwkSet, OidcError> {
        let err = |m: String| OidcError::Jwks(m);
        let mut resp = self
            .http
            .get(url)
            .header("accept", "application/json")
            .send()
            .await
            .map_err(|e| err(e.without_url().to_string()))?;
        if !resp.status().is_success() {
            return Err(err(format!("HTTP {}", resp.status().as_u16())));
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| err(e.to_string()))? {
            if body.len() + chunk.len() > MAX_JWKS_BYTES {
                return Err(err("JWKS document too large".into()));
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|e| err(format!("invalid JWKS: {e}")))
    }
}

fn valid_tag_key(k: &str) -> bool {
    (1..=128).contains(&k.chars().count())
        && k.chars()
            .all(|c| c.is_alphanumeric() || "_.:/=+@-".contains(c))
}

fn key_alg_matches(ka: KeyAlgorithm, alg: Algorithm) -> bool {
    matches!(
        (ka, alg),
        (KeyAlgorithm::RS256, Algorithm::RS256)
            | (KeyAlgorithm::RS384, Algorithm::RS384)
            | (KeyAlgorithm::RS512, Algorithm::RS512)
            | (KeyAlgorithm::PS256, Algorithm::PS256)
            | (KeyAlgorithm::PS384, Algorithm::PS384)
            | (KeyAlgorithm::PS512, Algorithm::PS512)
            | (KeyAlgorithm::ES256, Algorithm::ES256)
            | (KeyAlgorithm::ES384, Algorithm::ES384)
    )
}

/// Select a verification key: asymmetric only, family and declared `alg` consistent with the
/// token, not marked for encryption; by `kid`, or the single candidate when the token has none.
fn pick(set: &JwkSet, kid: Option<&str>, alg: Algorithm) -> Option<Jwk> {
    let usable = |k: &&Jwk| {
        let family_ok = match &k.algorithm {
            AlgorithmParameters::RSA(_) => matches!(
                alg,
                Algorithm::RS256
                    | Algorithm::RS384
                    | Algorithm::RS512
                    | Algorithm::PS256
                    | Algorithm::PS384
                    | Algorithm::PS512
            ),
            AlgorithmParameters::EllipticCurve(_) => {
                matches!(alg, Algorithm::ES256 | Algorithm::ES384)
            }
            _ => false,
        };
        family_ok
            && k.common
                .key_algorithm
                .is_none_or(|ka| key_alg_matches(ka, alg))
            && !matches!(k.common.public_key_use, Some(PublicKeyUse::Encryption))
    };
    match kid {
        Some(kid) => set
            .keys
            .iter()
            .filter(|k| k.common.key_id.as_deref() == Some(kid))
            .find(usable)
            .cloned(),
        None => {
            let mut c = set.keys.iter().filter(usable);
            match (c.next(), c.next()) {
                (Some(k), None) => Some(k.clone()),
                _ => None,
            }
        }
    }
}

#[cfg(test)]
mod tests;
