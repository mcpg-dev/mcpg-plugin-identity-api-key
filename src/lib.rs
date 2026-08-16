//! `dev.mcpg.identity.api-key` — static-registry API-key
//! `identity_provider` plugin.
//!
//! This crate is the implementation; the
//! operator-facing summary lives in `README.md`.
//!
//! # Layout
//!
//! - [`config`] — operator-supplied JSON shape + validation.
//! - The crate root wires the `IdentityProviderPlugin` (async) +
//!   `SyncIdentityResolver` (sync FFI) trait impls and the
//!   [`declare_plugin!`](mcpg_plugin_sdk::declare_plugin)
//!   invocation. Both impls share a `resolve_with_now` helper so
//!   the matcher logic isn't duplicated; the sync impl is what
//!   the cdylib FFI calls.
//!
//! # Trust model
//!
//! `resolution.trust_level: "verified"` (the default) gives a
//! matched caller the same trust bucket as an OIDC-verified JWT —
//! the constant-time digest compare cryptographically establishes
//! the caller controls the secret. Operators on a legacy
//! "header-asserted" contract (the key isn't a real secret, just
//! a bearer claim) downgrade to `"header_asserted"`; the gateway
//! maps that to `RequestIdentity::HttpHeader` (lower trust
//! bucket).

pub mod config;

use std::sync::Arc;
use std::time::SystemTime;

use async_trait::async_trait;
use mcpg_plugin_protocol::{
    IdentityProviderPlugin, IdentityResolution, PluginClass, PluginIdentity, PluginManifest,
};
use mcpg_plugin_sdk::declare_plugin;
use mcpg_plugin_sdk::ffi::SyncIdentityResolver;
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use tracing::{debug, info_span, warn};

pub use config::{ApiKeyConfig, ConfigError, KeyEntry, ResolutionConfig, TokenSource};

const PLUGIN_ID: &str = "dev.mcpg.identity.api-key";

fn record_resolve_outcome(result: &IdentityResolution, elapsed: std::time::Duration) {
    let outcome = match result {
        IdentityResolution::Resolved { .. } => "resolved",
        IdentityResolution::None => "none",
        IdentityResolution::Invalid { .. } => "invalid",
    };
    metrics::counter!(
        "mcpg_identity_api_key_resolutions_total",
        "outcome" => outcome,
    )
    .increment(1);
    metrics::histogram!("mcpg_identity_api_key_resolve_ms").record(elapsed.as_millis() as f64);
    match result {
        IdentityResolution::Resolved { identity } => debug!(
            subject = identity.subject_id.as_deref().unwrap_or(""),
            elapsed_ms = %elapsed.as_millis(),
            "api-key identity resolved"
        ),
        IdentityResolution::None => debug!(
            elapsed_ms = %elapsed.as_millis(),
            "api-key identity: no token — fall through"
        ),
        IdentityResolution::Invalid { reason, .. } => warn!(
            reason = %reason,
            elapsed_ms = %elapsed.as_millis(),
            "api-key identity: invalid token"
        ),
    }
}

/// Hashed registry entry. Stores the SHA-256 of the operator's
/// secret bytes alongside the metadata that flows into the
/// resolved `PluginIdentity` — the plaintext secret is dropped
/// after registration so the running plugin's memory never carries
/// it. Constant-time-compared against the SHA-256 of inbound
/// candidate tokens.
pub(crate) struct CompiledEntry {
    digest: [u8; 32],
    key_id: String,
    enabled: bool,
    expires_at: Option<OffsetDateTime>,
    roles: Vec<String>,
    groups: Vec<String>,
    scopes: Vec<String>,
    attributes: std::collections::BTreeMap<String, String>,
}

impl CompiledEntry {
    fn from(entry: KeyEntry) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(entry.secret.as_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        Self {
            digest,
            key_id: entry.key_id,
            enabled: entry.enabled,
            expires_at: entry.expires_at,
            roles: entry.roles,
            groups: entry.groups,
            scopes: entry.scopes,
            attributes: entry.attributes,
        }
    }
}

/// The plugin instance. Cheap to clone — heavy state lives behind
/// `Arc`. Both the async `IdentityProviderPlugin` and the sync
/// `SyncIdentityResolver` impls dispatch into the shared inner.
pub struct ApiKeyIdentityPlugin {
    inner: Arc<Inner>,
}

struct Inner {
    manifest: PluginManifest,
    token_sources: Vec<TokenSource>,
    entries: Vec<CompiledEntry>,
    resolution: ResolutionConfig,
}

impl ApiKeyIdentityPlugin {
    /// Factory used by `declare_plugin!`. Panics on bad
    /// config — same security stance as the OIDC sibling. An
    /// identity resolver that silently misconfigures is a security
    /// hole, not a harmless default.
    pub fn from_config_json(config_json: &str) -> Self {
        // Load-time manifest derivation builds + drops an instance only to read
        // its plugin-wide manifest, passing an empty config. Return a
        // manifest-only placeholder (empty registry) for that probe; a REAL
        // config (always non-empty — it carries token_sources + keys) still
        // flows through strict parse + validate below.
        if mcpg_plugin_protocol::is_manifest_probe_config(config_json) {
            return Self::from_validated_config(crate::config::ApiKeyConfig::manifest_probe());
        }
        let cfg = ApiKeyConfig::parse(config_json).unwrap_or_else(|err| {
            tracing::error!(
                plugin_id = PLUGIN_ID,
                error = %err,
                "api-key identity: config parse failed; refusing to register"
            );
            panic!(
                "api-key identity config parse failed: {err}. A misconfigured \
                 identity resolver is a security hole; refusing to load rather \
                 than falling back to defaults. Fix operator config and retry."
            )
        });
        Self::from_validated_config(cfg)
    }

    fn from_validated_config(cfg: ApiKeyConfig) -> Self {
        let entries: Vec<CompiledEntry> = cfg.keys.into_iter().map(CompiledEntry::from).collect();
        tracing::info!(
            plugin_id = PLUGIN_ID,
            keys_loaded = entries.len(),
            sources = cfg.token_sources.len(),
            "api-key identity: registry compiled"
        );
        Self {
            inner: Arc::new(Inner {
                manifest: PluginManifest {
                    id: PLUGIN_ID.into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    name: "Static API-Key Identity Resolver".into(),
                    plugin_class: PluginClass::IdentityProvider,
                    protocol_version: "1.0".into(),
                    // No outbound network — pure offline lookup.
                    license: None,
                    required_capabilities: Vec::new(),
                    tags: Vec::new(),
                    provides: Vec::new(),
                    provides_schemes: Vec::new(),
                    module_path_prefix: ::std::module_path!()
                        .split("::")
                        .next()
                        .unwrap_or("")
                        .to_owned(),
                    backend_profile: None,
                },
                token_sources: cfg.token_sources,
                entries,
                resolution: cfg.resolution,
            }),
        }
    }
}

/// Outcome of the resolver pipeline. Shared between the async +
/// sync trait impls.
fn resolve_with_now(
    inner: &Inner,
    headers: &[(String, String)],
    now: OffsetDateTime,
) -> IdentityResolution {
    let candidate = match find_candidate(&inner.token_sources, headers) {
        Some(c) => c,
        None => return IdentityResolution::None,
    };

    let inbound_digest = sha256(candidate.as_bytes());

    // Constant-time match: walk EVERY entry and accumulate via
    // bitor on Choice. `BTreeMap::get` would early-exit on
    // length / prefix differences and leak timing info.
    let mut matched: Option<&CompiledEntry> = None;
    let mut hits = 0u8;
    for entry in &inner.entries {
        let eq: bool = entry.digest.ct_eq(&inbound_digest).into();
        if eq {
            // First match wins; subsequent identical-digest hits
            // are impossible (deduped at registration), but if
            // they ever fired we'd surface it as a registration
            // bug rather than silently picking the first.
            hits = hits.saturating_add(1);
            if matched.is_none() {
                matched = Some(entry);
            }
        }
    }

    if hits == 0 {
        return IdentityResolution::Invalid {
            reason: "unknown key".into(),
            response_headers: Vec::new(),
        };
    }
    if hits > 1 {
        // Deterministic registration validates uniqueness, so
        // this is a logic bug if we ever see it. Fail closed.
        tracing::error!(
            plugin_id = PLUGIN_ID,
            hits,
            "api-key identity: digest collision in compiled registry — \
             registration validator should have prevented this"
        );
        return IdentityResolution::Invalid {
            reason: "internal error: digest collision".into(),
            response_headers: Vec::new(),
        };
    }
    let entry = matched.expect("hits >= 1 implies matched is Some");

    if !entry.enabled {
        return IdentityResolution::Invalid {
            reason: "key disabled".into(),
            response_headers: Vec::new(),
        };
    }
    if let Some(expires_at) = entry.expires_at
        && expires_at <= now
    {
        return IdentityResolution::Invalid {
            reason: "key expired".into(),
            response_headers: Vec::new(),
        };
    }

    IdentityResolution::Resolved {
        identity: PluginIdentity {
            kind: inner.resolution.trust_level.clone(),
            trust_level: inner.resolution.trust_level.clone(),
            subject_id: Some(entry.key_id.clone()),
            auth_provider: Some(inner.resolution.auth_provider_label.clone()),
            issuer: None,
            roles: entry.roles.clone(),
            groups: entry.groups.clone(),
            scopes: entry.scopes.clone(),
            attributes: entry.attributes.clone(),
        },
    }
}

/// Walk `token_sources` in order, returning the first non-empty
/// candidate. `None` if no source yielded anything — caller
/// surfaces this as `IdentityResolution::None` (chain falls
/// through to the next plugin).
fn find_candidate(sources: &[TokenSource], headers: &[(String, String)]) -> Option<String> {
    for source in sources {
        match source {
            TokenSource::Bearer => {
                if let Some(value) = lookup_header(headers, "authorization")
                    && let Some(rest) = strip_ascii_prefix(value, "Bearer ")
                    && !rest.is_empty()
                {
                    return Some(rest.to_owned());
                }
            }
            TokenSource::Header { header, prefix } => {
                if let Some(value) = lookup_header(headers, header) {
                    let rest = if prefix.is_empty() {
                        Some(value)
                    } else {
                        strip_ascii_prefix(value, prefix)
                    };
                    if let Some(token) = rest
                        && !token.is_empty()
                    {
                        return Some(token.to_owned());
                    }
                }
            }
        }
    }
    None
}

/// Case-insensitive header lookup. The HTTP transport hands us
/// `Vec<(String, String)>` pairs; header names are
/// case-insensitive per RFC 7230 §3.2.
fn lookup_header<'a>(headers: &'a [(String, String)], target: &str) -> Option<&'a str> {
    headers.iter().find_map(|(name, value)| {
        if name.eq_ignore_ascii_case(target) {
            Some(value.as_str())
        } else {
            None
        }
    })
}

/// Strip `prefix` from `s` case-insensitively (ASCII only, which
/// covers every meaningful HTTP scheme prefix). Returns `None` if
/// `s` doesn't start with `prefix`.
fn strip_ascii_prefix<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() < prefix.len() {
        return None;
    }
    let (head, tail) = s.split_at(prefix.len());
    if head.eq_ignore_ascii_case(prefix) {
        Some(tail)
    } else {
        None
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Async trait impl — used when the gateway path-deps this crate
/// directly. The cdylib FFI calls the sync impl below.
#[async_trait]
impl IdentityProviderPlugin for ApiKeyIdentityPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    async fn resolve_identity(
        &self,
        headers: &[(String, String)],
        _metadata: &mcpg_plugin_protocol::types::RequestMetadata,
        _config: &Value,
    ) -> IdentityResolution {
        // Plugin-scoped span so traces from api-key identity attribute
        // back to dev.mcpg.identity.api-key.
        let _span = info_span!("identity_api_key_resolve", plugin_id = PLUGIN_ID).entered();
        let started = std::time::Instant::now();
        let now = OffsetDateTime::from(SystemTime::now());
        let result = resolve_with_now(&self.inner, headers, now);
        record_resolve_outcome(&result, started.elapsed());
        result
    }
}

/// Sync trait impl — what the cdylib FFI macro `declare_plugin!`'s
/// `identity` arm dispatches to.
impl SyncIdentityResolver for ApiKeyIdentityPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    fn resolve_identity(
        &self,
        headers: &[(String, String)],
        _metadata: &mcpg_plugin_protocol::types::RequestMetadata,
        _config: &Value,
    ) -> IdentityResolution {
        let _span = info_span!("identity_api_key_resolve", plugin_id = PLUGIN_ID).entered();
        let started = std::time::Instant::now();
        let now = OffsetDateTime::from(SystemTime::now());
        let result = resolve_with_now(&self.inner, headers, now);
        record_resolve_outcome(&result, started.elapsed());
        result
    }
}

declare_plugin! {

    plugin_id: PLUGIN_ID,
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[],
    entities: [
        identity as id {
            inner_name: "",
            plugin_type: ApiKeyIdentityPlugin,
            // api-key identity is hash-set lookup — no cluster state needed.
            factory: |cfg: &str, _host: ::mcpg_plugin_sdk::HostHandle| -> ApiKeyIdentityPlugin {
                ApiKeyIdentityPlugin::from_config_json(cfg)
            },
        }
    ],
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn good_secret_a() -> &'static str {
        "0123456789abcdef0123456789abcdef"
    }

    fn good_secret_b() -> &'static str {
        "fedcba9876543210fedcba9876543210"
    }

    fn cheap_plugin() -> ApiKeyIdentityPlugin {
        let cfg = ApiKeyConfig {
            token_sources: vec![
                TokenSource::Bearer,
                TokenSource::Header {
                    header: "X-Api-Key".into(),
                    prefix: String::new(),
                },
            ],
            keys: vec![
                KeyEntry {
                    key_id: "key-a".into(),
                    secret: good_secret_a().into(),
                    enabled: true,
                    expires_at: None,
                    roles: vec!["service".into()],
                    groups: vec!["internal".into()],
                    scopes: vec!["read".into()],
                    attributes: {
                        let mut m = std::collections::BTreeMap::new();
                        m.insert("tenant".into(), "acme".into());
                        m
                    },
                },
                KeyEntry {
                    key_id: "key-b-disabled".into(),
                    secret: good_secret_b().into(),
                    enabled: false,
                    expires_at: None,
                    roles: vec![],
                    groups: vec![],
                    scopes: vec![],
                    attributes: Default::default(),
                },
            ],
            resolution: ResolutionConfig::default(),
        };
        ApiKeyIdentityPlugin::from_validated_config(cfg)
    }

    fn now_2026() -> OffsetDateTime {
        datetime!(2026-04-24 12:00 UTC)
    }

    #[test]
    fn manifest_carries_no_required_capabilities() {
        let plugin = cheap_plugin();
        let manifest = SyncIdentityResolver::manifest(&plugin);
        assert_eq!(manifest.id, PLUGIN_ID);
        assert_eq!(manifest.plugin_class, PluginClass::IdentityProvider);
        assert!(manifest.required_capabilities.is_empty());
    }

    #[test]
    fn descriptor_yaml_is_well_formed() {
        assert!(DESCRIPTOR_YAML.contains(&format!("id: {PLUGIN_ID}")));
        assert!(DESCRIPTOR_YAML.contains("class: identity_provider"));
        assert!(DESCRIPTOR_YAML.contains("runtime: native-cdylib-v1"));
        assert!(DESCRIPTOR_YAML.contains("required_capabilities: []"));
    }

    #[test]
    #[should_panic(expected = "config parse failed")]
    fn factory_panics_on_unparseable_config() {
        let _ = ApiKeyIdentityPlugin::from_config_json("not-json");
    }

    #[test]
    fn bearer_match_returns_resolved() {
        let plugin = cheap_plugin();
        let headers = vec![(
            "Authorization".into(),
            format!("Bearer {}", good_secret_a()),
        )];
        let r = resolve_with_now(&plugin.inner, &headers, now_2026());
        match r {
            IdentityResolution::Resolved { identity } => {
                assert_eq!(identity.subject_id.as_deref(), Some("key-a"));
                assert_eq!(identity.trust_level, "verified");
                assert_eq!(identity.kind, "verified");
                assert_eq!(identity.auth_provider.as_deref(), Some("api-key"));
                assert!(identity.issuer.is_none());
                assert_eq!(identity.roles, vec!["service".to_string()]);
                assert_eq!(identity.attributes.get("tenant"), Some(&"acme".to_string()));
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[test]
    fn x_api_key_match_returns_resolved() {
        let plugin = cheap_plugin();
        let headers = vec![("X-Api-Key".into(), good_secret_a().into())];
        let r = resolve_with_now(&plugin.inner, &headers, now_2026());
        match r {
            IdentityResolution::Resolved { identity } => {
                assert_eq!(identity.subject_id.as_deref(), Some("key-a"));
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[test]
    fn bearer_takes_precedence_over_x_api_key_when_both_match() {
        // Both sources yield candidates; first source (bearer)
        // wins. The X-Api-Key source is never
        // consulted, even though the value would also match.
        let plugin = cheap_plugin();
        let headers = vec![
            (
                "Authorization".into(),
                format!("Bearer {}", good_secret_a()),
            ),
            ("X-Api-Key".into(), good_secret_a().into()),
        ];
        let r = resolve_with_now(&plugin.inner, &headers, now_2026());
        assert!(matches!(r, IdentityResolution::Resolved { .. }));
    }

    #[test]
    fn no_credential_returns_none_not_invalid() {
        let plugin = cheap_plugin();
        let headers = vec![];
        let r = resolve_with_now(&plugin.inner, &headers, now_2026());
        assert!(matches!(r, IdentityResolution::None));
    }

    #[test]
    fn empty_token_after_prefix_returns_none() {
        // `Authorization: Bearer ` (trailing space, no token) —
        // candidate is empty. Treated as "no credential", chain
        // falls through.
        let plugin = cheap_plugin();
        let headers = vec![("Authorization".into(), "Bearer ".into())];
        let r = resolve_with_now(&plugin.inner, &headers, now_2026());
        assert!(matches!(r, IdentityResolution::None));
    }

    #[test]
    fn unknown_key_returns_invalid() {
        let plugin = cheap_plugin();
        let headers = vec![(
            "Authorization".into(),
            "Bearer wrong-secret-not-in-registry-yet-long-enough".into(),
        )];
        let r = resolve_with_now(&plugin.inner, &headers, now_2026());
        match r {
            IdentityResolution::Invalid { reason, .. } => assert_eq!(reason, "unknown key"),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn disabled_key_returns_invalid_with_reason() {
        let plugin = cheap_plugin();
        let headers = vec![("X-Api-Key".into(), good_secret_b().into())];
        let r = resolve_with_now(&plugin.inner, &headers, now_2026());
        match r {
            IdentityResolution::Invalid { reason, .. } => assert_eq!(reason, "key disabled"),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn expired_key_returns_invalid_with_reason() {
        // Fresh plugin with one expired entry, fed a now beyond
        // the expiry timestamp.
        let cfg = ApiKeyConfig {
            token_sources: vec![TokenSource::Bearer],
            keys: vec![KeyEntry {
                key_id: "expired".into(),
                secret: good_secret_a().into(),
                enabled: true,
                expires_at: Some(datetime!(2026-01-01 00:00 UTC)),
                roles: vec![],
                groups: vec![],
                scopes: vec![],
                attributes: Default::default(),
            }],
            resolution: ResolutionConfig::default(),
        };
        let plugin = ApiKeyIdentityPlugin::from_validated_config(cfg);
        let headers = vec![(
            "Authorization".into(),
            format!("Bearer {}", good_secret_a()),
        )];
        let r = resolve_with_now(&plugin.inner, &headers, now_2026());
        match r {
            IdentityResolution::Invalid { reason, .. } => assert_eq!(reason, "key expired"),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn future_expires_at_still_resolves() {
        let cfg = ApiKeyConfig {
            token_sources: vec![TokenSource::Bearer],
            keys: vec![KeyEntry {
                key_id: "fresh".into(),
                secret: good_secret_a().into(),
                enabled: true,
                expires_at: Some(datetime!(2027-01-01 00:00 UTC)),
                roles: vec![],
                groups: vec![],
                scopes: vec![],
                attributes: Default::default(),
            }],
            resolution: ResolutionConfig::default(),
        };
        let plugin = ApiKeyIdentityPlugin::from_validated_config(cfg);
        let headers = vec![(
            "Authorization".into(),
            format!("Bearer {}", good_secret_a()),
        )];
        let r = resolve_with_now(&plugin.inner, &headers, now_2026());
        assert!(matches!(r, IdentityResolution::Resolved { .. }));
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        // RFC 7230 §3.2 — header names are case-insensitive.
        let plugin = cheap_plugin();
        let headers = vec![(
            "AUTHORIZATION".into(),
            format!("Bearer {}", good_secret_a()),
        )];
        let r = resolve_with_now(&plugin.inner, &headers, now_2026());
        assert!(matches!(r, IdentityResolution::Resolved { .. }));
    }

    #[test]
    fn bearer_scheme_prefix_match_is_case_insensitive() {
        // RFC 7235 — auth scheme names match case-insensitively.
        let plugin = cheap_plugin();
        let headers = vec![(
            "Authorization".into(),
            format!("bearer {}", good_secret_a()),
        )];
        let r = resolve_with_now(&plugin.inner, &headers, now_2026());
        assert!(matches!(r, IdentityResolution::Resolved { .. }));
    }

    #[test]
    fn near_match_at_byte_31_returns_invalid_not_resolved() {
        // Smoke test for the constant-time matcher: build a key
        // that prefix-matches a real entry but diverges at the
        // last byte. A naive `==` early-exit would still surface
        // Invalid (the digest is different), so this test
        // doesn't *prove* timing-equality — what it proves is
        // that we don't accidentally accept partial matches via
        // a buggy splice / truncation in the matcher path.
        let plugin = cheap_plugin();
        let candidate = {
            let mut s = good_secret_a().to_string();
            // Mutate the last char.
            s.pop();
            s.push('Z');
            s
        };
        let headers = vec![("X-Api-Key".into(), candidate)];
        let r = resolve_with_now(&plugin.inner, &headers, now_2026());
        match r {
            IdentityResolution::Invalid { reason, .. } => assert_eq!(reason, "unknown key"),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn header_with_prefix_strips_correctly() {
        let cfg = ApiKeyConfig {
            token_sources: vec![TokenSource::Header {
                header: "X-Service-Key".into(),
                prefix: "key/".into(),
            }],
            keys: vec![KeyEntry {
                key_id: "k1".into(),
                secret: good_secret_a().into(),
                enabled: true,
                expires_at: None,
                roles: vec![],
                groups: vec![],
                scopes: vec![],
                attributes: Default::default(),
            }],
            resolution: ResolutionConfig::default(),
        };
        let plugin = ApiKeyIdentityPlugin::from_validated_config(cfg);
        let headers = vec![("X-Service-Key".into(), format!("key/{}", good_secret_a()))];
        let r = resolve_with_now(&plugin.inner, &headers, now_2026());
        assert!(matches!(r, IdentityResolution::Resolved { .. }));
    }

    #[test]
    fn header_with_prefix_rejects_unprefixed_value() {
        // Same setup but caller forgets the prefix — source
        // doesn't yield a candidate, which means None (not
        // Invalid). Operators using a non-empty prefix MUST
        // accept that callers without the prefix get
        // "anonymous", not "rejected".
        let cfg = ApiKeyConfig {
            token_sources: vec![TokenSource::Header {
                header: "X-Service-Key".into(),
                prefix: "key/".into(),
            }],
            keys: vec![KeyEntry {
                key_id: "k1".into(),
                secret: good_secret_a().into(),
                enabled: true,
                expires_at: None,
                roles: vec![],
                groups: vec![],
                scopes: vec![],
                attributes: Default::default(),
            }],
            resolution: ResolutionConfig::default(),
        };
        let plugin = ApiKeyIdentityPlugin::from_validated_config(cfg);
        let headers = vec![("X-Service-Key".into(), good_secret_a().into())];
        let r = resolve_with_now(&plugin.inner, &headers, now_2026());
        assert!(matches!(r, IdentityResolution::None));
    }

    #[test]
    fn header_asserted_trust_level_propagates_to_identity() {
        let resolution = ResolutionConfig {
            trust_level: "header_asserted".into(),
            ..ResolutionConfig::default()
        };
        let cfg = ApiKeyConfig {
            token_sources: vec![TokenSource::Bearer],
            keys: vec![KeyEntry {
                key_id: "legacy".into(),
                secret: good_secret_a().into(),
                enabled: true,
                expires_at: None,
                roles: vec![],
                groups: vec![],
                scopes: vec![],
                attributes: Default::default(),
            }],
            resolution,
        };
        let plugin = ApiKeyIdentityPlugin::from_validated_config(cfg);
        let headers = vec![(
            "Authorization".into(),
            format!("Bearer {}", good_secret_a()),
        )];
        let r = resolve_with_now(&plugin.inner, &headers, now_2026());
        match r {
            IdentityResolution::Resolved { identity } => {
                assert_eq!(identity.trust_level, "header_asserted");
                assert_eq!(identity.kind, "header_asserted");
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }
}
