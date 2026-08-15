//! Operator-supplied configuration for the api-key identity plugin.
//!
//! The gateway's secret-resolver
//! expansion happens BEFORE the plugin's `from_config_json` runs, so
//! by the time we see `KeyEntry::secret` it's plaintext bytes — same
//! contract every other plugin in the workspace already relies on.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("api-key config: parse error: {0}")]
    Parse(String),

    #[error("api-key config: invalid: {0}")]
    Invalid(String),
}

/// Top-level config the operator hands the plugin. Required:
/// `token_sources` (≥ 1), `keys` (≥ 1).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiKeyConfig {
    /// Header sources the plugin will inspect, in priority order.
    /// First matching source's value becomes the candidate token;
    /// later sources are skipped for the same request.
    pub token_sources: Vec<TokenSource>,

    /// Static key registry. Each entry's `secret` is plaintext
    /// bytes after the gateway's secret-resolver pre-walk.
    pub keys: Vec<KeyEntry>,

    /// Identity-resolution outcome shape. Optional — defaults to
    /// `trust_level: "verified"` + `auth_provider_label: "api-key"`.
    #[serde(default)]
    pub resolution: ResolutionConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TokenSource {
    /// Standard `Authorization: Bearer <token>`. Header name is
    /// fixed; scheme prefix matches case-insensitively.
    Bearer,
    /// Generic `<header>: <prefix><token>` extraction. `header`
    /// matches case-insensitively; `prefix` is stripped from the
    /// header value's start (default empty — the entire value is
    /// the token).
    Header {
        header: String,
        #[serde(default)]
        prefix: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyEntry {
    /// Stable identifier surfaced as the resolved
    /// `PluginIdentity::subject_id`. Operators see this in audit;
    /// keep it human-readable.
    pub key_id: String,

    /// The secret bytes. After the gateway's secret-resolver
    /// pre-walk, the operator's `${env.VAR}` / `vault://...` /
    /// `file:///...` reference is expanded to plaintext here.
    pub secret: String,

    /// Soft-revoke without removing the entry from the audit
    /// trail. Default `true`. A match against a `enabled: false`
    /// entry returns `Invalid { reason: "key disabled" }`.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Optional RFC3339 expiry. Past-now matches return
    /// `Invalid { reason: "key expired" }`.
    #[serde(
        default,
        skip_serializing,
        deserialize_with = "rfc3339_opt::deserialize"
    )]
    pub expires_at: Option<OffsetDateTime>,

    /// Roles the resolved identity carries. Surfaced via
    /// `PluginIdentity::roles` and downstream RBAC plugins.
    #[serde(default)]
    pub roles: Vec<String>,

    /// Groups the resolved identity carries.
    #[serde(default)]
    pub groups: Vec<String>,

    /// Scopes the resolved identity carries.
    #[serde(default)]
    pub scopes: Vec<String>,

    /// Free-form attributes attached to the resolved identity.
    #[serde(default)]
    pub attributes: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionConfig {
    /// `"verified"` (default) — gateway maps to
    /// `RequestIdentity::Verified`. The constant-time digest
    /// compare cryptographically establishes the caller controls
    /// the secret, so `"verified"` is the right shape for almost
    /// every deployment. `"header_asserted"` downgrades to
    /// `RequestIdentity::HttpHeader` for legacy contracts.
    #[serde(default = "default_trust_level")]
    pub trust_level: String,

    /// Stamp surfaced via `PluginIdentity::auth_provider`. Operators
    /// running multiple api-key plugin instances (e.g. one for
    /// partners, one for internal services) give each a distinct
    /// label so audit can tell them apart.
    #[serde(default = "default_auth_provider_label")]
    pub auth_provider_label: String,
}

impl Default for ResolutionConfig {
    fn default() -> Self {
        Self {
            trust_level: default_trust_level(),
            auth_provider_label: default_auth_provider_label(),
        }
    }
}

fn default_enabled() -> bool {
    true
}

fn default_trust_level() -> String {
    "verified".into()
}

fn default_auth_provider_label() -> String {
    "api-key".into()
}

/// Minimum entropy threshold for a registry key. 16 bytes ≈ 128
/// bits at base16 / base64; below that an operator likely pasted a
/// placeholder by accident. The plugin rejects shorter keys at
/// parse time with a precise `key_id` reference so the misconfig
/// surfaces loudly rather than silently accepting weak credentials.
const MIN_KEY_BYTES: usize = 16;

impl ApiKeyConfig {
    /// Minimal valid config for the host's load-time manifest-derivation probe
    /// (empty key registry, one bearer source). Resolves no caller; it exists
    /// only so the plugin can build + report its plugin-wide manifest without a
    /// real operator config.
    pub fn manifest_probe() -> Self {
        Self {
            token_sources: vec![TokenSource::Bearer],
            keys: Vec::new(),
            resolution: ResolutionConfig::default(),
        }
    }

    pub fn parse(config_json: &str) -> Result<Self, ConfigError> {
        let cfg: Self =
            serde_json::from_str(config_json).map_err(|e| ConfigError::Parse(e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.token_sources.is_empty() {
            return Err(ConfigError::Invalid(
                "`token_sources` must not be empty — at least one Bearer or Header source is required".into(),
            ));
        }
        for (idx, source) in self.token_sources.iter().enumerate() {
            if let TokenSource::Header { header, .. } = source
                && header.trim().is_empty()
            {
                return Err(ConfigError::Invalid(format!(
                    "`token_sources[{idx}].header` must not be empty"
                )));
            }
        }

        if self.keys.is_empty() {
            return Err(ConfigError::Invalid(
                "`keys` must not be empty — at least one registry entry is required".into(),
            ));
        }
        let mut seen_ids = std::collections::HashSet::new();
        for entry in &self.keys {
            if entry.key_id.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "every `keys[*].key_id` must be non-empty".into(),
                ));
            }
            if !seen_ids.insert(entry.key_id.as_str()) {
                return Err(ConfigError::Invalid(format!(
                    "`keys[*].key_id` must be unique — duplicate `{}`",
                    entry.key_id
                )));
            }
            if entry.secret.is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "`keys[*].secret` for key_id `{}` must not be empty — \
                     check the secret-resolver expansion (env / vault / file binding)",
                    entry.key_id
                )));
            }
            if entry.secret.len() < MIN_KEY_BYTES {
                return Err(ConfigError::Invalid(format!(
                    "`keys[*].secret` for key_id `{}` is shorter than {} bytes — \
                     regenerate at sufficient entropy (e.g. `openssl rand -hex 32`)",
                    entry.key_id, MIN_KEY_BYTES
                )));
            }
        }

        let trust = &self.resolution.trust_level;
        if trust != "verified" && trust != "header_asserted" {
            return Err(ConfigError::Invalid(format!(
                "`resolution.trust_level` must be `verified` or `header_asserted` — got `{trust}`"
            )));
        }
        if self.resolution.auth_provider_label.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "`resolution.auth_provider_label` must not be empty".into(),
            ));
        }
        Ok(())
    }
}

/// Deserialize-only serde adapter for `Option<OffsetDateTime>`
/// parsed as RFC3339. We never serialize the config back out
/// (operators write it; the plugin reads it once), so the
/// formatting half is unused — keeping `time`'s `formatting`
/// feature off keeps the dep minimal.
mod rfc3339_opt {
    use serde::{Deserialize, Deserializer};
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<OffsetDateTime>, D::Error> {
        let opt: Option<String> = Option::deserialize(d)?;
        opt.map(|s| OffsetDateTime::parse(&s, &Rfc3339).map_err(serde::de::Error::custom))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_secret() -> &'static str {
        // 32 hex chars = 16 bytes — exactly at the floor.
        "0123456789abcdef0123456789abcdef"
    }

    fn minimal_blob() -> String {
        format!(
            r#"{{
                "token_sources": [{{"kind": "bearer"}}],
                "keys": [{{"key_id": "k1", "secret": "{}"}}]
            }}"#,
            good_secret()
        )
    }

    #[test]
    fn minimal_config_parses() {
        let cfg = ApiKeyConfig::parse(&minimal_blob()).unwrap();
        assert_eq!(cfg.token_sources.len(), 1);
        assert!(matches!(cfg.token_sources[0], TokenSource::Bearer));
        assert_eq!(cfg.keys.len(), 1);
        assert_eq!(cfg.keys[0].key_id, "k1");
        assert!(cfg.keys[0].enabled);
        assert!(cfg.keys[0].expires_at.is_none());
        assert_eq!(cfg.resolution.trust_level, "verified");
        assert_eq!(cfg.resolution.auth_provider_label, "api-key");
    }

    #[test]
    fn header_source_parses() {
        let blob = format!(
            r#"{{
                "token_sources": [
                    {{"kind": "header", "header": "X-Api-Key"}},
                    {{"kind": "header", "header": "X-Service-Key", "prefix": "key/"}}
                ],
                "keys": [{{"key_id": "k1", "secret": "{}"}}]
            }}"#,
            good_secret()
        );
        let cfg = ApiKeyConfig::parse(&blob).unwrap();
        assert_eq!(cfg.token_sources.len(), 2);
        match &cfg.token_sources[1] {
            TokenSource::Header { header, prefix } => {
                assert_eq!(header, "X-Service-Key");
                assert_eq!(prefix, "key/");
            }
            _ => panic!("expected header source"),
        }
    }

    #[test]
    fn empty_token_sources_rejected() {
        let blob = format!(
            r#"{{"token_sources": [], "keys": [{{"key_id": "k1", "secret": "{}"}}]}}"#,
            good_secret()
        );
        let err = ApiKeyConfig::parse(&blob).unwrap_err();
        assert!(err.to_string().contains("token_sources"));
    }

    #[test]
    fn empty_keys_rejected() {
        let blob = r#"{"token_sources": [{"kind": "bearer"}], "keys": []}"#;
        let err = ApiKeyConfig::parse(blob).unwrap_err();
        assert!(err.to_string().contains("keys"));
    }

    #[test]
    fn empty_header_name_rejected() {
        let blob = format!(
            r#"{{
                "token_sources": [{{"kind": "header", "header": "  "}}],
                "keys": [{{"key_id": "k1", "secret": "{}"}}]
            }}"#,
            good_secret()
        );
        let err = ApiKeyConfig::parse(&blob).unwrap_err();
        assert!(err.to_string().contains("header"));
    }

    #[test]
    fn duplicate_key_id_rejected() {
        let blob = format!(
            r#"{{
                "token_sources": [{{"kind": "bearer"}}],
                "keys": [
                    {{"key_id": "k1", "secret": "{0}"}},
                    {{"key_id": "k1", "secret": "{0}"}}
                ]
            }}"#,
            good_secret()
        );
        let err = ApiKeyConfig::parse(&blob).unwrap_err();
        assert!(err.to_string().contains("k1"));
        assert!(err.to_string().contains("unique"));
    }

    #[test]
    fn empty_secret_rejected() {
        let blob = r#"{
            "token_sources": [{"kind": "bearer"}],
            "keys": [{"key_id": "k1", "secret": ""}]
        }"#;
        let err = ApiKeyConfig::parse(blob).unwrap_err();
        assert!(err.to_string().contains("secret"));
    }

    #[test]
    fn short_secret_rejected() {
        // 15 chars (15 bytes) — one below the 16-byte floor.
        let blob = r#"{
            "token_sources": [{"kind": "bearer"}],
            "keys": [{"key_id": "k1", "secret": "abcdefghijklmno"}]
        }"#;
        let err = ApiKeyConfig::parse(blob).unwrap_err();
        assert!(err.to_string().contains("16 bytes"));
    }

    #[test]
    fn invalid_trust_level_rejected() {
        let blob = format!(
            r#"{{
                "token_sources": [{{"kind": "bearer"}}],
                "keys": [{{"key_id": "k1", "secret": "{}"}}],
                "resolution": {{"trust_level": "anonymous", "auth_provider_label": "x"}}
            }}"#,
            good_secret()
        );
        let err = ApiKeyConfig::parse(&blob).unwrap_err();
        assert!(err.to_string().contains("trust_level"));
        assert!(err.to_string().contains("anonymous"));
    }

    #[test]
    fn header_asserted_trust_accepted() {
        let blob = format!(
            r#"{{
                "token_sources": [{{"kind": "bearer"}}],
                "keys": [{{"key_id": "k1", "secret": "{}"}}],
                "resolution": {{"trust_level": "header_asserted", "auth_provider_label": "legacy"}}
            }}"#,
            good_secret()
        );
        let cfg = ApiKeyConfig::parse(&blob).unwrap();
        assert_eq!(cfg.resolution.trust_level, "header_asserted");
        assert_eq!(cfg.resolution.auth_provider_label, "legacy");
    }

    #[test]
    fn unknown_field_rejected() {
        let blob = format!(
            r#"{{
                "token_sources": [{{"kind": "bearer"}}],
                "keys": [{{"key_id": "k1", "secret": "{}"}}],
                "bogus": 1
            }}"#,
            good_secret()
        );
        let err = ApiKeyConfig::parse(&blob).unwrap_err();
        assert!(err.to_string().contains("bogus"));
    }

    #[test]
    fn expires_at_rfc3339_parses() {
        let blob = format!(
            r#"{{
                "token_sources": [{{"kind": "bearer"}}],
                "keys": [{{"key_id": "k1", "secret": "{}", "expires_at": "2026-12-31T00:00:00Z"}}]
            }}"#,
            good_secret()
        );
        let cfg = ApiKeyConfig::parse(&blob).unwrap();
        assert!(cfg.keys[0].expires_at.is_some());
    }

    #[test]
    fn malformed_expires_at_rejected() {
        let blob = format!(
            r#"{{
                "token_sources": [{{"kind": "bearer"}}],
                "keys": [{{"key_id": "k1", "secret": "{}", "expires_at": "not-a-date"}}]
            }}"#,
            good_secret()
        );
        let err = ApiKeyConfig::parse(&blob).unwrap_err();
        // Serde error wraps the time-crate parse error.
        assert!(err.to_string().contains("parse") || err.to_string().contains("expires_at"));
    }

    #[test]
    fn metadata_round_trips() {
        let blob = format!(
            r#"{{
                "token_sources": [{{"kind": "bearer"}}],
                "keys": [{{
                    "key_id": "service-orders",
                    "secret": "{}",
                    "roles": ["service", "orders.read"],
                    "groups": ["internal"],
                    "scopes": ["orders.read"],
                    "attributes": {{"tenant_id": "acme"}}
                }}]
            }}"#,
            good_secret()
        );
        let cfg = ApiKeyConfig::parse(&blob).unwrap();
        let entry = &cfg.keys[0];
        assert_eq!(
            entry.roles,
            vec!["service".to_string(), "orders.read".to_string()]
        );
        assert_eq!(entry.groups, vec!["internal".to_string()]);
        assert_eq!(entry.scopes, vec!["orders.read".to_string()]);
        assert_eq!(entry.attributes.get("tenant_id"), Some(&"acme".to_string()));
    }
}
