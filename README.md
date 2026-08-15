# API Key Identity Resolver — `dev.mcpg.identity.api-key`

> class `identity_provider` · `native` · package `mcpg-plugin-identity-api-key` · artifact `libmcpg_plugin_identity_api_key.so`

Static-registry API-key identity provider. Resolves caller identity
from `Authorization: Bearer <key>` (or any operator-named header) by
constant-time SHA-256 digest match against an operator-supplied registry. Reach
for it for service-to-service auth with no external dependency — pure offline,
no outbound network.

## What it does
- Walks `token_sources` in order; first non-empty candidate wins. No candidate →
  `None` (the identity chain falls through to the next provider).
- SHA-256s the candidate and constant-time-compares against every registry
  digest (full-table walk blocks timing side-channels).
- No match → `Invalid { unknown key }`; matched-but-`enabled: false` →
  `Invalid { key disabled }`; matched-but-past-`expires_at` →
  `Invalid { key expired }`; else `Resolved` with the entry's metadata.
- `subject_id` is the matched `key_id`; trust level configurable
  (`verified` default, or `header_asserted`).
- Boot-time validation rejects sub-16-byte secrets and duplicate `key_id`s.
  No required capabilities.

## Configuration
Part of the identity chain, loaded via the top-level `plugins:` list (chain runs
in load order; `Resolved` wins, `None` falls through, `Invalid` continues):

```yaml
plugins:
  - id: dev.mcpg.identity.api-key
    class: identity_provider
    source: { path: ./plugins/libmcpg_plugin_identity_api_key.so }
    config:
      token_sources:
        - { kind: bearer }                 # Authorization: Bearer <token>
        - { kind: header, header: X-Api-Key, prefix: "" }
      keys:
        - key_id: service-orders           # surfaced as subject_id
          secret: "${env.MCPG_APIKEY_ORDERS}"   # >= 16 bytes after resolution
          roles: ["service", "orders.read"]
          groups: ["internal-services"]
          scopes: ["orders.read", "orders.write"]
          attributes: { tenant_id: acme }
        - key_id: partner-acme
          secret: "vault://secret/data/api-keys#acme"
          enabled: true                    # false soft-revokes
          expires_at: "2026-12-31T00:00:00Z"
          roles: ["partner"]
      resolution:
        trust_level: verified              # "verified" | "header_asserted"
        auth_provider_label: api-key
```

| Field | Type | Default | Description |
|---|---|---|---|
| `token_sources` | source[] | — | Ordered candidate sources. `bearer`, or `header { header, prefix? }`. |
| `keys` | key[] | — | Static key registry (below). |
| `resolution.trust_level` | string | `"verified"` | Trust level on resolved identity (`verified` / `header_asserted`). |
| `resolution.auth_provider_label` | string | `"api-key"` | `auth_provider` on the resolved identity. |

Per key (`keys[]`):

| Field | Type | Default | Description |
|---|---|---|---|
| `key_id` | string | — | Unique id; becomes `subject_id`. |
| `secret` | string | — | Key plaintext (via secret-resolver); ≥ 16 bytes. |
| `enabled` | bool | `true` | `false` soft-revokes the key. |
| `expires_at` | string? | `null` | RFC3339; past → `Invalid`. |
| `roles` / `groups` / `scopes` | string[] | `[]` | Stamped onto the resolved identity. |
| `attributes` | map | `{}` | Stamped onto the resolved identity. |

Reference secrets via `${env.VAR}` / `vault://...` / `file:///...` — never paste
plaintext. Bad config (unparseable, short secret, duplicate id) fails the plugin
to load.

## Build
```bash
cargo build -p mcpg-plugin-identity-api-key --features cdylib-export --release   # → target/release/libmcpg_plugin_identity_api_key.so
```

## Sign & load (production)
Sign the artifact, pin/verify via the entry's `signature:` block, and honour
revocations. See <https://mcpg.dev/docs/security/plugin-security>.

## See also
- Plugin system overview: `apps/gateway/docs/plugins.md`
- Full config reference: `apps/gateway/config.example.yaml`
