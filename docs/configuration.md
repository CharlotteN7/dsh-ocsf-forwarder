---
title: Configuration
nav_order: 3
---

# Configuration

[← dsh-ocsf-forwarder docs](index.md)

| Key | Default | Meaning |
|---|---|---|
| `spoolPath` | required | Absolute path of the SOC-lane spool. Created 0640, with its parent directories. One process at a time owns a path — see [Delivery and failure modes](operations.md#delivery-and-failure-modes). |
| `spoolMaxBytes` | `268435456` | Rotate to a new generation at this size. |
| `spoolMaxGenerations` | `16` | Rotated generations that may await the shipper. At this count rotation stops and the live file grows past `spoolMaxBytes` instead. |
| `spoolMaxTotalBytes` | `4294967296` | Second stop condition on rotation: bytes across the live spool and every rotated generation. Not a delete policy — see [Delivery and failure modes](operations.md#delivery-and-failure-modes). |
| `spoolHighWaterBytes` | `3221225472` | Total spool bytes at which the heartbeat is raised to `severity_id: 4`. Must not exceed `spoolMaxTotalBytes`, or load fails. |
| `statsIntervalMs` | `300000` | How often the forwarder's counters reach the log **and a heartbeat reaches the spool**. `0` reports and heartbeats only at unload. |
| `restricted.path` | — | Restricted lane: the same records plus the verbatim payload in `raw_data`. Created 0600. |
| `restricted.acknowledged` | `false` | Must be `true` for the restricted lane to open; the plugin fails at load otherwise. |
| `otlp.endpoint` | — | OTLP collector base URL. `/v1/logs` is appended when the URL has no path. Absent disables OTLP shipping. |
| `splunk.endpoint` | — | Splunk HEC base URL, typically `https://<host>:8088` (Splunk Cloud defaults to 443). `/services/collector/event` is appended when the URL has no path. |
| `splunk.token.source` / `.variable` / `.value` | `env` / — / — | Where the HEC token comes from. `env` names an environment variable; `literal` carries the token in configuration. Missing or empty fails at load. |
| `splunk.index` / `host` / `source` / `sourcetypePrefix` | — / this host / `dsh:session` / `ocsf` | HEC event metadata. `index` is omitted so the token's default index applies. `sourcetype` is `<prefix>:<OCSF class name>`. |
| `<shipper>.headers` / `batchSize` / `flushIntervalMs` / `timeoutMs` / `cursorPath` | `{}` / `256` / `5000` / `10000` / `<spoolPath>.cursor` | Delivery settings, on either shipper block. |
| `<shipper>.maxReadBytes` / `maxBackoffMs` / `quarantinePath` | `8388608` / `300000` / `<spoolPath>.quarantine` | Largest spool region read in one pass, the backoff ceiling, and where refused batches are set aside. The quarantine file holds whole OCSF records, so it is forced to 0640 — the SOC lane's own mode. |
| `fleet.tenantUid` / `labels` / `tags` | — | `metadata.tenant_uid`, `metadata.labels` (string list) and `metadata.tags` (a map, rendered as OCSF `key_value_object` entries). Never inferred. |
| `fleet.installUid` / `installUidPath` | generated / `$DSH_HOME/install-uid` | `device.uid`. Minted once and persisted, so a renamed host is still the same device — and so every plugin in this suite reports the same device. |
| `delegationTools` | `{}` | Tool name → provider, for delegation tools registry discovery cannot see. An entry may add a name; it may not un-name a discovered one. |
| `privacy.argumentValues` | `digest` | `omit`, `digest`, or `full` for tool-argument values. |
| `privacy.commandLine` | `digest` | `digest` or `full` for command lines. |
| `privacy.url` | `host` | `host`, `sanitized` (scheme + host + path), or `full`. A path carries a reset or invite token as readily as a query string does, so `sanitized` is a deliberate widening. |
| `privacy.hmacKey.source` | `ephemeral` | `ephemeral` (random per process), `env` (+`variable`), or `literal` (+`value`). Configured keys must be ≥ 32 bytes or load fails. |
| `seedReplay` | `full` | `full`, `boundary` (one marker record), or `none`. |
| `dropEventTypes` / `includeEventTypes` | `[]` | Adjust the drop policy. Dropped by default: `assistant/chunk`, `session/end-seed`, `session/title`, `session/title-llm-request`, `feedback/record`, `todo/write`. |
| `toolClasses` | `{}` | Classify tools the built-in table does not know. It cannot reclassify a known tool. |
| `extension.name` / `extension.placement` | `dsh` / `unmapped` | Key the extension attributes are stored under, and whether they sit under `unmapped` or at the top level. Every OCSF class is `additionalProperties: false`, so `attribute` produces records that fail validation. |
| `extension.uid` | — | OCSF extension uid, as assigned by the OCSF extension registry. `metadata.extensions` is omitted until one is configured: there is no free private range, and every unassigned value collides with somebody's. |
| `vendorName` | `dsh-security-plugins` | `metadata.product.vendor_name`. |

Every numeric key above must be a positive finite number, and the ones that count records or files
— `spoolMaxGenerations`, `<shipper>.batchSize`, `extension.uid` — must be whole numbers.
`statsIntervalMs` is the one exception: its `0` means what the table says. A value outside those
ranges fails at load, because the alternative is worse than a refused mount — `batchSize: 0` makes
the shipper loop without ever advancing its cursor, and a `timeoutMs` of `0` is a request that can
never complete.
