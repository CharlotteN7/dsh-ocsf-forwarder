# dsh-ocsf-forwarder

A read-side SIEM forwarder for [DeepSeek Harness](https://github.com/deepseek-ai). It observes the
session event firehose, normalises every event to **OCSF 1.9.0** with the native `ai_operation`
profile, and writes newline-delimited OCSF JSON to a local append-only spool, optionally shipping it
to an OTLP/HTTP collector.

`PLAN.md` holds the design and the complete event → OCSF mapping table for all 44 session event
types. `ADR.md` records the decisions that are not obvious from the code.

---

## What it does

- Subscribes to `session/event`, `session/created`, and `session/disposed`, and sweeps
  `ctx.sessions.list()` at mount.
- Correlates `tool/call` ↔ `tool/result` by `callId` and `approval/asked` ↔ `approval/decided` by
  `ApprovalRequestId`, emitting **approval decision latency** — the approval-fatigue signal.
- Classifies tool calls by what they do: `bash`/`pwsh`/`run_code` → Process Activity (1007),
  `read`/`write`/`edit` → File System Activity (1001), `web_fetch`/`web_search` → HTTP Activity
  (4002), approvals and sandbox/permission changes → Authorize Session (3003), everything else →
  API Activity (6003).
- Replays a resumed or forked session's constructor seed, which never reaches the live firehose.
- Keeps raw values out of the SOC lane: keyed digests, value classifications, and lengths instead.
  File paths, tool names, executable names, and bounded enumerations are the exceptions, and they
  are listed in [Two lanes](#two-lanes).

## What it does not do

- **It never writes to the session log.** `Session.append()` cannot set the envelope's `ignorable`
  flag, so a plugin-owned event type makes the next resume throw `SessionFormatUnsupportedError`
  and refuse the entire session while `list()` still shows it. All durable output goes to our own
  sink. The plugin registers no waterfall listener either, so it cannot change a tool call, an
  approval decision, or a model request.
- **It is not a containment boundary.** It runs in the agent's process at the agent's uid. An agent
  that can run `bash` can delete or rewrite the spool. What the plugin buys you is that records
  leave the host promptly when a shipper is configured, and that a gap is visible: `metadata.sequence`
  holes per session, and a shipper cursor that stopped advancing.
- It ships no detection content, no alerting, and no secret detectors.

## Install

The profile must already compose a runnable agent. A profile carrying only `@deepseek-ai/dsh-base`
has no runtime: add `@deepseek-ai/dsh-headless` (or another runnable bundle) alongside it, otherwise
the profile boots into a configuration with no agent loop and this plugin observes nothing.

```sh
dsh plugin --profile <name> add @deepseek-ai/dsh-headless
dsh plugin --profile <name> add dsh-ocsf-forwarder
dsh --profile <name> --dump-config      # verify the row is mounted
```

The bundle patch defaults the spool to `dshHomePath('ocsf/session.ocsf.jsonl')`. A profile patch
layer **replaces a row's whole `config`**, so an override must restate every key it wants:

```yaml
- id: dsh-ocsf-forwarder
  config:
    spoolPath: /var/log/dsh/session.ocsf.jsonl
    seedReplay: full
    privacy:
      hmacKey:
        source: env
        variable: DSH_OCSF_HMAC_KEY
    otlp:
      endpoint: https://collector.internal:4318
      headers:
        authorization: 'Bearer ${COLLECTOR_TOKEN}'
```

## Configuration

| Key | Default | Meaning |
|---|---|---|
| `spoolPath` | required | Absolute path of the SOC-lane spool. Created 0640, with its parent directories. One process at a time owns a path — see [Delivery and failure modes](#delivery-and-failure-modes). |
| `spoolMaxBytes` | `268435456` | Rotate to a new generation at this size. |
| `spoolMaxGenerations` | `16` | Rotated generations that may await the shipper. At this count rotation stops and the live file grows past `spoolMaxBytes` instead. |
| `statsIntervalMs` | `300000` | How often the forwarder's counters reach the log. `0` reports only at unload. |
| `restricted.path` | — | Restricted lane: the same records plus the verbatim payload in `raw_data`. Created 0600. |
| `restricted.acknowledged` | `false` | Must be `true` for the restricted lane to open; the plugin fails at load otherwise. |
| `otlp.endpoint` | — | Collector base URL. `/v1/logs` is appended when the URL has no path. Absent disables shipping. |
| `otlp.headers` / `batchSize` / `flushIntervalMs` / `timeoutMs` / `cursorPath` | `{}` / `256` / `5000` / `10000` / `<spoolPath>.cursor` | Shipper settings. |
| `otlp.maxReadBytes` / `maxBackoffMs` / `quarantinePath` | `8388608` / `300000` / `<spoolPath>.quarantine` | Largest spool region read in one pass, the backoff ceiling, and where refused batches are set aside. |
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

## A record

```json
{
  "class_uid": 1007, "category_uid": 1, "type_uid": 100701, "activity_id": 1,
  "severity_id": 1, "status_id": 0, "message": "tool call bash",
  "time": 1786881335332,
  "metadata": {
    "product": { "name": "dsh-ocsf-forwarder", "vendor_name": "dsh-security-plugins", "version": "0.1.0" },
    "version": "1.9.0", "profiles": ["ai_operation", "cloud", "osint"],
    "log_provider": "deepseek-harness", "log_name": "session",
    "uid": "01JB0SESSION:7", "correlation_uid": "01JB0SESSION:call_9f2",
    "sequence": 7, "logged_time": 1786823920155
  },
  "cloud": { "provider": "Other" }, "osint": [],
  "ai_agent": { "name": "deepseek-harness", "type_id": 1, "instance_uid": "01JB0SESSION" },
  "actor": { "process": { "pid": 4242, "name": "dsh" }, "user": { "name": "agent", "type_id": 1 } },
  "device": { "type_id": 0, "hostname": "app-01.example.test", "os": { "name": "linux", "type_id": 0 } },
  "user": { "name": "agent", "type_id": 1 },
  "process": { "name": "curl", "cmd_line": "hmac-sha256:d7df26fddfd3af030679709c66165379" },
  "observables": [{ "name": "process.cmd_line", "type_id": 8, "value": "hmac-sha256:d7df26…" }],
  "unmapped": {
    "dsh": {
      "v": 1, "session_id": "01JB0SESSION", "event_type": "tool/call", "seq": 7,
      "replayed": false, "cwd": "/srv/app", "tool": "bash", "tool_class": "process-launch",
      "arguments": [{ "key": "command", "class": "command", "length": 53, "digest": "hmac-sha256:d7df26…" }],
      "turn": 1, "step": 0, "call_id": "call_9f2", "phase": "invoke"
    }
  }
}
```

The model called `bash` with `curl -s https://api.example.test/v1/x?token=sk-live-1`. The record
says a process was launched, that its executable was `curl`, how long the command was, and gives a
digest that joins it to every other occurrence of the same command — and discloses neither the URL
nor the token.

Every OCSF class is `additionalProperties: false`, so the extension attributes live under
`unmapped`, which is the base event's own slot for exactly this. `cloud` and `osint` are stubs — a
host agent has no cloud deployment and no open-source intelligence — and `metadata.profiles`
declares both, because an attribute whose profile is undeclared fails validation just as an
undefined one does.

## Two lanes

The SOC lane is metadata, classifications, keyed digests, and lengths. The values it does carry
verbatim, because they are the security signal rather than its content, are: file paths; tool
names; executable names, taken after any leading `NAME=VALUE` assignments are stripped; hostnames;
URL scheme and host; and bounded enumerations such as an approval outcome, a turn end reason, a
sandbox mode, a provider error *code*, and a hook decision drawn from the hook protocol's own
`approve`/`allow`/`block`/`deny`/`ask`. Anything a model, a user, a provider, or a hook composed as
free text — prompts, completions, commands, `grep` patterns, approval prompt text, provider failure
messages, hook findings — reaches the SOC lane only as `HMAC-SHA256(key, value)` plus a character
count.

The restricted lane (`restricted.path` plus `restricted.acknowledged: true`, mode 0600) is the same
records with the verbatim event payload in `raw_data`, joined to the SOC lane on `metadata.uid`.

## Correlation

| Field | Joins |
|---|---|
| `metadata.uid` = `<session>:<seq>` | The idempotency key. Deduplicate on it. |
| `metadata.correlation_uid` | `<session>:<callId>` for a tool call and its result, `<session>:approval:<id>` for an approval pair, `<session>:turn:<n>`, `<session>:<turn>:<step>`. |
| `metadata.sequence` | The session-log seq — a per-session gap detector. |
| `ai_agent.instance_uid` / `unmapped.dsh.session_id` | The session. `parent_session_id` and `seed_length` stitch forks. |
| `unmapped.dsh.turn`, `.step`, `.call_id`, `.approval_id` | Agent-loop position and pairing ids. |

Approval latency is on the decision record as `duration` and `unmapped.dsh.approval_latency_ms`.

## Delivery and failure modes

The spool is written synchronously before anything is queued for shipping, so:

- A killed process leaves records on disk and a cursor that stopped advancing — a visible gap, not
  silent loss. A sink that refuses a write leaves the session cursor on the unwritten event, so an
  outage delays records rather than consuming them; the counters in the periodic
  `forwarded=… dropped=… unreadable=… failed=…` log line say which is happening.
- Delivery is **at-least-once**: the cursor advances only after the collector accepts a batch, so a
  crash resends. Deduplicate on `metadata.uid`.
- Capture is **at-most-once**: `session/event` fires post-commit but **pre-durable**, so a record can
  describe an event a later crash loses from the session log; conversely an event appended while the
  plugin was unmounted is not on the live path. `ctx.sessionQuery.readSession(id)` reads a full
  historical log for an offline backfill (it needs the `session-query-sqlite` row mounted).
- With `seedReplay: full` a resumed session re-emits its prior log. That is deliberate: coverage
  beats duplication for an audit lane, and `metadata.uid` makes the duplicates exact.

**Rotation.** At `spoolMaxBytes` the live file is renamed to a fixed-width timestamped generation —
`<spoolPath>.2026-08-16T11-42-22.123Z-000` — and a fresh live file is opened. A generation name is
never reused, so rotation never overwrites one. The shipper drains generations oldest-first, ahead
of the live file, and unlinks each only once the collector has acknowledged every byte in it. The
delivery cursor follows the rename onto the generation it now indexes, so rotation does not resend
what was already delivered out of that file. At
`spoolMaxGenerations` un-drained generations rotation stops: the live file grows past
`spoolMaxBytes` and the plugin logs why. That is deliberate — an audit lane that deletes
unacknowledged evidence to stay under a size limit is worse than one that gets loud and large.

**One writer per path.** A spool path is held by an exclusive `<spoolPath>.lock`. Two processes
sharing one path would each rename the inode the other is writing into, so the second one fails at
load with the pid that holds it. Give each process its own path — the bundle patch's
`dshHomePath(...)` default already does, per `$DSH_HOME`. A lock left by a process that no longer
exists is taken over.

**Retry and quarantine.** A batch the collector cannot take right now — a 5xx, a timeout, a
connection failure, a 408/425/429 — is retried with exponential backoff from `flushIntervalMs` up
to `maxBackoffMs`, and the cursor does not move. A batch it refuses on content — any other 4xx — is
appended to `otlp.quarantinePath` and stepped over, because retrying it forever would hold every
later record behind one the collector will never accept. Each quarantined batch is reported through
the plugin logger.

## Development

```sh
. ../env.sh                # Node ^22.19.0 || >=24, and pnpm
pnpm install
pnpm run typecheck
pnpm run test            # unit tests
pnpm run test:coverage   # unit tests with the coverage gate
pnpm run test:e2e        # builds, then boots a real dsh against a mock model
DSH_EXAMPLE_MODE=lib pnpm run test:e2e   # the installed form, resolved through package exports
```

The E2E harness copies this package **and its runtime dependency closure** into a throwaway
profile's `node_modules`, so the test exercises an installed plugin rather than one leaning on the
harness checkout's own modules. It boots the harness from `../dsh`; set `DSH_REPO` to point
elsewhere, or `DSH_CLI` at an installed `dsh` bin.
