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

```sh
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
| `spoolPath` | required | Absolute path of the SOC-lane spool. Created 0640, with its parent directories. |
| `spoolMaxBytes` | `268435456` | Rotate to `<spoolPath>.1` at this size. |
| `restricted.path` | — | Restricted lane: the same records plus the verbatim payload in `raw_data`. Created 0600. |
| `restricted.acknowledged` | `false` | Must be `true` for the restricted lane to open; the plugin fails at load otherwise. |
| `otlp.endpoint` | — | Collector base URL. `/v1/logs` is appended when the URL has no path. Absent disables shipping. |
| `otlp.headers` / `batchSize` / `flushIntervalMs` / `timeoutMs` / `cursorPath` | `{}` / `256` / `5000` / `10000` / `<spoolPath>.cursor` | Shipper settings. |
| `privacy.argumentValues` | `digest` | `omit`, `digest`, or `full` for tool-argument values. |
| `privacy.commandLine` | `digest` | `digest` or `full` for command lines. |
| `privacy.url` | `sanitized` | `host`, `sanitized` (scheme + host + path), or `full`. |
| `privacy.hmacKey.source` | `ephemeral` | `ephemeral` (random per process), `env` (+`variable`), or `literal` (+`value`). Configured keys must be ≥ 32 bytes or load fails. |
| `seedReplay` | `full` | `full`, `boundary` (one marker record), or `none`. |
| `dropEventTypes` / `includeEventTypes` | `[]` | Adjust the drop policy. Dropped by default: `assistant/chunk`, `session/end-seed`, `session/title`, `session/title-llm-request`, `feedback/record`, `todo/write`. |
| `toolClasses` | `{}` | Classify tools the built-in table does not know. It cannot reclassify a known tool. |
| `extension.name` / `extension.uid` / `extension.placement` | `dsh` / `999` / `attribute` | Extension identity, and whether its attributes sit at the top level or under `unmapped`. |
| `vendorName` | `deepseek-harness-security-plugins` | `metadata.product.vendor_name`. |

## A record

```json
{
  "class_uid": 1007, "category_uid": 1, "type_uid": 100701, "activity_id": 1,
  "severity_id": 1, "status_id": 0, "message": "tool call bash",
  "time": 1786881335332,
  "metadata": {
    "product": { "name": "dsh-ocsf-forwarder", "vendor_name": "…", "version": "0.1.0" },
    "version": "1.9.0", "profiles": ["ai_operation"],
    "extension": { "name": "dsh", "uid": 999, "version": "0.1.0" },
    "log_provider": "deepseek-harness", "log_name": "session",
    "uid": "01JB0SESSION:7", "correlation_uid": "01JB0SESSION:call_9f2",
    "sequence": 7, "logged_time": 1786823920155
  },
  "cloud": { "provider": "Other" }, "osint": [],
  "ai_agent": { "name": "deepseek-harness", "type_id": 1, "instance_uid": "01JB0SESSION" },
  "actor": { "process": { "pid": 2685893, "name": "dsh" }, "user": { "name": "horo", "type_id": 1 } },
  "device": { "type_id": 0, "hostname": "app-01.example.test", "os": { "name": "linux", "type_id": 0 } },
  "process": { "name": "curl", "cmd_line": "hmac-sha256:d7df26fddfd3af030679709c66165379" },
  "observables": [{ "name": "process.cmd_line", "type_id": 8, "value": "hmac-sha256:d7df26…" }],
  "dsh": {
    "v": 1, "session_id": "01JB0SESSION", "event_type": "tool/call", "seq": 7,
    "replayed": false, "cwd": "/srv/app", "tool": "bash", "tool_class": "process-launch",
    "arguments": [{ "key": "command", "class": "command", "length": 53, "digest": "hmac-sha256:d7df26…" }],
    "turn": 1, "step": 0, "call_id": "call_9f2", "phase": "invoke"
  }
}
```

The model called `bash` with `curl -s https://api.example.test/v1/x?token=sk-live-1`. The record
says a process was launched, that its executable was `curl`, how long the command was, and gives a
digest that joins it to every other occurrence of the same command — and discloses neither the URL
nor the token.

`cloud` and `osint` are required by these OCSF classes and meaningless for a host agent; they are
emitted as stubs so records validate rather than failing ingestion.

## Correlation

| Field | Joins |
|---|---|
| `metadata.uid` = `<session>:<seq>` | The idempotency key. Deduplicate on it. |
| `metadata.correlation_uid` | `<session>:<callId>` for a tool call and its result, `<session>:approval:<id>` for an approval pair, `<session>:turn:<n>`, `<session>:<turn>:<step>`. |
| `metadata.sequence` | The session-log seq — a per-session gap detector. |
| `ai_agent.instance_uid` / `dsh.session_id` | The session. `dsh.parent_session_id` and `dsh.seed_length` stitch forks. |
| `dsh.turn`, `dsh.step`, `dsh.call_id`, `dsh.approval_id` | Agent-loop position and pairing ids. |

Approval latency is on the decision record as `duration` and `dsh.approval_latency_ms`.

## Delivery and failure modes

The spool is written synchronously before anything is queued for shipping, so:

- A killed process leaves records on disk and a cursor that stopped advancing — a visible gap, not
  silent loss.
- Delivery is **at-least-once**: the cursor advances only after the collector accepts a batch, so a
  crash resends. Deduplicate on `metadata.uid`.
- Capture is **at-most-once**: `session/event` fires post-commit but **pre-durable**, so a record can
  describe an event a later crash loses from the session log; conversely an event appended while the
  plugin was unmounted is not on the live path. `ctx.sessionQuery.readSession(id)` reads a full
  historical log for an offline backfill (it needs the `session-query-sqlite` row mounted).
- With `seedReplay: full` a resumed session re-emits its prior log. That is deliberate: coverage
  beats duplication for an audit lane, and `metadata.uid` makes the duplicates exact.

## Development

```sh
. /path/to/workspace/env.sh
pnpm install
pnpm run typecheck
pnpm run test            # unit tests
pnpm run test:coverage   # unit tests with the coverage gate
pnpm run test:e2e        # builds, then boots a real dsh against a mock model
DSH_EXAMPLE_MODE=lib pnpm run test:e2e   # the installed form, resolved through package exports
```

The E2E harness copies this package **and its runtime dependency closure** into a throwaway
profile's `node_modules`, so the test exercises an installed plugin rather than one leaning on the
harness checkout's own modules.
