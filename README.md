# dsh-ocsf-forwarder

A read-side SIEM forwarder for [DeepSeek Harness](https://github.com/deepseek-ai). It observes the
session event firehose, normalises every event to **OCSF 1.9.0** with the native `ai_operation`
profile, and writes newline-delimited OCSF JSON to a local append-only spool, optionally shipping it
to **Splunk HTTP Event Collector** or an **OTLP/HTTP** collector.

The complete event → OCSF mapping table for all 44 session event types is under
[Event mapping](#event-mapping). `ADR.md` records the decisions that are not obvious from the code.

---

## What it does

- Subscribes to `session/event`, `session/created`, and `session/disposed`, and sweeps
  `ctx.sessions.list()` at mount.
- Correlates `tool/call` ↔ `tool/result` by `callId` and `approval/asked` ↔ `approval/decided` by
  `ApprovalRequestId`, emitting **approval decision latency** — the approval-fatigue signal.
- Classifies tool calls by what they do: `bash`/`pwsh`/`run_code`/`cordis_define`/`cordis_run` →
  Process Activity (1007), `read`/`write`/`edit` → File System Activity (1001),
  `web_fetch`/`web_search` → HTTP Activity (4002), approvals and sandbox/permission changes →
  Authorize Session (3003), everything else → API Activity (6003).
- Names the MCP server behind every `mcp__<server>__<tool>` call, so a SOC can pivot on which
  external server an agent talked to.
- Emits a **high-severity record when a tool hands the task to an external harness**, stating in
  the record that telemetry coverage ends at that boundary. See
  [Delegation](#delegation-and-the-coverage-boundary).
- Emits a periodic **heartbeat** carrying its counters, the live session count and the delivery
  cursor, so a host that goes quiet is distinguishable from one that is idle. See
  [Heartbeat](#heartbeat).
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
dsh plugin --profile <name> add @deepseek-ai/dsh-headless@0.1.0-rc.6
dsh plugin --profile <name> add dsh-ocsf-forwarder
dsh --profile <name> --dump-config      # verify the row is mounted
```

Pin `@deepseek-ai/dsh-headless` explicitly: its npm `latest` tag still points at
`0.0.1-rc.1`, so an unpinned install silently resolves to a much older harness.

**Install from the registry or a packed tarball, not from a git spec.**
`dsh plugin add github:CharlotteN7/dsh-ocsf-forwarder` resolves and writes the
dependency, but `lib/` is a build output that git does not carry and no
`prepare` script rebuilds it, so the row mounts and then fails to load. To
install from a checkout, build first and add the tarball:

```sh
git clone https://github.com/CharlotteN7/dsh-ocsf-forwarder && cd dsh-ocsf-forwarder
pnpm install && pnpm run build && pnpm pack
dsh plugin --profile <name> add ./dsh-ocsf-forwarder-0.1.0.tgz
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

To ship to Splunk instead, replace the `otlp` block with a `splunk` one. Exactly one destination
may be configured: two would share one cursor file and each step it past the other's deliveries,
so naming both fails at load.

```yaml
- id: dsh-ocsf-forwarder
  config:
    spoolPath: /var/log/dsh/session.ocsf.jsonl
    fleet:
      tenantUid: platform-eng
      labels: [prod, eu-west]
      tags:
        owner: soc
    splunk:
      endpoint: https://splunk.internal:8088
      index: dsh_security
      token:
        source: env
        variable: DSH_SPLUNK_HEC_TOKEN
```

## Configuration

| Key | Default | Meaning |
|---|---|---|
| `spoolPath` | required | Absolute path of the SOC-lane spool. Created 0640, with its parent directories. One process at a time owns a path — see [Delivery and failure modes](#delivery-and-failure-modes). |
| `spoolMaxBytes` | `268435456` | Rotate to a new generation at this size. |
| `spoolMaxGenerations` | `16` | Rotated generations that may await the shipper. At this count rotation stops and the live file grows past `spoolMaxBytes` instead. |
| `spoolMaxTotalBytes` | `4294967296` | Second stop condition on rotation: bytes across the live spool and every rotated generation. Not a delete policy — see [Delivery and failure modes](#delivery-and-failure-modes). |
| `spoolHighWaterBytes` | `3221225472` | Total spool bytes at which the heartbeat is raised to `severity_id: 4`. Must not exceed `spoolMaxTotalBytes`, or load fails. |
| `statsIntervalMs` | `300000` | How often the forwarder's counters reach the log **and a heartbeat reaches the spool**. `0` reports and heartbeats only at unload. |
| `restricted.path` | — | Restricted lane: the same records plus the verbatim payload in `raw_data`. Created 0600. |
| `restricted.acknowledged` | `false` | Must be `true` for the restricted lane to open; the plugin fails at load otherwise. |
| `otlp.endpoint` | — | OTLP collector base URL. `/v1/logs` is appended when the URL has no path. Absent disables OTLP shipping. |
| `splunk.endpoint` | — | Splunk HEC base URL, typically `https://<host>:8088` (Splunk Cloud defaults to 443). `/services/collector/event` is appended when the URL has no path. |
| `splunk.token.source` / `.variable` / `.value` | `env` / — / — | Where the HEC token comes from. `env` names an environment variable; `literal` carries the token in configuration. Missing or empty fails at load. |
| `splunk.index` / `host` / `source` / `sourcetypePrefix` | — / this host / `dsh:session` / `ocsf` | HEC event metadata. `index` is omitted so the token's default index applies. `sourcetype` is `<prefix>:<OCSF class name>`. |
| `<shipper>.headers` / `batchSize` / `flushIntervalMs` / `timeoutMs` / `cursorPath` | `{}` / `256` / `5000` / `10000` / `<spoolPath>.cursor` | Delivery settings, on either shipper block. |
| `<shipper>.maxReadBytes` / `maxBackoffMs` / `quarantinePath` | `8388608` / `300000` / `<spoolPath>.quarantine` | Largest spool region read in one pass, the backoff ceiling, and where refused batches are set aside. |
| `fleet.tenantUid` / `labels` / `tags` | — | `metadata.tenant_uid`, `metadata.labels` (string list) and `metadata.tags` (a map, rendered as OCSF `key_value_object` entries). Never inferred. |
| `fleet.installUid` / `installUidPath` | generated / `<spoolPath>.install-uid` | `device.uid`. Minted once and persisted, so a renamed host is still the same device. |
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
    "sequence": 7, "logged_time": 1786823920155, "original_time": "1786881335332",
    "tenant_uid": "platform-eng", "labels": ["prod"], "tags": [{ "name": "owner", "value": "soc" }]
  },
  "cloud": { "provider": "Other" }, "osint": [],
  "ai_agent": { "name": "deepseek-harness", "type_id": 1, "instance_uid": "01JB0SESSION" },
  "actor": { "process": { "pid": 4242, "name": "dsh" }, "user": { "name": "agent", "type_id": 1 } },
  "device": {
    "type_id": 0, "hostname": "app-01.example.test",
    "uid": "0c6f1f1a-9c1e-4f0a-9a63-6a1a6c5f1b2e",
    "os": { "name": "linux", "type_id": 0 }
  },
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

## Event mapping

All 44 session event types this build knows (`packages/core/session/src/known-event-types.ts` in
the harness, catalogued in its `docs/persistence-catalog.md`).
`type_uid = class_uid * 100 + activity_id`.

Tool events are classified by tool name first — see [Tool classification](#tool-classification) —
which is why they list several classes.

| # | Session event | OCSF class (`class_uid`) | `activity_id` | Status / notes |
|---|---|---|---|---|
| 1 | `agent/inbox/spliced` | API Activity (6003) | 3 Update | Counts only; inserted message text digested. |
| 2 | `agent-preset/selected` | Application Lifecycle (6002) | 8 Update | Composition change; preset id. |
| 3 | `approval/asked` | Authorize Session (3003) | 1 Assign Privileges | `status_id: 0` (pending). `privileges: [tool:<name>]`, `unmapped.dsh.approval_id`. The prompt `reason` quotes the command being approved, so it is digested. |
| 4 | `approval/decided` | Authorize Session (3003) | 1 Assign Privileges | `status_id: 1` for `allowed-once`, else `2`. `duration` + `unmapped.dsh.approval_latency_ms` from the paired ask. |
| 5 | `approval/policy` | Authorize Session (3003) | 1 Assign Privileges | Session policy switch (`ask`/`never`). |
| 6 | `assistant/chunk` | — | — | **Dropped.** Token-level stream deltas: highest-volume type in the log and pure content. The assembled `assistant/message` is byte-complete. Re-enable per deployment via `includeEventTypes`. |
| 7 | `assistant/message` | API Activity (6003) | 2 Read | Model completion. `message_context.ai_role_id: 2`, token counts from `usage`. Text digested in the SOC lane. |
| 8 | `command/run` | API Activity (6003) | 1 Create | Slash command; `api.operation = command:<name>`, args digested. Correlates to 9 by `commandId`. |
| 9 | `command/done` | API Activity (6003) | 3 Update | `status_id` from `kind`; `duration` from the paired `command/run`. |
| 10 | `compaction/start` | API Activity (6003) | 3 Update | Holds the compaction lock. |
| 11 | `compaction/end` | API Activity (6003) | 3 Update | `status_id: 2` when `error` present; `duration` from the pair. |
| 12 | `compaction/prune` | API Activity (6003) | 4 Delete | **History removal** — kept deliberately: shadowed seq range and token count are a tamper-relevant signal. The payload carries no `compactionId`, so the record is correlated by the range it replaced. |
| 13 | `compaction/summary` | API Activity (6003) | 3 Update | Model-written replacement for history. Summary text digested in the SOC lane; `ai_model` from the event's own `provider`/`model`. |
| 14 | `feedback/record` | API Activity (6003) | 1 Create | **Metadata only, and dropped by default** (`dropEventTypes`): free-text human remark about the session, no security value, high privacy cost. |
| 15 | `goal/change` | API Activity (6003) | 3 Update | Goal text digested. |
| 16 | `hook/invoked` | Process Activity (1007) | 1 Launch | A hook **is** a subprocess. `process.name` = hook point, `unmapped.dsh.handler_id`, `unmapped.dsh.dialect`. |
| 17 | `hook/result` | Process Activity (1007) | 2 Terminate | `status_id` from `decision`, reduced to the protocol's `approve`/`allow`/`block`/`deny`/`ask` with anything else recorded as `other` plus a digest; `process.exit_code`; `duration` = `durationMs`. |
| 18 | `llm/retry` | API Activity (6003) | 2 Read | `status_id: 2` (the attempt that failed), `status_detail` = failure code. |
| 19 | `llm/retry-started` | API Activity (6003) | 2 Read | `status_id: 0`; the wait completed and the next attempt starts. |
| 20 | `permission/preset` | Authorize Session (3003) | 1 Assign Privileges | `privileges: [preset:<name>]`. |
| 21 | `plan/mode` | API Activity (6003) | 3 Update | Plan mode on/off. |
| 22 | `request/context` | Application Lifecycle (6002) | 8 Update | Provider/model route change. Folds into `ai_model` for every later record in the session. |
| 23 | `request/header` | Application Lifecycle (6002) | 8 Update | **Capability-set change.** Tool *names* and count, model config, and a digest of the system prompt. Never the prompt text or tool schemas in the SOC lane. |
| 24 | `sandbox/mode` | Authorize Session (3003) | 1 Assign Privileges | Confinement change; `privileges: [sandbox:<mode>]`. High value. |
| 25 | `schedule/change` | Scheduled Job Activity (1006) | 1 Create / 2 Update / 3 Delete / 99 Other | From `operation` (`create` / `dispatch` / `delete`); `job: { name, uid }` from `schedule.id` on a create, `id` otherwise. |
| 26 | `session/end-seed` | — | — | **Dropped.** Internal construction marker; its meaning is carried by the seed-replay boundary record. |
| 27 | `session/title` | API Activity (6003) | 3 Update | **Dropped by default**: a model-written summary of the user's prompt — user content by another name. |
| 28 | `session/title-llm-request` | API Activity (6003) | 2 Read | **Dropped by default**: carries prompt text. |
| 29 | `step/start` | API Activity (6003) | 2 Read | Opens one model call plus its tool executions; `status_id: 0`. |
| 30 | `step/end` | API Activity (6003) | 2 Read | `status_id: 1`, `duration` from the paired `step/start`. |
| 31 | `subagent/descriptor` | Application Lifecycle (6002) | 3 Start | This session **is** the child. `mode` and `provider` only: the payload names no session id, so no `delegation` is invented. |
| 32 | `todo/write` | API Activity (6003) | 3 Update | **Dropped by default**: UI state made of user/model task text. Item count only if re-enabled. |
| 33 | `tool/call` | by tool name: 1007 / 1001 / 4002 / 6003 | by tool name | `status_id: 0` (in flight). `metadata.correlation_uid = <session>:<callId>`. |
| 34 | `tool/result` | by tool name (same class as its call) | by tool name | `status_id` from `content[0].isError`; `start_time`/`end_time`/`duration` from the correlated call. |
| 35 | `tool/code-dispatch-start` | by inner tool name | by tool name | Sub-call inside `run_code`; `unmapped.dsh.parent_call_id`. |
| 36 | `tool/code-dispatch` | by inner tool name | by tool name | Sub-call settlement; `status_id` from `isError`. |
| 37 | `tool-workflow/run-start` | Application Lifecycle (6002) | 3 Start | |
| 38 | `tool-workflow/run-end` | Application Lifecycle (6002) | 4 Stop | `status_id` from `stopReason`. |
| 39 | `tool-workflow/agent-start` | Application Lifecycle (6002) | 3 Start | Member agent. The one event that names a child: `delegation = { uid: childId, parent_uid: <this session> }`. |
| 40 | `tool-workflow/agent-end` | Application Lifecycle (6002) | 4 Stop | `status_id` from `outcome`. |
| 41 | `turn/start` | API Activity (6003) | 1 Create | The unit of agent work; `status_id: 0`. |
| 42 | `turn/end` | API Activity (6003) | 1 Create | **`TurnEndReason` is the outcome discriminant**; `duration` from the paired `turn/start`. A provider failure contributes its `code` and a digest of its message. |
| 43 | `user/message` | API Activity (6003) | 1 Create | `message_context.ai_role_id: 1`; `unmapped.dsh.message_source` distinguishes a human prompt from an injected context. Text digested in the SOC lane. |
| 44 | `web/deepseek-search-llm-request` | API Activity (6003) | 2 Read | Auxiliary search request; `ai_operation` with `api.service.name = 'deepseek-search'`. |

Unknown (out-of-repo, plugin-merged) event types fall through to API Activity 6003 / activity
`99 Other` with metadata only. `SessionEventMap` is merge-extensible, so the mapper's `switch` ends
in a documented default, never `assertNever`.

### Tool classification

`tool/call`, `tool/result`, and the two `tool/code-dispatch*` events are classified by tool name:

| Tools | Class | `activity_id` | Extra objects |
|---|---|---|---|
| `bash`, `pwsh`, `run_code`, `terminal_open`, `terminal_send` | Process Activity (1007) | 1 Launch | `process.cmd_line` (per `commandLine` policy), `process.name`, `actor.process` = the harness process |
| `terminal_close`, `terminal_signal`, `job_kill` | Process Activity (1007) | 2 Terminate | |
| `read`, `read_image`, `glob`, `grep` | File System Activity (1001) | 2 Read | `file: { name, path, type_id }` from `file_path`/`path`. A `grep` `pattern` is not a path and never fills one. |
| `write` | File System Activity (1001) | 1 Create | |
| `edit`, `str_replace_editor` | File System Activity (1001) | 3 Update | |
| `web_fetch`, `web_search` | HTTP Activity (4002) | 3 Get | `http_request: { http_method, url }` under the `url` policy; satisfies the class's `at_least_one: [http_request, http_response]` |
| everything else | API Activity (6003) | 2 Read | `api.operation = tool:<name>` |

The table is a `Record<string, ToolClass>` constant plus a documented default. It is **not**
configurable: misclassifying `bash` as an API call on a deployment's say-so would break every
process-based detection downstream. Deployments extend coverage for their own tools through
`toolClasses` (additive only — a config entry may add an unknown tool name, never reclassify a
known one).

## Shipping to a SIEM

The shipper is a byte cursor over the spool plus a **transport**: an encoder and a status
classifier, and nothing else. No transport sees the cursor, the spool or the quarantine file, so
adding a destination cannot change delivery semantics.

### Splunk HTTP Event Collector

Verified against Splunk's documentation on 2026-08-16 (`docs.splunk.com` now redirects to
`help.splunk.com`):

| | |
|---|---|
| Endpoint | `POST {base}/services/collector/event` — "which is where all JSON-formatted event requests must go" |
| Header | `Authorization: Splunk <token>`; the REST reference adds "The format is case-sensitive" |
| Body | Event objects stacked one after the other, one per line. Splunk states that "Both concatenated JSON objects and JSON arrays like this are accepted", so the concatenation here is the documented form rather than the only accepted one |
| `time` | Epoch **seconds** with a fractional millisecond part — UNIX time "in the format `<sec>.<ms>`" |
| `sourcetype` | `ocsf:<OCSF class name>`, for example `ocsf:process_activity` |

Each event carries `time`, `host`, `source`, `sourcetype`, optionally `index`, and the whole OCSF
record under `event`.

**Status handling.** Splunk publishes an error-code table but **no** retryable set, so the reading
below is ours. 2xx is acceptance. 429 ("HEC queue is at capacity") and 503 ("Server is busy",
"queues are full") are backpressure and hold the cursor. 400 is a content refusal and quarantines
the batch. **401 and 403 hold the cursor rather than quarantining**, which departs from the
OpenTelemetry Collector's Splunk exporter: both statuses mean the token is wrong, never that the
batch is bad, and stepping the cursor over records that would deliver fine once a rotated token is
fixed would be an unrecoverable loss of delivery. The signal that this is happening is the
heartbeat's `shipper_cursor` standing still. Note that Splunk also returns "Invalid token" and
"Token disabled" as **400** under its codes 21 and 22, so a 400 is not unambiguously a payload
fault; it is graded as one so that a genuinely malformed batch cannot block every record behind it.

**Splunk configuration.** There is no official Splunk add-on for OCSF and no Splunk-published OCSF
sourcetype convention, so `sourcetype` and field extraction are ours to define.
[`splunk/props.conf`](splunk/props.conf) ships beside this plugin with one stanza per class. There
is deliberately no `transforms.conf`: HEC sets `_time`, `host`, `source` and `sourcetype` from the
event envelope and the payload is JSON, so nothing needs an index-time transform.

**Splunk Cloud.** The hostname needs the HEC prefix — `http-inputs-<host>.splunkcloud.com` on AWS,
`http-inputs.<host>.splunkcloud.com` on GCP and Azure — and the default port is 443, not 8088.

### OTLP/HTTP

Each record becomes one OTLP `logRecord` whose body is the record's JSON, with `ocsf.class_uid` and
`ocsf.type_uid` as attributes so a collector routes without parsing the payload.

## Heartbeat

A periodic Application Lifecycle (6002) record reporting the live session count, the forwarder's
counters, the spool size and the shipper cursor. `statsIntervalMs` sets the cadence; one more is
written at unload with `unmapped.dsh.final: true`.

**OCSF has no heartbeat class.** There is no liveness, health-check, keepalive or checkpoint class
either — enumerating all 87 classes in 1.9.0 and searching name, caption and description for those
words returns nothing. This is therefore **not** a standard mapping: it is 6002 with
`activity_id: 99` (`Other`), `activity_name: "Heartbeat"`, and `unmapped.dsh.kind: "heartbeat"`,
until OCSF ships a slot.

A heartbeat belongs to no session. It carries no `ai_agent.instance_uid` and no
`unmapped.dsh.session_id`; its `metadata.uid` is `<install uid>:heartbeat:<n>` and
`metadata.sequence` is that `n`, so a *missing* heartbeat is detectable and not only a malformed
one. It is deliberately absent from the counters it reports.

| Attribute | Meaning |
|---|---|
| `live_sessions` | Sessions the store held when the heartbeat was taken. |
| `forwarded` / `dropped` / `unreadable` / `failed` | The forwarder's counters. |
| `spool_bytes` / `spool_high_water_bytes` / `spool_pressure` | Disk the spool occupies, the alarm threshold, and whether it has been crossed. |
| `rotation_stopped` | True once a stop condition has held rotation and the live file is growing. |
| `shipper_cursor` / `shipper_quarantined` / `shipper_destination` | Delivery position, refused records, and which destination. Absent with no shipper configured. |
| `uptime_ms` / `final` | How long this forwarder has been mounted, and whether this is its last heartbeat. |

`severity_id` rises to `4` when the spool crosses `spoolHighWaterBytes` or rotation has stopped, so
the SOC learns from the SIEM rather than from a full disk.

**Detecting absence** is well-trodden on the SIEM side and is not shipped here. Elastic's
Elasticsearch-query rule supports an "is below" comparator, which is what absence detection needs;
its separate Threshold rule type is one-directional and cannot express it. Sentinel's idiom is
`summarize max(TimeGenerated) by Computer`. In Splunk the pivot is `device.uid` against the
`ocsf:application_lifecycle` sourcetype.

## Delegation and the coverage boundary

`subagent-claude-code` and `subagent-codex` resolve a real external CLI and spawn it **in the parent
session's workspace**. There is no DSH session for the child, so no session event describes anything
it does: this plugin's coverage ends at the tool call. That is the most important gap in what a SOC
sees, so the call is graded `severity_id: 4`, classed as Process Activity, and says so in
`message`:

```json
{
  "class_uid": 1007, "severity_id": 4,
  "message": "tool call subagent_codex delegates to codex; session telemetry coverage ends at this boundary",
  "process": { "name": "codex" },
  "unmapped": { "dsh": {
    "tool": "subagent_codex", "tool_class": "delegation-external",
    "delegation_provider": "codex", "delegation_boundary": true, "delegation_coverage": "none"
  } }
}
```

The record carries the tool name and the provider name. It does **not** carry the prompt handed to
the other harness — that follows the same redaction policy as any other tool argument.

**The mapping is best-effort, and here is why.** The provider name is fixed per plugin row and is
not in the tool-call payload, so the plugin cannot name the destination harness from the event
alone. At mount it reads the composed `tool-subagent` rows out of `ctx.registry` and pairs each
row's `toolName` with its `provider`. Since `toolName` is a deployment choice, a row may be composed
after this plugin mounts, and a deployment may reach an external harness through a plugin this build
has never heard of, `delegationTools` lets you name one directly:

```yaml
    delegationTools:
      handoff_to_codex: codex
```

A configured entry may **add** a name. It cannot un-name one discovery found: repo-local
configuration is attacker-controlled, and re-pointing a discovered delegation tool at a benign
provider would silence the loudest record this plugin emits.

`spawn` and `fork` subagents are not delegation boundaries. They run in process and are fully
observed.

## Fleet identity

Every record carries the identity a multi-team SOC filters on. None of it is inferred — an invented
tenant is worse than an absent one, so an unconfigured field is omitted.

| Field | Source |
|---|---|
| `metadata.tenant_uid` | `fleet.tenantUid`. |
| `metadata.labels` | `fleet.labels`, a string list. |
| `metadata.tags` | `fleet.tags`, a map. OCSF types this as an array of `key_value_object`, so `{owner: soc}` is emitted as `[{"name":"owner","value":"soc"}]` — `labels` is the slot for bare strings. |
| `device.uid` | `fleet.installUid`, or a uid minted once and persisted at `fleet.installUidPath`. A hostname is not an identity: it changes when a laptop is renamed and collides across a fleet imaged from one template. |
| `metadata.original_time` | The session log's own rendering of the append time, passed through as a string. OCSF wants "a pass-through string in its native format… not normalized" — the normalised value is `time` — and says to omit it for generated events, so the heartbeat carries none. |

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
what was already delivered out of that file. Rotation stops at either of two bounds: `spoolMaxGenerations` un-drained generations, or
`spoolMaxTotalBytes` on disk across the live file and every generation. The live file then grows
past `spoolMaxBytes` and the plugin logs why. That is deliberate — an audit lane that deletes
unacknowledged evidence to stay under a size limit is worse than one that gets loud and large. The
second bound exists because a file count bounds nothing about the disk once the live file is the
one growing. Once a bound has stopped rotation, the two conditions are re-checked at most once a
minute rather than once per record, so an outage costs the agent one directory listing a minute;
rotation resumes within that window of the shipper draining a generation.

Neither bound is a retention policy and neither ever deletes a record. The alarm is
`spoolHighWaterBytes`, which sits below the stop condition and raises the heartbeat to
`severity_id: 4` while there is still room; a high-water mark above the stop condition would never
fire in time, so that combination fails at load.

**One writer per path.** A spool path is held by an exclusive `<spoolPath>.lock`. Two processes
sharing one path would each rename the inode the other is writing into, so the second one fails at
load with the pid that holds it. Give each process its own path — the bundle patch's
`dshHomePath(...)` default already does, per `$DSH_HOME`. A lock left by a process that no longer
exists is taken over.

**Retry and quarantine.** A batch the destination cannot take right now is retried with
exponential backoff from `flushIntervalMs` up to `maxBackoffMs`, and the cursor does not move. A
batch it refuses on content is appended to `quarantinePath` and stepped over, because retrying it
forever would hold every later record behind one the destination will never accept. Each
quarantined batch is reported through the plugin logger, naming the destination that refused it.
Which statuses fall where is the transport's decision: OTLP retries 5xx, timeouts, connection
failures and 408/425/429 and refuses any other 4xx; Splunk's reading is in
[Shipping to a SIEM](#splunk-http-event-collector) and differs on 401 and 403.

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
