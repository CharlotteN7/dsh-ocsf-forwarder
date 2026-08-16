# dsh-ocsf-forwarder — execution plan

A read-side DeepSeek Harness plugin that normalises session activity to OCSF and ships it to a SIEM.

Verified against harness `0.1.0-rc.6` (checkout `../dsh`) and
**OCSF schema 1.9.0**, released 2026-08-03 (`https://schema.ocsf.io/api/versions` reports `1.9.0` as the
current default; `1.10.0-dev` is in flight). Every class UID, activity enum, and object name below was read
from `https://schema.ocsf.io/api/1.9.0/...` rather than from memory.

---

## 1. Scope

**In scope**

- Subscribe to the harness `session/event` firehose and to `session/created`, plus a mount-time sweep of
  `ctx.sessions.list()`.
- Normalise every session event this build can produce (44 types, `dsh/docs/persistence-catalog.md`) into
  OCSF 1.9.0 records that carry the `ai_operation` profile.
- Correlate `tool/call` ↔ `tool/result` by `callId`, and `approval/asked` ↔ `approval/decided` by
  `ApprovalRequestId`, emitting the approval decision latency.
- Write newline-delimited OCSF JSON to a local append-only spool, and ship spooled records over OTLP/HTTP
  (logs) with a durable byte cursor.
- Two output lanes: a metadata/digest SOC lane and an optional restricted lane that may carry raw bodies.

**Non-goals**

- **Never appending to the session log.** `Session.append()` has no way to set the envelope's `ignorable`
  flag (the envelope is built literally as `{ type, seq, time, data, ...surfaceMetadata }`), so a
  plugin-owned event type makes the next resume throw `SessionFormatUnsupportedError` and refuse the whole
  session while `list()` still shows it. Out-of-band `sessionPersistence.append()` drops the live session's
  next event, and mutating `KNOWN_SESSION_EVENT_TYPES` is in-process only. This plugin is strictly
  read-side; all durable output goes to our own sink.
- Not a containment boundary. The plugin runs in the agent's own process at the agent's own uid. An agent
  that can run `bash` can delete the spool. The plugin raises the cost of covering tracks (records leave
  the host promptly when a shipper is configured); it does not prevent it.
- No detection content. No rules, no alerting, no severity policy beyond the mechanical mapping in §5.
- No secret detection. Redaction of *matched secrets* is `dsh-dlp`'s job; this plugin's privacy stance is
  categorical (§9), not detector-driven.
- No modification of any tool call, approval decision, model request, or session surface. The plugin
  registers zero waterfall listeners.

---

## 2. Sink decision: `session/event`, not a telemetry backend

`ctx.sessionTelemetry` is a single-implementation Cordis `Service`. `Service`'s constructor calls
`ctx.reflect.provide(name, ...)`, which throws `service "sessionTelemetry" has been registered at <fiber>`
on a duplicate (`dsh/vendor/cordis/src/reflect.ts:290`). The base bundle already mounts one
(`dsh/packages/bundle/base/cordis.patch.yml:148`, id `session-telemetry-otel`, `mode` defaulting to
`DISABLED`). So there are exactly three ways in, and they are mutually exclusive in the way the brief says:

| Option | What it means | Verdict |
|---|---|---|
| **A. Replace `session-telemetry-otel`** | Our bundle patch disables that row by id and registers `sessionTelemetry` ourselves, reusing `SessionTelemetryCoordinator` for capture. | **Rejected.** It silently removes a deployment's existing OTel export — a security plugin that deletes someone else's telemetry pipeline as a side effect of installation is not acceptable. It also couples us to the coordinator's fixed projection (first-chunk-only, its own severity map) and to a service whose absence is invisible to us. |
| **B. `session-telemetry/record` waterfall listener** | Attach beside the existing backend and transform records on their way out. | **Rejected as the primary path, kept as an optional mode.** Two disqualifiers: (1) the coordinator that dispatches this waterfall is constructed *by the backend plugin* (`dsh/packages/session/session-telemetry-otel/src/index.ts:239`), and only in `FULL`/`FEEDBACK_ONLY` mode — with the shipped default `DISABLED` we would receive nothing at all, silently. (2) The waterfall is dispatched synchronously on the capture hot path with **no** try/catch in Cordis's waterfall, so a throwing listener withholds that record permanently. A SIEM forwarder must not be able to delete the deployment's telemetry by failing. |
| **C. `session/event` observer** ✅ | `ctx.on('session/event', ...)` at the plugin's own (untagged, therefore unfiltered) context. | **Chosen.** It works with no telemetry service mounted at all; it is `@mode emit`, so listener failures are contained per listener (`try`/`catch` plus a `.catch` on any returned promise, `dsh/packages/core/session/src/index.ts:382-399`) and are logged, not propagated; it sees the event envelope verbatim (`seq`, `time`, `type`, `data`) rather than the coordinator's projection; and it cannot affect the agent loop's outcome. |

Option B stays on the roadmap (§11) as an opt-in `telemetryTap` mode for deployments already running the
OTel backend that want the OCSF lane fed from the same redacted capture stream. It is deliberately not in
this prototype: when it lands, the listener body must be wrapped in a total `try`/`catch` and *always*
return `next()`, so it can neither throw nor short-circuit.

Consequences we accept from option C:

- `session/event` fires **post-commit but pre-durable**. A record may reach our spool for an event that a
  later crash loses from the session log. We treat the harness log as the reference and note the skew in
  `README.md`; the alternative (`session/flush`, `@mode parallel`, awaited) would put us on the durability
  path, which is worse.
- The listener must never block: dispatch is synchronous on the agent-loop hot path. Mapping is pure
  function work; the spool write is a single `appendFileSync` on an already-open descriptor; the OTLP
  shipper runs on its own timer and never on the listener's stack.

---

## 3. OCSF target: 1.9.0 with the native `ai_operation` profile

OCSF has **no** GenAI/LLM/agent event classes and no registered `ai`/`genai` extension. Since 1.8.0 the
support is a **profile** — `ai_operation` — plus AI objects, layered onto existing classes. In 1.9.0 the
profile is declared on the `system`, `network`, `application`, and `iam` base events, so it is inherited by
every class we emit. Verified present at 1.9.0:

```
GET /api/1.9.0/profiles                -> [..., 'ai_operation', ...]
GET /api/1.9.0/profiles/ai_operation   -> attributes: ai_agent, ai_model, delegation, message_context
GET /api/1.9.0/objects/ai_agent        -> name, type, version, uid, type_id, ai_model, charter, instance_uid
GET /api/1.9.0/objects/message_context -> prompt_text, response_text, *_tokens, ai_role_id, application, service, uid
GET /api/1.9.0/objects/delegation      -> uid (required), issuer_uid, parent_uid, created_time
```

**We adopt the native surface and do not duplicate it.** Concretely, every record carries:

- `metadata.profiles: ['ai_operation', 'cloud', 'osint']` — one entry per profile-owned attribute the
  record carries (§5)
- `ai_agent`: `{ type_id: 1 (Native), name: 'deepseek-harness', version, instance_uid: <session id>, uid: <agent preset>, ai_model }`
  — `instance_uid` is exactly "per-run/conversation/session identity", which is what `session.id` is.
- `ai_model`: `{ ai_provider, name }` from the last `request/context` fold (`provider`, `model`).
- `message_context`: on prompt/completion-bearing events, with `ai_role_id` (1 User / 2 Assistant / 3 Tool)
  and the token counts from `assistant/message.usage`. **`prompt_text`/`response_text` are populated in the
  restricted lane only** (§9).
- `delegation`: on `tool-workflow/agent-start`, whose payload names the published child —
  `uid` = `childId`, `parent_uid` = this session. `subagent/descriptor` carries none: it is appended to the
  *child's* own log and names no session id, so the record's own `session_id` is the child and
  `unmapped.dsh.parent_session_id` is the lineage.

Agent-loop semantics OCSF has no home for (`turn`, `step`, `callId`, log `seq`, event type, tool effect
class, approval latency, sandbox mode, escalation target) go into **one extension-owned object**.

- Extension attributes live under `unmapped.dsh` by default. The OCSF FAQ prefers a registered extension to
  `unmapped` for event producers, but every class is `additionalProperties: false`: a top-level `dsh` key
  fails validation for every consumer that applies the published JSON Schema, which is the readership an
  audit lane exists for. `extension.placement: 'attribute'` puts the object at the top level for a
  deployment that has decided its own pipeline tolerates it.
- **No uid is claimed by default.** 999 is not a free private block — the registry assigns it to the
  `Development` extension — so `metadata.extensions` is omitted entirely until `extension.uid` names a uid
  the OCSF extension registry assigned this deployment. `metadata.extension`, the singular attribute, is
  deprecated since OCSF 1.1.0 and is not emitted at all; 1.9.0 wants the `metadata.extensions` list.

---

## 4. Event → OCSF mapping

All 44 event types of this build (`dsh/packages/core/session/src/known-event-types.ts`, documented in
`dsh/docs/persistence-catalog.md`). `type_uid = class_uid * 100 + activity_id`.

Tool events are classified by tool name first (`§4.1`), which is why they list several classes.

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
| 26 | `session/end-seed` | — | — | **Dropped.** Internal construction marker; its meaning is carried by the seed-replay boundary record (§7). |
| 27 | `session/title` | API Activity (6003) | 3 Update | **Dropped by default**: a model-written summary of the user's prompt — user content by another name. |
| 28 | `session/title-llm-request` | API Activity (6003) | 2 Read | **Dropped by default**: carries prompt text. |
| 29 | `step/start` | API Activity (6003) | 2 Read | Opens one model call plus its tool executions; `status_id: 0`. |
| 30 | `step/end` | API Activity (6003) | 2 Read | `status_id: 1`, `duration` from the paired `step/start`. |
| 31 | `subagent/descriptor` | Application Lifecycle (6002) | 3 Start | This session **is** the child. `mode` and `provider` only: the payload names no session id, so no `delegation` is invented. |
| 32 | `todo/write` | API Activity (6003) | 3 Update | **Dropped by default**: UI state made of user/model task text. Item count only if re-enabled. |
| 33 | `tool/call` | §4.1: 1007 / 1001 / 4002 / 6003 | §4.1 | `status_id: 0` (in flight). `metadata.correlation_uid = <session>:<callId>`. |
| 34 | `tool/result` | §4.1 (same class as its call) | §4.1 | `status_id` from `content[0].isError`; `start_time`/`end_time`/`duration` from the correlated call. |
| 35 | `tool/code-dispatch-start` | §4.1 (classified by inner tool) | §4.1 | Sub-call inside `run_code`; `unmapped.dsh.parent_call_id`. |
| 36 | `tool/code-dispatch` | §4.1 | §4.1 | Sub-call settlement; `status_id` from `isError`. |
| 37 | `tool-workflow/run-start` | Application Lifecycle (6002) | 3 Start | |
| 38 | `tool-workflow/run-end` | Application Lifecycle (6002) | 4 Stop | `status_id` from `stopReason`. |
| 39 | `tool-workflow/agent-start` | Application Lifecycle (6002) | 3 Start | Member agent. The one event that names a child: `delegation = { uid: childId, parent_uid: <this session> }`. |
| 40 | `tool-workflow/agent-end` | Application Lifecycle (6002) | 4 Stop | `status_id` from `outcome`. |
| 41 | `turn/start` | API Activity (6003) | 1 Create | The unit of agent work; `status_id: 0`. |
| 42 | `turn/end` | API Activity (6003) | 1 Create | **`TurnEndReason` is the outcome discriminant** (§5.3); `duration` from the paired `turn/start`. A provider failure contributes its `code` and a digest of its message. |
| 43 | `user/message` | API Activity (6003) | 1 Create | `message_context.ai_role_id: 1`; `unmapped.dsh.message_source` distinguishes a human prompt from an injected context. Text digested in the SOC lane. |
| 44 | `web/deepseek-search-llm-request` | API Activity (6003) | 2 Read | Auxiliary search request; `ai_operation` with `api.service.name = 'deepseek-search'`. |

Unknown (out-of-repo, plugin-merged) event types fall through to API Activity 6003 / activity `99 Other`
with metadata only. `SessionEventMap` is merge-extensible, so the mapper's `switch` ends in a documented
default, never `assertNever`.

### 4.1 Tool classification

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

The table is a `Record<string, ToolClass>` constant plus a documented default. It is **not** configurable:
misclassifying `bash` as an API call on a deployment's say-so would break every process-based detection
downstream. Deployments extend coverage for their own tools through `toolClasses` (additive only — a config
entry may add an unknown tool name, never reclassify a known one).

---

## 5. Required fields and correlation

### 5.1 Base fields on every record

Required by `base_event` at 1.9.0: `class_uid`, `category_uid`, `type_uid`, `activity_id`, `severity_id`,
`time`, `metadata`. Per-class extras we must fill (read from the 1.9.0 API):

- Process Activity 1007: `device`, `actor`, `process`, `cloud`, `osint`
- File System Activity 1001: `device`, `actor`, `file`, `cloud`, `osint`
- HTTP Activity 4002: `cloud`, `osint`, and `at_least_one: [http_request, http_response]`
- API Activity 6003: `actor`, `api` (whose `operation` is required), `cloud`, `osint`
- Authorize Session 3003: `user`, `cloud`, `osint`, and `at_least_one: [privileges, groups, iam_roles]`
- Scheduled Job Activity 1006: `device`, `job`, `cloud`, `osint`

`cloud` and `osint` are **not** class-intrinsic requirements: they belong to the `cloud` and `osint`
profiles, and a class requires them only once that profile is applied. Since we emit both objects we
declare both profiles in `metadata.profiles`; every class is `additionalProperties: false`, so carrying a
profile's attribute without declaring its profile is the validation failure the stubs were meant to avoid.
Both are meaningless for an on-host agent — `cloud: { provider: 'Other' }`, `osint: []` — and `README.md`
says so.

API Activity's `src_endpoint` **is** class-intrinsic. For an on-host agent the caller is the host, so the
record carries `{ hostname, svc_name: 'deepseek-harness' }`. Every class also requires its own subject
object on *every* record of that class, including the one reporting a call settling or being abandoned, so
a `tool/call`'s `process`, `file`, or `http_request` is retained on the pending-call entry and reused by
its `tool/result`.

Static per-process objects, built once at mount:

- `metadata.product = { name: 'dsh-ocsf-forwarder', vendor_name: <config>, version: <plugin version> }`
- `metadata.version = '1.9.0'`, `metadata.log_provider = 'deepseek-harness'`,
  `metadata.log_name = 'session'`, `metadata.profiles = ['ai_operation', 'cloud', 'osint']`
- `device = { type_id: 0, hostname: os.hostname(), os: { name, type_id } }`
- `actor = { process: { pid: process.pid, name: 'dsh' }, user: { name: os.userInfo().username, type_id: 1 } }`
- `src_endpoint = { hostname: os.hostname(), svc_name: 'deepseek-harness' }`, on API Activity only
- `observables`: hostname (`type_id: 1`), user name (`4`), command line (`13`), file path (`45`), URL
  (`6`), and every HMAC digest we emit as a hash (`8`).

Timing fields: `time` = the event's own `time` (epoch ms, exactly what OCSF requires);
`metadata.logged_time` = when we produced the record; `start_time`/`end_time`/`duration` on correlated
pairs.

### 5.2 Identity and correlation

The `SessionEvent` envelope carries only `type`, `seq`, `time`, `data`, `ignorable?` — **no session id, no
turn, step, or callId**. Every one of our records therefore carries its own identity:

| Field | Source |
|---|---|
| `metadata.uid` | `<sessionId>:<seq>` — the idempotency key. `seq` is contiguous from 0 and equals the log length at append, so this is unique and stable across replays. |
| `metadata.sequence` | the event `seq` (a monotonic gap detector per session). |
| `metadata.correlation_uid` | `<sessionId>:<callId>` for tool pairs, `<sessionId>:approval:<id>` for approvals, `<sessionId>:turn:<n>` for turn pairs, `<sessionId>:<turn>:<step>` for steps. |
| `ai_agent.instance_uid` | `session.id`, taken from the `Session` handed to the listener — it is never in the payload. |
| `unmapped.dsh.session_id` / `unmapped.dsh.parent_session_id` / `unmapped.dsh.seed_length` | `session.id`, `header.parentSession`, `header.seedLength` — fork lineage. |
| `unmapped.dsh.turn` / `unmapped.dsh.step` | bare numbers off the payload, matching upstream conventions. |
| `unmapped.dsh.call_id` | `tool/call.data.callId`; for `tool/result` it is **not** top-level — it is read from `data.message.source.callId` with `data.message.content[0].toolCallId` as the fallback. |
| `unmapped.dsh.approval_id` | `ApprovalRequestId`, repeated verbatim in the closing event. |
| `unmapped.dsh.v` | our own payload version, independent of `SESSION_FORMAT_VERSION`. |

### 5.3 Outcome mapping

`TurnEndReason` is a merge-extensible sum type over `kind`, not a string union:

| `reason.kind` | `status_id` | `severity_id` |
|---|---|---|
| `completed` | 1 Success | 1 Informational |
| `max-tokens` | 1 Success | 2 Low |
| `aborted` | 2 Failure | 2 Low (`status_detail` = cancel cause kind) |
| `blocked` | 2 Failure | 3 Medium |
| `interrupted` | 2 Failure | 3 Medium (crash-orphaned turn closed on reload) |
| `error` | 2 Failure | 4 High (`status_detail` = `LlmFailure.code`) |
| anything else (merged variant) | 0 Unknown | 1 Informational |

Tool outcomes come from `tool/result.data.message.content[0].isError` (`true` → `status_id: 2`,
`severity_id: 3`). Approval outcomes: `allowed-once` → 1, `rejected`/`cancelled`/`unavailable` → 2, with
`severity_id: 3` for `unavailable` (a fail-closed ask means the approval channel was missing).

### 5.4 The correlator

One `Correlator` object per plugin instance, holding four maps keyed by session:

- `calls: Map<CallId, { time, seq, name, class, arguments }>` — filled on `tool/call`, consumed and deleted
  on `tool/result` / `tool/code-dispatch`.
- `approvals: Map<ApprovalRequestId, { time, seq, toolName, callId? }>` — consumed on `approval/decided`,
  which is guaranteed to be exactly one per ask.
- `turns: Map<number, time>`, `steps: Map<string, time>` — for `duration`.

**Approval latency** = `decided.time − asked.time`, emitted as `duration` and `unmapped.dsh.approval_latency_ms`.
This is the approval-fatigue signal: a decision returned in 300 ms is a human who is not reading, and a
`unavailable` outcome in under 5 ms is a deployment with no approval channel at all.

Unmatched entries are not leaked: state is held in a `WeakMap` keyed by the `Session` object, and on
`session/disposed` any still-pending call/approval is flushed as a record with `status_id: 0` and
`unmapped.dsh.unresolved: true`, so an abandoned tool call is visible instead of silently absent.

---

## 6. Read path and ordering

`ctx.on('session/event', ...)` is registered from the plugin's own untagged context, so scope filtering
admits every session (`scopeOf(ctx) === undefined` → the carrier's filter returns `true`). `this` inside the
listener is an opaque scope carrier, **not** the Session; the Session is argument 0.

Rules the listener obeys, from the emit-site contract:

1. Never throw and never reject — failures are contained and logged at `warn`, so a throw is silent record
   loss. All mapping and sink work is inside one `try`/`catch` that logs and increments a drop counter.
2. Never block — dispatch is synchronous on the agent-loop hot path.
3. Never mutate `event.data` — it is deep-frozen and shared; the mapper only reads.

---

## 7. The seed-replay gap

Constructor seeds do **not** publish on `session/event`: `Session`'s constructor pushes the seed into the
log before the store attaches, and `firstLiveSeq = log.length` afterwards. On resume the seed is the entire
prior log; on fork it is the parent's prefix. A `session/end-seed` marker is appended at `firstLiveSeq`
(unless the seed already ends in one) and that append does not publish either.

Design:

- Adoption happens on `session/created` **and** in a mount-time sweep of `ctx.sessions.list()`, because
  `session/created` is not replayed on hot reload.
- Per session we keep a cursor in a `WeakMap<Session, number>` (next seq we expect to forward). On every
  `session/event` we forward `session.events.slice(cursor, event.seq + 1)` — the snapshot already contains
  the just-appended event. **One mechanism covers three problems**: the seed, the unpublished
  `session/end-seed` marker, and any event we missed because the plugin mounted mid-session.
- `seedReplay` config decides what happens to events below `firstLiveSeq`:
  - `full` (default) — every seed event is mapped and forwarded, marked `unmapped.dsh.replayed: true` with
    `metadata.logged_time` set to now and `time` still the original event time. Duplicates across resumes
    are exact, and `metadata.uid = <sessionId>:<seq>` makes them trivially dedupable in the SIEM. Coverage
    beats duplication for an audit lane.
  - `boundary` — one Application Lifecycle record per adopted session stating `unmapped.dsh.seed_length`,
    `unmapped.dsh.first_live_seq`, and `unmapped.dsh.parent_session_id`, so the SOC sees an explicit, greppable gap marker
    instead of silence.
  - `none` — upstream's telemetry stance (start at `firstLiveSeq`, at-most-once, no backfill).
- Sessions that are resumed and then disposed without a single live append still get their replay: the
  `session/disposed` handler flushes from the cursor to the end of the log.

`ctx.sessionQuery.readSession(id)` (full validated log, unpaginated) is the offline backfill tool for a
session this process never entered. It is documented in `README.md` as an operator procedure, not wired
into the hot path — it requires the `session-query-sqlite` row, which we must not assume.

---

## 8. Delivery: append-only spool plus shipper

```
session/event ──► map ──► SOC spool  (JSONL, appendFileSync, one record per line)
                    └───► restricted spool (optional, mode 0600)
                                       │
                        shipper ───────┘  reads by byte offset, POSTs OTLP/HTTP,
                                          persists <spool>.cursor after each ack
```

- **The spool is the source of truth.** It is written synchronously before anything is queued for shipping,
  so a killed process leaves records on disk, and the OTLP cursor tells an operator exactly how far
  delivery got. A killed plugin therefore leaves a **visible gap** (a `metadata.sequence` hole per session,
  and a cursor behind the file size) rather than silent loss. The same holds for a sink that refuses a
  write: the session cursor advances only after a record reaches the sink, so a full disk delays records
  and the `failed` counter rises, instead of the events being consumed unwritten.
- **Rotation** by `maxBytes`: rename to a fixed-width timestamped generation, `<spool>.<ISO instant>-<nnn>`,
  and reopen. Names are never reused, so no rotation overwrites a generation. The shipper drains
  generations oldest-first ahead of the live file and unlinks each only after every byte in it is
  acknowledged. There is no inode following: a rotated file is drained by name.
- **Rotation stops** at `spoolMaxGenerations` un-drained generations. The live file then grows past
  `maxBytes` and the plugin says why. Deleting an unacknowledged generation to stay under a size limit
  would make the audit lane destroy the evidence it exists to keep.
- **One writer per path.** A spool path is held by an exclusive `<spool>.lock`. A second process fails at
  load naming the pid that holds it; a lock owned by a process that no longer exists is taken over. Two
  writers on one path each rename the inode the other holds open, which destroys records silently.
- **OTLP/HTTP**: POST `{endpoint}/v1/logs` with `resourceLogs[].scopeLogs[].logRecords[]`, each record's
  `body` being the OCSF JSON object, `timeUnixNano` from `time`, `severityNumber` mapped from
  `severity_id`. Batching by `batchSize` and `flushIntervalMs`. A batch the collector cannot take right
  now — 5xx, timeout, connection failure, 408/425/429 — is retried with exponential backoff doubling from
  `flushIntervalMs` to `maxBackoffMs`, and never advances the cursor. A batch it refuses on content — any
  other 4xx — is appended to `quarantinePath` and stepped over, because a poison batch retried forever
  holds every later record behind it. Each pass reads at most `maxReadBytes`, so an hour of backlog is not
  one allocation. Headers (auth) come from config.
- `ctx.effect()`/`ctx.on('dispose')` closes the descriptor and performs one final flush attempt with a
  bounded timeout. Nothing is held only in memory: unshipped records are already on disk.

---

## 9. Two-lane privacy

The audit log must not become the exfiltration channel. A SOC lane that carries every file body, every
model completion, and every command line is a second copy of everything the agent touched, in a system with
a wider reader set than the workspace itself.

**Lane A — SOC (default, always on).** Metadata, classifications, and keyed digests only:

- Tool arguments: parsed defensively from the raw JSON string (it is model output — a wire boundary, so it
  is validated, and a parse failure yields `unmapped.dsh.arguments_parse_error` rather than a throw). For each
  top-level key we emit the key name, a value classification (`path` / `url` / `command` / `number` /
  `boolean` / `text`), the value length, and `HMAC-SHA256(key, value)` truncated to 32 hex characters.
- Command lines: `commandLine: 'digest' | 'full'`, default `digest` — `process.name` gets argv[0], and the
  full command line is replaced by its digest plus length. `full` is for deployments that have decided the
  SOC lane is trusted with commands.
- URLs: `url: 'host' | 'sanitized' | 'full'`, default `host` — scheme and host only. `sanitized` adds the
  path, which is a deliberate widening: a reset or invite token rides in a path as readily as in a query
  string.
- File paths are emitted verbatim: a path is the security signal and is not a secret. A `grep` *pattern* is
  not a path — it is a query the model composed, and it routinely contains the value it is hunting for —
  so it is digested like any other argument.
- Message and summary text: never present. Digest plus character count plus role only.
- Free text authored by a provider, a hook, or an approval prompt is never present either: a provider
  failure message is a flattened error chain, an approval prompt quotes the command it is asking about,
  and a hook's `decision` is typed `string` because it is folded from hook-authored JSON. Each contributes
  a digest plus a length; the hook decision additionally maps onto the protocol's own
  `approve`/`allow`/`block`/`deny`/`ask`, with anything else recorded as `other`.
- A `JSON.parse` failure on tool arguments records a fixed reason, never the parser's message: V8 quotes a
  window of the offending text, which for a malformed tool call is the raw model output.
- **No raw value composed by a model, a user, a provider, or a hook reaches this lane.** What does reach it
  verbatim is metadata: file paths, tool names, executable names (taken after leading `NAME=VALUE`
  assignments are stripped, because `SECRET=… cmd` puts the credential in the first token), hostnames, URL
  scheme and host, and bounded enumerations. Correlation works fine on digests: the same value in two
  sessions produces the same digest under the same key.

**Lane B — restricted (opt-in, separate file, mode 0600).** The same records with `raw_data` populated
(the event `data` verbatim) and `message_context.prompt_text`/`response_text` filled. Joined to lane A by
`metadata.uid`. Enabling it requires setting `restricted.path` *and* `restricted.acknowledged: true`; the plugin fails
loud at load otherwise, so nobody enables full-body capture by accident.

**The HMAC key** is `hmacKey: { source: 'ephemeral' | 'env' | 'literal' }`, default `ephemeral` (a random
32-byte key per process: correlation holds within a run, not across runs). `env` reads a named variable and
**throws at load** if it is missing or shorter than 32 bytes — misconfiguration fails loud, and a
silently-unkeyed digest is a rainbow-table target. Guard floor, deliberately not configurable: the raw
value is never written to lane A regardless of settings; only `full`-mode command lines and URLs (which are
categorically not secrets-by-construction) are exempt, and that exemption is per-category, not global.

---

## 10. Test matrix

| Surface | What it proves | Where |
|---|---|---|
| `Config` validation | required fields, defaults, restricted-lane acknowledgement gate, `hmacKey.source: 'env'` failing loud on a missing or short variable, OTLP endpoint validation | `tests/unit/config.spec.ts` |
| Mapper — tool events | `bash` → 1007/Launch with `type_uid` 100701; `read` → 1001/Read; `web_fetch` → 4002/Get with `http_request`; unknown tool → 6003; `tool/result` callId read from `message.source.callId` and from `content[0].toolCallId`; the composed record's OCSF identity | `tests/unit/map-tools.spec.ts` |
| Mapper — lifecycle | every `TurnEndReason.kind` → `status_id`/`severity_id`; a merged unknown `kind` falls through to Unknown; `request/header` carries tool names but no schemas or prompt text; hooks, subagents, workflows, compaction, schedules, and the generic fallback | `tests/unit/map-lifecycle.spec.ts` |
| Mapper — approvals | asked → 3003 pending with `privileges`; each `ApprovalOutcome` → `status_id`; sandbox/policy/preset changes | `tests/unit/map-authorization.spec.ts` |
| Correlator and replay | call↔result pairing by callId with `duration`; ask↔decide pairing by id with latency; unresolved entries flushed on dispose; two sessions with the same callId do not cross-talk; each `seedReplay` mode | `tests/unit/map-tools.spec.ts`, `tests/unit/map-authorization.spec.ts`, `tests/unit/forwarder.spec.ts` |
| Privacy | no raw argument value in a lane-A record; same value → same digest, different key → different digest; URL sanitisation drops the query string; restricted lane carries `raw_data` | `tests/unit/privacy.spec.ts`, `tests/unit/forwarder.spec.ts` |
| Payload readers | every reader returns `undefined` for the wrong type and for non-records | `tests/unit/read.spec.ts` |
| Spool + shipper | records are one JSON object per line and parse; file modes; rotation at `maxBytes`; the shipper advances its cursor only on acceptance, holds back a partial line, skips a corrupt one, and replays from the cursor after a restart; the HTTP call against a loopback collector | `tests/unit/sink.spec.ts`, `tests/unit/post-batch.spec.ts` |
| Mount | the plugin loads on a real Cordis fiber with only `sessions` provided, registers its listeners, opens both lanes with the right modes, and drains on unload | `tests/unit/mount.spec.ts` |
| **E2E (a)** | booted `dsh`, plugin mounted, mock model drives a real `bash` call → spool holds a 1007 record for the call and a 1007 record for the result, same `metadata.correlation_uid`, `status_id: 1`, `duration ≥ 0`, and no raw command in lane A | `tests/e2e/tool-call.e2e.ts` |
| **E2E (b)** | the model requests a sandbox escalation (`sandbox_permissions` + `justification`) under `workspace-write`, which drives the real `ApprovalService` → paired 3003 records, `unmapped.dsh.approval_latency_ms` present and ≥ 0, `status_id: 2` for the fail-closed `unavailable` outcome | `tests/e2e/approval.e2e.ts` |
| **E2E (c)** | a turn with no tool call still produces `turn/start`/`turn/end` records and the agent's own output is unchanged (the plugin is read-side) | `tests/e2e/tool-call.e2e.ts` |

E2E (b) needs no fixture plugin and no harness modification: the base bundle sets the approval policy to
`ask` unless `DSH_PERMISSION_MODE=danger-full-access`, and `approveEscalation` calls
`ctx.approval.request(...)` before anything executes. With no answerer composed in the headless profile the
ask fails closed to `unavailable` — which is itself the more interesting SOC signal.

E2E runs in both launch modes (`pnpm run test:e2e` and `DSH_EXAMPLE_MODE=lib pnpm run test:e2e`).
The harness installs this package's runtime dependency closure into the throwaway profile, so the
copied plugin resolves its own dependencies instead of reaching the harness checkout.

Coverage: `pnpm run test:coverage`. `CONVENTIONS.md` sets the bar at 100% per file; the suite
reaches 99.7% lines / 98.2% statements / 97.9% functions / 86.1% branches, the thresholds are pinned
below that, and the residual gap is described in `ADR.md` §9.

---

## 11. Phasing

1. **P1 — read path and spool.** Config, OCSF constants, base record builder, tool/approval/lifecycle
   mappers, correlator, spool sink, seed replay. Unit tests. This is the prototype's minimum bar.
2. **P2 — shipper.** OTLP/HTTP batch POST with the durable cursor and backoff.
3. **P3 — evidence.** The three E2E tests on the template harness.
4. **P4 — docs.** `README.md` (including the honest containment statement) and `ADR.md`.
5. **Later, not in this prototype.** `sessionQuery` backfill command; `telemetryTap` mode; a registered
   OCSF extension uid; an upstream contribution proposing a registration surface for out-of-repo session
   event types (upstream's own JSDoc calls it "deferred until such a consumer exists" — we are that
   consumer).

---

## 12. Limitations, stated honestly

1. **Not a containment boundary.** In-process, same uid as the agent. The spool is deletable by the agent
   it audits. Ship promptly if that matters.
2. **Pre-durable.** `session/event` fires post-commit but before persistence. A crash can leave a forwarded
   record whose session-log counterpart never made it to disk.
3. **At-least-once delivery, at-most-once capture.** The shipper may resend a batch it could not confirm
   (dedupe on `metadata.uid`). Conversely, an event that was never published — because the plugin was
   unmounted at that moment — is not recoverable from the live path; only the `sessionQuery` backfill
   procedure recovers it.
4. **Resume duplicates by design** under the default `seedReplay: 'full'`.
5. **`cloud`/`osint` are profile-satisfying stubs**, not facts about a cloud deployment or an
   intelligence feed. Both profiles are declared so the stubs validate.
6. **No OCSF extension uid is claimed.** 999 is the registry's assigned `Development` extension, not a free
   private slot, so `metadata.extensions` is omitted until a deployment configures a uid the registry
   assigned it. The extension attributes live under `unmapped`, which is where the base event puts data it
   does not model.
7. **Model requests are mapped to API Activity, not HTTP Activity**, deviating from the brief's initial
   guidance: the harness's LLM seam exposes provider, model, and token usage but no wire-level facts, and
   HTTP Activity requires `at_least_one: [http_request, http_response]` that we would have to fabricate.
   `web_fetch`/`web_search` **do** map to HTTP Activity, because there we have a real URL and method.
8. **The tool classification table is name-based.** A deployment that renames `bash` or ships a shell tool
   under another name gets API Activity until it adds a `toolClasses` entry.
9. **One process per spool path.** The path's exclusive lock makes a second writer fail at load rather
   than silently destroy records. The bundle patch's default path is per-`$DSH_HOME`, so two homes are
   already two paths; a deployment that points several processes at one shared path must give each its own.
10. **Rotation can stop.** With no shipper configured, or with the collector down long enough,
   `spoolMaxGenerations` generations accumulate and the live file then grows without bound. That is the
   deliberate trade: an audit lane may run out of disk, but it may not delete unacknowledged evidence.
11. **A quarantined batch is not delivered.** Records the collector refuses on content sit in
   `otlp.quarantinePath` until an operator looks at them.

The one hard constraint — never appending to the session log — is respected by construction: this plugin
registers no session writes at all.

An audit of the first implementation found two blockers and several high findings, all in the durable
output path: single-slot rotation combined with a shipper that read only the live file destroyed unshipped
records; concurrent `SpoolSink`s on one path destroyed each other's; six mapper and privacy paths carried
raw values into the SOC lane under stock configuration; a sink failure consumed the events it failed to
write; and the emitted records did not satisfy their OCSF classes. Every one is fixed, each with a
regression test, and the claims above are the corrected ones. The reasoning that made the original wrong
is worth stating: rotation was designed as a size cap and delivery as a byte cursor, and neither design
asked what happens to the bytes that move.
