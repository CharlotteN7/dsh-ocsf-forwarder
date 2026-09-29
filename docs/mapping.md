---
title: Record format and mapping
nav_order: 4
---

# Record format and mapping

[← dsh-ocsf-forwarder docs](index.md)

## A record

```json
{
  "class_uid": 1007, "category_uid": 1, "type_uid": 100701, "activity_id": 1,
  "severity_id": 1, "status_id": 0, "message": "tool call bash",
  "time": 1786881335332,
  "metadata": {
    "product": { "name": "dsh-ocsf-forwarder", "vendor_name": "dsh-security-plugins", "version": "0.5.1" },
    "version": "1.9.0", "profiles": ["ai_operation", "cloud", "osint", "record_integrity"],
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
  "process": {
    "name": "curl", "uid": "01JB0SESSION:call_9f2",
    "cmd_line": "hmac-sha256:d7df26fddfd3af030679709c66165379"
  },
  "attestation_list": [{
    "uid": "7a1f0c5e-6b2d-4c8a-9f31-2d5b8e0a1c74:41",
    "chain_uid": "7a1f0c5e-6b2d-4c8a-9f31-2d5b8e0a1c74",
    "prev_event": { "uid": "01JB0SESSION:6", "type_uid": 600302, "fingerprint": { "value": "9d1c…", "algorithm_id": 3, "encoding_id": 1 } },
    "fingerprint": { "value": "4b77…", "algorithm_id": 3, "encoding_id": 1 }
  }],
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

`process.uid` is the correlation uid, repeated on the record of this same process settling. The
OCSF `process` object constrains `at_least_one: [pid, uid, cpid]`, and no session event names the
child's operating-system pid, so the identifier is the one the schema defines for a producer to
assign — "a unique identifier for this process assigned by the producer (tool)". No pid is invented
to fill the slot.

`attestation_list` is the OCSF `record_integrity` profile: the record's own SHA-256 fingerprint and
the fingerprint of the record before it in the spool. [Tamper-evidence](integrity.md) gives the
canonicalisation a reader recomputes it from, and what it is and is not evidence of.

Every OCSF class is `additionalProperties: false`, so the extension attributes live under
`unmapped`, which is the base event's own slot for exactly this. `cloud` and `osint` are stubs — a
host agent has no cloud deployment and no open-source intelligence — and `metadata.profiles`
declares both, because an attribute whose profile is undeclared fails validation just as an
undefined one does.

The same rule decides where a class-owned attribute may appear. OCSF defines `src_endpoint` on
API Activity, Authorize Session and HTTP Activity, and this plugin emits it **only on API Activity
(6003)**, which is the one class that requires it: the caller of an approval or a `web_fetch` on a
host agent is the host the record already names in `device`. The top-level `user` object is only on
Authorize Session, the one class this plugin emits that defines it; the account behind every other
record is `actor.user`, which every class does define.

The conformance suite checks each class against its own OCSF definition rather than the union of
all seven, because the union accepts exactly the stampings `additionalProperties: false` rejects —
and it checks each nested object the same way, against the definition of that object, constraints
included. Walking only the top level let `process.exit_code` ship, an attribute the `process`
object does not define and class 1007 defines at the top level of the record.

## Event mapping

All 59 session event types this build knows (`packages/core/session/src/known-event-types.ts` in
the harness, catalogued in its `docs/persistence-catalog.md`), in the harness's own order. The
count is the vocabulary of the newest `@deepseek-ai/dsh-session` the peer range admits, which is
what `tests/unit/mapping-doc.spec.ts` reads it from.

An older harness in the range knows fewer, and not always a prefix: `0.1.1-rc.2` knows 48,
`0.1.2-rc.1` 51, `0.1.5-rc.3` 56 and `0.1.7-rc.2` 59, and the `0.1.5` line both **added** five
types and **renamed** three. `assistant/chunk` became `assistant/attempt` — a different event, not
a rename of the same one — and `tool/code-dispatch{,-start}` became `tool/ptc-dispatch{,-start}`
with their payloads unchanged, retired by the session format's v3-to-v4 migration. The dispatcher
still routes the two retired dispatch names, because the peer range admits builds that emit them;
they have no row here, because this table is the newest admitted vocabulary.
`type_uid = class_uid * 100 + activity_id`.

Tool events are classified by tool name first — see [Tool classification](#tool-classification) —
which is why they list several classes.

| # | Session event | OCSF class (`class_uid`) | `activity_id` | Status / notes |
|---|---|---|---|---|
| 1 | `agent-preset/selected` | Application Lifecycle (6002) | 8 Update | Composition change: the preset later turns run under, in `unmapped.dsh.agent_preset`. |
| 2 | `agent/inbox/spliced` | API Activity (6003) | 3 Update | **Messages inserted into the agent's pending list** — a steering surface. `unmapped.dsh.inbox_target`, `.splice_start`, `.removed_count`, `.inserted_count`, and one digest of the inserted text. |
| 3 | `approval/asked` | Authorize Session (3003) | 1 Assign Privileges | `status_id: 0` (pending). `privileges: [tool:<name>]`, `unmapped.dsh.approval_id`. The prompt `reason` quotes the command being approved, so it is digested. |
| 4 | `approval/decided` | Authorize Session (3003) | 1 Assign Privileges | `status_id: 1` for `allowed-once`, else `2`. `duration` + `unmapped.dsh.approval_latency_ms` from the paired ask. |
| 5 | `approval/policy` | Authorize Session (3003) | 1 Assign Privileges | Session policy switch (`ask`/`never`). |
| 6 | `assistant/attempt` | API Activity (6003) | 2 Read | **One model attempt that committed no surface message** — a failure, a retry, a cancellation, or a stream error. `status_id: 2`, `status_detail: no-surface-message`, paired to the step by `<session>:<turn>:<step>`. The embedded `stream` is the model’s own partial output and is never read: `unmapped.dsh.stream_records` counts it, which separates an attempt that produced nothing from one cut off part-way. Not the retired `assistant/chunk`, which was per-token and dropped. |
| 7 | `assistant/message` | API Activity (6003) | 2 Read | Model completion. `message_context.ai_role_id: 2`, token counts from `usage`. Text digested in the SOC lane. |
| 8 | `command/done` | API Activity (6003) | 3 Update | `status_id` and `status_detail` from `kind`; `duration` from the paired `command/run`, which also supplies the command name. The handler's outcome `text` is digested. |
| 9 | `command/run` | API Activity (6003) | 1 Create | Slash command; `api.operation = command:<name>`, `status_id: 0`, args digested. Correlates to `command/done` by `commandId`, as `<session>:command:<id>`. |
| 10 | `compaction/end` | API Activity (6003) | 3 Update | `status_id: 2` when `error` present; `duration` is how long the compaction held the lock, paired to `compaction/start` on `compactionId`. |
| 11 | `compaction/prune` | API Activity (6003) | 4 Delete | **History removal** — kept deliberately: shadowed seq range and token count are a tamper-relevant signal. The payload carries no `compactionId`, so the record is correlated by the range it replaced. |
| 12 | `compaction/start` | API Activity (6003) | 3 Update | Holds the compaction lock. |
| 13 | `compaction/summary` | API Activity (6003) | 3 Update | Model-written replacement for history. Summary text digested in the SOC lane. `ai_model` is the summarizer the compaction backend chose, from the event's own `provider`/`model`; `ai_agent.ai_model` stays the session route. |
| 14 | `deliverables/presented` | File System Activity (1001) | 2 Read | **The files a turn declared as its deliverables**, with their paths verbatim on `file.path`’s rule. The first path fills the class-required `file`; every path is in `unmapped.dsh.presented_paths` and contributes its own `file.path` observable. The model-written `description` is not read. Correlates to the `present` call as `<session>:<callId>`. A payload declaring no readable path produces no record: File System Activity has none without a `file`. |
| 15 | `developer/message` | Application Lifecycle (6002) | 8 Update | **Incremental session changes on the model surface** — the harness documents these as tool additions and removals, so a mid-session admission widens what one prompt can reach and it is graded `severity_id: 2`. `message_context.ai_role_id: 99` with `ai_role: developer`, because OCSF 1.9.0 defines no developer member. Text digested; `unmapped.dsh.header_seq` names the `request/header` that defines every added tool. |
| 16 | `feedback/message-delete` | — | — | **Dropped by default**: it names only the message whose rating went away, and says nothing without the put it removes. Re-enabled through `includeEventTypes`, it takes the generic fallback below. |
| 17 | `feedback/message-put` | — | — | **Dropped by default**: a human rating carrying the rater’s own free-text `note` — the trade `feedback/record` is already dropped on. Re-enabled, it takes the generic fallback below. |
| 18 | `feedback/record` | — | — | **Dropped by default**: a free-text human remark about the session — no security value, high privacy cost. Re-enabled through `includeEventTypes` it takes the generic fallback below: metadata only, no field of the payload. |
| 19 | `goal/change` | API Activity (6003) | 3 Update | `api.operation = goal:<operation>`. Goal id, revision, phase and block-reason code verbatim; the objective is digested. A clear carries its tombstone's id and revision. |
| 20 | `hook/invoked` | Process Activity (1007) | 1 Launch | A hook **is** a subprocess. `process.name` = hook point, `process.uid` = `<session>:hook:<handlerId>`, `unmapped.dsh.handler_id`, `unmapped.dsh.dialect`. |
| 21 | `hook/result` | Process Activity (1007) | 2 Terminate | `status_id` from `decision`, reduced to the protocol's `approve`/`allow`/`block`/`deny`/`ask` with anything else recorded as `other` plus a digest; `exit_code`, which class 1007 defines at the top level and the `process` object does not define at all; `duration` = `durationMs`. |
| 22 | `image/offload` | API Activity (6003) | 4 Delete | **Input images permanently omitted from every later model request.** Model-visible content removed while the log keeps it, which is `compaction/prune`’s shape, so it takes the same activity. `unmapped.dsh.offload_seqs` lists the surface nodes edited, with `.offload_target_count` and `.offload_image_count`; no image is read. |
| 23 | `llm/retry` | API Activity (6003) | 2 Read | `status_id: 2` (the attempt that failed), `status_detail` = failure code. Provider, retry number, cap, and delay in `unmapped.dsh`; the provider's failure message is digested. Correlates to `llm/retry-started` as `<session>:retry:<retryId>`. |
| 24 | `llm/retry-started` | API Activity (6003) | 2 Read | `status_id: 0`; the wait completed and the next attempt starts. Paired to `llm/retry` on `retryId`. |
| 25 | `model/selection` | Application Lifecycle (6002) | 8 Update | **The validated provider and model committed for the next request**, with `ai_model` on the record. It does *not* move the session route: `request/context` records what a request actually used, and folding a selection in would attribute the records between the two to a model that has served nothing. |
| 26 | `permission/preset` | Authorize Session (3003) | 1 Assign Privileges | `privileges: [preset:<name>]`. |
| 27 | `plan/mode` | API Activity (6003) | 3 Update | Plan mode on/off, in `unmapped.dsh.plan_mode_active`. |
| 28 | `request/context` | Application Lifecycle (6002) | 8 Update | Provider/model route change. Folds into `ai_model` for every later record in the session. |
| 29 | `request/header` | Application Lifecycle (6002) | 8 Update | **Capability-set change.** Tool *names* and count, model config, and a digest of the system prompt. Never the prompt text or tool schemas in the SOC lane. |
| 30 | `sandbox/mode` | Authorize Session (3003) | 1 Assign Privileges | Confinement change; `privileges: [sandbox:<mode>]`. High value. |
| 31 | `schedule/change` | Scheduled Job Activity (1006) | 1 Create / 2 Update / 3 Delete / 99 Other | From `operation` (`create` / `dispatch` / `delete`); `job: { name, uid }` from `schedule.id` on a create, `id` otherwise. |
| 32 | `session-log-deepseek/delivery-accepted` | API Activity (6003) | 1 Create | **The session log itself left the host.** `@deepseek-ai/dsh-session-log-deepseek` uploads every canonical event since the last watermark with a model request; this event records the endpoint accepting it. `api.service.name = 'deepseek-llm-api'`, plus `delivered_through_seq`, and `delivered_after_seq` / `delivered_event_count` once a preceding watermark has been observed — `first_observed_delivery` when none has. A marker naming another session was inherited through a fork seed and is graded `severity_id: 1`, because nothing left on this session's account. |
| 33 | `session/end-seed` | — | — | **Dropped.** Internal construction marker; its meaning is carried by the seed-replay boundary record. Re-enabled, it takes the generic fallback below. |
| 34 | `session/title` | — | — | **Dropped by default**: a model-written summary of the user's prompt — user content by another name. Re-enabled, it takes the generic fallback below. |
| 35 | `session/title-llm-request` | — | — | **Dropped by default**: carries prompt text. Re-enabled, it takes the generic fallback below. |
| 36 | `step/end` | API Activity (6003) | 2 Read | `status_id: 1`, `duration` from the paired `step/start`. |
| 37 | `step/start` | API Activity (6003) | 2 Read | Opens one model call plus its tool executions; `status_id: 0`. |
| 38 | `subagent/catalog` | Application Lifecycle (6002) | 3 Start | **The parent’s own record of a direct child**, and the third event type that names a child session by id, so it builds the same `delegation` link `team/member` and `tool-workflow/agent-start` do. `subagent_mode` and `catalog_version` verbatim; `label` is the delegating call’s model-written `description` and is digested. A payload naming no child produces no record. |
| 39 | `subagent/descriptor` | Application Lifecycle (6002) | 3 Start | This session **is** the child. `mode` and `provider` only: the payload names no session id, so no `delegation` is invented. |
| 40 | `subagent/model-selection-policy` | Authorize Session (3003) | 1 Assign Privileges | **The exact routes this session may hand a child agent**, as `privileges: [subagent-model:<provider>/<model>]`. A policy naming no complete route produces no record: OCSF constrains the class `at_least_one: [privileges, groups, iam_roles]`. |
| 41 | `system/message` | Application Lifecycle (6002) | 8 Update | **The rendered system prompt as it stands on the model-visible surface.** The same category of fact as `request/header`’s prompt digest, under the same redaction: `system_prompt_digest` + `system_prompt_length`, never the text. `system_prompt_empty` separates a cleared prompt from a changed one, and `message_id` identifies the surface node a later replacement rewrites. |
| 42 | `team/member` | Application Lifecycle (6002) | 3 Start | **An agent joined this session's team**, and the second event type that names a child session by id: `delegation = { uid: member.id, parent_uid: <this session> }`. Provider, `context` (`fresh`/`fork`) and provisioning phase verbatim; the member's brief is digested. |
| 43 | `team/message/delivered` | API Activity (6003) | 3 Update | Settles the message on `messageId`; `duration` + `unmapped.dsh.delivery_latency_ms` from the paired queueing. |
| 44 | `team/message/queued` | API Activity (6003) | 1 Create | **One agent addressed another.** Sender session, target session and `delivery` (`quiet`/`wakeup`, which decides whether the target acts on it now); `message_context.ai_role_id: 4`. The text itself is digested. Correlates to `team/message/delivered` as `<session>:team-message:<id>`. |
| 45 | `team/task` | API Activity (6003) | 3 Update / 4 Delete | Task snapshot: owner session, revision, status, blocked-by count, and **`write_scopes` verbatim** — a path pattern is the security signal, on the same reasoning as `file.path`. Subject and description are digested. No `1 Create`: the payload gives this plugin no way to tell a task's first revision from a later one. |
| 46 | `todo/write` | — | — | **Dropped by default**: UI state made of user and model task text. Re-enabled, it takes the generic fallback below — metadata only, and **not** an item count. |
| 47 | `tool-workflow/agent-end` | Application Lifecycle (6002) | 4 Stop | `status_id` from `outcome`. |
| 48 | `tool-workflow/agent-start` | Application Lifecycle (6002) | 3 Start | Member agent, with `delegation = { uid: childId, parent_uid: <this session> }`. One of the two event types that name a child by id; `team/member` is the other. |
| 49 | `tool-workflow/run-end` | Application Lifecycle (6002) | 4 Stop | `status_id` from `stopReason`. |
| 50 | `tool-workflow/run-start` | Application Lifecycle (6002) | 3 Start |  |
| 51 | `tool/call` | by tool name: 1007 / 1001 / 4002 / 6003 | by tool name | `status_id: 0` (in flight). `metadata.correlation_uid = <session>:<callId>`. |
| 52 | `tool/ptc-dispatch` | by inner tool name | by tool name | Sub-call settlement; `status_id` from `isError`. Renamed from `tool/code-dispatch` by the same migration, and routed the same way. |
| 53 | `tool/ptc-dispatch-start` | by inner tool name | by tool name | Sub-call inside `run_code`; `unmapped.dsh.parent_call_id` and `.root_call_id`. Named `tool/code-dispatch-start` before the session format’s v3-to-v4 migration; the dispatcher routes both names to one mapper, because the peer range admits builds on either side of the rename and the payload fields are unchanged. |
| 54 | `tool/result` | by tool name (same class as its call) | by tool name | `status_id` from `content[0].isError`; `start_time`/`end_time`/`duration` from the correlated call. |
| 55 | `turn/end` | API Activity (6003) | 1 Create | **`TurnEndReason` is the outcome discriminant**; `duration` from the paired `turn/start`. A provider failure contributes its `code` and a digest of its message. |
| 56 | `turn/start` | API Activity (6003) | 1 Create | The unit of agent work; `status_id: 0`. |
| 57 | `user/message` | API Activity (6003) | 1 Create | `message_context.ai_role_id: 1`; `unmapped.dsh.message_source` distinguishes a human prompt from an injected context. Text digested in the SOC lane. |
| 58 | `web/deepseek-search-llm-request` | API Activity (6003) | 2 Read | Auxiliary search request: `api.service.name = 'deepseek-search'`, `api.version` = `apiVersion`, and `ai_model` = the search provider's own model, which is not the session route. The query text is digested. |
| 59 | `workspace/changes` | API Activity (6003) | 99 Other | **The generic fallback, and that is the whole payload.** The event says a completed turn’s changed files were summarized and carries nothing but `turn`; the summary stays on the Host, served by `ctx.workspaceChanges.summary` while the session lives, so no file name is in the log. Reading it would mean injecting a live Host service, which this package does not do. |

**The generic fallback** is API Activity 6003 / activity `99 Other`, `api.operation` = the event
type, and `unmapped.dsh.event` plus whatever `turn` and `step` the payload happened to carry — no
other field of the payload, and nothing read from its content. Unknown (out-of-repo, plugin-merged)
event types take it, and so do the seven dropped types, on the deployments that re-enable them —
`assistant/chunk` is an eighth, dropped for the older harnesses in the peer range that still emit
it and absent from the table above for the same reason. `SessionEventMap` is merge-extensible, so the mapper's `switch` ends in a
documented default, never `assertNever`.

### Tool classification

`tool/call`, `tool/result`, and the two `tool/ptc-dispatch*` events are classified by tool name:

| Tools | Class | `activity_id` | Extra objects |
|---|---|---|---|
| `bash`, `pwsh`, `run_code`, `terminal_open`, `terminal_send` | Process Activity (1007) | 1 Launch | `process.cmd_line` (per `commandLine` policy), `process.name`, `process.uid` = the correlation uid, `actor.process` = the harness process |
| `terminal_close`, `terminal_signal`, `job_kill` | Process Activity (1007) | 2 Terminate | `process.uid`, as above |
| `read`, `read_image`, `glob`, `grep` | File System Activity (1001) | 2 Read | `file: { name, path, type_id }` from `file_path`/`path`. A `grep` `pattern` is not a path and never fills one. |
| `write` | File System Activity (1001) | 1 Create | |
| `edit`, `str_replace_editor` | File System Activity (1001) | 3 Update | |
| `web_fetch`, `web_search` | HTTP Activity (4002) | 3 Get | `http_request: { http_method, url }` under the `url` policy; satisfies the class's `at_least_one: [http_request, http_response]` |
| `load_workspace_dependencies` | Application Lifecycle (6002) | 1 Install | `application: { name: 'dsh-primary-runtime' }`, overriding the harness `application` every other 6002 record carries. See [Installing a runtime](#installing-a-runtime). |
| everything else | API Activity (6003) | 2 Read | `api.operation = tool:<name>` |

The table is a `Record<string, ToolClass>` constant plus a documented default. It is **not**
configurable: misclassifying `bash` as an API call on a deployment's say-so would break every
process-based detection downstream. Deployments extend coverage for their own tools through
`toolClasses` (additive only — a config entry may add an unknown tool name, never reclassify a
known one). `runtime-install` and `delegation-external` are deliberately outside the configurable
set: each one changes what the mapper reads, not only how a call is labelled.

### Installing a runtime

Desktop ships its own Python, Node and pnpm, and `load_workspace_dependencies` copies that payload
onto the host under `$DSH_HOME/dsh-runtimes/dsh-primary-runtime` on first use. The copy happens
inside the tool (`packages/skill/tool-workspace-dependencies/src/index.ts`, `installPrimaryRuntime`)
and appends **no session event of its own**, so the ordinary `tool/call` / `tool/result` pair is the
only trace an installed interpreter leaves in the log. Classified as an API read it said nothing at
all: the tool declares `parameters: {}`, so the call carries no argument to read.

The install report is therefore taken from the **result**. The tool declares an output schema and
renders its value as one JSON text block, so the `tool/result` record carries, in `unmapped.dsh`:
`runtime_python_path`, `runtime_node_path` and `runtime_pnpm_path` where the payload ships them,
`runtime_python_packages_path` and `runtime_node_packages_path`, and
`runtime_python_distributions` — the bundled distribution name → version map, plus its count. The
paths are emitted verbatim on `file.path`'s rule and each executable path also contributes a
`file.path` observable. The distribution map is a software inventory a SOC joins against
advisories; it excludes anything a user installed later, which is the tool's own documented limit.

A failed call's result text is a diagnostic rather than a report, so nothing is read from it and
the record is the `application` plus `status_id: 2`. Text that is not a JSON object yields no
attributes rather than a guess.

### Observables

A tool call contributes at most one observable — a runtime install contributes one per installed
executable, and `deliverables/presented` one per declared file — carrying the same value the
record's own object carries and typed for what that value actually is:

| `name` | `type_id` | Value |
|---|---|---|
| `process.cmd_line` | `8` Hash, or `13` Command Line under `commandLine: full` | The command under the `commandLine` policy — a keyed digest by default. The type follows the policy, so a digest is never presented to a SIEM as a command line. |
| `file.path` | `45` File Path | The `file_path`/`path` argument itself, emitted verbatim: a path is the security signal, not a secret. Never the argument record it was read from. Also each interpreter path a runtime install reported, and each path `deliverables/presented` declared. |
| `http_request.url.url_string` | `6` URL | The URL under the `url` policy — scheme and host by default, so the query string that carries reset and API tokens is gone before the record exists. |

A call whose arguments name no subject — a `grep` with only a pattern, a `web_fetch` whose URL does
not parse, any API-class tool — contributes none.

`observables[]` is the one place a redacted value and its raw source sit one line apart in the
mapper, so it is covered by an invariant rather than by a test per call site: a sentinel secret is
placed in every text-bearing session-event payload field, a full forwarder run is driven over them,
and the serialized SOC-lane records are searched for all of them at once.
