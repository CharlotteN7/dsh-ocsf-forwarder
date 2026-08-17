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
    "product": { "name": "dsh-ocsf-forwarder", "vendor_name": "dsh-security-plugins", "version": "0.1.0" },
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
  "process": { "name": "curl", "cmd_line": "hmac-sha256:d7df26fddfd3af030679709c66165379" },
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

`attestation_list` is the OCSF `record_integrity` profile: the record's own SHA-256 fingerprint and
the fingerprint of the record before it in the spool. [Tamper-evidence](integrity.md) gives the
canonicalisation a reader recomputes it from, and what it is and is not evidence of.

Every OCSF class is `additionalProperties: false`, so the extension attributes live under
`unmapped`, which is the base event's own slot for exactly this. `cloud` and `osint` are stubs — a
host agent has no cloud deployment and no open-source intelligence — and `metadata.profiles`
declares both, because an attribute whose profile is undeclared fails validation just as an
undefined one does.

The same rule decides where a class-owned attribute may appear. `src_endpoint` is only on API
Activity, Authorize Session and HTTP Activity records; the top-level `user` object is only on
Authorize Session, which is the one class this plugin emits that defines it. The account behind
every other record is `actor.user`, which every class does define. The conformance suite checks
each class against its own OCSF definition rather than the union of all seven, because the union
accepts exactly the stampings `additionalProperties: false` rejects.

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

### Observables

A tool call contributes at most one observable, carrying the same value the record's own object
carries and typed for what that value actually is:

| `name` | `type_id` | Value |
|---|---|---|
| `process.cmd_line` | `8` Hash, or `13` Command Line under `commandLine: full` | The command under the `commandLine` policy — a keyed digest by default. The type follows the policy, so a digest is never presented to a SIEM as a command line. |
| `file.path` | `45` File Path | The `file_path`/`path` argument itself, emitted verbatim: a path is the security signal, not a secret. Never the argument record it was read from. |
| `http_request.url.url_string` | `6` URL | The URL under the `url` policy — scheme and host by default, so the query string that carries reset and API tokens is gone before the record exists. |

A call whose arguments name no subject — a `grep` with only a pattern, a `web_fetch` whose URL does
not parse, any API-class tool — contributes none.

`observables[]` is the one place a redacted value and its raw source sit one line apart in the
mapper, so it is covered by an invariant rather than by a test per call site: a sentinel secret is
placed in every text-bearing session-event payload field, a full forwarder run is driven over them,
and the serialized SOC-lane records are searched for all of them at once.
