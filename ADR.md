# Architecture decisions

Decisions whose rationale is not obvious from the code. Newest last.

---

## 1. Source events from `session/event`, not from the telemetry seam

**Context.** `ctx.sessionTelemetry` is a single-implementation Cordis `Service`; a second
registration throws (`vendor/cordis/src/reflect.ts:290`), and the base bundle already mounts
`session-telemetry-otel` (`packages/bundle/base/cordis.patch.yml:148`). So an OCSF sink can either
replace that backend, attach as a `session-telemetry/record` waterfall listener, or bypass the seam.

**Decision.** Bypass it: subscribe to `session/event` from the plugin's own untagged context.

**Why not replace the backend.** Installing a security plugin must not silently delete a
deployment's existing OTel export. It would also bind us to the coordinator's fixed projection
(first-chunk-only for `assistant/chunk`, its own severity map) instead of the verbatim envelope.

**Why not the waterfall.** Two disqualifiers. The coordinator that dispatches
`session-telemetry/record` is constructed by the backend plugin and only in `FULL`/`FEEDBACK_ONLY`
mode (`packages/session/session-telemetry-otel/src/index.ts:239`); with the shipped default
`DISABLED` we would receive nothing, silently. And the waterfall is dispatched synchronously on the
capture hot path with no try/catch in Cordis, so a throwing listener withholds that record
permanently — a forwarder must not be able to delete the deployment's telemetry by failing.

**Consequence.** `session/event` is `@mode emit` with per-listener containment
(`packages/core/session/src/index.ts:382-399`), so our failures are logged and cannot affect the
agent loop. It is also **pre-durable**, which the README states plainly.

## 2. Adopt OCSF's native `ai_operation` profile instead of inventing agent classes

**Context.** As of OCSF 1.9.0 (2026-08-03, the current release) there are **no** GenAI/LLM/agent
event classes and no registered `ai` extension. AI support is the `ai_operation` profile —
`ai_agent`, `ai_model`, `message_context`, `delegation` — declared on the `system`, `network`,
`application`, and `iam` base events, so every class we emit inherits it. Verified against
`https://schema.ocsf.io/api/1.9.0/{profiles,objects,classes}/…`.

**Decision.** Emit standard classes declaring every profile whose attributes the record carries —
`ai_operation`, plus `cloud` and `osint` for the two stubs — mapping `ai_agent.instance_uid` to the
session id, `ai_model` to the folded `request/context` route, and `delegation` to the child named by
`tool-workflow/agent-start`. Agent-loop semantics OCSF has no home for (turn, step, call id, log
seq, tool class, phase, approval latency) go into one extension-owned object.

**Why `unmapped` after all.** The OCSF FAQ prefers a registered extension for event producers, and
that was the original choice. It is wrong here: every OCSF class is `additionalProperties: false`,
so a top-level `dsh` key fails the published JSON Schema for every consumer that applies it — which
is the readership an audit lane exists for. The extension object lives under `unmapped` by default,
and `extension.placement: 'attribute'` is available to a deployment that has decided its own
pipeline tolerates the top-level key.

**No uid is claimed.** 999 is not a free private block: the OCSF extension registry assigns it to
the `Development` extension. `metadata.extensions` is therefore omitted until `extension.uid` names
a uid the registry assigned this deployment. The singular `metadata.extension` has been deprecated
since OCSF 1.1.0 and is not emitted at all.

## 3. Model requests map to API Activity, not HTTP Activity

The brief's initial guidance put model requests on HTTP Activity (4002). The harness LLM seam
exposes provider, model, and token usage but no wire-level facts, and HTTP Activity carries a
`at_least_one: [http_request, http_response]` constraint we would have to satisfy with invented
data. `assistant/message` therefore maps to API Activity (6003) with `api.operation:
'llm.completion'` and the `ai_operation` profile carrying the real token accounting.
`web_fetch`/`web_search` **do** map to HTTP Activity, because there we have a genuine URL and method.

## 4. Read payloads defensively rather than through the typed event union

`AGENTS.md` says to trust TypeScript at typed same-process boundaries, and `session/event` is one.
This plugin still reads every payload through the small readers in `src/read.ts`. Three reasons:
`SessionEventMap` is merge-extensible, so payload types of events contributed by harness packages we
do not depend on — and by out-of-repo plugins — are outside our type graph by construction; the same
mapper runs over seed-replayed events restored from a durable log, which *is* a validation boundary;
and the listener must never throw, so an assumption that fails at runtime would become silent record
loss. The alternative was declaration-merging imports of a dozen harness packages purely for types.

## 5. One catch-up mechanism for three gaps

Constructor seeds never publish on `session/event`: the seed is pushed into the log before the store
attaches, and the `session/end-seed` marker the constructor appends at `firstLiveSeq` does not
publish either. Rather than special-case each, every observation walks `session.events` from a
per-session cursor up to the observed `seq`. That covers the seed, the unpublished marker, and any
event appended before the plugin mounted, with one code path. `seedReplay` then decides only where
the cursor starts.

`seedReplay: 'full'` is the default. Upstream's telemetry coordinator deliberately starts at
`firstLiveSeq` and accepts at-most-once; an audit lane makes the opposite trade, because a duplicate
carrying an exact `metadata.uid` costs a deduplication rule while a gap costs an investigation.

## 6. The tool classification table is not configurable downward

`toolClasses` can classify a tool the built-in table does not know; it cannot reclassify one it
does. Letting repo-local configuration demote `bash` from Process Activity to API Activity would
break every process-based detection downstream — the same reasoning as the guard floor in
`CONVENTIONS.md` §6.1. Deployment-varying choices (paths, endpoints, redaction policy, drop lists)
are configuration; this is a security invariant.

## 7. The restricted lane is a second file, not a config flag on the first

Full payload capture is a different audience, a different retention policy, and a different file
mode (0600 versus 0640). Naming a path is not enough to open it: `restricted.acknowledged: true` is
required, and the plugin fails at load otherwise, so nobody enables full-body capture by accident.
The two lanes carry the same `metadata.uid`, so an authorised analyst joins them.

## 8. Digests, not encryption, for correlation

The SOC lane replaces values with `HMAC-SHA256(key, value)` truncated to 128 bits. Correlation —
"the same file was read in these six sessions" — works on digests. The key defaults to a random
per-process value, which correlates within a run but not across runs; a deployment that wants
cross-run correlation sets `privacy.hmacKey.source: 'env'`, and a missing or short key then fails at
load rather than producing guessable digests. Plain hashing was rejected: an unkeyed digest of a
short path or command is a rainbow-table lookup.

## 9. Coverage thresholds sit at the level actually reached

`CONVENTIONS.md` §4 adopts 100% per-file coverage. The thresholds are pinned at whatever the suite
actually reaches rather than at an aspiration, so a regression fails the gate today instead of
after the gap is closed. Each is raised only by writing the test that raises it. §34 is why they
are checked per file rather than in aggregate.

## 10. The E2E installs the dependency closure

The harness copies the plugin (never symlinks: Node resolves a symlink to its real path, which moves
the parent walk off the profile tree). A copied package cannot reach its own pnpm store, so the run
was only working because the launcher's resolution happened to reach the harness checkout's copy of
`@deepseek-ai/schemastery`. The harness now copies the runtime dependency closure, dereferenced,
into a flat `node_modules` beside the install, and asserts every copied package resolves from
inside the profile tree. `packageDir` searches the real path as well as the given one, because a
pnpm package directory is a symlink into the store and its own dependencies live beside the real
location. Peer dependencies are deliberately excluded: every harness import in this package is
`import type`, so nothing is emitted at runtime, and Cordis must come from the running installation.

## 11. Approvals are driven in E2E through a real sandbox escalation

The approval test needed real `approval/asked` + `approval/decided` events without a fixture plugin
that fakes an `ask`. The base bundle sets the approval policy to `ask` unless
`DSH_PERMISSION_MODE=danger-full-access`, and `approveEscalation`
(`packages/sandbox/sandbox/src/escalation.ts`) calls `ctx.approval.request(...)` before anything
executes when the model passes `sandbox_permissions` + `justification`. The headless profile
composes no answerer, so the ask fails closed to `unavailable`. That path exercises the real
`ApprovalService`, the real audit pair, and produces the more interesting SOC signal: an agent asked
to widen its sandbox and the deployment had no channel to answer.

## 12. Rotation may stop; it may not delete an unacknowledged generation

The first implementation renamed the full spool over a single `<spool>.1` and reopened. Combined
with a shipper that only ever opened the live path, that made rotation a delete: the unshipped
backlog moved aside, the shipper resumed on an empty file and reported healthy, and the next
rotation overwrote it. Thirty records written, twenty-eight permanently gone.

Rotation now writes fixed-width timestamped generations whose names are never reused, so
lexicographic order is write order and no rotation can destroy one. The shipper drains generations
oldest-first ahead of the live file and unlinks each only after every byte in it is acknowledged.

The remaining question is what happens when generations accumulate faster than they drain. Deleting
the oldest is the conventional answer and is the wrong one here: it reintroduces the original bug
with more steps. Rotation stops at `spoolMaxGenerations` instead, the live file grows past
`spoolMaxBytes`, and the plugin says why. An audit lane may run out of disk. It may not quietly
delete the evidence it exists to keep.

## 13. A spool path has one writer, enforced by a lock file

Two `SpoolSink`s on one path each derive their size from their own `statSync` and rotate
independently, so one process renames the inode the other holds an open descriptor to. The probe
lost twelve of sixteen records with no corruption and nothing in any log.

Node's `fs` exposes no `flock`, so ownership is an exclusive `<spool>.lock` created with `wx`
holding the owner's pid. A second writer fails at load naming that pid — misconfiguration fails
loud, and the operator's fix is one path per process. A lock whose pid no longer exists is taken
over, so a crash does not need manual cleanup. `EPERM` from `process.kill(pid, 0)` counts as alive:
the process exists under another uid.

## 14. Refused batches are quarantined; unwell collectors are waited out

A boolean "did the collector take it" cannot tell a collector that is down from a batch a collector
will never accept, and treating both as retryable means one malformed record blocks delivery
forever behind the cursor. `PostBatch` returns `accepted` / `retry` / `reject`. A 5xx, a timeout, a
connection failure, and 408/425/429 are `retry`: the cursor holds and the shipper backs off
exponentially from `flushIntervalMs` to `maxBackoffMs`. Any other 4xx is `reject`: the batch goes to
`otlp.quarantinePath`, the cursor steps over it, and the operator is told. Quarantine is a
deliberate, reported, recoverable loss of *delivery*; the records are still on disk.

## 15. The forwarding cursor advances after the write, not before

`observe()` advanced the per-session cursor and then wrote, so a sink that threw consumed the event:
six records lost to a simulated `ENOSPC` and never retried when the disk recovered, with nothing but
a `metadata.sequence` hole to show for it. The cursor now moves only after a record reaches the
sink, and the walk stops at the first failure so the spool stays in log order. An outage becomes a
delay. The counters that say which is happening are logged periodically and at unload, because
`stats()` that nothing calls is not observability.

## 16. Metadata is what the SOC lane carries verbatim, and metadata is a short list

"No raw secret value reaches this lane" was true of the paths the design thought about and false on
six it did not. The failure mode was the same each time: a field that looks like an identifier but
is actually a rendering of the request. The first token of a command line is the executable — except
in `SECRET=… cmd`, where it is the secret. A `grep` pattern looks like a path argument and is a
search query. A provider `error.message` looks like a code and is a flattened error chain. An
approval prompt, a hook `decision`, and a `JSON.parse` error message are all free text composed by
something outside this plugin.

The rule that replaces the assumption: the SOC lane carries verbatim only file paths, tool names,
executable names, hostnames, URL scheme and host, and values drawn from a bounded enumeration this
build owns. Everything else is `HMAC-SHA256(key, value)` plus a character count. `privacy.url`
defaults to `host` for the same reason — a reset token rides in a path as readily as in a query
string — and `sanitized` is now the deliberate widening rather than the default.

## 17. A transport is an encoder and a status classifier, and nothing else

The shipper was already wire-format-agnostic: the cursor, the generation drain, the quarantine
and the backoff never looked at OTLP. Only `otlpPayload()` and the single post call site did. So
the seam is a `Transport { kind, endpoint, headers, contentType, encode, classify }`, and roughly
300 lines of drain logic moved to `sink/shipper.ts` unchanged.

The boundary is drawn where it is because a transport that could speak about delivery could
re-derive cursor semantics, and there is exactly one correct answer there: the cursor advances
after acceptance, never before. A transport says which of `accepted` / `retry` / `reject` a status
means and hands back a body. It cannot see the cursor, the spool, or the quarantine file.

`classify` takes the HTTP status and nothing else, which is a real limit: Splunk's HEC returns a
JSON body whose `code` disambiguates a 400 that means "bad payload" from a 400 that means "bad
token". Widening the seam to the response body was rejected — it is the first step towards a
transport that decides delivery — and §18 records what that costs.

## 18. What was verified about Splunk HEC, and where our reading of it differs

The HEC request format was verified on 2026-08-16 against Splunk's live documentation, which now
lives on `help.splunk.com` after `docs.splunk.com` began redirecting. Confirmed:
`POST {base}/services/collector/event` ("which is where all JSON-formatted event requests must
go"); `Authorization: Splunk <token>`, with the REST reference adding "The format is
case-sensitive"; a batch is "event objects stacked one after the other"; `time` is UNIX time "in
the format `<sec>.<ms>`", so epoch **seconds**, not milliseconds.

Two widely repeated claims about HEC do not hold. Splunk states "Both concatenated JSON objects
and JSON arrays like this are accepted", so an array is not rejected — the concatenation we emit
is the documented form, not the only accepted one. And Splunk publishes **no** retryable status
set; the widely copied 400/401/403-are-permanent rule is the OpenTelemetry Collector's
`splunkhecexporter`, not Splunk's.

Our reading therefore departs from that exporter on 401 and 403. Splunk's own error table maps
both to token problems — "Token is required", "Invalid authorization", "Token disabled", "Invalid
token" — never to a bad batch. Quarantining a spool because a token was rotated would step the
cursor over records that will deliver perfectly once the operator fixes the token, and quarantine
is a one-way door: nothing re-reads that file. So a 401 or 403 holds the cursor and backs off, and
the heartbeat's `shipper_cursor` is what tells the SOC delivery has stalled. 400 stays a refusal,
even though Splunk returns "Invalid token" and "Token disabled" as 400 under codes 21 and 22,
because it is the status a genuinely malformed batch arrives under and something has to keep one
bad record from blocking every record behind it.

429 is in the retry set on Splunk's authority, not the exporter's: codes 26 and 27, "HEC queue is
at capacity" and "HEC ACK channel is at capacity", are 429.

## 19. The heartbeat is 6002 plus an extension key, because OCSF has no slot for one

An agent that stops reporting is indistinguishable from an agent that is idle. `metadata.sequence`
detects a gap inside a session; it says nothing about a host that went quiet.

OCSF 1.9.0 has no heartbeat, liveness, health-check, keepalive or checkpoint class. Enumerating
all 87 classes at `https://schema.ocsf.io/api/1.9.0/classes` and searching name, caption and
description for those words returns nothing. So the heartbeat is Application Lifecycle (6002) with
`unmapped.dsh.kind: 'heartbeat'`, and the README says that plainly rather than implying a standard
mapping.

The activity is `Other` (99) with `activity_name: 'Heartbeat'`, not `Start` (3). The record reports
that the application is still running, which is not the same claim as that it started, and 6002
has no id for the difference.

Two consequences fell out of reading the class definition rather than trusting the plan.
`application_lifecycle` carries the constraint `at_least_one: [app, application]`, and `app` was
deprecated in 1.9.0 — so **every** 6002 record this plugin emits now carries an `application`
object naming the harness. The records emitted before this release did not, and would have failed
a consumer that applied the published schema. And OCSF says to omit `metadata.original_time` for a
generated event, so the heartbeat sets none while every record derived from a session event passes
its log time through.

The heartbeat is deliberately absent from the counters it reports. A self-report that counted
itself would make two consecutive heartbeats differ by one with no session activity behind the
difference, which is exactly the signal an idle-versus-broken check reads.

## 20. Fleet identity is configured, never inferred

`metadata.tenant_uid`, `metadata.labels` and `metadata.tags` were present in the schema and unused.
Each is now a configuration field with no default: an invented tenant is worse than an absent one,
because a SOC filter that silently matches the wrong records is harder to notice than one that
matches none.

`metadata.tags` is **not** a string list. OCSF types it as an array of `key_value_object`, each
needing a `name` plus a `value`, so the configuration takes a map and resolution renders the array.
`metadata.labels` is the string list.

`device.uid` carries a stable install uid, minted with `randomUUID()` on first run and persisted
beside the spool. A hostname is not an identity: it changes when a laptop is renamed and collides
across a fleet imaged from one template. The uid also keys the heartbeat's `metadata.uid`, which is
what lets a SIEM detect a *missing* heartbeat rather than only a malformed one.

`metadata.original_time` is the session log's own rendering of the append time, passed through as a
string. OCSF is explicit that it is "a pass-through string in its native format… not normalized" —
the normalised value is the base event's `time` — so reformatting it as ISO 8601 would be the one
thing the attribute exists not to be.

## 21. The disk bound is a second stop condition, not a delete policy

`spoolMaxGenerations` bounds the file count, which bounds nothing about the disk once the live file
is the one growing — the stated limitation in §12. `spoolMaxTotalBytes` is a second stop condition
on rotation, on exactly the same refuse-to-rotate terms. §12's reasoning is unchanged and is the
reason this is not a retention policy: an audit lane may run out of disk, it may not silently
delete unacknowledged evidence.

What was missing was a louder, earlier alarm. `spoolHighWaterBytes` sits below the stop condition,
and crossing it raises the heartbeat to `severity_id: 4`, so the SOC learns from the SIEM while
there is still room. A high-water mark above the stop condition would never fire before rotation
stopped, so that combination fails at load.

## 22. The delegation boundary is read from the registry, and configuration may only widen it

`subagent-claude-code` and `subagent-codex` resolve a real external CLI and spawn it in the parent
session's workspace. There is no DSH session for the child, so no session event describes anything
it does: telemetry coverage ends at the tool call. Until this release that boundary crossing was a
generic 6003 record, indistinguishable from a calculator call.

The provider name is fixed per plugin row and is **not** in the tool-call payload, so a record
cannot name the destination harness from the event alone. What the payload carries is the tool
name, and a `tool-subagent` row pairs a tool name with the provider it starts runs on. Those rows
are read out of `ctx.registry` at mount — the fibers of the runtime named `tool-subagent`, and
their `provider` / `toolName` config — which recovers the mapping without guessing.

It is best-effort and the README says so: `toolName` is a deployment choice, a row may be composed
after this plugin mounts, and a deployment may reach an external harness through a plugin this
build has never heard of. `delegationTools` exists for those cases, and it may only **add** a name.
A configured entry never displaces a discovered one, because repo-local configuration is
attacker-controlled and re-pointing a discovered delegation tool at a benign provider would silence
the loudest record this plugin emits — the same trust ranking as `CONVENTIONS.md` §5 and the same
reasoning as §6 above.

`spawn` and `fork` are deliberately not in the external-provider set. They run in process and are
fully observed; grading them as unobserved boundaries would bury the two that are.

## 23. MCP calls name their server, and nothing else about them changes

MCP tools register as `mcp__<serverName>__<rawName>`, and every one of them used to fall through to
API Activity as an opaque `tool:<name>`. The prefix is now split back apart: the server goes to
`api.service.name` as `mcp:<server>` and to `unmapped.dsh.mcp_server`, the tool name to
`unmapped.dsh.mcp_tool`. That is the whole change — which external MCP server an agent talked to is
the largest supply-chain blind spot in the stack, and it is answerable from two names.

The split is exact for the clean case and best-effort otherwise. The harness replaces characters
outside `[A-Za-z0-9_-]` with `_` and, when that or the 64-character cap changes the name, appends a
hash of the identity; a server namespace containing `__` after substitution is therefore ambiguous.
The first `__` after the prefix is taken as the separator, because a namespace is a short
deployment-chosen key and a tool name is not.

Nothing about the arguments changes. The SOC lane carries two names and the same redacted argument
list every other tool call gets.

## 24. `cordis_define` and `cordis_run` are process activity

Both were API Activity, which is what every unclassified tool gets. They compile and evaluate a
plugin body inside the harness process, under the agent's own uid and with the agent's own service
graph in reach; `tool-cordis`'s own README says to treat the toolset like bash access. Process
Activity (1007) makes every process-based detection a SOC already owns fire on them, which is the
entire point of the change.

`cordis_define` does not itself evaluate anything, so `Launch` overstates that one call in
isolation. Define-then-run is one capability and the pair is what a detection wants to see, so both
are graded the same rather than splitting the pair across two classes and losing the join.
`cordis_inspect_self` is read-only and stays an API call.

## 25. A refused rotation is re-checked on a window, not on every record

§12 and §21 say rotation stops rather than deleting an unacknowledged generation. What that left
behind was a hot-path defect: `write()` calls `rotate()` for every record once the live file is past
`spoolMaxBytes`, `rotate()` consults the two stop conditions before the refusal latch — a
`readdirSync` of the spool's directory plus a `statSync` per generation — and the byte counter is
reset only by a rotation that succeeds. So the counter stays past the threshold for the whole
outage, and every spooled record pays for a directory listing on the agent's event loop.

Measured on 300 records with 2000 files in the spool directory: 2 ms when the threshold has not been
reached, 312 ms once rotation is refused. That is ~1 ms of synchronous blocking per record,
indefinitely, triggered by exactly the collector outage the spool exists to survive, and it grows
with the directory.

A refusal now holds off the next check for 60 seconds. The latch alone would have been wrong —
rotation must resume once the shipper drains a generation, and nothing else re-arms it — and
resetting the byte counter would delay resumption by another whole `spoolMaxBytes`, which is
hundreds of megabytes. The window costs at most a minute of extra growth against that same
threshold. The rotation policy itself is unchanged: this is a hot-path fix, not a retention change.

## 26. Numeric configuration is range-checked at load

`z.number()` accepts every double, so `batchSize: 0` reached `index += this.options.batchSize` in
the shipper's batching loop and hung the agent process — a typo in `cordis.yml` turning into a
non-responsive `dsh` with no message anywhere. `timeoutMs: 0`, `spoolMaxBytes: 0` and a negative
`statsIntervalMs` are the same defect: a value the type accepts, a runtime that cannot use it, and a
failure that appears far from its cause.

The schema library cannot express the bound, so resolution does: one helper per range, applied to
every numeric as it is defaulted. Counts of records and files additionally require a whole number,
because half a batch is not a quantity the loop can make progress on. `statsIntervalMs` takes zero,
which the README documents as reporting at unload only, and is checked as non-negative instead.

This is upstream's rule, not a local preference: misconfiguration fails loud at load when it is
self-contained, and every one of these is.

## 27. The install uid lives under the harness home, not beside the spool

`device.uid` is documented as the stable install identity of a machine. It was persisted at
`<spoolPath>.install-uid`, and `dsh-netguard` — a separate spool, by design — did the same beside
its own. One host therefore minted two uids and its two OCSF producers disagreed about which device
they were describing, which breaks every SOC query that groups by device.

The default is now `$DSH_HOME/install-uid`, resolved the way the harness resolves its home, and
`dsh-netguard` resolves the same path. `fleet.installUidPath` still overrides it, and an explicit
`fleet.installUid` still skips the file entirely.

A uid an earlier release left beside the spool is read on first run and written through to the new
path, because an upgrade that re-identifies the host is exactly the loss of continuity the sidecar
exists to prevent. Where both packages carry a legacy uid, the first to mount seeds the shared file
and the other adopts it; never migrating would leave the two producers permanently disagreeing,
which is the defect being fixed.

Persisting is best effort, matching `dsh-netguard`'s helper, which this one had drifted from: a
directory this process cannot write costs the uid its stability across restarts and is reported,
but it does not fail the mount. Refusing to mount over an unwritable *sidecar* would cause the
outage the spool's own write path deliberately refuses to cause, one step earlier. The bare `catch`
around the read now says what it actually swallows — any read failure, not `ENOENT` alone.

## 28. This package's `metadata.uid` does not move, and `dsh-netguard`'s does

`dsh-netguard` emitted `<session>:<seq>` too, over a per-process counter of its own decisions
rather than the session log's event sequence. Both start near 1 in the same session, so
`session-88:4` named one record here and an unrelated Network Activity record there — and a SIEM
following this README's "deduplicate on `metadata.uid`" silently dropped one of them.

The namespace went into `dsh-netguard`'s key, not this one. This package is published and its
records are already in indexes; changing the key breaks deduplication for every existing consumer,
retroactively. `dsh-netguard` is `0.1.0` with none. The asymmetry is the decision — tidying the two
into one scheme later recreates the collision. `dsh-netguard`'s ADR §18 carries the same reasoning
from its side.

`metadata.correlation_uid` stays identical in both, because there the shared value is the whole
point: it is what joins a connection to the tool call that opened it.

## 29. A rotation failure leaves the spool with a descriptor, or the spool says it has none

Rotation closed the descriptor, cleared the field, renamed the file, and reopened. A `renameSync`
that threw — a directory that went read-only for a moment, a filesystem remounted `ro` — left `fd`
undefined for the rest of the process's life, and `write()`'s `if (this.fd === undefined) return`
turned that into a silent no-op. A probe of fifteen records through a real `SpoolSink`, with the
directory made read-only at record 3 and restored at record 5, lost nine of them: no warning, no
counter, and `pressure()` still reporting `rotationStopped: false`. Every operator-facing signal
said healthy while the audit sink was dead.

Three things were wrong, and the third is what made it severe rather than merely bad.

The rename is now the only statement inside the `try`, and a descriptor is taken again on the way
out of it either way — on the new generation when the rename went through, on the original path
when it did not. `bytes` is read back from the descriptor rather than assumed, so the reopened file
is measured rather than presumed empty. A failed rename also sets `rotationRefused`, because
rotation has stopped in exactly the sense §21's disk bound stops it and the live file is about to
grow past `spoolMaxBytes`.

A spool that nonetheless has no descriptor no longer returns silently. It counts every record it
drops, warns once per outage, and retries the open on each later write — immediately on the first
attempt, then backing off from 250 ms to 30 s, because the condition had usually already cleared by
the next record and a record dropped while waiting out a delay is evidence destroyed. `close()` is
excluded by an explicit flag: a deliberately closed spool ignoring writes is correct and stays
silent.

`pressure()` gained `sinkFailed` and `droppedRecords`, and the heartbeat carries both. A dead audit
sink reports `severity_id: 5` and `status_id: 2`, above the `4` that disk pressure reports, because
a spool that is filling still holds every record and one that is failing holds none. The heartbeat
is the only record still leaving the host at that point, so it is where the fact has to be.

None of this changes the rotation policy of §12 and §21. An audit lane may run out of disk; it may
not silently delete unacknowledged evidence, and it may not silently stop writing either.

The probe also reported a `<corrupt>` line, which is not one: it scans every file in the spool
directory, and `<spoolPath>.lock` holds the owning pid rather than JSON. No partial record line
exists — a rotation that fails leaves the live file exactly as the last complete `write()` left it,
because the rename is attempted only between whole lines.

## 30. Conformance is checked per class, because that is what `additionalProperties: false` means

The test named "adds no top-level attribute the base event does not define" checked every record
against one set that was the base event **plus every class-owned attribute any of the seven classes
uses**. Nothing it could catch was a violation of what its name promised: `src_endpoint` stamped
onto all seven classes survived a green run, which is the exact failure the name describes.

Each class is now checked against the base event plus its own definition, read from
`schema.ocsf.io/api/1.9.0/classes/<name>` with every profile applied. The same mutation now fails
on 1001, 1006, 1007 and 6002 — the four classes that do not define `src_endpoint` — and passes on
the three that do.

Turning it on found a real violation. `user` was stamped on every record, and among the classes
this plugin emits only Authorize Session defines it, so six of seven record classes carried an
attribute their schema forbids. It is now emitted only on 3003, where the class requires it. The
account behind every other record is `actor.user`, which every class defines and which was already
being emitted alongside it.

The table is narrowed to the attributes this plugin can emit rather than transcribing all ~70 per
class. That makes it stricter than OCSF: emitting an attribute a class does define but this plugin
has not emitted before fails until the table is updated. That is the intended cost — the entry is
one line, and the alternative is a set large enough to stop discriminating again.

## 31. The SOC lane's privacy rule is tested as an invariant, not per call site

`observables[]` had no test asserting any emitted value. The only assertion naming it was
`expect(mapping?.observables ?? []).toEqual([])`, hedged three ways so an undefined mapping, an
undefined array and an empty array all passed identically. Three mutations survived a full green
run: the URL observable carrying the raw URL instead of the redacted one, which would put reset and
API tokens into the SOC lane; the `file.path` observable carrying the whole argument record; and
`process.cmd_line` typed `13` (Command Line) while holding a digest.

The shipped code was correct in all three places. This was a missing guard rail, not a leak.

Each observable's `type_id` and `value` is now asserted per type, including under each policy that
widens it. But asserting call sites one at a time is what left this surface uncovered for three
releases, so the rule `privacy.ts` states — a raw argument value, message text, or command line
never reaches the SOC lane unless a deployment opted that whole category in — is now tested as
itself: a distinct sentinel secret goes into every text-bearing payload field a session event can
carry, a full forwarder run is driven over them, and the serialized records are searched for all of
them at once. A field nobody thought to write a test for fails this the moment it starts carrying
its input.

The restricted lane is driven in the same run and asserted to contain every sentinel, because a
sentinel that never reached a mapper would make the SOC-lane assertion vacuous for that surface.

Two values are deliberate exceptions and appear in the assertion as a named list rather than being
excluded from the payloads: a schedule id, which is a durable record identifier a SOC pivots on,
and the leading executable token of a command line, which `commandName` emits verbatim as metadata
and which §16 already covers.

## 32. A settled pair leaves the correlation map, and the quarantine file carries the spool's mode

Two more mutations survived a full green run.

Dropping `this.calls.delete(callId)` from `SessionState.closeCall` changed nothing any test could
see. In production every settled call would still be in the map at `dispose()`, and the unresolved
flush would re-emit all of them as `unresolved: true` — a stream of false "abandoned action" alerts
into the SIEM, one per tool call the agent ever completed. Disposal is now asserted to emit nothing
unresolved for a call and an approval that did settle, which is the behaviour the delete exists for.

The quarantine file's mode was `0o640` passed to `appendFileSync`, asserted nowhere; `0o666`
survived. It holds complete refused OCSF records, which is the same content as the spool, whose two
modes are asserted twice each. The mode is now forced with `chmodSync` after the append, for the
same reason the spool forces its own: `appendFileSync`'s `mode` applies only on creation and is
masked by the process umask, so the pre-existing code produced 0600 under a umask of 077 and an
exact assertion could not be written against it.

## 33. The DSH peer ranges are `^0.1.0-rc.6`; cordis stays exact

The peers were pinned to exactly `0.1.0-rc.6`. Upstream published `0.1.0-rc.7` on
2026-08-17T11:50Z, four hours after this package's own publish, and an exact pin turns a newer rc
into an install failure:

```
npm error ERESOLVE unable to resolve dependency tree
npm error Found: @deepseek-ai/dsh-session@0.1.0-rc.7
npm error Could not resolve dependency:
npm error peer @deepseek-ai/dsh-session@"0.1.0-rc.6" from dsh-ocsf-forwarder@0.3.0
```

A bare `npm install dsh-ocsf-forwarder` into an empty project still succeeds — npm installs the
pinned peer itself, and rc.6 is still on the registry. What fails is the case that matters: a
project that already resolves rc.7, which is what installing the rc.7 CLI gives it. pnpm resolves
either way, so `dsh plugin add` never surfaced this.

`@deepseek-ai/dsh-session` and `@deepseek-ai/dsh-session-telemetry` are now `^0.1.0-rc.6`, which
under semver admits every prerelease of `0.1.0` from rc.6 up. Three things were checked rather than
assumed:

- Every file in both packages is byte-identical between rc.6 and rc.7 except `package.json`, whose
  only differences are its own version and its own `^0.1.0-rc.6` → `^0.1.0-rc.7` ranges. The type
  surface this plugin compiles against did not move.
- Both rcs declare `@deepseek-ai/cordis: ^4.0.1`.
- The end-to-end suite — six tests, a real `dsh` subprocess, this plugin mounted — passes against
  the published rc.6 and rc.7 CLIs. CI now runs it as a matrix over both rather than the oldest
  alone, because a range is a promise about everything in it.

`@deepseek-ai/cordis` keeps its exact `4.0.1`. It is the service graph every registration goes
through; two resolved copies are two graphs, and there is no upstream version to widen towards.

## 34. The coverage gate is per file, because an aggregate one is met by the easy files

The gate was `lines 99 / functions 98 / branches 88 / statements 98` with no `perFile`. Aggregated
over twenty-one source files, that is a budget the well-covered files pay for the others:
`src/map/lifecycle.ts` sat at **75.93% branch** behind a comfortably passing 88% aggregate, and
`src/sink/spool.ts` at 90.9% while holding the defect in §29 — one transient rename failure killing
the audit sink for the life of the process, silently.

For the record, nobody weakened this. The `100/100/100/100` in the history was set by a docs-only
planning commit with no tests behind it; the first commit with real tests set branches to 79, and
it has been ratcheted upward since. The defect was that it was aggregate, not that it was low.

`perFile: true` is now set and every file carries its own entry at the level it reaches. Vitest
applies the top-level numbers to every file *in addition to* any glob entry rather than instead of
it, so the top level is the floor a newly added file must clear and the per-file entries ratchet
each existing file above it.

Closing the gap came first, and the entries record the result rather than excusing it: branches
went from 88.36% to 97.94% overall and lines to 100%, with thirteen of twenty-one files now at 100
on all four metrics. `src/map/lifecycle.ts` went from 75.93% to 98.39% branch, `src/sink/otlp.ts`
from 50% to 100%. No `v8 ignore` was added anywhere. What remains is the absent half of a few
`field === undefined ? {} : { field }` spreads and of two `error instanceof Error` renderings,
reachable only from inputs no boundary this plugin has produces.

Removing the tests that closed `lifecycle.ts` demonstrates the difference: the per-file gate fails
with `branches (87.7%) does not meet "src/map/lifecycle.ts" threshold (98.39%)`, while the
aggregate it would have been measured against is 95.65% — comfortably past the 88% that was there
before.

## 35. The hash chain is unkeyed, spans a process rather than a session, and says so

**Context.** The README already concedes that an agent which can run `bash` can delete or rewrite
the spool. OCSF 1.9.0 published the `record_integrity` profile on 2026-08-03: an
`attestation_list` on `base_event`, so every class this plugin emits accepts it, and no producer is
known to emit it yet.

**What the schema actually says**, read from
`schema.ocsf.io/api/1.9.0/{profiles/record_integrity,objects/attestation,objects/prev_event,objects/fingerprint}`:

- The fingerprint covers "the entire event, including the attestation's own `authority_uid`,
  `chain_uid`, and `prev_event` attributes, and excluding only the attestation's `fingerprint` and
  `signatures`". That is what makes the chain a chain: the predecessor's fingerprint is inside the
  hashed content, so editing a record breaks the record after it too.
- `attestation.uid` "distinguishes an individual attestation, such as a single entry within a
  tamper-evident chain, from the chain as a whole"; `chain_uid` identifies "the append-only chain,
  such as a forensic or audit log, that this event belongs to".
- `prev_event.uid` is the predecessor's `metadata.uid` and is **required**; `type_uid` "directs a
  consumer to the event class, and therefore the table or store, where the previous event resides".
- `fingerprint.value` is required and `fingerprint.algorithm_id` is required. `algorithm` and
  `encoding` are optional strings defined as the caption of their id.
- The `attestation` object constrains `at_least_one: [fingerprint, signatures]`.

**Where the brief was wrong.** "Every attestation produced during a single agent session shares one
`chain_uid`" is an *example* inside the `chain_uid` description, not a rule the schema states — the
rule is that the uid identifies the append-only log and is "stable for the lifetime of the chain".
A per-session chain would also be the wrong unit here: this plugin's spool interleaves every live
session plus heartbeats that belong to no session, so per-session chains would leave the
interleaving order and the heartbeats uncovered, and would not detect a whole session being cut out
of a file. A chain is therefore **one process writing one file**.

**Decision.** Chain per process per lane. `chain_uid` is a UUID minted at mount, `attestation.uid`
is `<chain_uid>:<index>` counting from zero, and the SOC and restricted lanes get separate chains
because they are separate files carrying different records — a link pointing into the other file
could not be checked from the file it is in.

**The fingerprints are unkeyed SHA-256, and this is the load-bearing decision.** An HMAC keyed the
way `privacy.hmacKey` is would be worse in both directions. The attacker the chain is nominally
against is the agent, which runs at our uid and reads the key out of our process; and a keyed chain
cannot be verified by anyone who does not hold the key, which forfeits the only property that makes
tamper-evidence useful to an auditor. `privacy.hmacKey` is keyed because its job is different: the
secret is what stops a dictionary attack recovering a digested value. Here there is nothing to hide
and only something to bind.

So the honest claim, which `docs/integrity.md` and the README both make in these words, is: the
chain detects a later edit, deletion, or reordering by anything that does not recompute the chain,
and it turns every record already shipped into an anchor the spool can be checked against — leaving
an undetectable-tampering window of one `flushIntervalMs`. It does **not** stop the agent from
writing a consistent forged chain. Overclaiming here would have been worse than not shipping it.

**`authority_uid` and `signatures` are omitted.** Both are "recommended", and both would be a
claim we cannot back: this producer holds no signing credential, so there is no identity to bind
and none to name. The installation that wrote the record is already in `device.uid`, inside the
hashed content. `algorithm` and `encoding` are omitted for a smaller reason — they are the captions
of ids the record already carries, and there are two fingerprint objects per record.

**Canonicalisation is RFC 8785 (JCS)**, documented in `docs/integrity.md` precisely enough to
reimplement: parse the line, drop `fingerprint` and `signatures` from the single attestation, sort
object keys by UTF-16 code unit, no whitespace, `JSON.stringify` number and string rendering, UTF-8,
SHA-256, lower-case hex. The spooled line itself is *not* canonical — it is written in insertion
order — so a verifier parses and re-serializes rather than hashing the line. The documentation
carries a twelve-line Python verifier that shares no code with this package; it agrees with
`dsh-ocsf-verify` on a spool containing quotes, backslashes, control characters, emoji, and a
non-integer number, which is the check that the specification above is the one the code implements.

**Attesting is on by default.** A tamper-evidence feature nobody enables covers nothing, and a
chain enabled halfway through a fleet's life is a chain with a hole in it. The cost was measured
rather than assumed: **29 µs** and **391 bytes** per record, against a mean record of 1369 bytes —
so 29% more spool and 29% more shipped bytes, which is the reason `integrity.attest: false` exists,
and a time cost two orders of magnitude below the 2.7 ms rotation check of §25 that was measurable
in the agent's response time.

**The chain advances only after the sink accepted the record.** A sink that throws leaves the
forwarder's cursor on the unwritten event and the next observation retries it (§15); advancing the
index first would give the retry a different chain position and a fingerprint the previous link
does not match — the plugin would manufacture the break it exists to detect.

**A verifier ships with it.** `dsh-ocsf-verify` is a linked bin over `verifyRecords`, which reads
nothing but spool files: it verifies a live spool together with its rotated generations oldest-first
because the chain runs through the rename, and it separates a chain that starts mid-way (a drained
generation, or a deleted front — the spool alone cannot tell those apart, and it says so) from an
interior gap, which is a break. An empty input reports `NOT VERIFIED` and exits non-zero: an audit
tool that exits zero on a file with nothing in it reports the absence of evidence as evidence.

**`OcsfMetadata.uid` became required.** It was optional and always set. `prev_event.uid` is the
predecessor's `metadata.uid` and the schema requires it, so the alternative was a `?? ''` on a
security path — a link to nothing, emitted as a valid-looking string.
