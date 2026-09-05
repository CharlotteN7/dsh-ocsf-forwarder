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

> **Superseded in part by [§27](#27-the-install-uid-lives-under-the-harness-home-not-beside-the-spool).**
> "Persisted beside the spool" is what §27 exists to overturn: one host with two spools minted two
> uids and its two OCSF producers disagreed about which device they described. The default is
> `$DSH_HOME/install-uid`. Everything else in this section stands.

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
went from 88.36% to 97.94% overall and lines to 100%. `src/map/lifecycle.ts` went from 75.93% to
98.39% branch, `src/sink/otlp.ts` from 50% to 100%. No `v8 ignore` was added anywhere. What remains
is the absent half of a few `field === undefined ? {} : { field }` spreads and of two
`error instanceof Error` renderings, reachable only from inputs no boundary this plugin has
produces.

The per-file count moves with the file count, so it is stated in one place — the header comment of
`vitest.config.ts`, which the gate is read from — rather than repeated here where it goes stale.

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

## 36. A process without a pid is identified, not invented

Every Process Activity record failed OCSF validation. The `process` object constrains
`at_least_one: [pid, uid, cpid]` and we emitted `{ name, cmd_line }` — so every `bash`, `run_code`,
`terminal_*`, `hook/*` and delegation record was invalid, which is most of what a SOC reads this
plugin for.

The session log never names the child's operating-system pid. `tool/call` carries the tool name and
the model's arguments; `hook/invoked` carries the hook point and the handler id. Neither the harness
nor this plugin ever sees the process the harness launched.

Two ways out were rejected. **Synthesising a pid** — the agent's own `process.pid`, a counter, a
hash of the call id — puts a number in the slot a SOC reads as an operating-system identifier, where
it would join to the wrong process on any host that also ships EDR telemetry. A fabricated process
identifier in a SOC record is worse than an absent object. **Omitting `process`** is not available
either: class 1007 lists it as a required attribute, so a record without it is invalid for a second
reason, and moving the information to `actor.process` would describe the harness rather than the
subprocess — `actor.process` already carries the harness's pid and says so.

`process.uid` is the slot OCSF defines for this: "a unique identifier for this process assigned by
the producer (tool). Facilitates correlation of a process event with other events for that process."
It is set to the correlation uid — `<session>:<callId>` for a tool call, `<session>:hook:<handlerId>`
for a hook — so the launch record and the record of that same process settling carry one identifier,
which is exactly what the attribute is for, and no number claims to be a pid.

`exit_code` moved with it. It is not one of the `process` object's 35 attributes; class 1007 defines
it at the top level of the record, and that is where it is emitted.

## 37. Conformance is checked one level down, because that is where the schema kept being broken

§30 narrowed the top-level check to each class's own definition. The test was still named "adds no
top-level attribute its own class does not define", and it meant it: it walked `Object.keys(record)`
and stopped. `device.bogus_nested_attr` on every record passed it.

Three real violations were behind that. `process.exit_code`, an attribute the `process` object does
not define. `metadata.extensions[].uid` emitted as a number where OCSF types it `string_t`.
`message_context` carrying neither of `at_least_one: [application, service]`. None was reachable by
any test in the suite, and one of them — the extension uid — is invisible until a deployment
configures the key, at which point every record it emits becomes invalid at the SIEM with nothing
local to say so. The conformance run now configures one, so the slot is exercised.

The nested table is narrowed per object exactly as §30 narrows per class, and for the same reason:
transcribing all 35 attributes of `process` or all ~60 of `device` produces a set large enough to
stop discriminating. Constraints are checked too, because `at_least_one` is what the `process`
defect violated and an attribute-only check would have passed it.

## 38. `extension.uid` is a string, and that is a configuration break

OCSF types `extension.uid` as `string_t`; `uid_numeric` is the numeric slot and its own note says a
producer may fill it "only in addition to `uid` and not as an alternative to it". The configuration
validated a positive integer and emitted one.

`extension: { uid: 999 }` no longer loads. That is deliberate. The alternative — accepting a number
and rendering it as a string — silently reinterprets a deployment's configuration, and the registry
assigns the value as a string anyway, so the new form is the one an operator already has written
down. `docs/configuration.md`'s "the ones that count records or files — `spoolMaxGenerations`,
`<shipper>.batchSize`, `extension.uid` — must be whole numbers" was the bug in prose form.

## 39. Nine event types got mappers; four rows got the truth instead

Thirteen of the forty-four rows in `docs/mapping.md` named a class and an activity for an event type
with no `case` in the dispatcher. All thirteen took the generic fallback: API Activity 6003 /
activity `99 Other`, the event type, and nothing else from the payload.

Nine now have mappers, chosen because the fallback dropped a fact a SOC reads the event for: a slash
command's name and arguments, a retry's provider failure code, an inbox splice's insert count, the
agent preset that changed the session's composition, the goal, the plan mode, the model that served
an auxiliary search request.

Four did not, because they are dropped by default and produce no record: `feedback/record`,
`session/title`, `session/title-llm-request` and `todo/write`. Their payloads are the reason they are
dropped — a human remark, a model-written restatement of the prompt, the prompt itself, user and
model task text. Writing a mapper for a path stock deployments never take, and paying its per-file
coverage in tests of a lane the documentation tells people not to open, buys a row in a table. The
rows say what re-enabling them actually produces instead, and the fallback is described once below
the table rather than reproduced in each row.

The table is now read by a test. It must match the harness's `KNOWN_SESSION_EVENT_TYPES` exactly,
once each and in order — the 44-row scope claim, held as an assertion — and every row naming a class
must name what the mapper emits. Against the 0.5.1 dispatcher it names all thirteen wrong rows and
nothing else.

## 40. The published verifier was wrong about our own records

`docs/integrity.md` shipped a Python verifier for third parties with a caveat: `json.dumps` matches
RFC 8785 "for these records: every number in them is an integer, and every object key is ASCII".
Both halves are false, and the failure mode is the worst one an audit tool has — a clean spool
reported as tampered.

A `hook/result` whose `durationMs` is sub-millisecond emits `"duration":1e-7`; Python renders the
same double `1e-07`. One character, and the snippet exits `altered` on a file `dsh-ocsf-verify`
calls INTACT. A model names its own tool arguments, and one holding an unpaired surrogate reaches
`unmapped.dsh.arguments[].key`, where `ensure_ascii=False` emits the raw code point and the
following `.encode("utf-8")` raises `UnicodeEncodeError`. And `extension.name` is a deployment
string that becomes an object key, so key order by code point rather than by UTF-16 code unit is
reachable too.

Restricting the example was considered and rejected: a third party's alternative to this snippet is
running our binary, which is the thing the snippet exists to avoid needing. It now implements
ECMAScript `Number::toString`, ECMAScript string escaping, and UTF-16 key order — about forty lines
— and says why `json.dumps` is not a substitute. Its number rendering was checked against
`JSON.stringify` over 12000 doubles including every boundary of the `Number::toString` exponent
rules. The two renderings it hinges on are pinned in the unit suite, so the page cannot quietly stop
describing what the spool contains.

## 41. What the SOC lane carries verbatim, stated completely

`docs/operations.md` listed the exceptions to the redaction rule and the list was short by five.
Model-chosen argument **names**, a `tool/result` error's `name` and `code`, `compaction/end.error`,
and `hook/invoked.matcher` all reached the SOC lane verbatim and were in no list.

`compaction/end.error` is now digested. It is a rendered failure — a model refusal, or an
exception's message — which is the same category as `turn/end`'s provider failure message, and that
one was already digested. Copying it into `status_detail` was an inconsistency, not a decision.

The other four are documented as deliberate, because a digest of each destroys what it is for. A
digest of the argument name `file_path` groups nothing and tells no one which argument a value
belonged to. An error's class name is chosen by the tool implementation, not composed per call. A
hook `matcher` is deployment-authored configuration, which is a different trust rank from the `grep`
pattern it resembles — that one is model-composed. Each is now a sentinel in the SOC-lane invariant
and appears in that test's list of expected exceptions, so widening the lane means editing a list
somebody has to justify.

The "bounded enumeration" claim was the weakest thing on the page. Only `hook/result.decision` is
reduced to a fixed set. `TurnEndReasonMap`, `ApprovalOutcome` and the sandbox modes are
merge-extensible: an out-of-repo plugin controls those values and they reach `status_detail`
verbatim. The page says so now rather than implying an enforcement that does not exist.

## 42. The counter line names the sink's drops, because `forwarded` never could

`docs/operations.md` said the periodic `forwarded=… dropped=… unreadable=… failed=…` line says
whether an outage is delaying records or consuming them. It cannot. `forwarded` counts records
handed to the sink; a spool that lost its descriptor accepts every record and drops it, and a dead
sink therefore reported `{forwarded: 3, dropped: 0, failed: 0}` — the same line a healthy one writes.
`dropped` is the drop *policy*, and `failed` is a contained exception in the listener; neither has
ever said anything about the spool.

The line now carries `sink_dropped` and `sink_failed` from the same `pressure()` call the heartbeat
already used, so the claim is true rather than the sentence being softened. The heartbeat's
`sink_failed` / `sink_dropped_records` at `severity_id: 5` remain the off-host signal, and the doc
now says which counter answers which question.

## 43. An OTLP query string survives the default path

`https://collector.test/?tenant=7` resolved to `https://collector.test/v1/logs`. The default path was
applied by constructing a URL from the path alone, which drops the query with it — and a collector
routing on `?tenant=7` then received every batch on its default tenant, with nothing anywhere saying
so. The two branches also disagreed: an endpoint that already named a path kept its query.

The query is preserved in both branches now. This is a silent-misdelivery fix, not a validation one:
there was no value to reject, only a value to stop discarding.

## 44. A suffix truncation is caught against a shipped record, and by nothing local

Against the shipped verifier, three spools built from one chain:

```
clean spool                INTACT   exit 0
interior record deleted    BROKEN   exit 1
last 3 records removed     INTACT   exit 0
```

Each record links to its predecessor, so a deletion breaks the record *after* the hole. Delete from
the end and there is no record after the hole: what remains is a shorter chain whose every link
still matches. `docs/integrity.md` claimed "a deletion is detected, by the gap in consecutive chain
entries" — true of an interior deletion, false of a suffix one, and the suffix one is the tampering
to expect, because erasing one's own recent activity needs no key and no code.

**How long a chain should be is not derivable from the chain.** No arrangement of hashing inside the
file fixes this; the length has to come from a party that cannot rewrite the file. So
`dsh-ocsf-verify --anchor` takes records back from the SIEM — one JSON record per line, as an export
gives them — and reports `truncated` when a chain stops before an entry an anchor accounts for, and
`anchor-mismatch` when the record at an anchored entry is not the one that shipped. The second is
what stops a tail rewritten to the right length from passing a length check.

**Rejected: adding the chain head to the heartbeat payload.** That was the obvious mechanism and it
is already built. Every attested record carries `attestation.uid` = `<chain_uid>:<entry index>` and
`attestation.prev_event.fingerprint`, both inside the hashed content, and the shipper posts spool
lines verbatim — so a shipped heartbeat *is* the claim "this chain reached entry N, and entry N-1
was this record". Copying those into `unmapped.dsh` would have added a field that is wrong in one of
the two lanes: the heartbeat record is built once and written to both chains, which have different
`chain_uid`s and different indices, so it would have had to be built per lane to carry a per-lane
fact already printed on the record beside it. It would also have needed new SOC-lane sentinels for a
value that is a hash. The heartbeat's real contribution is that it exists at all: it is what puts a
recent entry of every chain on the wire from a host that did nothing, so there is always something
to anchor on.

**Not a finding: an anchor naming a chain with no records in the input.** The shipper unlinks a
generation once the collector has acknowledged every byte in it, so a fully drained chain is absent
from the spool for entirely ordinary reasons and looks exactly like one deleted wholesale. Those
anchors are counted and the ambiguity is named; they do not change the exit status.

**An unknown option is now a usage error.** It used to be dropped: `--anchors` was filtered out as
an option and its operand read as a second spool, so the anchored check silently did not happen. A
truncation check that quietly does not run is worse than one that was never asked for.

## 45. `Session.events` became `snapshotEvents()`, and the peer ranges never admitted a prerelease

Four separate findings, one dependency pass. §33 widened the DSH peers to `^0.1.0-rc.6` believing
that "admits every prerelease of `0.1.0` from rc.6 up". It does — and nothing else. Checked with
the repository's own `semver@7.8.5`:

| version | `^0.1.0-rc.6` | `>=0.1.0-rc.6 <0.2.0 \|\| >=0.1.1-rc.0 <0.1.2-0 \|\| >=0.1.2-alpha.0 <0.1.3-0` |
|---|---|---|
| `0.1.0-rc.5` | no | no |
| `0.1.0-rc.6` / `-rc.7` / `-rc.8` | yes | yes |
| `0.1.1-rc.1` / `-rc.2` | **no** | yes |
| `0.1.1` | yes | yes |
| `0.1.2-alpha.2` / `-alpha.5` | **no** | yes |
| `0.1.2`, `0.1.3` | yes | yes |
| `0.1.3-rc.1` | no | **no** |
| `0.2.0-rc.1`, `0.2.0`, `1.0.0` | no | no |

node-semver lets a prerelease satisfy a range only when some comparator in the same set carries a
prerelease tag **and** the identical `major.minor.patch`. `^0.1.0-rc.6` desugars to
`>=0.1.0-rc.6 <0.2.0-0`, whose only prerelease comparator is on the `0.1.0` tuple — so the version
the `@deepseek-ai/dsh` CLI's `latest` tag points at, `0.1.1-rc.2`, was outside a range the e2e suite
had been passing against for weeks. One comparator set per prerelease patch tuple is the only way
to express this, which is why `0.1.3-rc.1` is not covered: each new prerelease line stays out until
someone runs the suite against it and adds a set, and that is the point of the enumeration.

**`Session.events` was replaced, not removed.** `Session.snapshotEvents(fromSeq?, toSeqExclusive?)`
landed in `@deepseek-ai/dsh-session@0.1.2-alpha.4` (`events` is still present in `alpha.2` and
`alpha.3`). Called with no arguments its implementation returns the same cached frozen array of the
whole log from index zero that the accessor returned, so the seed replay and the catch-up walk need
no redesign. `header.seedLength` moved in the same release to `Session.inheritedEventCount`, and
there it is not merely absent — the header parser throws on a `seedLength` key. `logOf` and
`seedLengthOf` read whichever spelling the resolved version has. That is not a shim for a capability
that went away; it is a choice between two published spellings of one that did not, and the peer
range admits versions on both sides of the change.

The break is not hypothetical and not gradual. Against `dsh@0.1.2-alpha.5` the unported plugin
mounted, the agent ran, and the spool held no session records at all — `catchUp` read `undefined`
and threw into the listener's containment once per event. The whole e2e suite passes against
`0.1.2-alpha.5` with the port.

**cordis went to `^4.0.1`.** §33 kept it at exactly `4.0.1` so that "two copies are two graphs". A
peer range installs nothing, so an exact pin cannot prevent a second copy — it can only refuse the
tree, which is what it did: `@deepseek-ai/dsh-session@0.1.2-alpha.5` peers `@deepseek-ai/cordis@^4.0.2`,
and a project on that line got `ERESOLVE ... peer @deepseek-ai/cordis@"4.0.1" from dsh-ocsf-forwarder`.
Every file `4.0.2` ships is byte-identical to `4.0.1`; only its own `package.json` moves. `^4.0.1` is
what DSH's own packages declare, and being stricter than the application that owns the graph buys
nothing.

**The devDependencies moved to `0.1.1-rc.2`**, so what the types are checked against is the newest
line the range promises rather than the oldest. Two consequences were handled rather than avoided.
`KNOWN_SESSION_EVENT_TYPES` went from 44 to 48 and `mapping-doc.spec.ts` named the four missing
rows; `team/member`, `team/message/delivered`, `team/message/queued` and `team/task` take the
generic fallback, and the table now says so instead of claiming a coverage it did not have. No
installed package declares their payloads — `dsh-session` lists the types and the interfaces are
declaration-merged by a package this plugin does not install — so there is nothing to map by name,
and two of them are now sentinels in the SOC-lane invariant because a queued team message is
agent-to-agent text the fallback must not read.

The other consequence: pnpm auto-installs the peers those devDependencies declare and resolves each
from its `latest` dist-tag, still `0.1.0-rc.6` for every `@deepseek-ai/dsh-*` package. Left alone
the development graph became two versions of one harness and `pnpm peers check` reported ten unmet
peers where it had reported none. They are pinned in `pnpm-workspace.yaml` `overrides` rather than
added as devDependencies, because nothing here imports any of them.

---

## 46. An append-only spool keeps its appends and loses its rotation

**Context.** `chattr +a` is the standard Linux hardening for an audit file: writes at the end
succeed, `ftruncate` and any `open` without `O_APPEND` return `EPERM`, and clearing the attribute
needs `CAP_LINUX_IMMUTABLE`. §44 made a truncated spool *detectable* against shipped records; this
makes it *hard*. The spool blocked it: `open(…, 'a', mode)` applies the mode only when it creates
the file, so an existing spool is re-stated with `fchmod`, and on an append-only file that call
returns `EPERM` and took the whole plugin down with it. Verified against `dsh@0.1.1-rc.2`: the
constructor threw, the plugin tree failed to load, and `dsh` exited non-zero before the agent
started. Not a degraded audit lane — no agent at all.

**Decision.** Tolerate `EPERM` from that `fchmod` and keep the descriptor. A spool this process
cannot chmod but can append to is a working spool; failing every write because the mode could not
be *re-asserted* hands an attacker the outage that hardening the file was meant to prevent. Every
other errno stays fatal, and the descriptor is closed before the throw rather than leaked — the
old code leaked one per refused open, which on the reopen path is one per record while a spool is
failing.

**Why the re-assertion still exists.** Without it an existing spool keeps whatever permissions it
was left with, which is exactly the case a fresh `open` cannot fix. Dropping the call would trade a
loud, rare failure for a silent, permanent one.

**Silence is conditional.** The tolerated `EPERM` warns only when the file grants bits the
configured mode does not. A file already at or inside the configured mode is what the `fchmod`
would have produced, so there is nothing for an operator to act on; wider bits are the SOC lane
readable by accounts the configuration meant to exclude, and no code here can fix that.

**Rotation is not made to work, because it cannot be.** `rename` on an append-only file is `EPERM`
too, so the live file can never become a generation. That failure already had correct handling —
report once, reopen the live file immediately, stand off a minute, report `rotation_stopped` — so
an append-only spool degrades into a permanently un-rotating one that drops nothing and says so.
Adding a config key to *express* that would be a second way to state what the filesystem already
says, and a rotation-disabled mode would still not reclaim the disk. The trade is documented
instead: append-only means unbounded growth and a privileged manual reclaim with the agent stopped.

**The directory attribute is a trap, and is documented as one.** `chattr +a` on the spool's
directory permits create, append, `chmod` *and truncate* on the files inside — so it buys nothing
against truncation — while refusing `unlink` and `rename`. That breaks rotation, breaks the
shipper's removal of a drained generation (which then blocks delivery of everything behind it), and
breaks `acquireLock`'s takeover of a lock left by a dead process, so one crash makes the plugin
unmountable. Every row of both tables in `docs/hardening.md` was executed against a real ext4 file
rather than reasoned about.

**What is proven and what is argued.** The unit and end-to-end tests set the real attribute where
this process can take `CAP_LINUX_IMMUTABLE` and skip where it cannot; an injected `EPERM` at the
`fchmodSync` seam covers the handling unconditionally, and the test file says which is which. The
skip is honest rather than silent: on a runner without the capability the append-only claims in
this repository are covered by the injected half only.

---

## 47. The three event types `0.1.2` added, and the four `team/*` ones nobody read

**Context.** §45 moved the devDependencies to `0.1.1-rc.2` and recorded that the four `team/*`
types take the generic fallback because "no installed package declares their payloads". Both halves
of that had aged. The peer range `~0.1.2-alpha.0` admits every `0.1.2` prerelease — node-semver
puts `0.1.2-rc.1` inside it — so the newest line the range promises had moved three releases past
what the devDependencies were checked against, and `KNOWN_SESSION_EVENT_TYPES` had grown from 48 to
51 as of `0.1.2-alpha.5` without the table noticing. And the `team/*` payloads are not undeclared: the merged
`SessionEventMap` the harness compiles its own vocabulary against is published inside every
`lib/typert.host.js` a harness package ships, `TeamMemberSnapshot`, `TeamMessageSnapshot` and
`TeamTaskSnapshot` included. Nothing here reads payloads through their types anyway — `src/read.ts`
exists because `SessionEventMap` is merge-extensible and every payload arrives from a durable log.

**Decision. Seven of the eight took a mapper.** The devDependencies and the `pnpm-workspace.yaml`
overrides moved to `0.1.2-rc.1` together, because `dsh-session@0.1.2-rc.1` reaches
`dsh-typert-protocol` through `dsh-llm` and an override pinned three releases back turns
`import { KNOWN_SESSION_EVENT_TYPES }` into a missing-export error.

- **`session-log-deepseek/delivery-accepted` → API Activity 6003 / `1 Create`.** The one session
  event that says the audit subject left the host: the base bundle's `session-log-deepseek` row,
  enabled, attaches the log's own canonical event envelopes to every model request and appends this
  event when the endpoint takes them. `severity_id: 2`, deliberately not high — acceptance is
  appended once per *successful model request*, and grading each one an incident buries the index.
  What acts is the record existing at all where policy forbids the upload, plus
  `api.service.name`. `delivered_after_seq` and `delivered_event_count` appear only once a
  preceding watermark has been observed; the first delivery says `first_observed_delivery` rather
  than subtracting from an assumed `-1`, which would claim the whole log went in one upload. A
  marker naming another session was inherited through a fork seed — the harness's own invariant —
  and is graded `severity_id: 1`, because nothing left on this session's account.
- **`team/message/queued` → API Activity 6003 / `1 Create`,** with the sender's session, the
  target's session, and `delivery`. `wakeup` is `severity_id: 3` and `quiet` is `2`: one makes the
  target act on the text now, the other waits for its own next turn. This is one agent putting
  instructions into another agent's inbox, and the fallback carried no sender, no target and no
  delivery mode. `team/message/delivered` closes the pair on `messageId`.
- **`team/member` → Application Lifecycle 6002 / `3 Start`,** and the second event type that names
  a child session by id, so it builds the same `delegation` link `tool-workflow/agent-start` does.
  §31's "the one event that names a child" is no longer true and the mapping table says so.
- **`team/task` → API Activity 6003 / `3 Update` or `4 Delete`.** `write_scopes` verbatim, on
  `file.path`'s reasoning: a path pattern is what a detection matches. **No `1 Create`**: the
  payload is a snapshot with a revision whose origin is unreadable here, so calling one of them the
  creation would be a guess.
- **`subagent/model-selection-policy` → Authorize Session 3003 / `1 Assign Privileges`,** as
  `privileges: [subagent-model:<provider>/<model>]`. It is a grant of a set of external endpoints,
  not a settings change. A policy naming no complete route produces **no record**: OCSF constrains
  the class `at_least_one: [privileges, groups, iam_roles]` and this plugin emits neither of the
  other two, so an empty grant is not a valid record and the event is reported unreadable.
- **`model/selection` → Application Lifecycle 6002 / `8 Update`,** carrying `ai_model`. It does
  **not** fold `state.aiModel`. `request/context` records the route a request actually used; a
  selection is what the *next* one should use, and folding it in would attribute every record
  between the two to a model that has served nothing.

**What is proven and how.** Every one of the twenty-eight new mapping assertions was run against
the previous code first and failed there; two that passed were rewritten until they did not,
because a test that passes against the generic fallback proves nothing about the mapper replacing
it. The eight types are in the conformance run, so their records are checked against the OCSF
1.9.0 class and object definitions rather than against the union — a `file` object added to the
`team/member` mapping is rejected as `6002: file`. The session-log delivery has an end-to-end test
that enables the row in a real profile, boots a real `dsh`, and asserts the mock's captured request
body carried `dsh_session_log` with the log's own events in it: the record and the egress it
describes are checked against each other rather than separately.

**What is not proven.** No package installed here emits any `team/*` event; `dsh-session` lists the
four types and the emitter is not in the `0.1.2-rc.1` tree. The payload fields come from the
harness's published Typert declaration catalogue, and the mappers read every one of them through
`src/read.ts`, so a build whose emitter writes something else yields absent attributes rather than
wrong ones — but no run in this repository has produced one of these events.

---

## 48. Anchors bound a chain from below, and the page claimed more than that

**Context.** §44 built anchoring: shipped records carry their own attestations, so the SIEM holds a
claim about how far a chain got that the writer of the spool cannot edit. `docs/integrity.md` then
said that any later rewrite "must either leave those records exactly as they were or produce a
chain that disagrees with what the SIEM already has, and `dsh-ocsf-verify --anchor` makes that
comparison". Run against the shipped verifier, it does not.

**What was measured.** Five spools, one honest and four tampered, verified with the published
`bin/dsh-ocsf-verify.mjs` and the exit status read directly rather than through a pipe:

| Tampering | Report | Exit |
|---|---|---|
| Cut entries 7-9 off the anchored chain | `truncated` | 1 |
| Edit entry 4 of the anchored chain, re-hashing the rest | `anchor-mismatch` | 1 |
| Replace the file with a fresh 7-entry chain under a new `chain_uid`, dropping 7-9 and editing 4 | `INTACT` | **0** |
| Append a second self-consistent chain of records that never happened | `INTACT` | **0** |
| Continue the anchored chain past entry 9 with records that never happened | `INTACT` | **0** |

**The reading.** `chain_uid` is minted by the writer and bound to nothing the writer cannot forge,
and `verifyRecords` counts an anchor naming an absent chain in `unmatchedAnchors` rather than
raising a finding, so `intact` stays true. A rewrite under a new chain does not *disagree* with the
anchors; it fails to *overlap* them and the comparison never runs. Its only trace is a line the
integrity page itself teaches operators to read as a shipper that drained a generation. And in the
other direction anchors say nothing at all: they bound a chain from below — entries `0…N` existed
and were these — never from above, so records can be *added* past `N`, or in a chain the SIEM has
never seen, and nothing contradicts them.

**Decision: state it, pin it, and do not change the exit code.** The overclaiming sentence is
corrected, a `Re-chaining and fabrication` section carries the table above, and
`tests/unit/integrity-tamper.spec.ts` pins all five outcomes so the day someone makes an
uncorroborated chain a finding, the pins fail and the decision gets recorded rather than absorbed.
Making `unmatchedAnchors > 0` fail today was rejected: on a host whose shipper legitimately drained
and unlinked a generation it is routine, and a check that fails routinely trains operators to
ignore it, which is the failure this whole design is trying to avoid. The query that *would* close
it — does the SIEM know this installation's chains, and does the spool contain the chain it last
saw — belongs to the SIEM, which holds both sides of it, and the page says so instead of pretending
the local verifier can.

## 49. An uncorroborated chain is a finding, and the count it replaced is a flag

§48 recorded that a spool replaced wholesale under a fresh `chain_uid` verified `INTACT` and exited
`0`, because the forged chain never *disagrees* with an anchor — it fails to *overlap* one, and the
comparison never runs. The only trace was the line `N anchor(s) name a chain with no records here`,
which `docs/integrity.md` itself teaches operators to read as a shipper that drained a generation.

Since 0.8.0 that absence is the finding `uncorroborated-chain`, and it exits `1` by default.

The cost is real and was weighed rather than discovered later. A host whose shipper legitimately
drained and unlinked every generation of a chain produces a byte-identical report, and **nothing on
that host distinguishes the two** — the spool cannot testify about records it no longer holds. So
the default makes a class of honest installation report `BROKEN`, and the counter-argument to it is
the strongest one in this file: a check that fails routinely trains operators to ignore it, which
costs more than it buys.

It is the default anyway, for one reason: a whole-spool replacement leaves *no other trace at all*.
Every other tampering shape this verifier knows about is caught by the chain itself. This one was
caught by nothing, and a control that stays silent on the single move that erases history is worse
than one an operator has to reason about. `--no-strict-anchors` restores the count, and reaching for
it is a claim about that host's retention.

The finding is raised **per chain, not per anchor** — twenty anchors on one absent chain is one
thing wrong, and the `chain_uid` is what an operator carries to the SIEM. It is raised only when
anchors were supplied, because with none there is nothing to corroborate against.

What this does **not** close is direction. Anchors still bound a chain from below and never from
above, so the fourth and fifth rows of §48's table — a second fabricated chain beside an intact one,
and records appended past the last anchored entry — disturb no anchor and are reported by neither
setting. Those remain pinned in `tests/unit/integrity-tamper.spec.ts` as limitations. The query that
closes them belongs to the SIEM, which holds both the delivered stream and the roster of
`chain_uid`s an installation ever shipped under; this verifier sees one host's files and cannot.

## 50. The `inspector` seam is declared, unimplemented, and not ours to provide

`@deepseek-ai/dsh-tool-cordis@0.1.2-rc.1` publishes the API catalogue the model reads. At
`lib/index.js:1558` it declares the seam key `inspector` — "Shared Host/Client service façade over
the realm's source publisher" — with two members: `publish(topic, payload, monotonicMs?): void` and
`readonly cordis: CordisRuntimeTreeReader`. Nothing provides it and nothing consumes it: across the
660 JavaScript files in the 224 `@deepseek-ai` package directories of the rc-1.2.1 cache, the word
appears only in that catalogue, in `dsh-subprocess-local`'s process inspector, and in
`dsh-client-ui-trajectory`'s record inspector, none of which is a context service. Four of the
catalogue's 68 keys have no provider there — `agentTeams`, `e2b`, `inspector`, `lsp` — and
`@deepseek-ai/dsh-e2b` and `@deepseek-ai/dsh-lsp` both resolve on the npm registry, so absence from
this cache is not evidence a key is unimplemented upstream. `@deepseek-ai/dsh-inspector` is a 404,
and none of the 241 `@deepseek-ai` names the registry search returns contains `inspect`.

This package is the observability one, so providing that key and turning published observations into
spooled OCSF records is the obvious home for it. It was measured rather than assumed, and it is not
being built. Four findings, of which the first two are each sufficient.

**Collision has no safe design.** `ReflectService.provide` (cordis 4.0.2, `src/reflect.ts`) throws
`service "<name>" has been registered at <fiber>` when the store already holds the key, inside the
`ctx.fiber.effect` it opens, so the second provider's fiber fails. What the second provider is
decides how bad that is:

| Load order | Our fiber | Harness fiber | A consumer that `inject`s `inspector` |
|---|---|---|---|
| Harness first | FAILED | ACTIVE | binds the harness implementation |
| Us first | ACTIVE | FAILED | **binds ours**, and reads `.cordis` as `undefined` |

The second row is the one that matters. The harness does not fail to boot; it boots with our object
in the seam, and its own consumers keep running against a façade whose second member does not exist.
Releasing our registration afterwards does not repair it — the failed fiber stays FAILED, the
consumer drops back to PENDING, and the key resolves to `undefined` for the rest of the process.
Standing down on detection covers only the first row: `ctx.get('inspector', false)` sees a provider
that already registered and cannot see one that registers later, and cordis offers no signal between
the two. Providing inside `ctx.isolate('inspector')` does avoid the collision — both fibers stay
ACTIVE and the consumer reaches the harness — precisely because nothing outside our own subtree can
see what we registered, which is not a seam.

Half the seam is also unimplementable here. `CordisRuntimeTreeReader.getTree(): Promise<CordisRuntimeTree>`
returns the harness's own runtime topology in the shape its inspector expects. Supplying that from
this package means inventing it, and a partial façade is exactly the hollow centre the no-stubs rule
exists to prevent, since a consumer reading `.cordis` gets `undefined` with nothing to distinguish
"not provided" from "provided by something that could not implement it".

**Attribution is advisory and forgery costs one line.** Cordis does carry a caller identity: a
`Service` sets `[symbols.tracker] = { associate: name, property: 'ctx' }`, so inside a method reached
as `ctx.inspector.publish(...)` the service's `this.ctx` is the *reading* context and
`this.ctx.fiber.name` names the calling plugin. It survives no adversary. The raw instance is one
property read away at `ctx.reflect.store[ctx[Context.isolate]['inspector']].value`, and

    raw.publish.call({ ctx: { fiber: { name: 'plugin-alpha' } } }, 'topic', {})

writes a record attributed to `plugin-alpha` from code that is not `plugin-alpha`. The honest path is
the fragile one: a detached `const p = ctx.inspector.publish` throws, because the traceable wrapper
binds `this` per property read. An attribution field in a SOC record that any in-process caller can
set to any other plugin's name is worse than no field, and it is not covered by the limitation this
package already discloses — that is about an agent that can run `bash`, whereas this is available to
a plugin holding nothing but a context.

Behind the forgery is the property the package rests on. Every record it emits today is a function of
a `session/event` the harness itself appended; the forwarder asserts nothing the harness did not
already assert. `publish()` ends that. It makes the audit spool writable by anything in the process,
at a rate bounded by the caller rather than by the harness's own activity — and §12 and §21 fix what
happens then, because rotation stops rather than deleting, so a flood is an eviction attack on the
live file's remaining room. Those records would need their own lane and their own chain, on §7's
terms, which contains the damage without addressing it: nothing consumes this seam today, so the
lane would ship empty, and the only party with a present reason to call `publish()` is one that wants
a byte into the SOC's evidence.

**Bounds and OCSF shape were both answerable, and neither rescues it.** A rate cap, a payload byte
cap, and a serialisability check with the rejects counted into the heartbeat follow the precedent
`batchSize`, `spoolHighWaterBytes` and `droppedRecords` already set; `publish` returning `void` means
the counter is the only channel back, which the heartbeat already is. For the record shape, OCSF
1.9.0 does define a home: `base_event`, `class_uid` 0 and `category_uid` 0, "a generic and concrete
event ... could be used to log events that are not otherwise defined by the schema", carrying
`unmapped` and supporting the `record_integrity` profile. Mapping an arbitrary third-party topic onto
6003 API Activity would misrepresent it; `base_event` would not. It is not free — its required set
includes `osint` and `cloud`, neither of which this package emits — but it is a real answer to a real
question, and the decision does not turn on it.

**Decision: do not provide `ctx.inspector`.** Not under a flag, and not with a stand-down check,
because the check only covers the harmless direction and the harmful one is silent. What would
change the answer is a harness that provides the key itself, at which point this package's move is
the opposite one — `inject` it and read what others publish, with the harness owning both the
identity of the publisher and the lifetime of the seam.
