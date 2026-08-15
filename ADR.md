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

**Decision.** Emit standard classes with `metadata.profiles: ['ai_operation']`, mapping
`ai_agent.instance_uid` to the session id, `ai_model` to the folded `request/context` route, and
`delegation` to subagent lineage. Agent-loop semantics OCSF has no home for (turn, step, call id,
log seq, tool class, phase, approval latency) go into one extension-owned object.

**Why not `unmapped`.** The OCSF FAQ is explicit: `unmapped` "is not recommended for event
producers"; a native producer should extend the schema. `extension.placement: 'unmapped'` remains
available for SIEMs whose validators reject unknown top-level attributes.

**Open point.** `extension.uid: 999` is OCSF's reserved development/private block. Correct for
private deployment, wrong for interchange — a public release must apply for a registered uid, which
is why both name and uid are configuration.

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

`CONVENTIONS.md` §4 adopts 100% per-file coverage. The suite reaches 99.6% lines / 97.8% statements
/ 97.5% functions / 79.8% branches, and the thresholds are pinned there so a regression fails. The
residual branch gap is almost entirely the absent half of `field === undefined ? {} : { field }`
spreads — the optional OCSF attributes — where the covering test would assert that an absent input
field produces an absent output field. That is a real gap, stated rather than hidden.

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
