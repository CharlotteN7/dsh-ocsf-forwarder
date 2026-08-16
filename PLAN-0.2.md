# dsh-ocsf-forwarder 0.2 — "deployable"

Theme: turn "needs an OpenTelemetry Collector first" into "points at your SIEM". Transport
is a commodity; the barrier to adoption today is that the only sink is OTLP/HTTP, which on a
developer workstation means standing up a second daemon on a machine the security team does
not own.

Detection content (the actual differentiator) is 0.3. It is deliberately after this release,
because a detection nobody can ingest is worth nothing.

## Bar for every item

Tests to the pinned coverage thresholds, a keyless E2E where behaviour is user-visible, and
a regression test that fails before the change. Do not lower any existing threshold.

---

## F1 — Pluggable transport seam, and a Splunk HEC sink

**Problem.** A SOC running Splunk cannot ingest from this plugin without first deploying a
Collector.

**The shipper is already correctly factored.** The cursor, generation draining, quarantine
and backoff logic in `src/sink/otlp.ts` is wire-format-agnostic. Only two points are
OTLP-specific: `otlpPayload()` and the single post call site. `PostBatch` is already an
injectable function type returning `accepted`/`retry`/`reject`.

**Change.** Rename `OtlpShipper` → `Shipper` and inject a
`Transport { endpoint, headers, encode(records): string, classify(status): BatchOutcome }`.
Roughly 300 lines of drain logic stay untouched. **A transport is an encoder plus a status
classifier and nothing more** — no transport may re-derive cursor semantics.

**HEC contract.** `POST {base}/services/collector/event`, header
`Authorization: Splunk <token>`, body = concatenated JSON objects with no array and no
separators, each `{"time":<epoch seconds>,"host":…,"source":…,"sourcetype":"ocsf:<class_name>","event":<record>}`.
Retry 5xx/timeout; treat 400/403 as `reject`.

> **Verification debt — do this first.** Splunk's documentation returned HTTP 403 to every
> automated fetch during research. The contract above is from research notes, **not**
> freshly verified against a live page. Confirm the endpoint path, the header form, and the
> body framing manually before writing code, and before citing Splunk in any README.

There is no official Splunk add-on for OCSF, so `sourcetype` and field extraction are ours
to define — ship a small props/transforms snippet alongside.

**Optional stretch.** Elastic `_bulk` on the same seam. The one fiddly part: a 200 response
with `errors: true` is a partial failure and **must not** advance the cursor past the failed
items.

---

## F2 — Heartbeat record

**Problem.** An agent that stops reporting is indistinguishable from an agent that is idle.
`metadata.sequence` gaps are detectable within a session; "this host went quiet" is not
detectable at all.

**Change.** A periodic Application Lifecycle (**6002**) record carrying live-session count,
the existing `ForwarderStats` counters, and the shipper cursor position. The interval timer
already exists at `src/index.ts:124`.

**Constraint to state in the README.** OCSF has **no** heartbeat, health-check, liveness or
checkpoint class — confirmed by class enumeration across `ocsf/ocsf-schema`. A chain
checkpoint was proposed during the `record_integrity` review and deliberately deferred. So
this is 6002 plus `unmapped.dsh.kind: 'heartbeat'` until OCSF ships a slot. Say so rather
than implying a standard mapping.

**Detection side is well-trodden** and worth documenting for users: Elastic's
Elasticsearch-query rule supports an "is below" comparator for absence detection (its
separate Threshold rule type is one-directional and cannot); Sentinel has the
`summarize max(TimeGenerated) by Computer` idiom.

---

## F3 — Fleet identity fields

Three `metadata` fields are present in the schema and unused today. Highest value-to-effort
item on the whole roadmap:

- **`tenant_uid`** — the org or business-unit key a multi-team SOC needs.
- **`labels`** / **`tags`** — environment tagging (prod/dev/CI).
- A stable install uid, so a renamed laptop does not become a new device.
- **`metadata.original_time`** — Recommended by OCSF, currently absent.

All configurable, none inferred. No hardcoded tunables.

---

## F4 — Disk-bounded retention

**Problem.** `spoolMaxGenerations` bounds file *count*, not disk usage, so a long collector
outage grows the live file without bound (a stated limitation in ADR §12).

**Change.** Add `spoolMaxTotalBytes` as a second stop condition on the **same
refuse-to-rotate semantics**. This is explicitly **not** a delete policy — ADR §12's
reasoning holds: an audit lane may run out of disk, it may not silently delete
unacknowledged evidence.

What is missing is a louder, earlier alarm. Pair it with a `severity_id: 4` record on the
heartbeat when the spool crosses a high-water mark, so the SOC learns from the SIEM rather
than from a full disk.

---

## F5 — Classification fixes

Two one-line table entries in `src/map/tools.ts` that materially change what a SOC sees:

1. **`cordis_define` / `cordis_run` → Process Activity 1007**, not API Activity 6003. They
   define and evaluate code inside the harness process; the tool-cordis README itself says
   "treat this toolset like bash access". Reclassifying makes every process-based detection
   a SOC already owns fire on them.
2. **MCP server attribution.** MCP tools register as `mcp__<serverName>__<rawName>`. Today
   every one falls through to 6003 as an opaque `tool:<name>`. Parse the prefix, emit
   `unmapped.dsh.mcp_server`, and set `api.service.name = mcp:<serverName>`. Roughly 20
   lines, and it gives a SOC the ability to pivot on which external MCP server an agent
   talked to — the largest supply-chain blind spot in the stack.

---

## F6 — Make external-harness delegation loud

**Problem, and it is the most important thing in this file.** `subagent-claude-code` and
`subagent-codex` spawn a **real external CLI in the parent session's workspace**. There is
**no DSH session for the child**, therefore no session events, therefore **zero telemetry
coverage of everything that child does**. Today that boundary crossing is a generic 6003
record.

**Change.** Emit a distinct, high-severity record when a delegation tool is invoked, stating
in the record that coverage ends at this boundary.

**Blocking constraint, to be handled honestly.** The provider name (`claude-code` / `codex`)
is fixed per plugin row and is **not** in the tool-call payload, so the plugin cannot name
the destination harness from the event alone. Read `ctx.registry` at mount to learn which
subagent providers are composed and stamp that into the session's records, with a
`delegationTools` config map as override. Document that the tool name is a deployment
choice, so the mapping is best-effort.

---

## Out of scope, recorded so it is not re-litigated

- **Detection content** (in-plugin indicators, Sigma pack) — 0.3, the differentiator.
- **`record_integrity` tamper-evidence** — 0.4. OCSF 1.9.0's `attestation` object fits
  uncannily (`chain_uid` = session id, `prev_event.uid` = our existing `metadata.uid`
  format), and its own docs use an agent session as the worked example.
- **Amazon Security Lake sink** — blocked upstream: custom sources support **OCSF 1.3 and
  earlier**, and we emit 1.9.0. Also requires Parquet. Revisit if the ceiling rises.
- **Kafka, Datadog, Sentry, syslog/CEF sinks** — rejected on audience. None is where a SOC
  writes detections.
- **`telemetryTap` mode** — rejected, and the deferral should be **closed** rather than
  carried. Under the shipped `DISABLED` default a tap receives nothing, silently: the worst
  possible failure for an audit lane.
- **Registering an OCSF extension uid** — the third-party block 988–999 is fully allocated.
  Contribute the missing agent-loop attributes to the `ai_operation` profile upstream
  instead.
