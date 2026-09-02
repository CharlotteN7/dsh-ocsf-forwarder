---
title: What it does and does not do
nav_order: 1
---

# What it does and does not do

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
  [Delegation](operations.md#delegation-and-the-coverage-boundary).
- Emits a periodic **heartbeat** carrying its counters, the live session count and the delivery
  cursor, so a host that goes quiet is distinguishable from one that is idle. See
  [Heartbeat](shipping.md#heartbeat).
- Chains every spooled record into an OCSF `record_integrity` attestation, so a record edited,
  reordered, or deleted from the middle of the spool is detectable — and, against records the SIEM
  already holds, so is a spool cut short at the end. Ships `dsh-ocsf-verify` to check both. See
  [Tamper-evidence](integrity.md), which also states plainly what the chain does **not** protect
  against.
- Replays a resumed or forked session's constructor seed, which never reaches the live firehose.
- Keeps raw values out of the SOC lane: keyed digests, value classifications, and lengths instead.
  File paths, tool names, executable names, durable identifiers, the names a model gives its own
  tool arguments, and a short list of enumerated outcomes are the exceptions, listed in full — with
  what "enumerated" does and does not guarantee — in [Two lanes](operations.md#two-lanes).

## What it does not do

- **It never writes to the session log.** `Session.append()` cannot set the envelope's `ignorable`
  flag, so a plugin-owned event type makes the next resume throw `SessionFormatUnsupportedError`
  and refuse the entire session while `list()` still shows it. All durable output goes to our own
  sink. The plugin registers no waterfall listener either, so it cannot change a tool call, an
  approval decision, or a model request.
- **It is not a containment boundary.** It runs in the agent's process at the agent's uid. An agent
  that can run `bash` can delete or rewrite the spool — and can recompute the hash chain over what
  it wrote, because the algorithm is published. What the plugin buys you is that records leave the
  host promptly when a shipper is configured, and that a gap is visible: the hash chain's entry
  numbering, `metadata.sequence` holes per session, and a shipper cursor that stopped advancing.
- It ships no detection content, no alerting, and no secret detectors.
