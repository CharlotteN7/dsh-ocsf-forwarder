---
title: Delegation, identity, lanes
nav_order: 6
---

# Delegation, identity, lanes

[← dsh-ocsf-forwarder docs](index.md)

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
| `device.uid` | `fleet.installUid`, or a uid minted once and persisted at `fleet.installUidPath`, which defaults to `$DSH_HOME/install-uid`. A hostname is not an identity: it changes when a laptop is renamed and collides across a fleet imaged from one template. The path is under the harness home rather than beside the spool so that `dsh-netguard`, whose spool is elsewhere, reports the same `device.uid` for this machine. A uid an earlier release left at `<spoolPath>.install-uid` is carried over on first run, so upgrading does not re-identify the host. Persisting is best effort: a home this process cannot write costs the uid its stability across restarts, and is reported, but never fails the mount. |
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
| `metadata.uid` = `<session>:<seq>` | The idempotency key. Deduplicate on it. `<seq>` is the session log's own event sequence. `dsh-netguard` writes `<session>:netguard:<seq>` over a counter of its own, so deduplicating an index holding both packages does not drop its records as duplicates of these. |
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

**A write failure never ends the spool.** Renaming the live file is the one moment the spool holds
no descriptor, so a failure there — a directory permission changed under it, a filesystem that went
read-only — is reported through the plugin logger and a descriptor is taken again immediately: on
the new generation when the rename went through, on the original file when it did not. Rotation is
then held off for a minute and `rotation_stopped` reads true, exactly as a refused rotation reads.

If the descriptor cannot be taken back at all, the spool says so rather than accepting records into
nothing. Every record it drops is counted, the first one logs a warning, and the heartbeat carries
`sink_failed: true` with `sink_dropped_records` at `severity_id: 5`. Each later write retries the
open — immediately on the first attempt, then backing off from 250 ms to 30 s — and the first
success logs how many records were lost in between. None of this is configurable: nothing about a
deployment makes a different retry rate correct, and a slower first retry only destroys evidence
whose cause has already cleared.

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
[Shipping to a SIEM](shipping.md#splunk-http-event-collector) and differs on 401 and 403.
