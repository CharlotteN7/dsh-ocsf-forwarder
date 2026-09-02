# dsh-ocsf-forwarder

A read-side SIEM forwarder for [DeepSeek Harness](https://github.com/deepseek-ai). It observes the
session event firehose, normalises every event to **OCSF 1.9.0** with the native `ai_operation`
profile, and writes newline-delimited OCSF JSON to a local append-only spool — optionally shipping
it to **Splunk HTTP Event Collector** or an **OTLP/HTTP** collector.

📖 **[Full documentation](https://charlotten7.github.io/dsh-ocsf-forwarder/)** — including the
complete event → OCSF mapping table for all 48 session event types.

## What it does

- Subscribes to `session/event`, `session/created` and `session/disposed`, and sweeps
  `ctx.sessions.list()` at mount.
- Correlates `tool/call` ↔ `tool/result` and `approval/asked` ↔ `approval/decided`, emitting
  **approval decision latency** — the approval-fatigue signal.
- Classifies tool calls by what they do: shell and code execution → Process Activity (1007),
  file tools → File System Activity (1001), web tools → HTTP Activity (4002), approvals and
  sandbox changes → Authorize Session (3003), everything else → API Activity (6003).
- Names the MCP server behind every `mcp__<server>__<tool>` call.
- Emits a **high-severity record when a tool hands the task to an external harness**, stating in
  the record that telemetry coverage ends at that boundary.
- Emits a periodic **heartbeat** carrying counters, live session count and delivery cursor, so a
  host that goes quiet is distinguishable from one that is idle. A spool that has stopped writing
  reports itself there at `severity_id: 5`, with the count of what it dropped.
- Chains every spooled record with the OCSF **`record_integrity`** profile, and ships
  `dsh-ocsf-verify` to check the chain.
- Replays a resumed or forked session's constructor seed, which never reaches the live firehose.
- Keeps raw values out of the SOC lane: keyed digests, value classifications and lengths instead.

## What it does not do

- **It never writes to the session log.** `Session.append()` cannot set the envelope's `ignorable`
  flag, so a plugin-owned event type makes the next resume throw `SessionFormatUnsupportedError`
  and refuse the entire session. All durable output goes to our own sink, and the plugin registers
  no waterfall listener, so it cannot change a tool call, an approval decision or a model request.
- **It is not a containment boundary.** It runs in the agent's process at the agent's uid; an agent
  that can run `bash` can delete or rewrite the spool — and can recompute the hash chain over what
  it wrote, because the algorithm is published. What it buys you is that records leave the host
  promptly and that a gap is *visible* — the chain's entry numbering, `metadata.sequence` holes per
  session, and a shipper cursor that stopped advancing.
- It ships no detection content, no alerting and no secret detectors.

[The full scope statement →](https://charlotten7.github.io/dsh-ocsf-forwarder/)

## Install

The profile must already compose a runnable agent — a profile carrying only
`@deepseek-ai/dsh-base` has no agent loop and this plugin would observe nothing:

```sh
dsh plugin --profile <name> add @deepseek-ai/dsh-headless@0.1.1-rc.2
dsh plugin --profile <name> add dsh-ocsf-forwarder
dsh --profile <name> --dump-config      # verify the row is mounted
```

Pin `@deepseek-ai/dsh-headless` explicitly — the `@deepseek-ai/dsh-*` libraries' npm `latest` tag
still points at `0.0.1-rc.1`. Install from the registry or a packed tarball, **not** from a git
spec: `lib/` is a build output git does not carry.

Runs on dsh `0.1.0-rc.6` through `0.1.2-alpha.5`; CI runs the end-to-end suite against every line
in that range.

[Install in full →](https://charlotten7.github.io/dsh-ocsf-forwarder/install.html)

## Configure

```yaml
- id: dsh-ocsf-forwarder
  config:
    spoolPath: /var/log/dsh/ocsf.jsonl      # absolute; created 0640
    splunk:
      endpoint: https://splunk.example:8088
      token: { source: env, variable: SPLUNK_HEC_TOKEN }
    privacy:
      hmacKey: { source: env, variable: DSH_OCSF_KEY }
```

Every numeric key that is resolved must be a positive finite number, and those counting records or
files must be whole numbers — `statsIntervalMs` is the one exception, where `0` means "only at
unload". A value outside those ranges fails at load, because the alternative is worse than a
refused mount: `batchSize: 0` makes the shipper loop without ever advancing its cursor. A shipper
block with no `endpoint` configures no shipper and is not resolved, so nothing in it is checked.

The default privacy posture keeps raw values out of the SOC lane — argument values and command
lines are digested, URLs reduced to their host. A second **restricted lane** carries verbatim
payloads and must be explicitly acknowledged before it will open.

[Every configuration key →](https://charlotten7.github.io/dsh-ocsf-forwarder/configuration.html) ·
[Record format and the mapping table →](https://charlotten7.github.io/dsh-ocsf-forwarder/mapping.html)

## Shipping to a SIEM

Splunk HEC and OTLP/HTTP are both supported; configure exactly one per spool. Delivery is
cursor-based off the spool, so a collector outage costs nothing but disk, and the spool refuses to
delete an un-drained generation rather than silently discarding unacknowledged evidence.

[Splunk and OTLP setup →](https://charlotten7.github.io/dsh-ocsf-forwarder/shipping.html) ·
[Delivery and failure modes →](https://charlotten7.github.io/dsh-ocsf-forwarder/operations.html)

## Tamper-evidence

Every record carries an OCSF 1.9.0 `record_integrity` attestation: the SHA-256 fingerprint of the
record, plus the uid and fingerprint of the record before it. Editing, reordering, or deleting a
record from the middle of a spool breaks the chain at that record and at the one after it.

```sh
dsh-ocsf-verify /var/log/dsh/ocsf.jsonl                       # 0 intact, 1 broken, 2 unreadable
dsh-ocsf-verify --anchor shipped.jsonl /var/log/dsh/ocsf.jsonl
```

Deleting from the **end** breaks nothing — the shorter chain still verifies — so that check needs a
reference the writer cannot reach. Every shipped record is one: `--anchor` takes records back from
the SIEM and reports a spool that stops short of them. Without anchors the report says `no anchor`
rather than implying it checked.

The fingerprints are **unkeyed**, so anyone can recompute them — which is the point, and which also
means the chain does not resist the agent it observes.

[The canonicalisation, the threat model, and the cost →](https://charlotten7.github.io/dsh-ocsf-forwarder/integrity.html)

On Linux the complementary move is `chattr +a` on the spool, which makes truncation and rewriting
fail rather than merely detectable. The plugin tolerates the `chmod` that attribute refuses — but
it also refuses the rename, so **rotation stops permanently** and the file's size becomes a manual
job. Harden the live spool file only; hardening its directory breaks the mount.

[What `chattr +a` buys, costs, and breaks →](https://charlotten7.github.io/dsh-ocsf-forwarder/hardening.html)

## Running it with `dsh-netguard`

Both packages emit OCSF into one index and share the `correlation_uid` scheme
`<session>:<callId>`, so a Network Activity record from netguard joins to this package's Process
Activity record for the same tool call — answering *which tool call opened this connection*.

`metadata.uid` is deliberately **not** shared: this package's key is `<session>:<seq>` over the
session log's event sequence, and netguard namespaces its own as `<session>:netguard:<seq>` so a
SIEM deduplicating on that field cannot mistake one package's records for the other's.

## Development

```sh
nvm use 22           # Node ^22.19.0 || >=24, and pnpm 11
pnpm install
pnpm run typecheck
pnpm run test:coverage
pnpm run test:e2e    # boots a real dsh against a mock model; no API key
```

Design decisions and their rationale live in [ADR.md](ADR.md). Security policy is in
[SECURITY.md](SECURITY.md).

## License

MIT
