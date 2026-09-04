---
title: Tamper-evidence
nav_order: 7
---

# Tamper-evidence: the `record_integrity` profile

[← dsh-ocsf-forwarder docs](index.md)

Every spooled record carries an OCSF 1.9.0 `record_integrity` attestation: the SHA-256 fingerprint
of the record itself, plus the uid and fingerprint of the record written before it. The chain lets
a reader tell whether the records they are holding are the records that were written — but not, on
its own, whether there were more of them. That last question needs an
[anchor](#truncation-the-deletion-the-chain-cannot-see).

**Read [what this does not protect against](#what-the-chain-does-not-protect-against) before you
rely on it.** It is a shorter list than the marketing for this kind of feature usually admits.

## What one record carries

```json
{
  "class_uid": 1007,
  "metadata": { "uid": "01JB0SESSION:8", "profiles": ["ai_operation", "cloud", "osint", "record_integrity"] },
  "attestation_list": [
    {
      "uid": "7a1f0c5e-6b2d-4c8a-9f31-2d5b8e0a1c74:41",
      "chain_uid": "7a1f0c5e-6b2d-4c8a-9f31-2d5b8e0a1c74",
      "prev_event": {
        "uid": "01JB0SESSION:7",
        "type_uid": 100701,
        "fingerprint": { "value": "9d1c…", "algorithm_id": 3, "encoding_id": 1 }
      },
      "fingerprint": { "value": "4b77…", "algorithm_id": 3, "encoding_id": 1 }
    }
  ]
}
```

| Attribute | Value |
|---|---|
| `attestation.uid` | `<chain_uid>:<entry index>`, counting from `0`. Entries are consecutive within a chain, which is what makes an **interior** deletion visible. A deletion at the end leaves a shorter run of consecutive entries and is invisible here; see [Truncation](#truncation-the-deletion-the-chain-cannot-see). |
| `attestation.chain_uid` | A UUID minted per process **per lane**. The SOC and restricted lanes are separate files carrying different records, so each has its own chain; a link that pointed into the other file could not be checked from the file it is in. |
| `attestation.fingerprint` | SHA-256 (`algorithm_id: 3`) of this record's canonical serialization, hex (`encoding_id: 1`). |
| `attestation.prev_event` | The previous record's `metadata.uid`, `type_uid`, and fingerprint. Absent on the chain's genesis entry, and only there. |
| `metadata.profiles` | Carries `record_integrity`, because every OCSF class is `additionalProperties: false` and an attribute whose profile is undeclared fails validation exactly as an undefined one does. |

`authority_uid` and `signatures` are **not** emitted. This producer holds no signing credential, so
there is no identity to bind and none to name; the installation that wrote the record is already in
`device.uid`, which is inside the hashed content. The object's constraint
`at_least_one: [fingerprint, signatures]` is met by the fingerprint.

## Canonicalisation, exactly

A third party must be able to recompute every fingerprint without this package. The rule is:

1. Take the record **as it is on the line**, parsed as JSON.
2. In its single `attestation_list` entry, remove `fingerprint` and `signatures`. Remove nothing
   else: `uid`, `chain_uid`, and the whole `prev_event` object stay, which is why the link to the
   predecessor cannot be edited without invalidating the fingerprint.
3. Serialize the whole record with **RFC 8785 (JSON Canonicalization Scheme)**: object keys sorted
   by UTF-16 code unit, no insignificant whitespace, strings and numbers rendered as ECMAScript
   `JSON.stringify` renders them.
4. Encode that text as UTF-8, take SHA-256, and render it as lower-case hex.

That string is `attestation.fingerprint.value`. The next record's `prev_event.fingerprint.value` is
the same string, copied.

Two details a verifier must not get wrong:

- **The line's own byte order is not the canonical order.** The spool is written with plain
  `JSON.stringify`, in insertion order. Parse the line and re-serialize it canonically; do not hash
  the line.
- **The whole record is covered**, including `metadata.logged_time`, the `unmapped.dsh` extension
  object, and — in the restricted lane — `raw_data`. Nothing is excluded but the two attestation
  fields named above.

### A reference verifier, in something that is not this package

```python
import hashlib, json, math, sys

ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}

def jstring(text):                             # a JSON string as JSON.stringify writes one
    out = ['"']
    for char in text:
        point = ord(char)
        if char in ESCAPES:
            out.append(ESCAPES[char])
        elif point < 0x20 or 0xD800 <= point <= 0xDFFF:
            out.append("\\u%04x" % point)       # ECMAScript escapes an unpaired surrogate
        else:
            out.append(char)
    return "".join(out) + '"'

def jnumber(value):                            # ECMAScript Number::toString, which RFC 8785 defers to
    if value != value or value in (math.inf, -math.inf):
        raise ValueError("JSON has no rendering for this number")
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    mantissa, _, exponent = repr(abs(float(value))).partition("e")   # shortest round-tripping digits
    whole, _, fraction = mantissa.partition(".")
    digits = (whole + fraction).lstrip("0")
    n = len(digits) + int(exponent or 0) - len(fraction)             # value == 0.<digits> * 10**n
    digits = digits.rstrip("0")
    k = len(digits)
    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * -n + digits
    tail = "e" + ("+" if n > 0 else "-") + str(abs(n - 1))
    return sign + digits[0] + ("" if k == 1 else "." + digits[1:]) + tail

def canonical(value):                          # RFC 8785
    if value is None:
        return "null"
    if value is True or value is False:
        return "true" if value else "false"
    if isinstance(value, str):
        return jstring(value)
    if isinstance(value, (int, float)):
        return jnumber(value)
    if isinstance(value, list):
        return "[" + ",".join(canonical(item) for item in value) + "]"
    order = lambda key: key.encode("utf-16-be", "surrogatepass")     # by UTF-16 code unit
    return "{" + ",".join(jstring(k) + ":" + canonical(value[k]) for k in sorted(value, key=order)) + "}"

prev = None
for path in sys.argv[1:]:                  # generations oldest first, then the live file
    for number, line in enumerate(open(path, encoding="utf-8"), start=1):
        record = json.loads(line)
        attestation, = record["attestation_list"]
        claimed = attestation["fingerprint"]["value"]
        bare = {k: v for k, v in attestation.items() if k not in ("fingerprint", "signatures")}
        covered = dict(record, attestation_list=[bare])
        text = canonical(covered).encode("utf-8", "surrogatepass")
        if hashlib.sha256(text).hexdigest() != claimed:
            sys.exit(f"{path}:{number} altered")
        if prev is not None and attestation.get("prev_event", {}).get("fingerprint", {}).get("value") != prev:
            sys.exit(f"{path}:{number} broken link")
        prev = claimed
print("intact")
```

`json.dumps(record, sort_keys=True, separators=(",", ":"))` is **not** a substitute, and the three
places it differs are all reachable from a clean spool:

- **Numbers.** RFC 8785 renders a number as ECMAScript's `Number::toString` does; Python's does not
  agree with it. A `hook/result` with a sub-millisecond `durationMs` emits `"duration":1e-7`, which
  Python writes `1e-07` — one character, a whole spool reported as `altered`. `1e-5` and `1e21`
  differ too, and both reach a record as tool-argument values under `privacy.argumentValues: full`.
- **Unpaired surrogates.** A model chooses its own argument names, and one holding a lone surrogate
  reaches `unmapped.dsh.arguments[].key`. ECMAScript escapes it as `\ud800`; Python emits the raw
  code point and then `.encode("utf-8")` raises `UnicodeEncodeError` — the verifier does not report
  a wrong answer, it stops.
- **Key order.** Keys sort by UTF-16 code unit, not by code point. Every key OCSF defines is ASCII,
  where the two agree, but `extension.name` is a deployment string and becomes an object key.

`dsh-ocsf-verify` handles all three, because it re-serializes through the same `JSON.stringify` the
spool was written with. A verifier for records from another producer should use a real JCS
implementation rather than either of these.

## Chains, rotation, and gaps

A chain is **one process writing one file**. It survives rotation: renaming the live file to a
generation does not end a chain, so a spool plus its generations verify as one continuous sequence
when they are read oldest-first. It does **not** survive a restart: the next process mints a new
`chain_uid` and starts again at entry `0`. Carrying a chain across restarts would mean trusting a
state file that is writable by exactly the party the chain is supposed to be evidence against, and
a genesis entry is not weaker than a link to a state file anyone can rewrite.

A verifier therefore distinguishes three things a spool file can show:

| What it sees | What it means |
|---|---|
| A chain whose first entry is `0`, with no `prev_event` | A process started here. Nothing is missing before it. |
| A chain whose first entry is `N > 0`, with a `prev_event` | Entries `0…N-1` are not in this input. Normal after the shipper drained and unlinked a generation; also what deleting the front of a spool looks like. The spool alone cannot tell those apart — the shipper's cursor can, and so can the SIEM, which already has the delivered entries. |
| An interior jump from entry `N` to `N+2`, or a `prev_event` that does not match the record before it | Records were removed, reordered, or edited. This is a break. |
| A chain whose last entry is `N`, with nothing after it | The writer stopped there — or entries after `N` were removed. **Nothing in the spool tells those apart**; see [Truncation](#truncation-the-deletion-the-chain-cannot-see). |

Because a whole chain can be deleted without leaving a trace *in the spool*, the count of chains is
not evidence of anything by itself. What makes deletion visible is the copy that already left the
host: configure a shipper, and check the spool against what it delivered.

## Truncation: the deletion the chain cannot see

Every record links to the one before it, so deleting a record breaks the record after the hole.
Delete from the **end** and there is no record after the hole. What is left is a shorter chain whose
every remaining link still matches, and it verifies clean:

```
clean spool                INTACT   exit 0
interior record deleted    BROKEN   exit 1
last 3 records removed     INTACT   exit 0
```

This needs no key, no code, and no privilege beyond writing the file, and erasing one's own recent
activity is the tampering to expect. **No arrangement of hashes inside the file fixes it.** How long
a chain should be is not derivable from the chain; it has to come from somewhere the writer of the
file cannot reach.

### Anchors

That somewhere is the copy that already left the host. Every shipped record carries its own
attestation, so for each record the SIEM holds the chain it belonged to, the entry index it
occupied, and its fingerprint. Any one of them is an **anchor**: a claim that the chain reached at
least that entry, made by a party who cannot edit the spool.

`dsh-ocsf-verify --anchor` takes those records back — as the SIEM holds them, one JSON record per
line — and reports the two things the spool alone cannot show:

| Finding | What it means |
|---|---|
| `truncated` | The chain in this input stops before an entry an anchor accounts for. Records were removed from the end. |
| `anchor-mismatch` | The record at an anchored entry is not the record that was shipped. A tail rewritten to the right length, rather than simply cut. |

```sh
dsh-ocsf-verify --anchor shipped.jsonl /var/log/dsh/ocsf.jsonl
```

Only `attestation_list` is read out of an anchor record, so a SIEM export that reordered or dropped
other attributes still anchors. An anchor input the verifier can read no attestation out of exits
`2` rather than reporting a check it did not make.

The [heartbeat](shipping.md#heartbeat) is what keeps an anchor available on a quiet host. It is an
ordinary chain entry, it ships like every other record, and one is written every `statsIntervalMs`
and one more at unload — so asking the SIEM for an installation's most recent record always returns
something to anchor against, even for a host that did nothing.

### What anchoring buys, and what it does not

- **It is not a local check.** A `dsh-ocsf-verify` run against a truncated spool with no anchors
  cannot tell, and nothing can make it. It says so instead: every chain line reports either the
  entry an anchor covers it through or `no anchor`, and `INTACT` on an unanchored chain claims only
  that the records present are consistent with each other.
- **The residual window is whatever has not been delivered.** Records written after the last one
  the collector acknowledged have no anchor and remain silently removable — one `flushIntervalMs`,
  five seconds by default. An operator who anchors on the heartbeat alone rather than on the newest
  record of any kind has a window of one `statsIntervalMs` instead, five minutes by default. With
  no shipper configured nothing leaves the host, there are no anchors, and suffix truncation is
  undetectable outright.
- **An anchor naming a chain with no records in the input is not a finding.** A chain whose
  generations the shipper drained and unlinked looks exactly like one deleted wholesale. The report
  counts those anchors and names the ambiguity rather than guessing at it.
- **An agent that can rewrite the spool can also stop the forwarder**, and that is a different
  failure — a louder one. The heartbeats stop, which is detectable at the SIEM by the absence rules
  in [Heartbeat](shipping.md#heartbeat), and no anchor is needed to see it.

## What the chain does not protect against

**The agent this plugin observes.** The plugin runs in the agent's process at the agent's uid. An
agent that can run `bash` can delete the spool, rewrite it, and recompute a consistent chain over
the result — the algorithm is published on this page precisely so that anyone can recompute it, and
that includes the attacker. No arrangement of hashing inside this process changes that; a key held
in the same process is a key the same attacker reads.

This is the same honesty the [`privacy.hmacKey`](configuration.md) setting demands. That key exists
so a SOC can join on equal values without seeing them, and its secrecy is what stops a dictionary
attack on the digests. Here there is nothing to hide, only something to bind — so the fingerprints
are **unkeyed**, and an HMAC would have bought no resistance against the one attacker who matters
while destroying the property that anyone can verify the chain.

What the chain does buy:

- **A later edit is detected.** Anything that changes a spooled record — an editor, a log-mangling
  script, a corrupted copy, a helpful "cleanup", a second process that got past the lock file — is
  visible at the record it touched and at the record after it.
- **An interior deletion is detected**, by the gap in consecutive chain entries, which is stronger
  than the per-session `metadata.sequence` gap detector because it covers every record in the file
  including heartbeats and records from other sessions. **A deletion at the end of the file is
  not**: see [Truncation](#truncation-the-deletion-the-chain-cannot-see), which needs an anchor
  from the shipped stream and cannot be done locally at all.
- **Records already off the host become anchors,** *for the chain they belong to.* The SIEM holds
  fingerprints for everything shipped, and a rewrite that keeps the same `chain_uid` must either
  leave those records exactly as they were or produce fingerprints that disagree with the SIEM's,
  which `dsh-ocsf-verify --anchor` reports as `anchor-mismatch`. A rewrite that does **not** keep
  the `chain_uid` is a different matter — see [Re-chaining](#re-chaining-and-fabrication) — and so
  is anything added rather than changed. The undetectable-tampering window for an in-chain edit is
  the time between a record being written and being delivered: one `flushIntervalMs`, five seconds
  by default.
- **Nothing about the agent's honesty.** A record that was never written is not missing from a
  chain that never contained it. This is tamper-evidence for the audit trail, not attestation of
  the agent's behaviour.

## Re-chaining and fabrication

`chain_uid` is minted by the writer and is bound to nothing the writer cannot forge. There is no
roster of chains that legitimately existed, so the verifier cannot ask whether a chain *should*
exist — only whether one the anchors name is *here*. Since 0.8.0 it treats that absence as a
finding. Each row below is reproduced in `tests/unit/integrity-tamper.spec.ts`:

| What a tamperer does | Verifier's answer |
|---|---|
| Cuts entries `7-9` off the anchored chain | `truncated`, **exit 1** |
| Edits entry `4` of the anchored chain, re-hashing the rest | `anchor-mismatch`, **exit 1** |
| **Replaces the whole file** with a fresh 7-entry chain under a new `chain_uid`, dropping `7-9` and editing `4` | `uncorroborated-chain`, **exit 1** — but `INTACT`, exit 0, under `--no-strict-anchors` |
| **Adds a second chain** of records that never happened, leaving the honest chain untouched | `INTACT`, **exit 0** |
| **Continues the anchored chain** past its anchored end with records that never happened | `INTACT`, **exit 0** |

The first two are the moves the anchor check was built for. The third is what a reader of this page
does instead once they know that: it does not *disagree* with the anchors, it fails to *overlap*
them. Until 0.8.0 the comparison simply never ran, and all it left behind was
`10 anchor(s) name a chain with no records here` — a count, not a finding, and one this page's own
[Chains, rotation, and gaps](#chains-rotation-and-gaps) section teaches operators to read as a
shipper that drained a generation. It is now `uncorroborated-chain` and exits `1`.

**This is a real trade, stated plainly.** A host whose shipper legitimately drained and unlinked
every generation of a chain produces exactly the same report, and no evidence on that host
distinguishes the two — that is why the count existed. `--no-strict-anchors` restores it, and using
it is a claim about that host's retention, not a way to quieten a report. The default is strict
because a spool replaced wholesale leaves no other trace at all, and a control that stays silent on
the one move that erases history is worse than one an operator has to reason about.

The fourth and fifth are untouched by that default, and are the other half:
**anchors bound a chain from below, never from above.**
They say entries `0…N` existed and what they were. They say nothing about entries after `N`, and
nothing at all about a chain the SIEM has never seen. So records can be *added* — an
`approval/decided` with outcome `rejected`, to make an action that ran look blocked — and neither
the file nor the anchors contradict them.

Two things narrow this in practice, and neither closes it:

- **A SIEM already holding the delivered stream can do what the verifier does not.** An
  installation's `device.uid` is inside every hashed record, and the delivered stream names every
  `chain_uid` that installation ever shipped under. A chain appearing in a spool that the SIEM has
  no record of, or a spool whose chains do not include the one the SIEM last saw, is a query — not
  one `dsh-ocsf-verify` runs for you.
- **Fabrication has to survive the rest of the evidence.** A forged `approval/decided` still has to
  agree with a real `tool/call`, a real `metadata.sequence` run for its session, and the shipped
  copy of both. That is work, and it is not verification.

Whether an anchor naming an absent chain should become a finding rather than a count is a
deployment question this package has not answered: on a host whose shipper legitimately drained and
unlinked a generation it is routine, and making it fail would train operators to ignore it — the
failure mode the whole design is trying to avoid.

## Verifying a spool

```sh
dsh-ocsf-verify /var/log/dsh/ocsf.jsonl
dsh-ocsf-verify --anchor shipped.jsonl /var/log/dsh/ocsf.jsonl
```

The command is installed with the package (`node_modules/.bin/dsh-ocsf-verify`). It takes one or
more spool paths, verifies each together with its rotated generations oldest-first, and exits `0`
when the input is intact, `1` when it is not, and `2` when it could not be read. `--anchor` is
repeatable and names records the SIEM already holds; without it the end of every chain is taken on
the file's word. `--json` prints the whole report — every finding with its file, line, and record
uid — for a scheduled check. An option the command does not take is a usage error rather than
something ignored, because a dropped `--anchor` would report a truncation check that never ran.

```
3241 record(s) in 2 file(s), 3241 attested, 1 chain(s)
  chain 7a1f0c5e-…: 3241 record(s), entries 0-3240, from its genesis entry, anchored through entry 3240
INTACT: every record hashes to its own fingerprint and every link matches.
```

Unanchored, the same chain line ends `no anchor — nothing here can show whether entries after 3240
were removed`, which is the honest reading of `INTACT` on a file nobody corroborated.

The finding kinds are `altered`, `broken-link`, `missing-records`, `out-of-order`, `unattested`,
`malformed`, `unparsable`, and — only when anchors were supplied — `truncated` and
`anchor-mismatch`. An empty input reports `NOT VERIFIED` and exits `1`: an audit tool that exits `0` on a
file with nothing in it reports the absence of evidence as evidence.

The same check is available programmatically — `verifyRecords`, `anchorsOf`, `formatReport`, and
`spoolFiles` are exported from the package root — and the algorithm is small enough that the reference
implementation above is a reasonable thing to run instead.

## Cost

The chain runs synchronously on the agent's event loop, once per record, in both lanes.

| | Measured |
|---|---|
| Added time per record | **~29 µs** (one canonical serialization plus one SHA-256), against ~4 µs for the `JSON.stringify` the spool already did |
| Added bytes per record | **+391 bytes**, on a mean record of 1369 bytes — **+29%** on the spool and on everything shipped |

Measured over 20 000 records from a real forwarder run with
`pnpm exec tsx scripts/measure-attestation-cost.ts`; the number moves with the machine, not with
the record. The size cost is the reason `integrity.attest: false` exists. The time cost is not:
29 µs a record is two orders of magnitude below the 2.7 ms per record that a filesystem check on
this same path once cost, and that check was measurable in the agent's response time.
