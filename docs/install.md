---
title: Install and compose
nav_order: 2
---

# Install and compose

[← dsh-ocsf-forwarder docs](index.md)

The profile must already compose a runnable agent. A profile carrying only `@deepseek-ai/dsh-base`
has no runtime: add `@deepseek-ai/dsh-headless` (or another runnable bundle) alongside it, otherwise
the profile boots into a configuration with no agent loop and this plugin observes nothing.

```sh
dsh plugin --profile <name> add @deepseek-ai/dsh-headless@0.1.1-rc.2
dsh plugin --profile <name> add dsh-ocsf-forwarder
dsh --profile <name> --dump-config      # verify the row is mounted
```

Pin `@deepseek-ai/dsh-headless` explicitly: the npm `latest` tag of the `@deepseek-ai/dsh-*`
libraries still points at `0.0.1-rc.1`, so an unpinned install silently resolves to a much older
harness.

## Which harness versions this works on

CI runs the whole end-to-end suite — a real `dsh` subprocess with this plugin mounted — against
every one of these:

| dsh | Notes |
|---|---|
| `0.1.0-rc.6`, `0.1.0-rc.7`, `0.1.0-rc.8` | `0.1.0-rc.8` is where the session vocabulary grew the four `team/*` types. |
| `0.1.1-rc.2` | The `latest` dist-tag of the `@deepseek-ai/dsh` CLI. |
| `0.1.2-alpha.5` | The line where `Session.events` became `Session.snapshotEvents()` and `header.seedLength` became `Session.inheritedEventCount`. This plugin reads whichever the resolved version has. |

**Peer ranges.** `@deepseek-ai/dsh-session` and `@deepseek-ai/dsh-session-telemetry` are

```
>=0.1.0-rc.6 <0.2.0 || >=0.1.1-rc.0 <0.1.2-0 || >=0.1.2-alpha.0 <0.1.3-0
```

which is longer than it looks like it should be because node-semver lets a prerelease satisfy a
range **only** when some comparator in the same set carries a prerelease tag *and* the identical
`major.minor.patch`. `^0.1.0-rc.6` therefore admitted `0.1.0-rc.8` and `0.1.1` but not
`0.1.1-rc.2` — the version the CLI's `latest` tag points at — and not `0.1.2-alpha.5` either:

```
npm error ERESOLVE unable to resolve dependency tree
npm error Found: @deepseek-ai/dsh-session@0.1.2-alpha.5
npm error Could not resolve dependency:
npm error peer @deepseek-ai/dsh-session@"^0.1.0-rc.6" from dsh-ocsf-forwarder@0.6.0
```

**What the range cannot cover.** One comparator set per prerelease patch tuple is the only way to
express this, so a future `0.1.3-rc.1` is *not* admitted and needs a set of its own. That is
deliberate: each new prerelease line is untested until someone runs the suite against it, and
widening the range is where that gets noticed.

`@deepseek-ai/cordis` is `^4.0.1` rather than exactly `4.0.1`. The exact pin was there so the
service graph every registration goes through is one graph — but a peer range does not install
anything, so the exact pin achieved the opposite: `@deepseek-ai/dsh-session@0.1.2-alpha.5` peers
`@deepseek-ai/cordis@^4.0.2`, and a project on that line could no longer add this plugin at all.
Every file `4.0.2` ships is byte-identical to `4.0.1`; only its own `package.json` differs. `^4.0.1`
is what DSH's own packages declare, and being stricter than the application that owns the graph
buys nothing.

**Install from the registry or a packed tarball, not from a git spec.**
`dsh plugin add github:CharlotteN7/dsh-ocsf-forwarder` resolves and writes the
dependency, but `lib/` is a build output that git does not carry and no
`prepare` script rebuilds it, so the row mounts and then fails to load. To
install from a checkout, build first and add the tarball:

```sh
git clone https://github.com/CharlotteN7/dsh-ocsf-forwarder && cd dsh-ocsf-forwarder
pnpm install && pnpm run build && pnpm pack
dsh plugin --profile <name> add ./dsh-ocsf-forwarder-0.5.1.tgz   # the version in package.json
```

The bundle patch defaults the spool to `dshHomePath('ocsf/session.ocsf.jsonl')`. A profile patch
layer **replaces a row's whole `config`**, so an override must restate every key it wants:

```yaml
- id: dsh-ocsf-forwarder
  config:
    spoolPath: /var/log/dsh/session.ocsf.jsonl
    seedReplay: full
    privacy:
      hmacKey:
        source: env
        variable: DSH_OCSF_HMAC_KEY
    otlp:
      endpoint: https://collector.internal:4318
      headers:
        authorization: 'Bearer ${COLLECTOR_TOKEN}'
```

To ship to Splunk instead, replace the `otlp` block with a `splunk` one. Exactly one destination
may be configured: two would share one cursor file and each step it past the other's deliveries,
so naming both fails at load.

```yaml
- id: dsh-ocsf-forwarder
  config:
    spoolPath: /var/log/dsh/session.ocsf.jsonl
    fleet:
      tenantUid: platform-eng
      labels: [prod, eu-west]
      tags:
        owner: soc
    splunk:
      endpoint: https://splunk.internal:8088
      index: dsh_security
      token:
        source: env
        variable: DSH_SPLUNK_HEC_TOKEN
```
