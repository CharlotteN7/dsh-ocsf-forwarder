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
dsh plugin --profile <name> add @deepseek-ai/dsh-headless@0.1.0-rc.6
dsh plugin --profile <name> add dsh-ocsf-forwarder
dsh --profile <name> --dump-config      # verify the row is mounted
```

Pin `@deepseek-ai/dsh-headless` explicitly: its npm `latest` tag still points at
`0.0.1-rc.1`, so an unpinned install silently resolves to a much older harness.

**Install from the registry or a packed tarball, not from a git spec.**
`dsh plugin add github:CharlotteN7/dsh-ocsf-forwarder` resolves and writes the
dependency, but `lib/` is a build output that git does not carry and no
`prepare` script rebuilds it, so the row mounts and then fails to load. To
install from a checkout, build first and add the tarball:

```sh
git clone https://github.com/CharlotteN7/dsh-ocsf-forwarder && cd dsh-ocsf-forwarder
pnpm install && pnpm run build && pnpm pack
dsh plugin --profile <name> add ./dsh-ocsf-forwarder-0.1.0.tgz
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
