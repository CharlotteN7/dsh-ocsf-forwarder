# Security policy

## Reporting a vulnerability

Email **nsof@protonmail.com**. Please do not open a public issue for a
vulnerability report.

Include what you need to make the problem reproducible: the plugin version, the
configuration in effect (with any keys removed), and the smallest input that
shows the behaviour. You will get an acknowledgement within a week.

## What counts as a vulnerability here

This plugin is a read-side audit forwarder. The things worth reporting are:

- **A raw value reaching the SOC lane.** Any path by which text composed by a
  model, a user, a provider, or a hook appears verbatim in a SOC-lane record
  under stock configuration. `README.md` lists exactly what that lane may carry
  verbatim; anything outside that list is a bug of this class.
- **Records lost or destroyed.** Any way the spool, its rotated generations, or
  the shipper cursor can lose a record that was accepted for writing, other
  than the two documented and reported cases: a quarantined batch, and a
  deployment that ran out of disk after rotation stopped.
- **Key or digest weakness.** Anything that makes the HMAC correlation digests
  invertible or guessable, or that leaks the configured key.
- **Anything the plugin changes.** It registers no waterfall listener and never
  appends to the session log. A way for it to alter a tool call, an approval
  decision, a model request, or the session log is a vulnerability regardless of
  impact.

## What is out of scope

The plugin runs **in the agent's own process at the agent's own uid**. It is not
a containment boundary and `README.md` says so. An agent that can run `bash` can
delete or rewrite the spool, the cursor, and the lock file. Reports that an
agent with local execution can tamper with local files are working as
documented; ship records off the host promptly if that matters.

Vulnerabilities in the DeepSeek Harness itself belong to that project.
