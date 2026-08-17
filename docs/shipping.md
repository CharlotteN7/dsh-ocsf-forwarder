---
title: Shipping to a SIEM
nav_order: 5
---

# Shipping to a SIEM

[← dsh-ocsf-forwarder docs](index.md)

The shipper is a byte cursor over the spool plus a **transport**: an encoder and a status
classifier, and nothing else. No transport sees the cursor, the spool or the quarantine file, so
adding a destination cannot change delivery semantics.

### Splunk HTTP Event Collector

Verified against Splunk's documentation on 2026-08-16 (`docs.splunk.com` now redirects to
`help.splunk.com`):

| | |
|---|---|
| Endpoint | `POST {base}/services/collector/event` — "which is where all JSON-formatted event requests must go" |
| Header | `Authorization: Splunk <token>`; the REST reference adds "The format is case-sensitive" |
| Body | Event objects stacked one after the other, one per line. Splunk states that "Both concatenated JSON objects and JSON arrays like this are accepted", so the concatenation here is the documented form rather than the only accepted one |
| `time` | Epoch **seconds** with a fractional millisecond part — UNIX time "in the format `<sec>.<ms>`" |
| `sourcetype` | `ocsf:<OCSF class name>`, for example `ocsf:process_activity` |

Each event carries `time`, `host`, `source`, `sourcetype`, optionally `index`, and the whole OCSF
record under `event`.

**Status handling.** Splunk publishes an error-code table but **no** retryable set, so the reading
below is ours. 2xx is acceptance. 429 ("HEC queue is at capacity") and 503 ("Server is busy",
"queues are full") are backpressure and hold the cursor. 400 is a content refusal and quarantines
the batch. **401 and 403 hold the cursor rather than quarantining**, which departs from the
OpenTelemetry Collector's Splunk exporter: both statuses mean the token is wrong, never that the
batch is bad, and stepping the cursor over records that would deliver fine once a rotated token is
fixed would be an unrecoverable loss of delivery. The signal that this is happening is the
heartbeat's `shipper_cursor` standing still. Note that Splunk also returns "Invalid token" and
"Token disabled" as **400** under its codes 21 and 22, so a 400 is not unambiguously a payload
fault; it is graded as one so that a genuinely malformed batch cannot block every record behind it.

**Splunk configuration.** There is no official Splunk add-on for OCSF and no Splunk-published OCSF
sourcetype convention, so `sourcetype` and field extraction are ours to define.
[`splunk/props.conf`](splunk/props.conf) ships beside this plugin with one stanza per class. There
is deliberately no `transforms.conf`: HEC sets `_time`, `host`, `source` and `sourcetype` from the
event envelope and the payload is JSON, so nothing needs an index-time transform.

**Splunk Cloud.** The hostname needs the HEC prefix — `http-inputs-<host>.splunkcloud.com` on AWS,
`http-inputs.<host>.splunkcloud.com` on GCP and Azure — and the default port is 443, not 8088.

### OTLP/HTTP

Each record becomes one OTLP `logRecord` whose body is the record's JSON, with `ocsf.class_uid` and
`ocsf.type_uid` as attributes so a collector routes without parsing the payload.

## Heartbeat

A periodic Application Lifecycle (6002) record reporting the live session count, the forwarder's
counters, the spool size and the shipper cursor. `statsIntervalMs` sets the cadence; one more is
written at unload with `unmapped.dsh.final: true`.

**OCSF has no heartbeat class.** There is no liveness, health-check, keepalive or checkpoint class
either — enumerating all 87 classes in 1.9.0 and searching name, caption and description for those
words returns nothing. This is therefore **not** a standard mapping: it is 6002 with
`activity_id: 99` (`Other`), `activity_name: "Heartbeat"`, and `unmapped.dsh.kind: "heartbeat"`,
until OCSF ships a slot.

A heartbeat belongs to no session. It carries no `ai_agent.instance_uid` and no
`unmapped.dsh.session_id`; its `metadata.uid` is `<install uid>:heartbeat:<n>` and
`metadata.sequence` is that `n`, so a *missing* heartbeat is detectable and not only a malformed
one. It is deliberately absent from the counters it reports.

| Attribute | Meaning |
|---|---|
| `live_sessions` | Sessions the store held when the heartbeat was taken. |
| `forwarded` / `dropped` / `unreadable` / `failed` | The forwarder's counters. |
| `spool_bytes` / `spool_high_water_bytes` / `spool_pressure` | Disk the spool occupies, the alarm threshold, and whether it has been crossed. |
| `rotation_stopped` | True once a stop condition has held rotation and the live file is growing. |
| `shipper_cursor` / `shipper_quarantined` / `shipper_destination` | Delivery position, refused records, and which destination. Absent with no shipper configured. |
| `uptime_ms` / `final` | How long this forwarder has been mounted, and whether this is its last heartbeat. |

`severity_id` rises to `4` when the spool crosses `spoolHighWaterBytes` or rotation has stopped, so
the SOC learns from the SIEM rather than from a full disk.

**Detecting absence** is well-trodden on the SIEM side and is not shipped here. Elastic's
Elasticsearch-query rule supports an "is below" comparator, which is what absence detection needs;
its separate Threshold rule type is one-directional and cannot express it. Sentinel's idiom is
`summarize max(TimeGenerated) by Computer`. In Splunk the pivot is `device.uid` against the
`ocsf:application_lifecycle` sourcetype.
