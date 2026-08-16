/**
 * The Splunk HTTP Event Collector transport.
 *
 * Verified against Splunk's own documentation on 2026-08-16 (the pages now
 * live on `help.splunk.com`; `docs.splunk.com` redirects there):
 *
 * - `POST {base}/services/collector/event` is where JSON event requests go —
 *   "Note that the request is going to the /services/collector/event endpoint,
 *   which is where all JSON-formatted event requests must go".
 * - The header is `Authorization: Splunk <token>`, and the REST reference adds
 *   "The format is case-sensitive."
 * - A batch is "event objects stacked one after the other". Splunk states that
 *   "Both concatenated JSON objects and JSON arrays like this are accepted",
 *   so the concatenation this transport emits is the documented form rather
 *   than the only accepted one.
 * - `time` is UNIX time "in the format <sec>.<ms>" — epoch **seconds** with a
 *   fractional millisecond part, not epoch milliseconds.
 *
 * Splunk publishes no retryable status set; {@link classifySplunkStatus}
 * documents the reading this plugin applies and why.
 * @module sink/splunk
 */

import { CLASS_NAME, type ClassUid } from '../ocsf/constants.ts'
import type { OcsfRecord } from '../ocsf/types.ts'
import type { BatchOutcome, Transport } from './transport.ts'

/** Path appended to the configured HEC base URL. */
export const HEC_EVENT_PATH = '/services/collector/event'

/** Authorization scheme HEC requires. Splunk documents the keyword as case-sensitive. */
const HEC_AUTH_SCHEME = 'Splunk'

/** `sourcetype` for a record whose `class_uid` this build does not name. */
const UNKNOWN_CLASS_NAME = 'base_event'

/** Milliseconds per second, for the epoch-seconds conversion HEC's `time` requires. */
const MS_PER_SECOND = 1000

/**
 * How a HEC response status is read.
 *
 * Splunk documents an error-code table but no retryable set, so this is ours.
 * 429 ("HEC queue is at capacity") and 503 ("Server is busy", "queues are
 * full") are backpressure and must not consume records. 400 is the content
 * refusal — "No data", "Invalid data format", "Incorrect index", "Event field
 * is required".
 *
 * 401 and 403 are treated as transient rather than as a refusal, which is a
 * deliberate departure from the OpenTelemetry Collector's Splunk exporter
 * (which marks 400/401/403 permanent). Both statuses mean the *token* is
 * wrong — "Token is required", "Invalid authorization", "Token disabled",
 * "Invalid token" — never that the batch is bad. Quarantining a whole spool
 * because a token was rotated would step the cursor over records that will
 * deliver perfectly once the operator fixes the token; holding the cursor
 * makes the same failure recoverable, and the heartbeat's cursor position is
 * what tells the SOC delivery has stalled. Splunk's own table also returns
 * "Invalid token" and "Token disabled" as **400** (codes 21 and 22), so a 400
 * is not unambiguously a payload fault either — it is graded as one because
 * that is the reading under which a genuinely malformed batch cannot block
 * every record behind it.
 * @param status - the HTTP status HEC returned.
 * @returns what the shipper should do with the batch.
 */
export function classifySplunkStatus(status: number): BatchOutcome {
  if (status >= 200 && status < 300) return 'accepted'
  if (status === 400) return 'reject'
  return 'retry'
}

/** Everything a HEC event envelope carries besides the record itself. */
export interface SplunkEventMetadata {
  /** `host` stamped on every event. */
  readonly host: string
  /** `source` stamped on every event. */
  readonly source: string
  /** `sourcetype` is `<prefix>:<OCSF class name>`. */
  readonly sourcetypePrefix: string
  /** `index`, omitted so the token's default index applies. */
  readonly index?: string
}

/**
 * Wrap one OCSF record in the HEC event envelope.
 * @param record - the record to ship.
 * @param metadata - the envelope fields this deployment stamps.
 * @returns the event object, ready to serialize.
 */
export function splunkEvent(record: OcsfRecord, metadata: SplunkEventMetadata): unknown {
  const className = CLASS_NAME[record.class_uid as ClassUid] ?? UNKNOWN_CLASS_NAME
  return {
    // Epoch seconds with a fractional millisecond part, which is the format
    // Splunk documents; `record.time` is epoch milliseconds.
    time: record.time / MS_PER_SECOND,
    host: metadata.host,
    source: metadata.source,
    sourcetype: `${metadata.sourcetypePrefix}:${className}`,
    ...metadata.index === undefined ? {} : { index: metadata.index },
    event: record,
  }
}

/**
 * Encode one batch as HEC's stacked-object protocol.
 *
 * Each object is newline-terminated. Splunk's own batch example separates
 * objects with a newline, and a newline is not a separator HEC treats as data,
 * so the framing stays readable in a capture without changing what is parsed.
 * @param records - the records in the batch, in spool order.
 * @param metadata - the envelope fields this deployment stamps.
 * @returns the request body.
 */
export function splunkPayload(records: readonly OcsfRecord[], metadata: SplunkEventMetadata): string {
  return records.map(record => `${JSON.stringify(splunkEvent(record, metadata))}\n`).join('')
}

/**
 * Build the Splunk HEC transport.
 * @param endpoint - the HEC base URL; {@link HEC_EVENT_PATH} is appended when the URL has no path.
 * @param token - the HEC token, placed in the authorization header.
 * @param headers - extra request headers.
 * @param metadata - the envelope fields this deployment stamps.
 * @returns the transport.
 */
export function createSplunkTransport(
  endpoint: string,
  token: string,
  headers: Readonly<Record<string, string>>,
  metadata: SplunkEventMetadata,
): Transport {
  return {
    kind: 'splunk-hec',
    endpoint,
    headers: { ...headers, authorization: `${HEC_AUTH_SCHEME} ${token}` },
    contentType: 'application/json',
    encode: records => splunkPayload(records, metadata),
    classify: classifySplunkStatus,
  }
}
