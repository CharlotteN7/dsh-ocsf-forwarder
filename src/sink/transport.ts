/**
 * The wire seam between the shipper and a SIEM.
 *
 * A transport is an encoder plus a status classifier and nothing more. The
 * cursor, the generation drain, the quarantine and the backoff live in the
 * shipper and are wire-format-agnostic, so a new destination adds a
 * {@link Transport} and changes nothing about delivery semantics. No transport
 * may re-derive cursor semantics: the only thing it says about a batch is which
 * of the three {@link BatchOutcome} values the response means.
 * @module sink/transport
 */

import type { OcsfRecord } from '../ocsf/types.ts'

/**
 * What the destination did with one batch.
 *
 * `retry` and `reject` are kept apart because they need opposite handling: a
 * collector that is down must never cause records to be dropped, and a batch
 * the collector rejects on its content must never stall the ones behind it.
 */
export type BatchOutcome =
  /** Accepted; the cursor may advance past the batch. */
  | 'accepted'
  /** Transient failure; the batch is resent after a backoff. */
  | 'retry'
  /** Refused on content; the batch is quarantined and stepped over. */
  | 'reject'

/** HTTP statuses that are transient despite being client errors. */
const RETRYABLE_CLIENT_STATUS: ReadonlySet<number> = new Set([408, 425, 429])

/**
 * The default status reading, shared by every HTTP transport: success is
 * acceptance, a client error is a refusal unless it means "not now", and
 * everything else is worth retrying.
 * @param status - the HTTP status the destination returned.
 * @returns what the shipper should do with the batch.
 */
export function classifyHttpStatus(status: number): BatchOutcome {
  if (status >= 200 && status < 300) return 'accepted'
  if (status >= 400 && status < 500 && !RETRYABLE_CLIENT_STATUS.has(status)) return 'reject'
  return 'retry'
}

/** One SIEM's wire format: where to post, how to encode, how to read the answer. */
export interface Transport {
  /** Which destination this is, for log lines and error messages. */
  readonly kind: string
  /** The exact URL each batch is posted to. */
  readonly endpoint: string
  /** Request headers, including whatever authorization the destination needs. */
  readonly headers: Readonly<Record<string, string>>
  /** `content-type` of the request body. */
  readonly contentType: string
  /**
   * Serialize one batch.
   * @param records - the records in the batch, in spool order.
   * @returns the request body.
   */
  encode(records: readonly OcsfRecord[]): string
  /**
   * Read one response status.
   * @param status - the HTTP status the destination returned.
   * @returns what the shipper should do with the batch.
   */
  classify(status: number): BatchOutcome
}

/** The HTTP call the shipper makes; injectable so tests need no network. */
export type PostBatch = (transport: Transport, body: string, timeoutMs: number) => Promise<BatchOutcome>

/**
 * POST one batch with `fetch`, letting the transport read the status.
 * @param transport - the destination's wire format.
 * @param body - the encoded batch.
 * @param timeoutMs - per-request timeout.
 * @returns what the destination did with the batch.
 */
export const postBatch: PostBatch = async (transport, body, timeoutMs) => {
  const controller = new AbortController()
  const timer = setTimeout(() => { controller.abort() }, timeoutMs)
  try {
    const response = await fetch(transport.endpoint, {
      method: 'POST',
      headers: { 'content-type': transport.contentType, ...transport.headers },
      body,
      signal: controller.signal,
    })
    return transport.classify(response.status)
  } catch {
    // Any transport failure: the cursor stays put and the batch is retried.
    return 'retry'
  } finally {
    clearTimeout(timer)
  }
}
