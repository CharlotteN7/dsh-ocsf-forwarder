/**
 * The OTLP/HTTP shipper: reads the spool by byte offset, posts batches of OCSF
 * records as OTLP log records, and advances a durable cursor only after the
 * collector accepts them.
 *
 * Delivery is at-least-once by construction. The cursor never moves past an
 * unacknowledged batch, so a crashed process resends rather than skips; the
 * SIEM deduplicates on `metadata.uid`.
 * @module sink/otlp
 */

import { openSync, readFileSync, readSync, statSync, writeFileSync } from 'node:fs'
import { closeSync } from 'node:fs'
import type { ResolvedOtlp } from '../config.ts'
import type { OcsfRecord } from '../ocsf/types.ts'

/** OTLP severity numbers for the OCSF severities we emit. */
const OTLP_SEVERITY: Readonly<Record<number, number>> = Object.freeze({
  0: 0, 1: 9, 2: 13, 3: 17, 4: 21, 5: 21, 6: 24,
})

/** Convert one OCSF record into an OTLP `logRecord`. */
function toLogRecord(record: OcsfRecord): unknown {
  const time = typeof record.time === 'number' ? record.time : Date.now()
  const severity = typeof record.severity_id === 'number' ? record.severity_id : 0
  return {
    timeUnixNano: String(time * 1_000_000),
    observedTimeUnixNano: String(Date.now() * 1_000_000),
    severityNumber: OTLP_SEVERITY[severity] ?? 0,
    body: { stringValue: JSON.stringify(record) },
    attributes: [
      { key: 'ocsf.class_uid', value: { intValue: String(record.class_uid) } },
      { key: 'ocsf.type_uid', value: { intValue: String(record.type_uid) } },
    ],
  }
}

/**
 * Wrap records in the OTLP logs request envelope.
 * @param records - the records to ship.
 * @param productName - reported as `service.name` on the resource.
 * @returns the JSON body of one OTLP/HTTP logs request.
 */
export function otlpPayload(records: readonly OcsfRecord[], productName: string): unknown {
  return {
    resourceLogs: [{
      resource: { attributes: [{ key: 'service.name', value: { stringValue: productName } }] },
      scopeLogs: [{
        scope: { name: 'dsh-ocsf-forwarder' },
        logRecords: records.map(toLogRecord),
      }],
    }],
  }
}

/** The HTTP call the shipper makes; injectable so tests need no network. */
export type PostBatch = (url: string, headers: Readonly<Record<string, string>>, body: string, timeoutMs: number) => Promise<boolean>

/**
 * POST one batch with `fetch`.
 * @param url - the collector's logs endpoint.
 * @param headers - configured request headers.
 * @param body - the serialized OTLP payload.
 * @param timeoutMs - per-request timeout.
 * @returns whether the collector accepted the batch.
 */
export const postBatch: PostBatch = async (url, headers, body, timeoutMs) => {
  const controller = new AbortController()
  const timer = setTimeout(() => { controller.abort() }, timeoutMs)
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...headers },
      body,
      signal: controller.signal,
    })
    return response.ok
  } catch {
    // Any transport failure: the cursor stays put and the batch is retried.
    return false
  } finally {
    clearTimeout(timer)
  }
}

/**
 * Ships spooled records to an OTLP/HTTP collector, tracking a durable byte
 * cursor into the spool file.
 */
export class OtlpShipper {
  private timer: NodeJS.Timeout | undefined
  private draining = false

  /**
   * @param options - the resolved shipper settings.
   * @param spoolPath - the spool file the shipper reads.
   * @param productName - reported as `service.name`.
   * @param post - the HTTP call, injectable for tests.
   * @param onError - reports a drain failure.
   */
  constructor(
    private readonly options: ResolvedOtlp,
    private readonly spoolPath: string,
    private readonly productName: string,
    private readonly post: PostBatch = postBatch,
    private readonly onError: (error: unknown) => void = () => {},
  ) {}

  /** Begin draining on the configured interval. The timer never holds the process open. */
  start(): void {
    if (this.timer !== undefined) return
    this.timer = setInterval(() => { void this.drain() }, this.options.flushIntervalMs)
    this.timer.unref()
  }

  /** Stop the timer. Unshipped records stay in the spool. */
  stop(): void {
    if (this.timer === undefined) return
    clearInterval(this.timer)
    this.timer = undefined
  }

  /**
   * Read the spool from the cursor and ship what is there.
   * @returns the number of records the collector accepted.
   */
  async drain(): Promise<number> {
    if (this.draining) return 0
    this.draining = true
    try {
      return await this.drainOnce()
    } catch (error: unknown) {
      this.onError(error)
      return 0
    } finally {
      this.draining = false
    }
  }

  /** The byte offset delivery has reached, as persisted by the last successful batch. */
  cursor(): number {
    try {
      const raw = readFileSync(this.options.cursorPath, 'utf8')
      const value = Number.parseInt(raw.trim(), 10)
      return Number.isFinite(value) && value >= 0 ? value : 0
    } catch {
      // ENOENT only: nothing has shipped yet.
      return 0
    }
  }

  /** One drain pass: read, post in batches, persist the cursor after each batch. */
  private async drainOnce(): Promise<number> {
    const start = this.cursor()
    const size = statSync(this.spoolPath).size
    // A spool smaller than the cursor was rotated; restart from its beginning.
    const from = size < start ? 0 : start
    if (size === from) return 0

    const fd = openSync(this.spoolPath, 'r')
    let text: string
    try {
      const buffer = Buffer.allocUnsafe(size - from)
      readSync(fd, buffer, 0, buffer.length, from)
      text = buffer.toString('utf8')
    } finally {
      closeSync(fd)
    }

    // A trailing partial line is left for the next pass: its bytes stay
    // uncounted, so the cursor never advances past an incomplete record.
    const lastBreak = text.lastIndexOf('\n')
    if (lastBreak < 0) return 0
    const complete = text.slice(0, lastBreak + 1)
    const lines = complete.split('\n').filter(line => line.length > 0)

    let shipped = 0
    let offset = from
    for (let index = 0; index < lines.length; index += this.options.batchSize) {
      const slice = lines.slice(index, index + this.options.batchSize)
      const records = slice.flatMap((line): OcsfRecord[] => {
        try {
          return [JSON.parse(line) as OcsfRecord]
        } catch (error: unknown) {
          // A truncated or corrupt line is reported and skipped; refusing the
          // whole spool over one bad line would stop delivery entirely.
          this.onError(error)
          return []
        }
      })
      const accepted = records.length === 0 || await this.post(
        this.options.url,
        this.options.headers,
        JSON.stringify(otlpPayload(records, this.productName)),
        this.options.timeoutMs,
      )
      if (!accepted) break
      offset += Buffer.byteLength(slice.join('\n')) + slice.length
      shipped += records.length
      writeFileSync(this.options.cursorPath, String(offset))
    }
    return shipped
  }
}
