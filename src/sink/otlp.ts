/**
 * The OTLP/HTTP shipper: reads the spool by byte offset, posts batches of OCSF
 * records as OTLP log records, and advances a durable cursor only after the
 * collector accepts them.
 *
 * Delivery is at-least-once by construction. The cursor never moves past an
 * unacknowledged batch, so a crashed process resends rather than skips; the
 * SIEM deduplicates on `metadata.uid`.
 *
 * Rotated generations are drained before the live file and in the order they
 * were written, and a generation is removed only once every byte in it has
 * been acknowledged. A batch the collector refuses on its content — a 4xx that
 * is not a timeout or a rate limit — is written to the quarantine file and
 * stepped over, because retrying it forever would block every later record
 * behind one the collector will never take.
 * @module sink/otlp
 */

import { appendFileSync, closeSync, openSync, readFileSync, readSync, statSync, unlinkSync, writeFileSync } from 'node:fs'
import type { ResolvedOtlp } from '../config.ts'
import type { OcsfRecord } from '../ocsf/types.ts'
import { rotatedGenerations } from './spool.ts'

/** OTLP severity numbers for the OCSF severities we emit. */
const OTLP_SEVERITY: Readonly<Record<number, number>> = Object.freeze({
  0: 0, 1: 9, 2: 13, 3: 17, 4: 21, 5: 21, 6: 24,
})

/** HTTP statuses that are transient despite being client errors. */
const RETRYABLE_CLIENT_STATUS: ReadonlySet<number> = new Set([408, 425, 429])

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

/**
 * What the collector did with one batch.
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

/** The HTTP call the shipper makes; injectable so tests need no network. */
export type PostBatch = (url: string, headers: Readonly<Record<string, string>>, body: string, timeoutMs: number) => Promise<BatchOutcome>

/**
 * POST one batch with `fetch`.
 * @param url - the collector's logs endpoint.
 * @param headers - configured request headers.
 * @param body - the serialized OTLP payload.
 * @param timeoutMs - per-request timeout.
 * @returns what the collector did with the batch.
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
    if (response.ok) return 'accepted'
    if (response.status >= 400 && response.status < 500 && !RETRYABLE_CLIENT_STATUS.has(response.status)) return 'reject'
    return 'retry'
  } catch {
    // Any transport failure: the cursor stays put and the batch is retried.
    return 'retry'
  } finally {
    clearTimeout(timer)
  }
}

/** How far one file was drained, and whether anything is left in it. */
interface FileProgress {
  readonly shipped: number
  /** True when every byte that was there has been acknowledged or quarantined. */
  readonly drained: boolean
}

/**
 * Ships spooled records to an OTLP/HTTP collector, tracking a durable byte
 * cursor into the live spool file and draining rotated generations first.
 */
export class OtlpShipper {
  private timer: NodeJS.Timeout | undefined
  private draining = false
  private retried = false
  /** Consecutive drains that ended on a transient failure; drives the backoff. */
  private failures = 0
  /** Earliest time the next drain may run, while a backoff is in effect. */
  private nextAttemptAt = 0
  /** Records written to the quarantine file since this process started. */
  private quarantined = 0
  /** How far each rotated generation was drained in this process. */
  private readonly generationOffsets = new Map<string, number>()
  /** Generations already accounted for, so a newly appeared one is recognisable. */
  private readonly knownGenerations = new Set<string>()

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
   * Read the spool from the cursor and ship what is there, unless a backoff
   * from an earlier transient failure is still in effect.
   * @returns the number of records the collector accepted.
   */
  async drain(): Promise<number> {
    if (this.draining) return 0
    if (Date.now() < this.nextAttemptAt) return 0
    this.draining = true
    this.retried = false
    try {
      const shipped = await this.drainOnce()
      this.applyBackoff()
      return shipped
    } catch (error: unknown) {
      this.onError(error)
      return 0
    } finally {
      this.draining = false
    }
  }

  /** The byte offset delivery has reached in the live spool, as last persisted. */
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

  /** How many records this process has written to the quarantine file. */
  quarantinedCount(): number {
    return this.quarantined
  }

  /** Widen or clear the backoff window according to how the last drain ended. */
  private applyBackoff(): void {
    if (!this.retried) {
      this.failures = 0
      this.nextAttemptAt = 0
      return
    }
    this.failures += 1
    const delay = Math.min(
      this.options.flushIntervalMs * 2 ** (this.failures - 1),
      this.options.maxBackoffMs,
    )
    this.nextAttemptAt = Date.now() + delay
  }

  /**
   * Move the live cursor onto the generation it now indexes.
   *
   * Rotation renames the file the cursor pointed into. Everything before that
   * offset was already delivered, so without this the generation is re-shipped
   * from its first byte on every rotation — allowed by at-least-once, but a
   * whole `spoolMaxBytes` of avoidable duplicates. The cursor predates the
   * first of the newly appeared generations, so it indexes the oldest of them.
   * @param generations - the generations present at the start of this pass.
   */
  private carryCursor(generations: readonly string[]): void {
    const fresh = generations.filter(generation => !this.knownGenerations.has(generation))
    for (const generation of generations) this.knownGenerations.add(generation)
    const oldest = fresh[0]
    if (oldest === undefined) return
    const carried = this.cursor()
    if (carried === 0) return
    this.generationOffsets.set(oldest, carried)
    writeFileSync(this.options.cursorPath, '0')
  }

  /** One drain pass: every rotated generation oldest-first, then the live file. */
  private async drainOnce(): Promise<number> {
    let shipped = 0
    const generations = rotatedGenerations(this.spoolPath)
    this.carryCursor(generations)
    for (const generation of generations) {
      const progress = await this.drainFile(
        generation,
        () => this.generationOffsets.get(generation) ?? 0,
        offset => { this.generationOffsets.set(generation, offset) },
      )
      shipped += progress.shipped
      // Ordering is part of the promise: a later generation must not overtake
      // one the collector has not finished taking.
      if (!progress.drained) return shipped
      unlinkSync(generation)
      this.generationOffsets.delete(generation)
      this.knownGenerations.delete(generation)
    }
    const live = await this.drainFile(
      this.spoolPath,
      () => this.cursor(),
      offset => { writeFileSync(this.options.cursorPath, String(offset)) },
    )
    return shipped + live.shipped
  }

  /**
   * Ship one file from its offset to its end, one bounded read window at a
   * time so an hour-long backlog never becomes one allocation.
   */
  private async drainFile(
    path: string,
    readOffset: () => number,
    saveOffset: (offset: number) => void,
  ): Promise<FileProgress> {
    let shipped = 0
    for (;;) {
      const size = statSync(path).size
      let from = readOffset()
      if (size < from) {
        // The file shrank under the cursor: it was truncated or replaced.
        from = 0
        saveOffset(0)
      }
      if (from >= size) return { shipped, drained: true }

      const capped = size - from > this.options.maxReadBytes
      let text = this.readWindow(path, from, capped ? this.options.maxReadBytes : size - from)
      let lastBreak = text.lastIndexOf('\n')
      if (lastBreak < 0 && capped) {
        // One record is longer than the read window. Reading it whole spends
        // more memory once; refusing to would stall delivery permanently.
        text = this.readWindow(path, from, size - from)
        lastBreak = text.lastIndexOf('\n')
      }
      // A trailing partial line is left for the next pass: its bytes stay
      // uncounted, so the cursor never advances past an incomplete record.
      if (lastBreak < 0) return { shipped, drained: false }
      const complete = text.slice(0, lastBreak + 1)
      const lines = complete.split('\n').filter(line => line.length > 0)
      if (lines.length === 0) {
        saveOffset(from + Buffer.byteLength(complete))
        continue
      }

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
        const outcome = records.length === 0 ? 'accepted' : await this.post(
          this.options.url,
          this.options.headers,
          JSON.stringify(otlpPayload(records, this.productName)),
          this.options.timeoutMs,
        )
        if (outcome === 'retry') {
          this.retried = true
          return { shipped, drained: false }
        }
        if (outcome === 'reject') {
          this.quarantine(slice)
        } else {
          shipped += records.length
        }
        // Each spooled line contributes its own bytes plus its newline.
        offset += slice.reduce((sum, line) => sum + Buffer.byteLength(line) + 1, 0)
        saveOffset(offset)
      }
    }
  }

  /** Read `length` bytes of one file starting at `from`. */
  private readWindow(path: string, from: number, length: number): string {
    const fd = openSync(path, 'r')
    try {
      const buffer = Buffer.allocUnsafe(length)
      readSync(fd, buffer, 0, length, from)
      return buffer.toString('utf8')
    } finally {
      closeSync(fd)
    }
  }

  /** Move a batch the collector refused into the quarantine file. */
  private quarantine(lines: readonly string[]): void {
    appendFileSync(this.options.quarantinePath, `${lines.join('\n')}\n`, { mode: 0o640 })
    this.quarantined += lines.length
    this.onError(new Error(
      `ocsf-forwarder: collector refused ${String(lines.length)} record(s); quarantined to ${this.options.quarantinePath}`,
    ))
  }
}
