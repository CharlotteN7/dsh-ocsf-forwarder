/**
 * The shipper: reads the spool by byte offset, posts batches of OCSF records
 * through a {@link Transport}, and advances a durable cursor only after the
 * destination accepts them.
 *
 * Delivery is at-least-once by construction. The cursor never moves past an
 * unacknowledged batch, so a crashed process resends rather than skips; the
 * SIEM deduplicates on `metadata.uid`.
 *
 * Rotated generations are drained before the live file and in the order they
 * were written, and a generation is removed only once every byte in it has
 * been acknowledged. A batch the destination refuses on its content is written
 * to the quarantine file and stepped over, because retrying it forever would
 * block every later record behind one the destination will never take.
 *
 * Nothing here knows a wire format. The transport supplies the endpoint, the
 * encoding, and the status reading; the cursor discipline is the shipper's
 * alone.
 * @module sink/shipper
 */

import {
  appendFileSync, chmodSync, closeSync, openSync, readFileSync, readSync, statSync, unlinkSync, writeFileSync,
} from 'node:fs'
import type { ResolvedShipper } from '../config.ts'
import type { OcsfRecord } from '../ocsf/types.ts'
import { rotatedGenerations } from './spool.ts'
import { postBatch, type PostBatch } from './transport.ts'

/**
 * Mode of the quarantine file. It holds whole refused records, so it is the SOC
 * lane's mode: readable by the operator's group, never by the world.
 */
const QUARANTINE_MODE = 0o640

/** How far one file was drained, and whether anything is left in it. */
interface FileProgress {
  readonly shipped: number
  /** True when every byte that was there has been acknowledged or quarantined. */
  readonly drained: boolean
}

/**
 * Ships spooled records to a SIEM, tracking a durable byte cursor into the live
 * spool file and draining rotated generations first.
 */
export class Shipper {
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

  /** `dev:ino` of the file the live cursor's offset counts bytes of. */
  private cursorIdentity: string | undefined
  /** Generations already accounted for, so a newly appeared one is recognisable. */
  private readonly knownGenerations = new Set<string>()

  /**
   * @param options - the resolved shipper settings, including its transport.
   * @param spoolPath - the spool file the shipper reads.
   * @param post - the HTTP call, injectable for tests.
   * @param onError - reports a drain failure.
   */
  constructor(
    private readonly options: ResolvedShipper,
    private readonly spoolPath: string,
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
   * @returns the number of records the destination accepted.
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
    if (fresh.length === 0) return
    const carried = this.cursor()
    if (carried === 0) return
    // Which generation this offset belongs to is a question of file identity,
    // not of position. Taking the oldest is right only when exactly one
    // rotation happened since it was written; if the shipper advanced the
    // cursor between two rotations the offset indexes the *newest* fresh
    // generation, and carrying it onto the oldest skips that generation's head
    // before the drain calls it complete and unlinks it.
    const owner = this.cursorIdentity === undefined
      ? undefined
      : fresh.find(generation => fileIdentity(generation) === this.cursorIdentity)
    // Without a match we cannot say which file the offset counts. Dropping it
    // re-ships each generation from its first byte: duplicates, not a gap.
    if (owner !== undefined) this.generationOffsets.set(owner, carried)
    this.cursorIdentity = undefined
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
      // one the destination has not finished taking.
      if (!progress.drained) return shipped
      unlinkSync(generation)
      this.generationOffsets.delete(generation)
      this.knownGenerations.delete(generation)
    }
    const live = await this.drainFile(
      this.spoolPath,
      () => this.cursor(),
      offset => {
        this.cursorIdentity = fileIdentity(this.spoolPath)
        writeFileSync(this.options.cursorPath, String(offset))
      },
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
      const opened = statSync(path)
      const size = opened.size
      // `drainFile` addresses the spool by path and byte offset across an
      // `await`, and the spool rotates in this same process, so the path can
      // name a different file by the time a batch settles. An offset written
      // then counts bytes of a file this path no longer names.
      const identity = `${String(opened.dev)}:${String(opened.ino)}`
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
          this.options.transport,
          this.options.transport.encode(records),
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
        // Rotation landed while this batch was in flight. Leaving the cursor
        // alone costs a re-send next pass, which at-least-once already allows;
        // writing it here would step the cursor over undelivered records.
        if (fileIdentity(path) !== identity) return { shipped, drained: false }
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

  /**
   * Move a batch the destination refused into the quarantine file.
   *
   * The file holds complete OCSF records, so it carries the SOC lane's mode.
   * `appendFileSync`'s `mode` applies only when it creates the file and is
   * masked by the process umask, so the mode is forced afterwards the way the
   * spool forces its own.
   */
  private quarantine(lines: readonly string[]): void {
    appendFileSync(this.options.quarantinePath, `${lines.join('\n')}\n`, { mode: QUARANTINE_MODE })
    chmodSync(this.options.quarantinePath, QUARANTINE_MODE)
    this.quarantined += lines.length
    this.onError(new Error(
      `ocsf-forwarder: ${this.options.transport.kind} destination refused ${String(lines.length)} record(s); `
      + `quarantined to ${this.options.quarantinePath}`,
    ))
  }
}

/**
 * `dev:ino` of a path, or `undefined` when it names nothing.
 *
 * Two files share one path over time — rotation renames the spool out from
 * under it — so this pair, not the path, identifies the bytes an offset counts.
 * @param path - the path to identify.
 * @returns the identity, or `undefined` when the path could not be read.
 */
function fileIdentity(path: string): string | undefined {
  try {
    const entry = statSync(path)
    return `${String(entry.dev)}:${String(entry.ino)}`
  } catch {
    return undefined
  }
}
