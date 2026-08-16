/**
 * The append-only local spool: one OCSF record per line, written
 * synchronously.
 *
 * The spool is the source of truth. Writing it before anything is queued for
 * shipping is what makes a killed process leave a visible gap — records on
 * disk plus a shipper cursor that stopped advancing — instead of silent loss.
 *
 * Two rules keep that promise under rotation and under concurrency. Rotation
 * renames the full file to a fresh timestamped generation and never reuses or
 * overwrites a name, so no rotated file is ever destroyed by another rotation;
 * only the shipper removes one, and only after the collector acknowledged
 * every byte in it. And one process at a time owns a spool path, enforced by
 * an exclusive lock file taken at construction, because two processes rotating
 * the same path would each rename the inode the other is still writing into.
 * @module sink/spool
 */

import {
  closeSync, fchmodSync, mkdirSync, openSync, readFileSync, readdirSync,
  renameSync, statSync, unlinkSync, writeSync,
} from 'node:fs'
import { basename, dirname, join } from 'node:path'
import type { OcsfRecord } from '../ocsf/types.ts'

/** A destination for finished records. */
export interface Sink {
  /**
   * Accept one record. Must not block on I/O beyond a local append. A failed
   * append throws so the caller can leave its cursor on the unwritten event.
   * @param record - the finished OCSF record.
   */
  write(record: OcsfRecord): void
  /** Release the destination's resources. */
  close(): void
}

/** How a spool file is created. */
export interface SpoolOptions {
  /** Absolute path of the spool file. */
  readonly path: string
  /** Rotate once the file reaches this many bytes. */
  readonly maxBytes: number
  /** How many rotated generations may exist before rotation stops. */
  readonly maxGenerations: number
  /** File mode; the restricted lane uses 0o600. */
  readonly mode: number
  /** Reports a condition an operator must act on; must not throw. */
  readonly onWarn?: (message: string) => void
}

/** Matches one rotated generation of a spool file: `<name>.<ISO stamp>-<counter>`. */
const GENERATION_SUFFIX = /\.\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}\.\d{3}Z-\d{3}$/

/** Width of the per-millisecond collision counter in a generation name. */
const COUNTER_DIGITS = 3

/**
 * Rotated generations of one spool, oldest first.
 *
 * The name is a fixed-width timestamp, so lexicographic order is chronological
 * order and the shipper can drain the backlog in the order it was written.
 * @param spoolPath - the live spool path.
 * @returns absolute paths of the rotated files, oldest first.
 */
export function rotatedGenerations(spoolPath: string): readonly string[] {
  const dir = dirname(spoolPath)
  const prefix = basename(spoolPath)
  let entries: readonly string[]
  try {
    entries = readdirSync(dir)
  } catch {
    // ENOENT only: nothing has been spooled yet, so there are no generations.
    return []
  }
  return entries
    .filter(entry => entry.startsWith(`${prefix}.`) && GENERATION_SUFFIX.test(entry.slice(prefix.length)))
    .sort()
    .map(entry => join(dir, entry))
}

/** The timestamp part of a generation name: an ISO instant with path-safe separators. */
function stamp(now: number): string {
  return new Date(now).toISOString().replace(/:/g, '-')
}

/**
 * Take an exclusive lock on a spool path, or fail loud.
 *
 * `flock` is not exposed by Node's `fs`, so ownership is expressed as a lock
 * file created with `wx`. A lock left behind by a process that no longer
 * exists is taken over; a lock held by a live process is refused, because
 * sharing a spool path between processes silently destroys records.
 * @param lockPath - the lock file's path.
 * @returns the open descriptor of the lock file.
 */
function acquireLock(lockPath: string): number {
  try {
    const fd = openSync(lockPath, 'wx')
    writeSync(fd, `${String(process.pid)}\n`)
    return fd
  } catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
  }
  const owner = Number.parseInt(readFileSync(lockPath, 'utf8').trim(), 10)
  if (Number.isFinite(owner) && owner > 0 && isAlive(owner)) {
    throw new Error(
      `ocsf-forwarder: spool ${lockPath.replace(/\.lock$/, '')} is already held by pid ${String(owner)}; `
      + 'give this process its own spoolPath rather than sharing one',
    )
  }
  unlinkSync(lockPath)
  const fd = openSync(lockPath, 'wx')
  writeSync(fd, `${String(process.pid)}\n`)
  return fd
}

/** Whether a pid names a process this user can still see. */
function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0)
    return true
  } catch (error: unknown) {
    // EPERM means the process exists under another uid, so the lock is live.
    return (error as NodeJS.ErrnoException).code === 'EPERM'
  }
}

/** Newline-delimited JSON spool with size-triggered rotation into numbered generations. */
export class SpoolSink implements Sink {
  private fd: number | undefined
  private lockFd: number | undefined
  private bytes = 0
  private counter = 0
  private lastStamp = ''
  private rotationRefused = false

  /**
   * Take the spool path's lock, then open (or create) the file, creating
   * parent directories as needed.
   * @param options - path, rotation thresholds, file mode, and the warning channel.
   */
  constructor(private readonly options: SpoolOptions) {
    mkdirSync(dirname(options.path), { recursive: true })
    this.lockFd = acquireLock(`${options.path}.lock`)
    try {
      this.fd = this.open()
    } catch (error: unknown) {
      this.releaseLock()
      throw error
    }
    this.bytes = statSync(options.path).size
  }

  /**
   * Append one record as a single line.
   * @param record - the finished OCSF record.
   */
  write(record: OcsfRecord): void {
    if (this.fd === undefined) return
    const line = Buffer.from(`${JSON.stringify(record)}\n`, 'utf8')
    // `writeSync` may satisfy only part of a large buffer; the remainder is
    // written here rather than left as a truncated line for the shipper.
    let written = 0
    while (written < line.length) {
      written += writeSync(this.fd, line, written, line.length - written)
    }
    this.bytes += line.length
    if (this.bytes >= this.options.maxBytes) this.rotate()
  }

  /** Close the descriptor and release the path's lock; further writes are ignored. */
  close(): void {
    if (this.fd !== undefined) {
      closeSync(this.fd)
      this.fd = undefined
    }
    this.releaseLock()
  }

  /** Open the live path in append mode and force the configured permissions onto it. */
  private open(): number {
    const fd = openSync(this.options.path, 'a', this.options.mode)
    // `open(…, 'a', mode)` only applies the mode when it creates the file, so
    // an existing spool would keep whatever permissions it was left with.
    fchmodSync(fd, this.options.mode)
    return fd
  }

  /**
   * Rename the full file to a fresh generation and reopen an empty one.
   *
   * Rotation stops once `maxGenerations` un-drained generations exist. The
   * live file then grows past `maxBytes`, which is loud and recoverable;
   * deleting a generation to make room would destroy the only copy of records
   * the collector has not acknowledged.
   */
  private rotate(): void {
    if (this.fd === undefined) return
    if (rotatedGenerations(this.options.path).length >= this.options.maxGenerations) {
      if (!this.rotationRefused) {
        this.rotationRefused = true
        this.options.onWarn?.(
          `spool ${this.options.path} has ${String(this.options.maxGenerations)} un-drained rotated generations; `
          + 'growing past spoolMaxBytes instead of deleting unshipped records',
        )
      }
      return
    }
    this.rotationRefused = false
    const current = stamp(Date.now())
    this.counter = current === this.lastStamp ? this.counter + 1 : 0
    this.lastStamp = current
    closeSync(this.fd)
    this.fd = undefined
    renameSync(this.options.path, `${this.options.path}.${current}-${String(this.counter).padStart(COUNTER_DIGITS, '0')}`)
    this.fd = this.open()
    this.bytes = 0
  }

  /** Drop the lock file so another process may take the path. */
  private releaseLock(): void {
    if (this.lockFd === undefined) return
    closeSync(this.lockFd)
    this.lockFd = undefined
    try {
      unlinkSync(`${this.options.path}.lock`)
    } catch {
      // ENOENT only: an operator or a crash cleaner already removed it.
    }
  }
}

/** A sink that forwards to several destinations, containing each one's failure. */
export class FanOutSink implements Sink {
  /**
   * @param sinks - the destinations, in write order.
   * @param onError - reports one destination's failure without failing the write.
   */
  constructor(
    private readonly sinks: readonly Sink[],
    private readonly onError: (error: unknown) => void,
  ) {}

  /**
   * Write to every destination.
   * @param record - the finished OCSF record.
   */
  write(record: OcsfRecord): void {
    for (const sink of this.sinks) {
      try {
        sink.write(record)
      } catch (error: unknown) {
        this.onError(error)
      }
    }
  }

  /** Close every destination. */
  close(): void {
    for (const sink of this.sinks) {
      try {
        sink.close()
      } catch (error: unknown) {
        this.onError(error)
      }
    }
  }
}
