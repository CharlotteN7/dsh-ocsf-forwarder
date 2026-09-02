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
 *
 * A third rule keeps it under an I/O failure. Rotation is the only moment this
 * spool holds no descriptor, and a failure there must not end with it holding
 * none: the descriptor is always taken again, a spool that nonetheless has none
 * warns and counts what it drops instead of accepting records into nothing, and
 * every later write retries the open. `pressure()` carries both facts, so a
 * dead audit sink is visible in the same heartbeat as a full one.
 * @module sink/spool
 */

import {
  closeSync, fchmodSync, fstatSync, mkdirSync, openSync, readFileSync, readdirSync,
  renameSync, statSync, unlinkSync, writeSync,
} from 'node:fs'
import { basename, dirname, join } from 'node:path'
import type { OcsfRecord } from '../ocsf/types.ts'

/** A destination for finished records. */
export interface Sink {
  /**
   * Accept one record. Must not block on I/O beyond a local append. A failed
   * append throws so the caller can leave its cursor on the unwritten event;
   * an append that succeeded reports any trouble that followed it out of band,
   * because the caller must not retry a record already on disk.
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
  /**
   * Bytes across the live file and every rotated generation before rotation
   * stops. The second stop condition, on the same refuse-to-rotate terms as
   * {@link SpoolOptions.maxGenerations}: `spoolMaxGenerations` bounds the file
   * count, which bounds nothing about the disk once the live file is the one
   * growing.
   */
  readonly maxTotalBytes: number
  /** File mode; the restricted lane uses 0o600. */
  readonly mode: number
  /** Reports a condition an operator must act on; must not throw. */
  readonly onWarn?: (message: string) => void
  /** Injectable so a test can drive the rotation re-check window. */
  readonly now?: () => number
}

/** Matches one rotated generation of a spool file: `<name>.<ISO stamp>-<counter>`. */
const GENERATION_SUFFIX = /\.\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}\.\d{3}Z-\d{3}$/

/** Width of the per-millisecond collision counter in a generation name. */
const COUNTER_DIGITS = 3

/**
 * How long a refused rotation stands before the filesystem is consulted again.
 *
 * A stop condition is cleared by the shipper draining a generation, which it
 * attempts every `flushIntervalMs` — five seconds by default. Noticing up to a
 * minute late costs the live file a minute of growth against a threshold
 * measured in hundreds of megabytes, and it keeps a directory listing per
 * spooled record off the agent's event loop for as long as the collector is
 * down. It is fixed rather than configurable for the same reason the counter
 * width is: nothing about a deployment makes another value right.
 */
const ROTATION_RECHECK_MS = 60_000

/**
 * First delay before a spool left without a descriptor tries to open one again.
 *
 * The first retry after a failure is immediate, because the condition that took
 * the descriptor away is usually already gone by the next record — a rotation
 * that lost a race with a directory permission change, an unlink under the live
 * file — and a record dropped while waiting out a delay is evidence destroyed.
 * Only once an immediate retry has itself failed does the delay open, doubling
 * to {@link MAX_REOPEN_BACKOFF_MS}. Fixed rather than configurable for the same
 * reason {@link ROTATION_RECHECK_MS} is: nothing about a deployment makes
 * retrying a failed `open` at another rate correct.
 */
const REOPEN_BACKOFF_MS = 250

/** Longest delay between attempts to reopen a failed spool. */
const MAX_REOPEN_BACKOFF_MS = 30_000

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
 * One filesystem failure named for an operator: the `errno` code when there is
 * one, which is the part that says what to fix, and the whole error otherwise.
 * @param error - what a `node:fs` call threw.
 * @returns the code, or the error rendered as a string.
 */
function describe(error: unknown): string {
  const code = (error as NodeJS.ErrnoException).code
  return code === undefined ? String(error) : code
}

/** One file mode as an operator writes it: four octal digits behind a leading zero. */
function octal(mode: number): string {
  return `0${mode.toString(8).padStart(4, '0')}`
}

/** Size of one file, or zero when it has been removed under us. */
function sizeOf(path: string): number {
  try {
    return statSync(path).size
  } catch {
    // ENOENT only: the shipper unlinks a generation the moment it is drained.
    return 0
  }
}

/**
 * Bytes one spool occupies across its live file and every rotated generation.
 * @param spoolPath - the live spool path.
 * @returns the total size in bytes.
 */
export function spoolTotalBytes(spoolPath: string): number {
  return [spoolPath, ...rotatedGenerations(spoolPath)].reduce((sum, file) => sum + sizeOf(file), 0)
}

/** What a spool can say about its own health and disk pressure. */
export interface SpoolPressure {
  /** Bytes across the live file and every rotated generation. */
  readonly totalBytes: number
  /**
   * True once a stop condition has held rotation and the live file is growing
   * past `maxBytes`, or a rename failed and rotation is standing off.
   */
  readonly rotationStopped: boolean
  /**
   * True while the spool has no open descriptor after an I/O failure, which
   * means every record handed to it is being dropped. Deliberate closure is
   * not this state.
   */
  readonly sinkFailed: boolean
  /** Records this spool has dropped since construction because it had no descriptor. */
  readonly droppedRecords: number
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
  /** Earliest time a refused rotation consults the filesystem again. */
  private nextRotationCheckAt = 0
  /** Set by {@link SpoolSink.close}, which is the one state where dropping a write is correct. */
  private closed = false
  /** Records dropped because the spool had no descriptor to write them to. */
  private dropped = 0
  /** Holds the dead-sink warning to one message per outage. */
  private failureWarned = false
  /** Holds the rotation-failure warning to one message per outage. */
  private rotationFailureWarned = false
  /** Holds the un-enforced-mode warning to one message per process. */
  private modeWarned = false
  /** Earliest time a failed spool tries to open a descriptor again. */
  private nextReopenAt = 0
  /** Current reopen delay, zero until an immediate retry has failed. */
  private reopenBackoffMs = 0
  /** Clock behind the generation stamps and the rotation re-check window. */
  private readonly now: () => number

  /**
   * Take the spool path's lock, then open (or create) the file, creating
   * parent directories as needed.
   * @param options - path, rotation thresholds, file mode, and the warning channel.
   */
  constructor(private readonly options: SpoolOptions) {
    this.now = options.now ?? Date.now
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
   * Append one record as a single line, reopening the file first when an
   * earlier failure left this spool without a descriptor.
   *
   * A spool with no descriptor drops the record, and says so: an audit sink
   * that has stopped writing must not be indistinguishable from an idle one.
   * The warning is latched to one message per outage, and every dropped record
   * is counted into {@link SpoolSink.pressure}.
   * @param record - the finished OCSF record.
   */
  write(record: OcsfRecord): void {
    if (this.closed) return
    if (this.fd === undefined) this.reopen()
    if (this.fd === undefined) {
      this.dropped += 1
      if (!this.failureWarned) {
        this.failureWarned = true
        this.options.onWarn?.(
          `spool ${this.options.path} has no writable descriptor and is dropping records; `
          + 'every record handed to it until it reopens is lost',
        )
      }
      return
    }
    const line = Buffer.from(`${JSON.stringify(record)}\n`, 'utf8')
    // `writeSync` may satisfy only part of a large buffer; the remainder is
    // written here rather than left as a truncated line for the shipper.
    let written = 0
    while (written < line.length) {
      written += writeSync(this.fd, line, written, line.length - written)
    }
    this.bytes += line.length
    // A refused rotation leaves `bytes` past the threshold for every later
    // record, so without the re-check window `rotate` would list the spool
    // directory once per spooled record for as long as the stop condition holds.
    if (this.bytes >= this.options.maxBytes && this.now() >= this.nextRotationCheckAt) this.rotate(this.fd)
  }

  /**
   * What this spool currently occupies, whether rotation has stopped, and
   * whether it can write at all.
   * @returns the health and disk pressure a heartbeat reports.
   */
  pressure(): SpoolPressure {
    return {
      totalBytes: spoolTotalBytes(this.options.path),
      rotationStopped: this.rotationRefused,
      sinkFailed: this.fd === undefined && !this.closed,
      droppedRecords: this.dropped,
    }
  }

  /** Close the descriptor and release the path's lock; further writes are ignored. */
  close(): void {
    this.closed = true
    if (this.fd !== undefined) {
      closeSync(this.fd)
      this.fd = undefined
    }
    this.releaseLock()
  }

  /**
   * Open the live path in append mode and put the configured permissions on it.
   *
   * `open(…, 'a', mode)` applies the mode only when it creates the file, so an
   * existing spool would otherwise keep whatever permissions it was left with.
   * The re-assertion is best effort, because the appends are worth more than
   * it is. `EPERM` is what a spool hardened with `chattr +a` returns for
   * `fchmod`, and what a spool owned by another account returns; both still
   * take appends. A spool this process cannot chmod but can write to is a
   * working spool, and
   * failing every write because the mode could not be re-stated would hand an
   * attacker the outage that making the file append-only was meant to prevent.
   * Any other `errno` is an open this spool has no business keeping, so the
   * descriptor is closed rather than leaked past the throw.
   * @returns the open descriptor.
   */
  private open(): number {
    const fd = openSync(this.options.path, 'a', this.options.mode)
    try {
      fchmodSync(fd, this.options.mode)
    } catch (error: unknown) {
      if ((error as NodeJS.ErrnoException).code !== 'EPERM') {
        closeSync(fd)
        throw error
      }
      this.warnUnenforcedMode(fd)
    }
    return fd
  }

  /**
   * Report a spool whose mode could not be re-asserted and which grants more
   * than the configured mode does.
   *
   * A file already at or inside the configured mode is what the `fchmod` would
   * have produced, so there is nothing for an operator to act on and nothing to
   * say. Wider bits are the SOC lane readable by accounts it was configured to
   * exclude, which is a finding — named once per process, because the condition
   * repeats on every reopen and every rotation.
   * @param fd - the descriptor whose file's actual mode is read.
   */
  private warnUnenforcedMode(fd: number): void {
    if (this.modeWarned) return
    const actual = fstatSync(fd).mode & 0o7777
    if ((actual & ~this.options.mode) === 0) return
    this.modeWarned = true
    this.options.onWarn?.(
      `spool ${this.options.path} is mode ${octal(actual)} and could not be changed to `
      + `${octal(this.options.mode)} (EPERM); an append-only or foreign-owned spool cannot be `
      + 'chmod-ed, so records keep appending at the wider mode',
    )
  }

  /**
   * Rename the full file to a fresh generation and reopen an empty one.
   *
   * Rotation stops once either bound is reached — `maxGenerations` un-drained
   * generations, or `maxTotalBytes` on disk. The live file then grows past
   * `maxBytes`, which is loud and recoverable; deleting a generation to make
   * room would destroy the only copy of records the collector has not
   * acknowledged. An audit lane may run out of disk. It may not quietly delete
   * the evidence it exists to keep.
   *
   * A refusal holds off the next attempt for {@link ROTATION_RECHECK_MS}, so a
   * stop condition that lasts an outage costs one directory listing a minute
   * rather than one per record.
   *
   * The rename is the one point where this spool holds no descriptor, so a
   * failure there is reported and a descriptor is taken again unconditionally —
   * on the new generation when the rename went through, on the original path
   * when it did not. A spool left without a descriptor writes nothing for the
   * rest of the process's life, which for an audit lane is worse than any
   * rotation outcome.
   * @param fd - the open descriptor to close, taken as an argument so the one
   *   caller's guarantee that it has one is what the type says.
   */
  private rotate(fd: number): void {
    const reason = this.rotationBlockedBy()
    if (reason !== undefined) {
      this.nextRotationCheckAt = this.now() + ROTATION_RECHECK_MS
      if (!this.rotationRefused) {
        this.rotationRefused = true
        this.options.onWarn?.(
          `spool ${this.options.path} ${reason}; growing past spoolMaxBytes instead of deleting unshipped records`,
        )
      }
      return
    }
    const current = stamp(this.now())
    this.counter = current === this.lastStamp ? this.counter + 1 : 0
    this.lastStamp = current
    closeSync(fd)
    this.fd = undefined
    // A rotation failure is not an outage to wait out before reopening: the
    // live file is still there and still writable in every case but the one
    // that broke the rename.
    this.nextReopenAt = 0
    this.reopenBackoffMs = 0
    try {
      renameSync(this.options.path, `${this.options.path}.${current}-${String(this.counter).padStart(COUNTER_DIGITS, '0')}`)
      this.rotationRefused = false
      this.rotationFailureWarned = false
    } catch (error: unknown) {
      // Rotation has stopped just as surely as a refusal stops it, so the
      // operator-facing signal says so and the next attempt stands off.
      this.rotationRefused = true
      this.nextRotationCheckAt = this.now() + ROTATION_RECHECK_MS
      if (!this.rotationFailureWarned) {
        this.rotationFailureWarned = true
        this.options.onWarn?.(
          `spool ${this.options.path} could not be rotated (${describe(error)}); `
          + 'growing past spoolMaxBytes until the condition clears',
        )
      }
    }
    this.reopen()
  }

  /**
   * Take a descriptor on the live path again, subject to the backoff a failed
   * attempt opens.
   *
   * `bytes` is read back from the descriptor rather than assumed, because the
   * file this reopens is empty after a rotation and holds everything written
   * before the failure after a failed one.
   */
  private reopen(): void {
    if (this.now() < this.nextReopenAt) return
    let fd: number
    try {
      fd = this.open()
    } catch {
      // Whatever denied the open — a revoked permission, a removed directory,
      // an exhausted descriptor table — is reported by `write` as the dropped
      // records it causes, which is the count an operator can act on.
      this.reopenBackoffMs = this.reopenBackoffMs === 0
        ? REOPEN_BACKOFF_MS
        : Math.min(this.reopenBackoffMs * 2, MAX_REOPEN_BACKOFF_MS)
      this.nextReopenAt = this.now() + this.reopenBackoffMs
      return
    }
    this.fd = fd
    this.bytes = fstatSync(fd).size
    this.reopenBackoffMs = 0
    this.nextReopenAt = 0
    if (this.failureWarned) {
      this.failureWarned = false
      this.options.onWarn?.(
        `spool ${this.options.path} reopened after a write failure; `
        + `${String(this.dropped)} record(s) were dropped while it had no descriptor`,
      )
    }
  }

  /**
   * Which stop condition, if either, holds rotation right now.
   * @returns the condition, phrased for the operator, or `undefined` to rotate.
   */
  private rotationBlockedBy(): string | undefined {
    const generations = rotatedGenerations(this.options.path).length
    if (generations >= this.options.maxGenerations) {
      return `has ${String(this.options.maxGenerations)} un-drained rotated generations`
    }
    const total = spoolTotalBytes(this.options.path)
    if (total >= this.options.maxTotalBytes) {
      return `occupies ${String(total)} bytes, at or past spoolMaxTotalBytes (${String(this.options.maxTotalBytes)})`
    }
    return undefined
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
