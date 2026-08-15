/**
 * The append-only local spool: one OCSF record per line, written
 * synchronously.
 *
 * The spool is the source of truth. Writing it before anything is queued for
 * shipping is what makes a killed process leave a visible gap — records on
 * disk plus a shipper cursor that stopped advancing — instead of silent loss.
 * @module sink/spool
 */

import { closeSync, mkdirSync, openSync, renameSync, statSync, writeSync } from 'node:fs'
import { dirname } from 'node:path'
import type { OcsfRecord } from '../ocsf/types.ts'

/** A destination for finished records. */
export interface Sink {
  /**
   * Accept one record. Must not block on I/O beyond a local append and must
   * not throw: the caller runs on the agent-loop hot path.
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
  /** File mode; the restricted lane uses 0o600. */
  readonly mode: number
}

/** Newline-delimited JSON spool with size-triggered rotation. */
export class SpoolSink implements Sink {
  private fd: number | undefined
  private bytes = 0

  /**
   * Open (or create) the spool file, creating parent directories as needed.
   * @param options - path, rotation threshold, and file mode.
   */
  constructor(private readonly options: SpoolOptions) {
    mkdirSync(dirname(options.path), { recursive: true })
    this.fd = openSync(options.path, 'a', options.mode)
    this.bytes = statSync(options.path).size
  }

  /**
   * Append one record as a single line.
   * @param record - the finished OCSF record.
   */
  write(record: OcsfRecord): void {
    if (this.fd === undefined) return
    const line = `${JSON.stringify(record)}\n`
    writeSync(this.fd, line)
    this.bytes += Buffer.byteLength(line)
    if (this.bytes >= this.options.maxBytes) this.rotate()
  }

  /** Close the descriptor; further writes are ignored. */
  close(): void {
    if (this.fd === undefined) return
    closeSync(this.fd)
    this.fd = undefined
  }

  /** Rename the full file aside and reopen an empty one at the same path. */
  private rotate(): void {
    if (this.fd === undefined) return
    closeSync(this.fd)
    renameSync(this.options.path, `${this.options.path}.1`)
    this.fd = openSync(this.options.path, 'a', this.options.mode)
    this.bytes = 0
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
