/**
 * A spool hardened with `chattr +a`, and the `fchmod` that hardening denies.
 *
 * The two halves of this file are deliberately different evidence, and the
 * names say which is which. The `chattr` tests set the real attribute on a real
 * file and let the kernel refuse; they need `CAP_LINUX_IMMUTABLE`, so they run
 * only where this process can actually take it and skip everywhere else. The
 * injected tests make `fchmodSync` throw at the one call the attribute reaches.
 * That is the same errno at the same seam, and it is the only half that runs
 * unprivileged — but an injected `EPERM` is a test of this module's handling,
 * not proof that the attribute behaves as documented.
 */
import { spawnSync } from 'node:child_process'
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { resolveConfig } from '../../src/config.ts'
import { Shipper } from '../../src/sink/shipper.ts'
import { SpoolSink, rotatedGenerations } from '../../src/sink/spool.ts'
import type { OcsfRecord } from '../../src/ocsf/types.ts'

/**
 * The errno the stubbed `fchmodSync` raises, or `undefined` to let the real
 * call through. Hoisted because the module factory below is evaluated before
 * this file's own bindings are initialised.
 */
const denial = vi.hoisted(() => ({ code: undefined as string | undefined }))

vi.mock('node:fs', async (importOriginal) => {
  const real = await importOriginal<typeof import('node:fs')>()
  return {
    ...real,
    fchmodSync(fd: number, mode: number): void {
      if (denial.code === undefined) {
        real.fchmodSync(fd, mode)
        return
      }
      const error: NodeJS.ErrnoException = new Error(`${denial.code}: fchmod`)
      error.code = denial.code
      throw error
    },
  }
})

/**
 * Run `chattr <flag> <path>`, escalating once through `sudo -n`.
 *
 * `-n` never prompts, so this is silent where the escalation is not granted.
 * @param flag - `+a` or `-a`.
 * @param path - the file or directory to change.
 * @returns whether the attribute was changed.
 */
function chattr(flag: string, path: string): boolean {
  if (spawnSync('chattr', [flag, path], { stdio: 'ignore' }).status === 0) return true
  return spawnSync('sudo', ['-n', 'chattr', flag, path], { stdio: 'ignore' }).status === 0
}

/** Whether this process can set the append-only attribute on a temporary file. */
const canSetAppendOnly = ((): boolean => {
  if (process.platform !== 'linux') return false
  const dir = mkdtempSync(join(tmpdir(), 'dsh-ocsf-chattr-'))
  const probe = join(dir, 'probe')
  writeFileSync(probe, '')
  const set = chattr('+a', probe)
  if (set) chattr('-a', probe)
  rmSync(dir, { recursive: true, force: true })
  return set
})()

/**
 * Run `body` with `path` append-only, clearing the attribute whatever happens —
 * a file left with it set cannot be removed by the temporary-directory cleanup.
 * @param path - the file to harden.
 * @param body - what to run against it.
 */
function withAppendOnly(path: string, body: () => void): void {
  expect(chattr('+a', path)).toBe(true)
  try {
    body()
  } finally {
    chattr('-a', path)
  }
}

/** {@link withAppendOnly} for a body that awaits. */
async function withAppendOnlyAsync(path: string, body: () => Promise<void>): Promise<void> {
  expect(chattr('+a', path)).toBe(true)
  try {
    await body()
  } finally {
    chattr('-a', path)
  }
}

let home: string

beforeEach(() => {
  denial.code = undefined
  home = mkdtempSync(join(tmpdir(), 'dsh-ocsf-append-only-'))
})
afterEach(() => {
  denial.code = undefined
  rmSync(home, { recursive: true, force: true })
})

function record(uid: string): OcsfRecord {
  return {
    class_uid: 1007,
    category_uid: 1,
    type_uid: 100701,
    activity_id: 1,
    severity_id: 1,
    time: 1_700_000_000_000,
    metadata: { product: { name: 'p', vendor_name: 'v', version: '1' }, version: '1.9.0', uid },
    cloud: { provider: 'Other' },
    osint: [],
  }
}

/** A spool with generous limits unless a test narrows them. */
function spool(path: string, overrides: Partial<ConstructorParameters<typeof SpoolSink>[0]> = {}): SpoolSink {
  return new SpoolSink({
    path, maxBytes: 1_000_000, maxGenerations: 8, maxTotalBytes: 1_000_000_000, mode: 0o640, ...overrides,
  })
}

/** Record uids in one file, in write order. */
function uidsIn(file: string): string[] {
  return readFileSync(file, 'utf8')
    .split('\n')
    .filter(line => line.length > 0)
    .map(line => String((JSON.parse(line) as OcsfRecord).metadata.uid))
}

describe('a spool whose mode cannot be re-asserted', () => {
  it('keeps appending when the chmod is denied and the file is no wider than configured', () => {
    const path = join(home, 'ocsf.jsonl')
    writeFileSync(path, '', { mode: 0o600 })
    denial.code = 'EPERM'
    const warnings: string[] = []

    const sink = spool(path, { mode: 0o640, onWarn: message => warnings.push(message) })
    sink.write(record('S:0'))
    sink.write(record('S:1'))
    const pressure = sink.pressure()
    sink.close()

    expect(uidsIn(path)).toEqual(['S:0', 'S:1'])
    expect(pressure.sinkFailed).toBe(false)
    expect(pressure.droppedRecords).toBe(0)
    // 0600 is what the denied chmod would have produced from 0640, so there is
    // nothing for an operator to act on and nothing to say.
    expect(warnings).toEqual([])
  })

  it('names a spool wider than its configured mode once, not once per open', () => {
    const dir = join(home, 'wide')
    mkdirSync(dir)
    const path = join(dir, 'ocsf.jsonl')
    writeFileSync(path, '', { mode: 0o644 })
    denial.code = 'EPERM'
    const warnings: string[] = []
    let clock = 1_700_000_000_000

    const sink = spool(path, {
      mode: 0o600, maxBytes: 200, onWarn: message => warnings.push(message), now: () => clock,
    })
    try {
      // Renaming needs write permission on the directory, so the rotation these
      // records trigger fails and reopens the same wide file: three more opens
      // on the file the construction already warned about.
      chmodSync(dir, 0o500)
      for (let index = 0; index < 4; index += 1) {
        sink.write(record(`S:${String(index)}`))
        clock += 60_000
      }
    } finally {
      chmodSync(dir, 0o700)
    }
    sink.close()

    const modeWarnings = warnings.filter(message => message.includes('could not be changed to'))
    expect(modeWarnings).toHaveLength(1)
    expect(modeWarnings[0]).toContain('0644')
    expect(modeWarnings[0]).toContain('0600')
    expect(uidsIn(path)).toEqual(['S:0', 'S:1', 'S:2', 'S:3'])
    expect(statSync(path).mode & 0o7777).toBe(0o644)
  })

  it('refuses an open whose mode call failed for anything but a denied chmod', () => {
    const path = join(home, 'ocsf.jsonl')
    denial.code = 'EIO'

    expect(() => spool(path)).toThrow(expect.objectContaining({ code: 'EIO' }))

    // The path's lock was released on the way out, so the next construction can
    // take it rather than reporting the dead process as its holder.
    denial.code = undefined
    const sink = spool(path)
    sink.write(record('S:0'))
    sink.close()
    expect(uidsIn(path)).toEqual(['S:0'])
  })

  it.runIf(process.platform === 'linux')('closes the descriptor it is about to throw past', () => {
    const path = join(home, 'ocsf.jsonl')
    denial.code = 'EIO'
    const before = readdirSync('/proc/self/fd').length

    for (let attempt = 0; attempt < 64; attempt += 1) {
      expect(() => spool(path)).toThrow(expect.objectContaining({ code: 'EIO' }))
    }

    // A descriptor left open per refused construction is a file-descriptor leak
    // on the spool's own reopen path, which runs once per record while a spool
    // is failing.
    expect(readdirSync('/proc/self/fd').length).toBeLessThan(before + 8)
  })
})

describe('a spool made append-only with chattr +a', () => {
  it.runIf(canSetAppendOnly)('accepts records the kernel will not let it chmod', () => {
    const path = join(home, 'ocsf.jsonl')
    writeFileSync(path, '', { mode: 0o640 })
    const warnings: string[] = []

    withAppendOnly(path, () => {
      const sink = spool(path, { mode: 0o640, onWarn: message => warnings.push(message) })
      sink.write(record('S:0'))
      sink.write(record('S:1'))
      const pressure = sink.pressure()
      sink.close()

      expect(uidsIn(path)).toEqual(['S:0', 'S:1'])
      expect(pressure.sinkFailed).toBe(false)
      expect(pressure.droppedRecords).toBe(0)
      expect(warnings).toEqual([])
    })
  })

  it.runIf(canSetAppendOnly)('cannot rotate, and keeps every record in the live file instead', () => {
    const path = join(home, 'ocsf.jsonl')
    writeFileSync(path, '', { mode: 0o640 })
    const warnings: string[] = []
    let clock = 1_700_000_000_000

    withAppendOnly(path, () => {
      const sink = spool(path, {
        mode: 0o640, maxBytes: 200, onWarn: message => warnings.push(message), now: () => clock,
      })
      for (let index = 0; index < 30; index += 1) {
        sink.write(record(`S:${String(index)}`))
        // Past the stand-off each time, so every one of these attempts the
        // rename the attribute refuses.
        clock += 60_000
      }
      const pressure = sink.pressure()
      sink.close()

      expect(uidsIn(path)).toEqual(Array.from({ length: 30 }, (_, index) => `S:${String(index)}`))
      expect(rotatedGenerations(path)).toEqual([])
      expect(statSync(path).size).toBeGreaterThan(200)
      expect(pressure.sinkFailed).toBe(false)
      expect(pressure.droppedRecords).toBe(0)
      // Rotation is stopped for the life of the attribute, and says so where a
      // refused rotation says it: nothing here silently deletes evidence.
      expect(pressure.rotationStopped).toBe(true)
      const refusals = warnings.filter(message => message.includes('could not be rotated'))
      expect(refusals).toHaveLength(1)
      expect(refusals[0]).toContain('EPERM')
    })
  })

  it.runIf(canSetAppendOnly)('stops the shipper at a generation it is not allowed to unlink', async () => {
    const path = join(home, 'ocsf.jsonl')
    const writer = spool(path, { maxBytes: 200 })
    for (let index = 0; index < 12; index += 1) writer.write(record(`S:${String(index)}`))
    writer.close()
    const generation = rotatedGenerations(path)[0]
    expect(generation).toBeDefined()

    const errors: unknown[] = []
    const resolved = resolveConfig({
      spoolPath: path,
      fleet: { installUid: 'install-test' },
      otlp: { endpoint: 'http://collector:4318' },
    })
    const shipper = new Shipper(resolved.shipper!, path, async () => 'accepted', error => errors.push(error))

    await withAppendOnlyAsync(generation as string, async () => {
      await shipper.drain()
      await shipper.drain()
    })

    // Every byte of the generation was accepted, so the shipper tried to remove
    // it — and cannot. Ordering forbids stepping over it, so the live file's
    // cursor never moves and delivery has stopped for good.
    expect(errors.map(error => (error as NodeJS.ErrnoException).code)).toContain('EPERM')
    expect(shipper.cursor()).toBe(0)
    expect(rotatedGenerations(path)).toContain(generation)
  })
})
