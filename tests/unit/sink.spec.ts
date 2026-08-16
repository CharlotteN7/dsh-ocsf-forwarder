/** The spool's durability behaviour and the shipper's cursor discipline. */
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { resolveConfig } from '../../src/config.ts'
import { OtlpShipper, otlpPayload, type BatchOutcome, type PostBatch } from '../../src/sink/otlp.ts'
import { FanOutSink, SpoolSink, rotatedGenerations, type Sink } from '../../src/sink/spool.ts'
import type { OcsfRecord } from '../../src/ocsf/types.ts'

let home: string

beforeEach(() => { home = mkdtempSync(join(tmpdir(), 'dsh-ocsf-sink-')) })
afterEach(() => { rmSync(home, { recursive: true, force: true }) })

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
  return new SpoolSink({ path, maxBytes: 1_000_000, maxGenerations: 8, mode: 0o640, ...overrides })
}

/** Every record uid on disk, across the live spool and every rotated generation. */
function uidsOnDisk(path: string): string[] {
  return [...rotatedGenerations(path), path]
    .flatMap(file => readFileSync(file, 'utf8').split('\n'))
    .filter(line => line.length > 0)
    .map(line => String((JSON.parse(line) as OcsfRecord).metadata.uid))
}

describe('the spool', () => {
  it('writes one parseable JSON object per line and creates its directory', () => {
    const path = join(home, 'nested', 'ocsf.jsonl')
    const sink = spool(path)
    sink.write(record('a'))
    sink.write(record('b'))
    sink.close()

    const lines = readFileSync(path, 'utf8').trim().split('\n')
    expect(lines).toHaveLength(2)
    expect((JSON.parse(lines[1] as string) as OcsfRecord).metadata.uid).toBe('b')
  })

  it('creates the spool with the mode it was given', () => {
    const path = join(home, 'restricted.jsonl')
    spool(path, { mode: 0o600 }).close()
    expect(statSync(path).mode & 0o777).toBe(0o600)
  })

  it('applies its mode to a spool file that already exists', () => {
    const path = join(home, 'pre-existing.jsonl')
    writeFileSync(path, '', { mode: 0o644 })
    spool(path, { mode: 0o600 }).close()
    expect(statSync(path).mode & 0o777).toBe(0o600)
  })

  it('writes a record larger than one write buffer as a single intact line', () => {
    const path = join(home, 'ocsf.jsonl')
    const large = record('big') as OcsfRecord & { message?: string }
    const sink = spool(path, { maxBytes: 64 * 1024 * 1024 })
    sink.write({ ...large, message: 'x'.repeat(4 * 1024 * 1024) })
    sink.close()

    const lines = readFileSync(path, 'utf8').split('\n').filter(line => line.length > 0)
    expect(lines).toHaveLength(1)
    expect((JSON.parse(lines[0] as string) as OcsfRecord).metadata.uid).toBe('big')
  })

  it('ignores writes after close instead of throwing on the hot path', () => {
    const path = join(home, 'ocsf.jsonl')
    const sink = spool(path)
    sink.close()
    sink.close()
    expect(() => { sink.write(record('a')) }).not.toThrow()
    expect(readFileSync(path, 'utf8')).toBe('')
  })
})

describe('rotation', () => {
  it('keeps every record across repeated rotations instead of overwriting one slot', () => {
    const path = join(home, 'ocsf.jsonl')
    const sink = spool(path, { maxBytes: 200 })
    for (let index = 0; index < 30; index += 1) sink.write(record(`S:${String(index)}`))
    sink.close()

    const expected = Array.from({ length: 30 }, (_, index) => `S:${String(index)}`)
    expect(uidsOnDisk(path)).toEqual(expected)
    expect(rotatedGenerations(path).length).toBeGreaterThan(1)
  })

  it('names generations so that lexicographic order is write order', () => {
    const path = join(home, 'ocsf.jsonl')
    const sink = spool(path, { maxBytes: 200 })
    for (let index = 0; index < 12; index += 1) sink.write(record(`S:${String(index)}`))
    sink.close()

    const generations = rotatedGenerations(path)
    expect([...generations].sort()).toEqual([...generations])
    const first = readFileSync(generations[0] as string, 'utf8')
    expect(first).toContain('"S:0"')
  })

  it('stops rotating and reports it rather than deleting an un-drained generation', () => {
    const path = join(home, 'ocsf.jsonl')
    const warnings: string[] = []
    const sink = spool(path, { maxBytes: 200, maxGenerations: 2, onWarn: message => warnings.push(message) })
    for (let index = 0; index < 30; index += 1) sink.write(record(`S:${String(index)}`))
    sink.close()

    expect(rotatedGenerations(path)).toHaveLength(2)
    expect(uidsOnDisk(path)).toHaveLength(30)
    expect(statSync(path).size).toBeGreaterThan(200)
    expect(warnings[0]).toContain('un-drained rotated generations')
  })
})

describe('spool ownership', () => {
  it('refuses a second writer on one path instead of letting them destroy each other', () => {
    const path = join(home, 'shared.jsonl')
    const first = spool(path)
    expect(() => spool(path)).toThrow(/already held by pid/)
    first.write(record('a'))
    first.close()
    expect(uidsOnDisk(path)).toEqual(['a'])
  })

  it('takes over a lock left behind by a process that no longer exists', () => {
    const path = join(home, 'stale.jsonl')
    writeFileSync(`${path}.lock`, '2147483645\n')
    const sink = spool(path)
    sink.write(record('a'))
    sink.close()
    expect(uidsOnDisk(path)).toEqual(['a'])
  })

  it('releases the path when it closes', () => {
    const path = join(home, 'ocsf.jsonl')
    spool(path).close()
    expect(existsSync(`${path}.lock`)).toBe(false)
    spool(path).close()
  })

  it('gives the path back when the spool itself cannot be opened', () => {
    const path = join(home, 'a-directory')
    mkdirSync(path)
    expect(() => spool(path)).toThrow()
    expect(existsSync(`${path}.lock`)).toBe(false)
  })

  it('finds no generations for a spool whose directory does not exist yet', () => {
    expect(rotatedGenerations(join(home, 'absent', 'ocsf.jsonl'))).toEqual([])
  })
})

describe('fan-out', () => {
  it('contains a destination failure and still writes the others', () => {
    const written: string[] = []
    const failing: Sink = { write() { throw new Error('disk full') }, close() { throw new Error('late') } }
    const working: Sink = { write(item) { written.push(String(item.metadata.uid)) }, close() {} }
    const errors: unknown[] = []
    const sink = new FanOutSink([failing, working], error => errors.push(error))
    sink.write(record('a'))
    sink.close()
    expect(written).toEqual(['a'])
    expect(errors).toHaveLength(2)
  })
})

describe('the OTLP payload', () => {
  it('wraps records as OTLP log records carrying the OCSF class', () => {
    const payload = JSON.parse(JSON.stringify(otlpPayload([record('a')], 'dsh-ocsf-forwarder'))) as {
      resourceLogs: { scopeLogs: { logRecords: { timeUnixNano: string; attributes: { key: string }[] }[] }[] }[]
    }
    const first = payload.resourceLogs[0]?.scopeLogs[0]?.logRecords[0]
    expect(first?.timeUnixNano).toBe('1700000000000000000')
    expect(first?.attributes.map(attribute => attribute.key)).toEqual(['ocsf.class_uid', 'ocsf.type_uid'])
  })
})

describe('the shipper', () => {
  /** Uids the collector was handed, in delivery order. */
  function delivered(body: string): string[] {
    const payload = JSON.parse(body) as { resourceLogs: { scopeLogs: { logRecords: { body: { stringValue: string } }[] }[] }[] }
    return (payload.resourceLogs[0]?.scopeLogs[0]?.logRecords ?? [])
      .map(line => String((JSON.parse(line.body.stringValue) as OcsfRecord).metadata.uid))
  }

  function shipper(post: PostBatch, overrides: Record<string, unknown> = {}): {
    instance: OtlpShipper
    path: string
    cursor: string
    quarantine: string
  } {
    const path = join(home, 'ocsf.jsonl')
    const resolved = resolveConfig({
      spoolPath: path,
      otlp: { endpoint: 'http://collector:4318', batchSize: 10, ...overrides },
    })
    return {
      instance: new OtlpShipper(resolved.otlp!, path, 'test', post),
      path,
      cursor: resolved.otlp!.cursorPath,
      quarantine: resolved.otlp!.quarantinePath,
    }
  }

  it('ships spooled records and advances the cursor to the file size', async () => {
    const posted: string[] = []
    const { instance, path, cursor } = shipper(async (_url, _headers, body) => { posted.push(body); return 'accepted' })
    writeFileSync(path, `${JSON.stringify(record('a'))}\n${JSON.stringify(record('b'))}\n`)

    expect(await instance.drain()).toBe(2)
    expect(posted).toHaveLength(1)
    expect(Number(readFileSync(cursor, 'utf8'))).toBe(statSync(path).size)
    expect(await instance.drain()).toBe(0)
  })

  it('drains rotated generations oldest-first and removes each one it has delivered', async () => {
    const seen: string[] = []
    const { instance, path } = shipper(async (_url, _headers, body) => { seen.push(...delivered(body)); return 'accepted' })
    const sink = spool(path, { maxBytes: 200 })
    for (let index = 0; index < 30; index += 1) sink.write(record(`S:${String(index)}`))
    sink.close()
    expect(rotatedGenerations(path).length).toBeGreaterThan(1)

    expect(await instance.drain()).toBe(30)
    expect(seen).toEqual(Array.from({ length: 30 }, (_, index) => `S:${String(index)}`))
    expect(rotatedGenerations(path)).toEqual([])
  })

  it('keeps a generation it could not deliver, and every record still on disk', async () => {
    const { instance, path } = shipper(async () => 'retry')
    const sink = spool(path, { maxBytes: 200 })
    for (let index = 0; index < 30; index += 1) sink.write(record(`S:${String(index)}`))
    sink.close()
    const before = rotatedGenerations(path).length

    expect(await instance.drain()).toBe(0)
    expect(rotatedGenerations(path)).toHaveLength(before)
    expect(uidsOnDisk(path)).toHaveLength(30)
  })

  it('leaves the cursor untouched when the collector cannot take the batch', async () => {
    const { instance, path, cursor } = shipper(async () => 'retry')
    writeFileSync(path, `${JSON.stringify(record('a'))}\n`)
    expect(await instance.drain()).toBe(0)
    expect(instance.cursor()).toBe(0)
    expect(() => readFileSync(cursor, 'utf8')).toThrow()
  })

  it('quarantines a batch the collector refuses instead of blocking every record behind it', async () => {
    let attempts = 0
    const seen: string[] = []
    const { instance, path, quarantine } = shipper(async (_url, _headers, body) => {
      attempts += 1
      const uids = delivered(body)
      if (uids.includes('poison')) return 'reject'
      seen.push(...uids)
      return 'accepted'
    }, { batchSize: 1 })
    writeFileSync(path, [record('a'), record('poison'), record('b')].map(item => `${JSON.stringify(item)}\n`).join(''))

    expect(await instance.drain()).toBe(2)
    expect(seen).toEqual(['a', 'b'])
    expect(instance.quarantinedCount()).toBe(1)
    expect(readFileSync(quarantine, 'utf8')).toContain('"poison"')
    expect(instance.cursor()).toBe(statSync(path).size)
    expect(attempts).toBe(3)
  })

  it('backs off after a transient failure instead of hammering the collector', async () => {
    let attempts = 0
    const { instance, path } = shipper(async () => { attempts += 1; return 'retry' }, { flushIntervalMs: 60_000 })
    writeFileSync(path, `${JSON.stringify(record('a'))}\n`)

    expect(await instance.drain()).toBe(0)
    expect(attempts).toBe(1)
    // The backoff window is open, so the next drain does not reach the wire.
    expect(await instance.drain()).toBe(0)
    expect(attempts).toBe(1)
  })

  it('resumes at full rate once the collector recovers', async () => {
    let outcome: BatchOutcome = 'retry'
    const { instance, path } = shipper(async () => outcome, { flushIntervalMs: 0 })
    writeFileSync(path, `${JSON.stringify(record('a'))}\n`)
    expect(await instance.drain()).toBe(0)
    outcome = 'accepted'
    expect(await instance.drain()).toBe(1)
    writeFileSync(path, `${JSON.stringify(record('a'))}\n${JSON.stringify(record('b'))}\n`)
    expect(await instance.drain()).toBe(1)
  })

  it('drains a backlog larger than one read window across successive passes', async () => {
    const seen: string[] = []
    const { instance, path } = shipper(
      async (_url, _headers, body) => { seen.push(...delivered(body)); return 'accepted' },
      { maxReadBytes: 400, batchSize: 1 },
    )
    writeFileSync(path, Array.from({ length: 12 }, (_, index) => `${JSON.stringify(record(`S:${String(index)}`))}\n`).join(''))

    expect(await instance.drain()).toBe(12)
    expect(seen).toEqual(Array.from({ length: 12 }, (_, index) => `S:${String(index)}`))
    expect(instance.cursor()).toBe(statSync(path).size)
  })

  it('resumes from the persisted cursor after a restart', async () => {
    const posted: unknown[] = []
    const { instance, path, cursor } = shipper(async (_url, _headers, body) => { posted.push(body); return 'accepted' })
    const first = `${JSON.stringify(record('a'))}\n`
    writeFileSync(path, first)
    await instance.drain()
    writeFileSync(path, `${first}${JSON.stringify(record('b'))}\n`)

    const restarted = new OtlpShipper(
      resolveConfig({ spoolPath: path, otlp: { endpoint: 'http://collector:4318' } }).otlp!,
      path,
      'test',
      async () => 'accepted',
    )
    expect(restarted.cursor()).toBe(Buffer.byteLength(first))
    expect(await restarted.drain()).toBe(1)
    expect(Number(readFileSync(cursor, 'utf8'))).toBe(statSync(path).size)
  })

  it('steps past a read window holding nothing but blank lines', async () => {
    const { instance, path } = shipper(async () => 'accepted', { maxReadBytes: 3 })
    writeFileSync(path, `\n\n\n${JSON.stringify(record('a'))}\n`)
    expect(await instance.drain()).toBe(1)
    expect(instance.cursor()).toBe(statSync(path).size)
  })

  it('holds back a partially written trailing line', async () => {
    const { instance, path } = shipper(async () => 'accepted')
    writeFileSync(path, `${JSON.stringify(record('a'))}\n{"partial":`)
    expect(await instance.drain()).toBe(1)
    expect(instance.cursor()).toBe(Buffer.byteLength(`${JSON.stringify(record('a'))}\n`))
  })

  it('stops at the first batch it could not deliver so later records are retried', async () => {
    let calls = 0
    const { instance, path } = shipper(
      async () => { calls += 1; return calls === 1 ? 'accepted' : 'retry' },
      { batchSize: 1, flushIntervalMs: 0 },
    )
    writeFileSync(path, [record('a'), record('b'), record('c')].map(item => `${JSON.stringify(item)}\n`).join(''))
    expect(await instance.drain()).toBe(1)
    expect(instance.cursor()).toBe(Buffer.byteLength(`${JSON.stringify(record('a'))}\n`))
  })

  it('skips a corrupt line instead of stalling delivery', async () => {
    const errors: unknown[] = []
    const path = join(home, 'ocsf.jsonl')
    const resolved = resolveConfig({ spoolPath: path, otlp: { endpoint: 'http://collector:4318' } })
    const instance = new OtlpShipper(resolved.otlp!, path, 'test', async () => 'accepted', error => errors.push(error))
    writeFileSync(path, `{"broken\n${JSON.stringify(record('b'))}\n`)
    expect(await instance.drain()).toBe(1)
    expect(errors).toHaveLength(1)
  })

  it('restarts from the beginning when the spool was truncated under it', async () => {
    const { instance, path, cursor } = shipper(async () => 'accepted')
    writeFileSync(cursor, '100000')
    writeFileSync(path, `${JSON.stringify(record('a'))}\n`)
    expect(await instance.drain()).toBe(1)
  })

  it('reports a drain failure instead of throwing at the timer', async () => {
    const errors: unknown[] = []
    const missing = join(home, 'missing.jsonl')
    const resolved = resolveConfig({ spoolPath: missing, otlp: { endpoint: 'http://collector:4318' } })
    const instance = new OtlpShipper(resolved.otlp!, missing, 'test', async () => 'accepted', error => errors.push(error))
    expect(await instance.drain()).toBe(0)
    expect(errors).toHaveLength(1)
  })

  it('starts and stops its timer without holding the process open', () => {
    const { instance } = shipper(async () => 'accepted')
    instance.start()
    instance.start()
    instance.stop()
    instance.stop()
  })
})
