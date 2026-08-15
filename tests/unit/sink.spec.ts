/** The spool's durability behaviour and the shipper's cursor discipline. */
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { resolveConfig } from '../../src/config.ts'
import { OtlpShipper, otlpPayload, type PostBatch } from '../../src/sink/otlp.ts'
import { FanOutSink, SpoolSink, type Sink } from '../../src/sink/spool.ts'
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

describe('the spool', () => {
  it('writes one parseable JSON object per line and creates its directory', () => {
    const path = join(home, 'nested', 'ocsf.jsonl')
    const spool = new SpoolSink({ path, maxBytes: 1_000_000, mode: 0o640 })
    spool.write(record('a'))
    spool.write(record('b'))
    spool.close()

    const lines = readFileSync(path, 'utf8').trim().split('\n')
    expect(lines).toHaveLength(2)
    expect((JSON.parse(lines[1] as string) as OcsfRecord).metadata.uid).toBe('b')
  })

  it('creates the spool with the mode it was given', () => {
    const path = join(home, 'restricted.jsonl')
    new SpoolSink({ path, maxBytes: 1_000, mode: 0o600 }).close()
    expect(statSync(path).mode & 0o777).toBe(0o600)
  })

  it('rotates once the file reaches its ceiling', () => {
    const path = join(home, 'ocsf.jsonl')
    const spool = new SpoolSink({ path, maxBytes: 200, mode: 0o640 })
    spool.write(record('a'))
    spool.write(record('b'))
    spool.close()
    expect(readFileSync(`${path}.1`, 'utf8').length).toBeGreaterThan(0)
    expect(readFileSync(path, 'utf8')).toBe('')
  })

  it('ignores writes after close instead of throwing on the hot path', () => {
    const path = join(home, 'ocsf.jsonl')
    const spool = new SpoolSink({ path, maxBytes: 1_000_000, mode: 0o640 })
    spool.close()
    spool.close()
    expect(() => { spool.write(record('a')) }).not.toThrow()
    expect(readFileSync(path, 'utf8')).toBe('')
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
  function shipper(post: PostBatch, batchSize = 10): { instance: OtlpShipper; spool: string; cursor: string } {
    const spool = join(home, 'ocsf.jsonl')
    const resolved = resolveConfig({ spoolPath: spool, otlp: { endpoint: 'http://collector:4318', batchSize } })
    return {
      instance: new OtlpShipper(resolved.otlp!, spool, 'test', post),
      spool,
      cursor: resolved.otlp!.cursorPath,
    }
  }

  it('ships spooled records and advances the cursor to the file size', async () => {
    const posted: string[] = []
    const { instance, spool, cursor } = shipper(async (_url, _headers, body) => { posted.push(body); return true })
    writeFileSync(spool, `${JSON.stringify(record('a'))}\n${JSON.stringify(record('b'))}\n`)

    expect(await instance.drain()).toBe(2)
    expect(posted).toHaveLength(1)
    expect(Number(readFileSync(cursor, 'utf8'))).toBe(statSync(spool).size)
    expect(await instance.drain()).toBe(0)
  })

  it('leaves the cursor untouched when the collector rejects the batch', async () => {
    const { instance, spool, cursor } = shipper(async () => false)
    writeFileSync(spool, `${JSON.stringify(record('a'))}\n`)
    expect(await instance.drain()).toBe(0)
    expect(instance.cursor()).toBe(0)
    expect(() => readFileSync(cursor, 'utf8')).toThrow()
  })

  it('resumes from the persisted cursor after a restart', async () => {
    const posted: unknown[] = []
    const { instance, spool, cursor } = shipper(async (_url, _headers, body) => { posted.push(body); return true })
    const first = `${JSON.stringify(record('a'))}\n`
    writeFileSync(spool, first)
    await instance.drain()
    writeFileSync(spool, `${first}${JSON.stringify(record('b'))}\n`)

    const restarted = new OtlpShipper(
      resolveConfig({ spoolPath: spool, otlp: { endpoint: 'http://collector:4318' } }).otlp!,
      spool,
      'test',
      async () => true,
    )
    expect(restarted.cursor()).toBe(Buffer.byteLength(first))
    expect(await restarted.drain()).toBe(1)
    expect(Number(readFileSync(cursor, 'utf8'))).toBe(statSync(spool).size)
  })

  it('holds back a partially written trailing line', async () => {
    const { instance, spool } = shipper(async () => true)
    writeFileSync(spool, `${JSON.stringify(record('a'))}\n{"partial":`)
    expect(await instance.drain()).toBe(1)
    expect(instance.cursor()).toBe(Buffer.byteLength(`${JSON.stringify(record('a'))}\n`))
  })

  it('stops at the first rejected batch so later records are retried', async () => {
    let calls = 0
    const { instance, spool } = shipper(async () => { calls += 1; return calls === 1 }, 1)
    writeFileSync(spool, [record('a'), record('b'), record('c')].map(item => `${JSON.stringify(item)}\n`).join(''))
    expect(await instance.drain()).toBe(1)
    expect(await instance.drain()).toBe(0)
  })

  it('skips a corrupt line instead of stalling delivery', async () => {
    const errors: unknown[] = []
    const spool = join(home, 'ocsf.jsonl')
    const resolved = resolveConfig({ spoolPath: spool, otlp: { endpoint: 'http://collector:4318' } })
    const instance = new OtlpShipper(resolved.otlp!, spool, 'test', async () => true, error => errors.push(error))
    writeFileSync(spool, `{"broken\n${JSON.stringify(record('b'))}\n`)
    expect(await instance.drain()).toBe(1)
    expect(errors).toHaveLength(1)
  })

  it('restarts from the beginning when the spool was rotated under it', async () => {
    const { instance, spool, cursor } = shipper(async () => true)
    writeFileSync(cursor, '100000')
    writeFileSync(spool, `${JSON.stringify(record('a'))}\n`)
    expect(await instance.drain()).toBe(1)
  })

  it('reports a drain failure instead of throwing at the timer', async () => {
    const errors: unknown[] = []
    const resolved = resolveConfig({ spoolPath: join(home, 'missing.jsonl'), otlp: { endpoint: 'http://collector:4318' } })
    const instance = new OtlpShipper(resolved.otlp!, join(home, 'missing.jsonl'), 'test', async () => true, error => errors.push(error))
    expect(await instance.drain()).toBe(0)
    expect(errors).toHaveLength(1)
  })

  it('starts and stops its timer without holding the process open', () => {
    const { instance } = shipper(async () => true)
    instance.start()
    instance.start()
    instance.stop()
    instance.stop()
  })
})
