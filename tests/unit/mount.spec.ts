/** The plugin's export shape and what mounting it registers, without booting an agent. */
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import type { Session, SessionEvent } from '@deepseek-ai/dsh-session'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import * as plugin from '../../src/index.ts'
import { Config, inject, name } from '../../src/index.ts'
import type { OcsfRecord } from '../../src/ocsf/types.ts'
import { dshOf } from './support.ts'

let home: string

beforeEach(() => { home = mkdtempSync(join(tmpdir(), 'dsh-ocsf-mount-')) })
afterEach(() => { rmSync(home, { recursive: true, force: true }) })

/**
 * A session shaped like the one the store hands a listener. The cast is the
 * one place a test stands in for the store: `Session`'s private log and
 * surface manager are irrelevant to a read-side observer.
 */
function session(id: string): { id: string; firstLiveSeq: number; seq: number; events: SessionEvent[]; header: object } {
  return { id, firstLiveSeq: 0, seq: 0, events: [], header: {} }
}

/** Dispatch one event the way the session store does. */
function emitEvent(ctx: Context, subject: ReturnType<typeof session>, event: SessionEvent): void {
  ctx.emit('session/event', subject as unknown as Session, event)
}

/** A context with just the services the plugin injects, and the plugin mounted on it. */
async function mounted(overrides: Partial<Parameters<typeof Config>[0]> = {}): Promise<{
  ctx: Context
  spoolPath: string
  unload: () => Promise<void>
}> {
  const spoolPath = join(home, 'ocsf', 'session.jsonl')
  const ctx = new Context()
  const live: unknown[] = []
  ctx.reflect.provide('sessions', { list: () => live })
  const fiber = ctx.plugin(plugin, { spoolPath, ...overrides })
  await fiber
  return { ctx, spoolPath, unload: async () => { await fiber.dispose() } }
}

/** Records the plugin spooled, in order. */
function spooled(spoolPath: string): OcsfRecord[] {
  return readFileSync(spoolPath, 'utf8').split('\n').filter(line => line.length > 0)
    .map(line => JSON.parse(line) as OcsfRecord)
}

/** Whether one record is the forwarder reporting on itself rather than on a session. */
function isHeartbeat(record: OcsfRecord): boolean {
  return dshOf(record)['kind'] === 'heartbeat'
}

/** The spooled records that describe a session, with the forwarder's own heartbeats removed. */
function sessionRecords(spoolPath: string): OcsfRecord[] {
  return spooled(spoolPath).filter(record => !isHeartbeat(record))
}

describe('plugin exports', () => {
  it('declares its name and the service it needs', () => {
    expect(name).toBe('dsh-ocsf-forwarder')
    expect(inject).toEqual(['sessions'])
  })

  it('rejects configuration without a spool path', () => {
    expect(() => Config({} as never)).toThrow()
  })
})

describe('mounting', () => {
  it('creates the spool and writes a record for an observed event', async () => {
    const { ctx, spoolPath } = await mounted()
    const subject = session('s1')
    subject.events.push({ type: 'turn/start', seq: 0, time: 1_000, data: { turn: 1 } } as SessionEvent)
    emitEvent(ctx, subject, subject.events[0] as SessionEvent)

    const records = spooled(spoolPath)
    expect(records).toHaveLength(1)
    expect(records[0]?.class_uid).toBe(6003)
    expect(statSync(spoolPath).mode & 0o777).toBe(0o640)
  })

  it('flushes an unresolved tool call when the session is disposed', async () => {
    const { ctx, spoolPath } = await mounted()
    const subject = session('s1')
    subject.events.push({
      type: 'tool/call',
      seq: 0,
      time: 1_000,
      data: { turn: 1, step: 0, callId: 'c1', name: 'bash', arguments: '{"command":"sleep 900"}' },
    } as SessionEvent)
    emitEvent(ctx, subject, subject.events[0] as SessionEvent)
    ctx.emit('session/disposed', subject as unknown as Session)

    const records = spooled(spoolPath)
    expect(records).toHaveLength(2)
    expect(dshOf(records[1] as OcsfRecord)['unresolved']).toBe(true)
  })

  it('adopts a session that was already live when it mounted', async () => {
    const spoolPath = join(home, 'ocsf', 'session.jsonl')
    const ctx = new Context()
    const existing = session('s0')
    existing.events.push({ type: 'turn/start', seq: 0, time: 1_000, data: { turn: 1 } } as SessionEvent)
    Object.assign(existing, { firstLiveSeq: 1, seq: 1 })
    ctx.reflect.provide('sessions', { list: () => [existing] })
    const fiber = ctx.plugin(plugin, { spoolPath, seedReplay: 'boundary' })
    await fiber

    expect(spooled(spoolPath)).toHaveLength(1)
    await fiber.dispose()
  })

  it('reads the composed delegation rows out of the registry at mount', async () => {
    const spoolPath = join(home, 'ocsf', 'session.jsonl')
    const ctx = new Context()
    ctx.reflect.provide('sessions', { list: () => [] })
    // A stand-in for the row `@deepseek-ai/dsh-tool-subagent` mounts: the
    // plugin's display name and its `provider` / `toolName` config are the
    // only parts this forwarder reads.
    const toolSubagent = {
      name: 'tool-subagent',
      apply: (_ctx: Context, _config: { provider: string; toolName: string }) => {},
    }
    await ctx.plugin(toolSubagent, { provider: 'claude-code', toolName: 'handoff' })
    const fiber = ctx.plugin(plugin, { spoolPath })
    await fiber

    const subject = session('s1')
    subject.events.push({
      type: 'tool/call',
      seq: 0,
      time: 1_000,
      data: { turn: 1, step: 0, callId: 'c1', name: 'handoff', arguments: '{"prompt":"go"}' },
    } as SessionEvent)
    emitEvent(ctx, subject, subject.events[0] as SessionEvent)

    const record = spooled(spoolPath)[0] as OcsfRecord
    expect(record.severity_id).toBe(4)
    expect(dshOf(record)['delegation_provider']).toBe('claude-code')
    await fiber.dispose()
  })

  it('heartbeats on its interval, not only at unload', async () => {
    const { spoolPath, unload } = await mounted({ statsIntervalMs: 10 })
    await new Promise<void>(resolve => setTimeout(resolve, 60))
    expect(spooled(spoolPath).filter(isHeartbeat).length).toBeGreaterThan(1)
    await unload()
  })

  it('adopts a session announced after mount', async () => {
    const { ctx, spoolPath } = await mounted({ seedReplay: 'boundary' })
    const subject = session('s2')
    Object.assign(subject, { firstLiveSeq: 2, events: [] })
    ctx.emit('session/created', subject as unknown as Session)
    expect(spooled(spoolPath)).toHaveLength(1)
  })

  it('opens the restricted lane owner-only when it is acknowledged', async () => {
    const restrictedPath = join(home, 'restricted.jsonl')
    const { ctx } = await mounted({ restricted: { path: restrictedPath, acknowledged: true } })
    const subject = session('s1')
    subject.events.push({ type: 'turn/start', seq: 0, time: 1_000, data: { turn: 1 } } as SessionEvent)
    emitEvent(ctx, subject, subject.events[0] as SessionEvent)
    expect(statSync(restrictedPath).mode & 0o777).toBe(0o600)
    expect(spooled(restrictedPath)).toHaveLength(1)
  })

  it('starts a shipper when an OTLP endpoint is configured', async () => {
    const { ctx, spoolPath, unload } = await mounted({ otlp: { endpoint: 'http://127.0.0.1:1/v1/logs', flushIntervalMs: 60_000 } })
    const subject = session('s1')
    subject.events.push({ type: 'turn/start', seq: 0, time: 1_000, data: { turn: 1 } } as SessionEvent)
    emitEvent(ctx, subject, subject.events[0] as SessionEvent)
    // Teardown drains once; the unreachable collector leaves the spool intact.
    await unload()
    expect(sessionRecords(spoolPath)).toHaveLength(1)
  })

  it('releases the spool on unload, so the same path can be mounted again', async () => {
    const { spoolPath, unload } = await mounted()
    await unload()
    expect(sessionRecords(spoolPath)).toHaveLength(0)
    const again = await mounted()
    await again.unload()
  })

  it('spools a heartbeat at unload, so a host that went away says so through the SIEM', async () => {
    const { ctx, spoolPath, unload } = await mounted({ statsIntervalMs: 0 })
    const subject = session('s1')
    subject.events.push({ type: 'turn/start', seq: 0, time: 1_000, data: { turn: 1 } } as SessionEvent)
    emitEvent(ctx, subject, subject.events[0] as SessionEvent)
    await unload()

    const beats = spooled(spoolPath).filter(isHeartbeat)
    expect(beats).toHaveLength(1)
    const attributes = dshOf(beats[0] as OcsfRecord)
    expect(beats[0]?.class_uid).toBe(6002)
    expect(attributes['forwarded']).toBe(1)
    expect(attributes['final']).toBe(true)
    expect(attributes['live_sessions']).toBe(0)
    expect(attributes['spool_bytes']).toBeGreaterThan(0)
    expect(attributes['shipper_cursor']).toBeUndefined()
  })

  it('reports the shipper cursor on the heartbeat when a destination is configured', async () => {
    const { spoolPath, unload } = await mounted({
      statsIntervalMs: 0,
      otlp: { endpoint: 'http://127.0.0.1:1/v1/logs', flushIntervalMs: 60_000 },
    })
    await unload()
    const attributes = dshOf(spooled(spoolPath).filter(isHeartbeat)[0] as OcsfRecord)
    expect(attributes['shipper_cursor']).toBe(0)
    expect(attributes['shipper_destination']).toBe('otlp')
  })

  it('mints an install uid beside the spool and stamps it on every record', async () => {
    const { ctx, spoolPath } = await mounted()
    const subject = session('s1')
    subject.events.push({ type: 'turn/start', seq: 0, time: 1_000, data: { turn: 1 } } as SessionEvent)
    emitEvent(ctx, subject, subject.events[0] as SessionEvent)

    const installUid = readFileSync(`${spoolPath}.install-uid`, 'utf8').trim()
    expect(installUid).toMatch(/^[0-9a-f-]{36}$/)
    expect(spooled(spoolPath)[0]?.device?.uid).toBe(installUid)
  })

  it('reports its counters to the log, so a broken forwarder does not read as an idle one', async () => {
    const lines: string[] = []
    const { ctx, unload } = await mounted({ statsIntervalMs: 0 })
    ctx.logger.info = (message: unknown): void => { lines.push(String(message)) }
    const subject = session('s1')
    subject.events.push({ type: 'turn/start', seq: 0, time: 1_000, data: { turn: 1 } } as SessionEvent)
    emitEvent(ctx, subject, subject.events[0] as SessionEvent)
    await unload()
    expect(lines.some(line => line.includes('forwarded=1') && line.includes('failed=0'))).toBe(true)
  })
})
