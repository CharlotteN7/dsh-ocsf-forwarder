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
    expect((records[1]?.['dsh'] as Record<string, unknown>)['unresolved']).toBe(true)
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
    expect(spooled(spoolPath)).toHaveLength(1)
  })

  it('releases the spool on unload', async () => {
    const { spoolPath, unload } = await mounted()
    await unload()
    expect(statSync(spoolPath).size).toBe(0)
  })
})
