/** Adoption, seed replay, catch-up, and the unresolved flush. */
import { describe, expect, it } from 'vitest'
import { Forwarder, type ForwardableSession } from '../../src/forwarder.ts'
import type { MappableEvent } from '../../src/map/index.ts'
import type { OcsfRecord } from '../../src/ocsf/types.ts'
import type { Sink } from '../../src/sink/spool.ts'
import { dshOf, testConfig, testEnvironment } from './support.ts'
import type { ResolvedConfig } from '../../src/config.ts'

/** A sink that keeps every record it is handed. */
class MemorySink implements Sink {
  readonly records: OcsfRecord[] = []
  write(record: OcsfRecord): void { this.records.push(record) }
  close(): void {}
}

/** A session whose log the test controls. */
class FakeSession implements ForwardableSession {
  readonly events: MappableEvent[] = []

  constructor(
    readonly id: string,
    readonly firstLiveSeq: number,
    readonly header: ForwardableSession['header'] = {},
  ) {}

  get seq(): number { return this.events.length }

  /** Append an event the way `Session.append` would, and return it. */
  append(type: string, data: unknown, time = 1_000 + this.events.length): MappableEvent {
    const event = { type, seq: this.events.length, time, data }
    this.events.push(event)
    return event
  }
}

function forwarder(config: ResolvedConfig = testConfig()): { instance: Forwarder; sink: MemorySink; errors: unknown[] } {
  const sink = new MemorySink()
  const errors: unknown[] = []
  return {
    instance: new Forwarder(testEnvironment(config), config, sink, undefined, error => errors.push(error)),
    sink,
    errors,
  }
}

/** Event types of the records a sink collected. */
function types(sink: MemorySink): string[] {
  return sink.records.map(record => String(dshOf(record)['event_type']))
}

describe('live forwarding', () => {
  it('forwards each observed event once', () => {
    const { instance, sink } = forwarder()
    const session = new FakeSession('s1', 0)
    instance.adopt(session)
    for (const type of ['turn/start', 'step/start', 'step/end', 'turn/end']) {
      instance.observe(session, session.append(type, { turn: 1, step: 0, reason: { kind: 'completed' } }))
    }
    expect(types(sink)).toEqual(['turn/start', 'step/start', 'step/end', 'turn/end'])
  })

  it('does not forward a type the drop policy excludes', () => {
    const { instance, sink } = forwarder()
    const session = new FakeSession('s1', 0)
    instance.observe(session, session.append('assistant/chunk', { turn: 1, step: 0, chunk: {} }))
    expect(sink.records).toEqual([])
    expect(instance.stats().dropped).toBe(1)
  })

  it('counts an event whose payload lacks the identity a record needs', () => {
    const { instance, sink } = forwarder()
    const session = new FakeSession('s1', 0)
    instance.observe(session, session.append('tool/call', { name: 'bash' }))
    expect(sink.records).toEqual([])
    expect(instance.stats().unreadable).toBe(1)
  })

  it('catches up on events appended while the plugin was not listening', () => {
    const { instance, sink } = forwarder()
    const session = new FakeSession('s1', 0)
    session.append('turn/start', { turn: 1 })
    session.append('step/start', { turn: 1, step: 0 })
    instance.observe(session, session.append('step/end', { turn: 1, step: 0 }))
    expect(types(sink)).toEqual(['turn/start', 'step/start', 'step/end'])
  })

  it('contains a sink failure instead of throwing at the listener', () => {
    const config = testConfig()
    const errors: unknown[] = []
    const failing: Sink = { write() { throw new Error('disk full') }, close() {} }
    const instance = new Forwarder(testEnvironment(config), config, failing, undefined, error => errors.push(error))
    const session = new FakeSession('s1', 0)
    expect(() => { instance.observe(session, session.append('turn/start', { turn: 1 })) }).not.toThrow()
    expect(errors).toHaveLength(1)
    expect(instance.stats().failed).toBe(1)
  })

  it('retries an event the sink refused once the sink recovers', () => {
    const config = testConfig()
    const written: string[] = []
    let full = true
    const flaky: Sink = {
      write(record) {
        if (full) throw Object.assign(new Error('ENOSPC: no space left on device'), { code: 'ENOSPC' })
        written.push(String(record.metadata.uid))
      },
      close() {},
    }
    const instance = new Forwarder(testEnvironment(config), config, flaky, undefined, () => {})
    const session = new FakeSession('s1', 0)
    const events = Array.from({ length: 6 }, (_, index) =>
      session.append('tool/call', { turn: 1, step: 0, callId: `c${String(index)}`, name: 'bash', arguments: '{"command":"id"}' }))
    for (const event of events) instance.observe(session, event)
    expect(written).toEqual([])

    full = false
    for (const event of events) instance.observe(session, event)
    expect(written).toEqual(['s1:0', 's1:1', 's1:2', 's1:3', 's1:4', 's1:5'])
  })

  it('leaves the rest of a catch-up pending rather than stepping over it', () => {
    const config = testConfig()
    const written: string[] = []
    let calls = 0
    const oneBad: Sink = {
      write(record) {
        calls += 1
        if (calls === 2) throw new Error('EIO')
        written.push(String(record.metadata.uid))
      },
      close() {},
    }
    const instance = new Forwarder(testEnvironment(config), config, oneBad, undefined, () => {})
    const session = new FakeSession('s1', 0)
    for (let index = 0; index < 5; index += 1) session.append('step/start', { turn: 1, step: index })
    const last = session.events[4] as MappableEvent

    instance.observe(session, last)
    expect(written).toEqual(['s1:0'])
    // The failed event is still the cursor, so the rest arrive in log order.
    instance.observe(session, last)
    expect(written).toEqual(['s1:0', 's1:1', 's1:2', 's1:3', 's1:4'])
  })

  it('walks only the events it has not forwarded, not the whole log per append', () => {
    const config = testConfig()
    const sink = new MemorySink()
    const instance = new Forwarder(testEnvironment(config), config, sink, undefined, () => {})
    const session = new FakeSession('s1', 0)
    const total = 500
    for (let index = 0; index < total; index += 1) session.append('step/start', { turn: 1, step: index })

    // A quadratic catch-up reads roughly n²/2 elements out of the log; a
    // cursor-based one reads each element once.
    const appended = [...session.events]
    let reads = 0
    const counted = new Proxy(session.events, {
      get(target, property, receiver): unknown {
        if (typeof property === 'string' && /^\d+$/.test(property)) reads += 1
        return Reflect.get(target, property, receiver) as unknown
      },
    })
    Object.defineProperty(session, 'events', { get: () => counted })

    for (const event of appended) instance.observe(session, event)
    expect(sink.records).toHaveLength(total)
    expect(reads).toBeLessThan(total * 4)
  })
})

describe('seed replay', () => {
  /** A resumed session: three seed events plus the end-seed marker, then live work. */
  function resumed(): FakeSession {
    const session = new FakeSession('s2', 4, { parentSession: 'parent-1', seedLength: 3 })
    session.append('turn/start', { turn: 1 })
    session.append('tool/call', { turn: 1, step: 0, callId: 'c1', name: 'bash', arguments: '{"command":"id"}' })
    session.append('turn/end', { turn: 1, reason: { kind: 'completed' } })
    session.append('session/end-seed', {})
    return session
  }

  it('replays the whole seed by default and marks the replayed records', () => {
    const { instance, sink } = forwarder()
    const session = resumed()
    instance.adopt(session)
    instance.observe(session, session.append('turn/start', { turn: 2 }))

    expect(types(sink)).toEqual(['turn/start', 'tool/call', 'turn/end', 'turn/start'])
    const replayed = sink.records.map(record => dshOf(record)['replayed'])
    expect(replayed).toEqual([true, true, true, false])
    expect(sink.records[0]?.metadata.uid).toBe('s2:0')
  })

  it('emits one boundary marker instead of the seed under boundary mode', () => {
    const { instance, sink } = forwarder(testConfig({ seedReplay: 'boundary' }))
    const session = resumed()
    instance.adopt(session)
    instance.observe(session, session.append('turn/start', { turn: 2 }))

    expect(types(sink)).toEqual(['session/adopted', 'turn/start'])
    const marker = sink.records[0] as OcsfRecord
    expect(dshOf(marker)['seed_events']).toBe(4)
    expect(dshOf(marker)['forked_from']).toBe('parent-1')
    expect(marker.metadata.uid).toBe('s2:adopted:4')
  })

  it('emits nothing for the seed under none mode', () => {
    const { instance, sink } = forwarder(testConfig({ seedReplay: 'none' }))
    const session = resumed()
    instance.adopt(session)
    instance.observe(session, session.append('turn/start', { turn: 2 }))
    expect(types(sink)).toEqual(['turn/start'])
  })

  it('contains a failure while adopting rather than failing the session store', () => {
    const config = testConfig({ seedReplay: 'boundary' })
    const errors: unknown[] = []
    const failing: Sink = { write() { throw new Error('disk full') }, close() {} }
    const instance = new Forwarder(testEnvironment(config), config, failing, undefined, error => errors.push(error))
    expect(() => { instance.adopt(resumed()) }).not.toThrow()
    expect(errors).toHaveLength(1)
    expect(instance.stats().failed).toBe(1)
  })

  it('adopts a session only once', () => {
    const { instance, sink } = forwarder(testConfig({ seedReplay: 'boundary' }))
    const session = resumed()
    instance.adopt(session)
    instance.adopt(session)
    expect(types(sink)).toEqual(['session/adopted'])
  })

  it('carries the fork lineage on every record', () => {
    const { instance, sink } = forwarder()
    const session = new FakeSession('child', 0, { parentSession: 'parent-1', seedLength: 2, agentPreset: 'review', cwd: '/srv/app' })
    instance.observe(session, session.append('turn/start', { turn: 1 }))
    const attributes = dshOf(sink.records[0] as OcsfRecord)
    expect(attributes['parent_session_id']).toBe('parent-1')
    expect(attributes['seed_length']).toBe(2)
    expect(attributes['agent_preset']).toBe('review')
    expect(attributes['cwd']).toBe('/srv/app')
  })
})

describe('disposal', () => {
  it('flushes events that arrived after the last observation', () => {
    const { instance, sink } = forwarder()
    const session = new FakeSession('s1', 0)
    instance.observe(session, session.append('turn/start', { turn: 1 }))
    session.append('turn/end', { turn: 1, reason: { kind: 'completed' } })
    instance.dispose(session)
    expect(types(sink)).toEqual(['turn/start', 'turn/end'])
  })

  it('reports a tool call and an approval that never settled', () => {
    const { instance, sink } = forwarder()
    const session = new FakeSession('s1', 0)
    instance.observe(session, session.append('tool/call', { turn: 1, step: 0, callId: 'c9', name: 'bash', arguments: '{"command":"sleep 900"}' }))
    instance.observe(session, session.append('approval/asked', { id: 'a9', toolName: 'bash' }))
    instance.dispose(session)

    const unresolved = sink.records.filter(record => dshOf(record)['unresolved'] === true)
    expect(unresolved).toHaveLength(2)
    expect(unresolved[0]?.metadata.uid).toBe('s1:unresolved:c9')
    expect(unresolved[1]?.metadata.uid).toBe('s1:unresolved:approval:a9')
  })

  it('measures an abandoned call against the log clock, not the wall clock', () => {
    const { instance, sink } = forwarder()
    const session = new FakeSession('s1', 0)
    // A resumed session replays events appended long before this process ran.
    const replayTime = Date.now() - 72 * 3_600_000
    instance.observe(session, session.append('tool/call', {
      turn: 1, step: 0, callId: 'c9', name: 'bash', arguments: '{"command":"sleep 900"}',
    }, replayTime))
    instance.observe(session, session.append('turn/end', { turn: 1, reason: { kind: 'completed' } }, replayTime + 250))
    instance.dispose(session)

    const unresolved = sink.records.find(record => dshOf(record)['unresolved'] === true)
    expect(unresolved?.duration).toBe(250)
  })
})

describe('the restricted lane', () => {
  it('duplicates each record with the verbatim payload, joined by the same key', () => {
    const config = testConfig()
    const soc = new MemorySink()
    const restricted = new MemorySink()
    const instance = new Forwarder(testEnvironment(config), config, soc, restricted, () => {})
    const session = new FakeSession('s1', 0)
    instance.observe(session, session.append('tool/call', {
      turn: 1, step: 0, callId: 'c1', name: 'bash', arguments: '{"command":"echo sk-live-1"}',
    }))

    expect(JSON.stringify(soc.records)).not.toContain('sk-live-1')
    expect(String(restricted.records[0]?.raw_data)).toContain('sk-live-1')
    expect(restricted.records[0]?.metadata.uid).toBe(soc.records[0]?.metadata.uid)
  })
})
