/** The heartbeat record: what it says, and when it raises the alarm. */
import { describe, expect, it } from 'vitest'
import { Forwarder } from '../../src/forwarder.ts'
import { HEARTBEAT_KIND, mapHeartbeat, type HeartbeatState } from '../../src/map/heartbeat.ts'
import { CLASS, SEVERITY, STATUS } from '../../src/ocsf/constants.ts'
import type { OcsfRecord } from '../../src/ocsf/types.ts'
import type { Sink } from '../../src/sink/spool.ts'
import { dshOf, testConfig, testEnvironment } from './support.ts'

/** A heartbeat with a healthy spool, unless the test says otherwise. */
function state(overrides: Partial<HeartbeatState> = {}): HeartbeatState {
  return {
    liveSessions: 2,
    stats: { forwarded: 41, dropped: 3, unreadable: 1, failed: 0 },
    spoolBytes: 100,
    spoolHighWaterBytes: 1_000,
    rotationStopped: false,
    sinkFailed: false,
    droppedRecords: 0,
    uptimeMs: 60_000,
    final: false,
    ...overrides,
  }
}

describe('the heartbeat mapping', () => {
  it('carries the live session count, the counters, and the delivery cursor', () => {
    const mapping = mapHeartbeat(state({ cursor: 4_096, quarantined: 2, destination: 'splunk-hec' }))
    expect(mapping.classUid).toBe(CLASS.applicationLifecycle)
    expect(mapping.attributes?.['kind']).toBe(HEARTBEAT_KIND)
    expect(mapping.attributes?.['live_sessions']).toBe(2)
    expect(mapping.attributes?.['forwarded']).toBe(41)
    expect(mapping.attributes?.['dropped']).toBe(3)
    expect(mapping.attributes?.['unreadable']).toBe(1)
    expect(mapping.attributes?.['failed']).toBe(0)
    expect(mapping.attributes?.['shipper_cursor']).toBe(4_096)
    expect(mapping.attributes?.['shipper_quarantined']).toBe(2)
    expect(mapping.attributes?.['shipper_destination']).toBe('splunk-hec')
  })

  it('names itself Other, because OCSF has no liveness activity to claim', () => {
    const mapping = mapHeartbeat(state())
    expect(mapping.activityId).toBe(99)
    expect(mapping.activityName).toBe('Heartbeat')
  })

  it('omits the shipper fields when no destination is configured', () => {
    const mapping = mapHeartbeat(state())
    expect(mapping.attributes?.['shipper_cursor']).toBeUndefined()
    expect(mapping.attributes?.['shipper_destination']).toBeUndefined()
  })

  it('stays informational while the spool is below its high-water mark', () => {
    const mapping = mapHeartbeat(state())
    expect(mapping.severityId).toBe(SEVERITY.informational)
    expect(mapping.attributes?.['spool_pressure']).toBe(false)
  })

  it('raises the alarm once the spool crosses the high-water mark', () => {
    const mapping = mapHeartbeat(state({ spoolBytes: 1_000 }))
    expect(mapping.severityId).toBe(SEVERITY.high)
    expect(mapping.attributes?.['spool_pressure']).toBe(true)
    expect(mapping.message).toContain('high-water mark')
  })

  it('raises the alarm once rotation has stopped, whatever the byte count says', () => {
    expect(mapHeartbeat(state({ rotationStopped: true })).severityId).toBe(SEVERITY.high)
  })

  it('reports a spool that has stopped writing above every disk-pressure alarm', () => {
    const mapping = mapHeartbeat(state({ sinkFailed: true, droppedRecords: 9 }))
    expect(mapping.severityId).toBe(SEVERITY.critical)
    expect(mapping.statusId).toBe(STATUS.failure)
    expect(mapping.attributes?.['sink_failed']).toBe(true)
    expect(mapping.attributes?.['sink_dropped_records']).toBe(9)
    expect(mapping.message).toContain('dropped 9 record(s)')
  })

  it('says the sink is writing when it is', () => {
    const mapping = mapHeartbeat(state())
    expect(mapping.attributes?.['sink_failed']).toBe(false)
    expect(mapping.attributes?.['sink_dropped_records']).toBe(0)
    expect(mapping.statusId).toBe(STATUS.success)
  })
})

describe('emitting a heartbeat', () => {
  /** Heartbeats one forwarder wrote, in order. */
  function beats(count: number): OcsfRecord[] {
    const records: OcsfRecord[] = []
    const sink: Sink = { write: record => { records.push(record) }, close: () => {} }
    const config = testConfig()
    const forwarder = new Forwarder(testEnvironment(config), config, sink, undefined, error => { throw error })
    for (let index = 0; index < count; index += 1) forwarder.heartbeat(state())
    return records
  }

  it('belongs to no session, so nothing is misattributed to one', () => {
    const [record] = beats(1)
    expect(record?.ai_agent?.instance_uid).toBeUndefined()
    expect(dshOf(record as OcsfRecord)['session_id']).toBeUndefined()
    expect(dshOf(record as OcsfRecord)['event_type']).toBe('forwarder/heartbeat')
  })

  it('keys itself on the install uid and a sequence, so a gap is detectable', () => {
    const records = beats(3)
    expect(records.map(record => record.metadata.uid)).toEqual([
      'install-test:heartbeat:0', 'install-test:heartbeat:1', 'install-test:heartbeat:2',
    ])
    expect(records.map(record => record.metadata.sequence)).toEqual([0, 1, 2])
  })

  it('stays out of the counters it reports', () => {
    const records: OcsfRecord[] = []
    const sink: Sink = { write: record => { records.push(record) }, close: () => {} }
    const config = testConfig()
    const forwarder = new Forwarder(testEnvironment(config), config, sink, undefined, error => { throw error })
    forwarder.heartbeat(state())
    forwarder.heartbeat(state())
    expect(forwarder.stats().forwarded).toBe(0)
  })

  it('contains a sink failure rather than throwing out of the timer', () => {
    const errors: unknown[] = []
    const config = testConfig()
    const failing: Sink = { write() { throw new Error('disk full') }, close() {} }
    const forwarder = new Forwarder(testEnvironment(config), config, failing, undefined, error => errors.push(error))
    expect(() => { forwarder.heartbeat(state()) }).not.toThrow()
    expect(errors).toHaveLength(1)
    expect(forwarder.stats().failed).toBe(1)
  })
})
