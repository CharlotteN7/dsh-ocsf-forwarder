/**
 * Class-intrinsic OCSF 1.9.0 conformance of the records a real run produces.
 *
 * The required sets below are the class definitions read from
 * `schema.ocsf.io/api/1.9.0/classes/<name>` with no profile applied, so an
 * attribute listed here is one the class itself demands of every record.
 */
import { describe, expect, it } from 'vitest'
import { Forwarder, type ForwardableSession } from '../../src/forwarder.ts'
import type { MappableEvent } from '../../src/map/index.ts'
import { CLASS } from '../../src/ocsf/constants.ts'
import type { OcsfRecord } from '../../src/ocsf/types.ts'
import type { Sink } from '../../src/sink/spool.ts'
import { testConfig, testEnvironment } from './support.ts'

/** `class_uid` → the attributes that class requires of every one of its records. */
const REQUIRED: Readonly<Record<number, readonly string[]>> = Object.freeze({
  [CLASS.fileSystemActivity]: ['time', 'class_uid', 'category_uid', 'type_uid', 'activity_id', 'severity_id', 'metadata', 'device', 'actor', 'file'],
  [CLASS.scheduledJobActivity]: ['time', 'class_uid', 'category_uid', 'type_uid', 'activity_id', 'severity_id', 'metadata', 'device', 'job'],
  [CLASS.processActivity]: ['time', 'class_uid', 'category_uid', 'type_uid', 'activity_id', 'severity_id', 'metadata', 'device', 'actor', 'process'],
  [CLASS.authorizeSession]: ['time', 'class_uid', 'category_uid', 'type_uid', 'activity_id', 'severity_id', 'metadata', 'user', 'privileges'],
  [CLASS.httpActivity]: ['time', 'class_uid', 'category_uid', 'type_uid', 'activity_id', 'severity_id', 'metadata', 'http_request'],
  [CLASS.applicationLifecycle]: ['time', 'class_uid', 'category_uid', 'type_uid', 'activity_id', 'severity_id', 'metadata'],
  [CLASS.apiActivity]: ['time', 'class_uid', 'category_uid', 'type_uid', 'activity_id', 'severity_id', 'metadata', 'actor', 'api', 'src_endpoint'],
})

/** Attributes the base event defines; anything else at the top level is a schema violation. */
const BASE_EVENT_ATTRIBUTES: ReadonlySet<string> = new Set([
  'activity_id', 'activity_name', 'category_uid', 'class_uid', 'cloud', 'count', 'duration',
  'end_time', 'enrichments', 'message', 'metadata', 'observables', 'osint', 'raw_data',
  'severity_id', 'start_time', 'status_detail', 'status_id', 'time', 'timezone_offset',
  'type_uid', 'unmapped',
  // Class-owned and profile-owned attributes the mappers fill.
  'actor', 'ai_agent', 'ai_model', 'api', 'delegation', 'device', 'file', 'http_request',
  'job', 'message_context', 'privileges', 'process', 'src_endpoint', 'user',
])

/** One run covering every mapper, driven the way the session store drives one. */
function emitted(): readonly OcsfRecord[] {
  const config = testConfig()
  const records: OcsfRecord[] = []
  const sink: Sink = { write: record => { records.push(record) }, close: () => {} }
  const events: MappableEvent[] = [
    { type: 'turn/start', seq: 0, time: 1_000, data: { turn: 1 } },
    { type: 'request/context', seq: 1, time: 1_001, data: { provider: 'deepseek', model: 'deepseek-chat' } },
    { type: 'step/start', seq: 2, time: 1_002, data: { turn: 1, step: 0 } },
    { type: 'assistant/message', seq: 3, time: 1_003, data: { turn: 1, step: 0, message: { content: [{ type: 'text', text: 'ok' }] } } },
    { type: 'tool/call', seq: 4, time: 1_004, data: { turn: 1, step: 0, callId: 'c1', name: 'bash', arguments: '{"command":"ls -la"}' } },
    { type: 'tool/result', seq: 5, time: 1_005, data: { message: { source: { callId: 'c1' }, content: [{ toolCallId: 'c1' }] } } },
    { type: 'tool/call', seq: 6, time: 1_006, data: { turn: 1, step: 0, callId: 'c2', name: 'read', arguments: '{"file_path":"/etc/hosts"}' } },
    { type: 'tool/result', seq: 7, time: 1_007, data: { message: { source: { callId: 'c2' } } } },
    { type: 'tool/call', seq: 8, time: 1_008, data: { turn: 1, step: 0, callId: 'c3', name: 'web_fetch', arguments: '{"url":"https://x.test/a"}' } },
    { type: 'tool/result', seq: 9, time: 1_009, data: { message: { source: { callId: 'c3' } } } },
    { type: 'tool/result', seq: 10, time: 1_010, data: { message: { source: { callId: 'ghost' } } } },
    { type: 'approval/asked', seq: 11, time: 1_011, data: { id: 'a1', toolName: 'bash', callId: 'c4' } },
    { type: 'approval/decided', seq: 12, time: 1_012, data: { id: 'a1', outcome: 'allowed-once' } },
    { type: 'sandbox/mode', seq: 13, time: 1_013, data: { mode: 'danger-full-access' } },
    { type: 'schedule/change', seq: 14, time: 1_014, data: { version: 1, operation: 'create', schedule: { id: 's1' } } },
    { type: 'subagent/descriptor', seq: 15, time: 1_015, data: { version: 2, mode: 'one-shot', provider: 'task' } },
    { type: 'hook/invoked', seq: 16, time: 1_016, data: { turn: 1, point: 'PreToolUse', handlerId: 'h1' } },
    { type: 'hook/result', seq: 17, time: 1_017, data: { turn: 1, point: 'PreToolUse', handlerId: 'h1', decision: 'allow', exitCode: 0 } },
    { type: 'user/message', seq: 18, time: 1_018, data: { source: { kind: 'human' }, content: [{ type: 'text', text: 'hi' }] } },
    { type: 'tool-workflow/run-end', seq: 19, time: 1_019, data: { runId: 'wf1', stopReason: 'completed' } },
    { type: 'compaction/prune', seq: 20, time: 1_020, data: { shadowedRange: { start: 1, end: 2 }, shadowedSeqs: [1], shadowedTokenCount: 9 } },
    { type: 'agent/inbox/spliced', seq: 21, time: 1_021, data: { target: 'next-turn' } },
    { type: 'tool/call', seq: 22, time: 1_022, data: { turn: 1, step: 0, callId: 'never', name: 'bash', arguments: '{"command":"sleep 999"}' } },
    { type: 'approval/asked', seq: 23, time: 1_023, data: { id: 'a2', toolName: 'write' } },
  ]
  const session: ForwardableSession = { id: 'S1', firstLiveSeq: 0, seq: events.length, events, header: { cwd: '/srv' } }
  const forwarder = new Forwarder(testEnvironment(config), config, sink, undefined, error => { throw error })
  forwarder.adopt(session)
  for (const event of events) forwarder.observe(session, event)
  forwarder.dispose(session)
  return records
}

describe('OCSF 1.9.0 conformance', () => {
  const records = emitted()

  it('covers every class this plugin emits', () => {
    const classes = new Set(records.map(record => record.class_uid))
    expect([...classes].sort((a, b) => a - b)).toEqual(Object.values(CLASS).sort((a, b) => a - b))
  })

  it('fills every attribute the record class requires', () => {
    const violations = records
      .map((record) => {
        const fields = record as unknown as Record<string, unknown>
        const missing = (REQUIRED[record.class_uid] ?? []).filter(name => fields[name] === undefined)
        return missing.length === 0
          ? undefined
          : `${String(record.class_uid)} <- ${String(record.metadata.uid)}: ${missing.join(', ')}`
      })
      .filter(entry => entry !== undefined)
    expect(violations).toEqual([])
  })

  it('adds no top-level attribute the base event does not define', () => {
    const extra = new Set(records.flatMap(record => Object.keys(record).filter(key => !BASE_EVENT_ATTRIBUTES.has(key))))
    expect([...extra]).toEqual([])
  })

  it('declares a profile for every profile-owned attribute it carries', () => {
    for (const record of records) {
      expect(record.metadata.profiles).toContain('ai_operation')
      if (record.cloud !== undefined) expect(record.metadata.profiles).toContain('cloud')
      if (record.osint !== undefined) expect(record.metadata.profiles).toContain('osint')
    }
  })

  it('uses the extensions list rather than the attribute deprecated since 1.1.0', () => {
    for (const record of records) {
      expect((record.metadata as unknown as Record<string, unknown>)['extension']).toBeUndefined()
    }
  })

  it('derives type_uid from the class and activity of every record', () => {
    for (const record of records) {
      expect(record.type_uid).toBe(record.class_uid * 100 + record.activity_id)
    }
  })
})
