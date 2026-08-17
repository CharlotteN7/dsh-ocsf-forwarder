/**
 * Class-intrinsic OCSF 1.9.0 conformance of the records a real run produces.
 *
 * The required sets below are the class definitions read from
 * `schema.ocsf.io/api/1.9.0/classes/<name>` with no profile applied, so an
 * attribute listed here is one the class itself demands of every record.
 */
import { describe, expect, it } from 'vitest'
import { Forwarder, type ForwardableSession } from '../../src/forwarder.ts'
import { AttestingSink, RECORD_INTEGRITY_PROFILE } from '../../src/integrity/attest.ts'
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
  // `application` is not in the class's required list; it is forced by the
  // class constraint `at_least_one: [app, application]`, and `app` has been
  // deprecated since 1.9.0.
  [CLASS.applicationLifecycle]: ['time', 'class_uid', 'category_uid', 'type_uid', 'activity_id', 'severity_id', 'metadata', 'application'],
  [CLASS.apiActivity]: ['time', 'class_uid', 'category_uid', 'type_uid', 'activity_id', 'severity_id', 'metadata', 'actor', 'api', 'src_endpoint'],
})

/** Attributes the base event defines, which every class therefore accepts. */
const BASE_EVENT_ATTRIBUTES: readonly string[] = [
  'activity_id', 'activity_name', 'category_uid', 'class_uid', 'cloud', 'count', 'duration',
  'end_time', 'enrichments', 'message', 'metadata', 'observables', 'osint', 'raw_data',
  'severity_id', 'start_time', 'status_detail', 'status_id', 'time', 'timezone_offset',
  'type_uid', 'unmapped',
]

/**
 * Per class, the attributes that class defines beyond the base event, narrowed
 * to the ones this plugin can emit.
 *
 * Read from `schema.ocsf.io/api/1.9.0/classes/<name>` with every profile
 * applied. Checking against the union of all seven would pass anything any one
 * class happens to define — `src_endpoint` stamped onto all seven survived a
 * green run — so each class is checked against its own definition, which is
 * what `additionalProperties: false` actually means. Emitting an attribute a
 * class does define but the plugin has not emitted before is a deliberate
 * change, and updating this table is how it gets made.
 */
const CLASS_ATTRIBUTES: Readonly<Record<number, readonly string[]>> = Object.freeze({
  [CLASS.fileSystemActivity]: ['actor', 'ai_agent', 'ai_model', 'api', 'attestation_list', 'delegation', 'device', 'file', 'message_context'],
  [CLASS.scheduledJobActivity]: ['actor', 'ai_agent', 'ai_model', 'api', 'attestation_list', 'delegation', 'device', 'job', 'message_context'],
  [CLASS.processActivity]: ['actor', 'ai_agent', 'ai_model', 'api', 'attestation_list', 'delegation', 'device', 'message_context', 'process'],
  [CLASS.authorizeSession]: [
    'actor', 'ai_agent', 'ai_model', 'api', 'attestation_list', 'delegation', 'device', 'http_request',
    'message_context', 'privileges', 'src_endpoint', 'user',
  ],
  [CLASS.httpActivity]: [
    'actor', 'ai_agent', 'ai_model', 'api', 'attestation_list', 'delegation', 'device', 'file', 'http_request',
    'message_context', 'src_endpoint',
  ],
  [CLASS.applicationLifecycle]: [
    'actor', 'ai_agent', 'ai_model', 'api', 'application', 'attestation_list', 'delegation', 'device',
    'message_context',
  ],
  [CLASS.apiActivity]: [
    'actor', 'ai_agent', 'ai_model', 'api', 'attestation_list', 'delegation', 'device', 'http_request',
    'message_context', 'src_endpoint',
  ],
})

/**
 * The objects the `record_integrity` profile brings, each attribute mapped to
 * the JSON type its OCSF type resolves to, and marked when the object requires
 * it. Read from `schema.ocsf.io/api/1.9.0/objects/<name>`; `attestation_list`
 * itself is `is_array` on every class that defines it.
 *
 * An OCSF object is closed exactly as a class is, so this is the same check as
 * the per-class one above, applied one level down: emitting `chain_id` instead
 * of `chain_uid`, or a hex string where an integer id belongs, would produce
 * records that validate nowhere and that no consumer could join on.
 */
const PROFILE_OBJECTS: Readonly<Record<string, Readonly<Record<string, { type: string; required?: true }>>>> = Object.freeze({
  attestation: {
    uid: { type: 'string' },
    chain_uid: { type: 'string' },
    authority_uid: { type: 'string' },
    prev_event: { type: 'object' },
    fingerprint: { type: 'object' },
    signatures: { type: 'object' },
  },
  prev_event: {
    uid: { type: 'string', required: true },
    type_uid: { type: 'number' },
    fingerprint: { type: 'object' },
  },
  fingerprint: {
    value: { type: 'string', required: true },
    algorithm: { type: 'string' },
    algorithm_id: { type: 'number', required: true },
    encoding: { type: 'string' },
    encoding_id: { type: 'number' },
    serialization: { type: 'string' },
    serialization_id: { type: 'number' },
  },
})

/** Which object type each nested attribute of the profile carries. */
const PROFILE_OBJECT_OF_ATTRIBUTE: Readonly<Record<string, string>> = Object.freeze({
  prev_event: 'prev_event',
  fingerprint: 'fingerprint',
})

/**
 * Check one emitted object against its schema definition, and everything it
 * nests.
 * @param name - the OCSF object name.
 * @param value - the object as emitted.
 * @returns one entry per violation, naming the attribute.
 */
function objectViolations(name: string, value: Readonly<Record<string, unknown>>): string[] {
  const definition = PROFILE_OBJECTS[name] as Readonly<Record<string, { type: string; required?: true }>>
  const violations: string[] = []
  for (const [key, required] of Object.entries(definition)) {
    if (required.required === true && value[key] === undefined) violations.push(`${name}.${key}: missing, and required`)
  }
  for (const [key, member] of Object.entries(value)) {
    const attribute = definition[key]
    if (attribute === undefined) {
      violations.push(`${name}.${key}: not defined by the object`)
      continue
    }
    if (typeof member !== attribute.type) violations.push(`${name}.${key}: ${typeof member}, not ${attribute.type}`)
    const nested = PROFILE_OBJECT_OF_ATTRIBUTE[key]
    if (nested !== undefined) violations.push(...objectViolations(nested, member as Record<string, unknown>))
  }
  return violations
}

/** One run covering every mapper, driven the way the session store drives one. */
function emitted(): readonly OcsfRecord[] {
  const config = testConfig({
    delegationTools: { subagent_claude_code: 'claude-code' },
    fleet: { installUid: 'install-test', tenantUid: 'acme', labels: ['prod'], tags: { owner: 'soc' } },
  })
  const records: OcsfRecord[] = []
  const collector: Sink = { write: record => { records.push(record) }, close: () => {} }
  // The lane as it is actually assembled: the forwarder writes through the
  // chain, so the records checked here are the ones a consumer receives.
  const sink: Sink = new AttestingSink(collector, 'chain-conformance')
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
    { type: 'tool/call', seq: 24, time: 1_024, data: { turn: 1, step: 0, callId: 'c5', name: 'cordis_run', arguments: '{"pluginId":"p"}' } },
    { type: 'tool/result', seq: 25, time: 1_025, data: { message: { source: { callId: 'c5' } } } },
    { type: 'tool/call', seq: 26, time: 1_026, data: { turn: 1, step: 0, callId: 'c6', name: 'mcp__github__create_issue', arguments: '{"title":"x"}' } },
    { type: 'tool/result', seq: 27, time: 1_027, data: { message: { source: { callId: 'c6' } } } },
    { type: 'tool/call', seq: 28, time: 1_028, data: { turn: 1, step: 0, callId: 'c7', name: 'subagent_claude_code', arguments: '{"prompt":"go"}' } },
    { type: 'tool/result', seq: 29, time: 1_029, data: { message: { source: { callId: 'c7' } } } },
  ]
  const session: ForwardableSession = { id: 'S1', firstLiveSeq: 0, seq: events.length, events, header: { cwd: '/srv' } }
  const forwarder = new Forwarder(testEnvironment(config), config, sink, undefined, error => { throw error })
  forwarder.adopt(session)
  for (const event of events) forwarder.observe(session, event)
  forwarder.dispose(session)
  forwarder.heartbeat({
    liveSessions: 1,
    stats: forwarder.stats(),
    spoolBytes: 0,
    spoolHighWaterBytes: 1_000,
    rotationStopped: false,
    sinkFailed: false,
    droppedRecords: 0,
    uptimeMs: 5,
    final: true,
  })
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

  it('adds no top-level attribute its own class does not define', () => {
    const violations = new Set(records.flatMap((record) => {
      const allowed = new Set([...BASE_EVENT_ATTRIBUTES, ...CLASS_ATTRIBUTES[record.class_uid] ?? []])
      return Object.keys(record)
        .filter(key => !allowed.has(key))
        .map(key => `${String(record.class_uid)}: ${key}`)
    }))
    expect([...violations].sort()).toEqual([])
  })

  it('declares a profile for every profile-owned attribute it carries', () => {
    for (const record of records) {
      expect(record.metadata.profiles).toContain('ai_operation')
      if (record.cloud !== undefined) expect(record.metadata.profiles).toContain('cloud')
      if (record.osint !== undefined) expect(record.metadata.profiles).toContain('osint')
      if (record.attestation_list !== undefined) expect(record.metadata.profiles).toContain(RECORD_INTEGRITY_PROFILE)
    }
  })

  it('fills the record_integrity objects with the attributes the schema defines, and no others', () => {
    const violations = new Set(records.flatMap((record) => {
      const list = record.attestation_list ?? []
      return list.flatMap(attestation => objectViolations('attestation', attestation as unknown as Record<string, unknown>))
    }))
    expect([...violations].sort()).toEqual([])
  })

  it('meets the attestation constraint at_least_one: [fingerprint, signatures] on every record', () => {
    expect(records.length).toBeGreaterThan(0)
    for (const record of records) {
      expect(record.attestation_list).toHaveLength(1)
      expect(record.attestation_list?.[0]?.fingerprint?.value).toMatch(/^[0-9a-f]{64}$/)
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

  it('names an application on every Application Lifecycle record, as the class constraint demands', () => {
    const lifecycle = records.filter(record => record.class_uid === CLASS.applicationLifecycle)
    expect(lifecycle.length).toBeGreaterThan(0)
    for (const record of lifecycle) {
      expect(record.application?.name).toBe('deepseek-harness')
    }
  })

  it('stamps the fleet identity onto every record', () => {
    for (const record of records) {
      expect(record.metadata.tenant_uid).toBe('acme')
      expect(record.metadata.labels).toEqual(['prod'])
      expect(record.metadata.tags).toEqual([{ name: 'owner', value: 'soc' }])
      expect(record.device?.uid).toBe('install-test')
    }
  })

  it('passes the log time through as original_time for a collected event, and omits it for a generated one', () => {
    const collected = records.find(record => record.metadata.uid === 'S1:0')
    expect(collected?.metadata.original_time).toBe('1000')
    const heartbeat = records.find(record => record.metadata.uid?.includes(':heartbeat:'))
    expect(heartbeat?.metadata.original_time).toBeUndefined()
  })
})
