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
  [CLASS.processActivity]: ['actor', 'ai_agent', 'ai_model', 'api', 'attestation_list', 'delegation', 'device', 'exit_code', 'message_context', 'process'],
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

/** One attribute of an OCSF object, as the object defines it. */
interface ObjectAttribute {
  /** The JSON type the OCSF type resolves to; `array` covers every `is_array` attribute. */
  readonly type: 'string' | 'number' | 'boolean' | 'object' | 'array'
  readonly required?: true
  /** The OCSF object this attribute — or, for an array, each of its members — carries. */
  readonly object?: string
}

/** One OCSF object definition. */
interface ObjectDefinition {
  readonly attributes: Readonly<Record<string, ObjectAttribute>>
  /** The object's own `at_least_one` constraint, when it has one. */
  readonly atLeastOne?: readonly string[]
}

/**
 * Every OCSF object this plugin emits, read from
 * `schema.ocsf.io/api/1.9.0/objects/<name>`, with each attribute's JSON type,
 * whether the object requires it, and the object it nests.
 *
 * An OCSF object is closed exactly as a class is, so this is the per-class
 * check of §30 applied all the way down. Walking only `Object.keys(record)`
 * left every nested object unchecked: `device.bogus_nested_attr` passed, and
 * `process.exit_code` — which the `process` object does not define, and which
 * class 1007 defines at the top level — shipped through it.
 *
 * Each object is narrowed to the attributes this plugin can emit, for the
 * reason §30 gives: transcribing all ~35 of `process` or all ~60 of `device`
 * produces a set large enough to stop discriminating. Emitting an attribute an
 * object does define but this plugin has not emitted before fails until the
 * entry is added, and adding it is how that change gets made deliberately.
 */
const OBJECTS: Readonly<Record<string, ObjectDefinition>> = Object.freeze({
  metadata: {
    attributes: {
      product: { type: 'object', required: true, object: 'product' },
      version: { type: 'string', required: true },
      profiles: { type: 'array' },
      extensions: { type: 'array', object: 'extension' },
      log_provider: { type: 'string' },
      log_name: { type: 'string' },
      uid: { type: 'string' },
      correlation_uid: { type: 'string' },
      sequence: { type: 'number' },
      logged_time: { type: 'number' },
      original_time: { type: 'string' },
      tenant_uid: { type: 'string' },
      labels: { type: 'array' },
      tags: { type: 'array', object: 'key_value_object' },
    },
  },
  product: {
    attributes: { name: { type: 'string' }, vendor_name: { type: 'string' }, version: { type: 'string' } },
    atLeastOne: ['name', 'uid'],
  },
  extension: {
    // `uid` is `string_t`; `uid_numeric` is the numeric slot, and a number here
    // invalidates every record the deployment emits.
    attributes: { name: { type: 'string' }, uid: { type: 'string' }, version: { type: 'string', required: true } },
    atLeastOne: ['name', 'uid'],
  },
  key_value_object: {
    attributes: { name: { type: 'string', required: true }, value: { type: 'string' } },
    atLeastOne: ['value', 'values'],
  },
  application: {
    attributes: { name: { type: 'string' }, uid: { type: 'string' } },
    atLeastOne: ['uid', 'name'],
  },
  cloud: { attributes: { provider: { type: 'string', required: true } } },
  network_endpoint: {
    attributes: { hostname: { type: 'string' }, svc_name: { type: 'string' } },
    atLeastOne: ['ip', 'uid', 'name', 'hostname', 'svc_name', 'instance_uid', 'interface_uid', 'interface_name', 'domain'],
  },
  ai_agent: {
    attributes: {
      name: { type: 'string' },
      type_id: { type: 'number' },
      version: { type: 'string' },
      instance_uid: { type: 'string' },
      uid: { type: 'string' },
      ai_model: { type: 'object', object: 'ai_model' },
    },
    atLeastOne: ['name', 'uid'],
  },
  ai_model: {
    attributes: { name: { type: 'string', required: true }, ai_provider: { type: 'string', required: true } },
    atLeastOne: ['name', 'uid'],
  },
  message_context: {
    attributes: {
      ai_role_id: { type: 'number' },
      application: { type: 'object', object: 'application' },
      prompt_tokens: { type: 'number' },
      completion_tokens: { type: 'number' },
      total_tokens: { type: 'number' },
    },
    atLeastOne: ['application', 'service'],
  },
  delegation: {
    attributes: {
      uid: { type: 'string', required: true },
      parent_uid: { type: 'string' },
      created_time: { type: 'number' },
    },
  },
  actor: {
    attributes: { process: { type: 'object', object: 'process' }, user: { type: 'object', object: 'user' } },
    atLeastOne: ['process', 'user', 'iam_role', 'invoked_by', 'session', 'application', 'app_name', 'app_uid'],
  },
  device: {
    attributes: {
      type_id: { type: 'number', required: true },
      hostname: { type: 'string' },
      uid: { type: 'string' },
      os: { type: 'object', object: 'os' },
    },
    atLeastOne: ['ip', 'uid', 'name', 'hostname', 'instance_uid', 'interface_uid', 'interface_name'],
  },
  os: {
    attributes: { name: { type: 'string', required: true }, type_id: { type: 'number', required: true } },
  },
  user: {
    attributes: { name: { type: 'string' }, type_id: { type: 'number' } },
    atLeastOne: ['account', 'name', 'uid'],
  },
  process: {
    // The object has 35 attributes and `exit_code` is not among them.
    attributes: {
      name: { type: 'string' },
      pid: { type: 'number' },
      cmd_line: { type: 'string' },
      uid: { type: 'string' },
    },
    atLeastOne: ['pid', 'uid', 'cpid'],
  },
  file: {
    attributes: {
      name: { type: 'string', required: true },
      path: { type: 'string' },
      type_id: { type: 'number', required: true },
    },
  },
  api: {
    attributes: {
      operation: { type: 'string', required: true },
      service: { type: 'object', object: 'service' },
      version: { type: 'string' },
    },
  },
  service: { attributes: { name: { type: 'string' } }, atLeastOne: ['name', 'uid'] },
  http_request: {
    attributes: { http_method: { type: 'string' }, url: { type: 'object', object: 'url' } },
  },
  url: {
    attributes: { url_string: { type: 'string' }, hostname: { type: 'string' } },
    atLeastOne: ['url_string', 'path'],
  },
  job: {
    attributes: { name: { type: 'string' }, uid: { type: 'string' } },
    atLeastOne: ['name', 'type_id'],
  },
  observable: {
    attributes: {
      name: { type: 'string' },
      type_id: { type: 'number', required: true },
      value: { type: 'string' },
    },
  },
  attestation: {
    attributes: {
      uid: { type: 'string' },
      chain_uid: { type: 'string' },
      prev_event: { type: 'object', object: 'prev_event' },
      fingerprint: { type: 'object', object: 'fingerprint' },
    },
    atLeastOne: ['fingerprint', 'signatures'],
  },
  prev_event: {
    attributes: {
      uid: { type: 'string', required: true },
      type_uid: { type: 'number' },
      fingerprint: { type: 'object', object: 'fingerprint' },
    },
  },
  fingerprint: {
    attributes: {
      value: { type: 'string', required: true },
      algorithm_id: { type: 'number', required: true },
      encoding_id: { type: 'number' },
    },
  },
})

/**
 * The OCSF object each record attribute carries. An attribute absent from this
 * map holds no object — a scalar, a string list, or `unmapped`, whose whole
 * point is that the schema does not define what is inside it.
 */
const OBJECT_OF_ATTRIBUTE: Readonly<Record<string, string>> = Object.freeze({
  metadata: 'metadata',
  application: 'application',
  cloud: 'cloud',
  src_endpoint: 'network_endpoint',
  ai_agent: 'ai_agent',
  ai_model: 'ai_model',
  message_context: 'message_context',
  delegation: 'delegation',
  actor: 'actor',
  device: 'device',
  user: 'user',
  process: 'process',
  file: 'file',
  api: 'api',
  http_request: 'http_request',
  job: 'job',
  observables: 'observable',
  attestation_list: 'attestation',
})

/** Whether an emitted member matches the JSON type its OCSF type resolves to. */
function typeOf(member: unknown): string {
  return Array.isArray(member) ? 'array' : typeof member
}

/**
 * Check one emitted object against its OCSF definition, and everything it
 * nests.
 * @param name - the OCSF object name.
 * @param path - where the object sits in the record, for the violation message.
 * @param value - the object as emitted.
 * @returns one entry per violation, naming the attribute.
 */
function objectViolations(name: string, path: string, value: Readonly<Record<string, unknown>>): string[] {
  const definition = OBJECTS[name] as ObjectDefinition
  const violations: string[] = []
  for (const [key, attribute] of Object.entries(definition.attributes)) {
    if (attribute.required === true && value[key] === undefined) violations.push(`${path}.${key}: missing, and required`)
  }
  if (definition.atLeastOne !== undefined && !definition.atLeastOne.some(key => value[key] !== undefined)) {
    violations.push(`${path}: none of at_least_one [${definition.atLeastOne.join(', ')}]`)
  }
  for (const [key, member] of Object.entries(value)) {
    const attribute = definition.attributes[key]
    if (attribute === undefined) {
      violations.push(`${path}.${key}: not defined by the ${name} object`)
      continue
    }
    if (typeOf(member) !== attribute.type) {
      violations.push(`${path}.${key}: ${typeOf(member)}, not ${attribute.type}`)
      continue
    }
    if (attribute.object === undefined) continue
    const members = attribute.type === 'array' ? member as unknown[] : [member]
    members.forEach((entry, index) => {
      const where = attribute.type === 'array' ? `${path}.${key}[${String(index)}]` : `${path}.${key}`
      violations.push(...objectViolations(attribute.object as string, where, entry as Record<string, unknown>))
    })
  }
  return violations
}

/**
 * Every violation in one record's nested objects.
 * @param record - the record as a consumer receives it.
 * @returns one entry per violation.
 */
function nestedViolations(record: OcsfRecord): string[] {
  const fields = record as unknown as Record<string, unknown>
  return Object.entries(OBJECT_OF_ATTRIBUTE).flatMap(([attribute, object]) => {
    const value = fields[attribute]
    if (value === undefined) return []
    const members = Array.isArray(value) ? value : [value]
    return members.flatMap((entry, index) => objectViolations(
      object,
      Array.isArray(value) ? `${attribute}[${String(index)}]` : attribute,
      entry as Record<string, unknown>,
    ))
  })
}

/** One run covering every mapper, driven the way the session store drives one. */
function emitted(): readonly OcsfRecord[] {
  const config = testConfig({
    delegationTools: { subagent_claude_code: 'claude-code' },
    fleet: { installUid: 'install-test', tenantUid: 'acme', labels: ['prod'], tags: { owner: 'soc' } },
    // A registered uid is configured so `metadata.extensions` is on every
    // record here: the list is omitted without one, and an unchecked slot is
    // where `uid` being emitted as a number went unnoticed.
    extension: { uid: '999' },
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

  it('fills every nested object with the attributes its own OCSF object defines, and no others', () => {
    expect(records.length).toBeGreaterThan(0)
    const violations = new Set(records.flatMap(record => nestedViolations(record)))
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
