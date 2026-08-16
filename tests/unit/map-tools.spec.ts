/** Tool classification, call/result correlation, and the record fields each one produces. */
import { describe, expect, it } from 'vitest'
import { SessionState } from '../../src/correlate.ts'
import { mapEvent } from '../../src/map/index.ts'
import { mapUnresolvedCall } from '../../src/map/tool-events.ts'
import { classifyTool, parseArguments } from '../../src/map/tools.ts'
import { CLASS, SEVERITY, STATUS, typeUid } from '../../src/ocsf/constants.ts'
import { buildRecord } from '../../src/ocsf/record.ts'
import { dshOf, testConfig, testEnvironment } from './support.ts'

const SESSION = 'session-1'

function call(name: string, args: unknown, seq = 1, time = 1_000): { type: string; seq: number; time: number; data: unknown } {
  return {
    type: 'tool/call',
    seq,
    time,
    data: { turn: 1, step: 0, callId: 'call-1', name, arguments: JSON.stringify(args) },
  }
}

function result(callId: string, isError: boolean, seq = 2, time = 1_250): { type: string; seq: number; time: number; data: unknown } {
  return {
    type: 'tool/result',
    seq,
    time,
    data: {
      turn: 1,
      step: 0,
      message: { source: { kind: 'tool', callId }, content: [{ type: 'tool-result', toolCallId: callId, isError }] },
    },
  }
}

describe('tool classification', () => {
  it('classifies the shipped tools by what they do', () => {
    const config = testConfig()
    expect(classifyTool('bash', config)).toBe('process-launch')
    expect(classifyTool('run_code', config)).toBe('process-launch')
    expect(classifyTool('terminal_close', config)).toBe('process-terminate')
    expect(classifyTool('read', config)).toBe('file-read')
    expect(classifyTool('write', config)).toBe('file-write')
    expect(classifyTool('edit', config)).toBe('file-update')
    expect(classifyTool('web_fetch', config)).toBe('http')
    expect(classifyTool('todo_write', config)).toBe('api')
  })

  it('lets a deployment classify a tool the table does not know', () => {
    const config = testConfig({ toolClasses: { my_shell: 'process-launch' } })
    expect(classifyTool('my_shell', config)).toBe('process-launch')
  })

  it('keeps the built-in classification of a known tool', () => {
    const config = testConfig({ toolClasses: { bash: 'api' } })
    expect(classifyTool('bash', config)).toBe('process-launch')
  })
})

describe('argument parsing', () => {
  it('reports a parse failure instead of throwing', () => {
    expect(parseArguments('{not json').error).toBeDefined()
    expect(parseArguments('[1,2]').error).toBe('tool arguments are not a JSON object')
    expect(parseArguments('{"a":1}').record).toEqual({ a: 1 })
  })

  it('states only that parsing failed, never a window of the text that failed', () => {
    const malformed = '{"command": curl -u admin:hunter2 https://x}'
    expect(parseArguments(malformed).error).toBe('tool arguments are not valid JSON')
    expect(parseArguments(malformed).error).not.toContain('hunter2')
    expect(parseArguments('{"command": "export AWS_KEY=wJalrXUtnFEMIK').error).not.toContain('wJalr')
    expect(parseArguments('sorry, I meant to run: psql -W hunter2').error).not.toContain('psql')
  })
})

describe('tool/call mapping', () => {
  it('maps a bash call onto Process Activity with a launch activity', () => {
    const config = testConfig()
    const state = new SessionState()
    const mapping = mapEvent(SESSION, call('bash', { command: 'ls -la /etc', description: 'list' }), state, config)
    expect(mapping?.classUid).toBe(CLASS.processActivity)
    expect(mapping?.activityId).toBe(1)
    expect(mapping?.statusId).toBe(STATUS.unknown)
    expect(mapping?.correlationUid).toBe(`${SESSION}:call-1`)
    expect(mapping?.process?.name).toBe('ls')
  })

  it('maps a read call onto File System Activity and keeps the path', () => {
    const mapping = mapEvent(SESSION, call('read', { file_path: '/srv/app/.env' }), new SessionState(), testConfig())
    expect(mapping?.classUid).toBe(CLASS.fileSystemActivity)
    expect(mapping?.activityId).toBe(2)
    expect(mapping?.file?.path).toBe('/srv/app/.env')
    expect(mapping?.file?.name).toBe('.env')
  })

  it('maps a web_fetch call onto HTTP Activity with a redacted URL', () => {
    const mapping = mapEvent(
      SESSION,
      call('web_fetch', { url: 'https://example.test/data?token=secret#frag' }),
      new SessionState(),
      testConfig(),
    )
    expect(mapping?.classUid).toBe(CLASS.httpActivity)
    expect(mapping?.httpRequest?.url?.url_string).toBe('https://example.test')
  })

  it('names the executable of a command that begins with an environment assignment', () => {
    const mapping = mapEvent(
      SESSION,
      call('bash', { command: 'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENG aws s3 cp x s3://b' }),
      new SessionState(),
      testConfig(),
    )
    expect(mapping?.process?.name).toBe('aws')
    expect(JSON.stringify(mapping)).not.toContain('wJalrXUtnFEMIK7MDENG')
  })

  it('treats a grep pattern as a query to digest, never as a file path', () => {
    const mapping = mapEvent(
      SESSION,
      call('grep', { pattern: 'password\\s*=\\s*"hunter2"' }),
      new SessionState(),
      testConfig(),
    )
    expect(mapping?.classUid).toBe(CLASS.fileSystemActivity)
    expect(mapping?.file?.path).toBeUndefined()
    expect(mapping?.observables ?? []).toEqual([])
    expect(JSON.stringify(mapping)).not.toContain('hunter2')
  })

  it('maps an unknown tool onto API Activity naming the operation', () => {
    const mapping = mapEvent(SESSION, call('mystery_tool', { a: 1 }), new SessionState(), testConfig())
    expect(mapping?.classUid).toBe(CLASS.apiActivity)
    expect(mapping?.api?.operation).toBe('tool:mystery_tool')
  })

  it('reports unmappable payloads rather than inventing a call id', () => {
    expect(mapEvent(SESSION, { type: 'tool/call', seq: 1, time: 1, data: { name: 'bash' } }, new SessionState(), testConfig()))
      .toBeUndefined()
  })
})

describe('tool/result correlation', () => {
  it('pairs a result with its call and carries the duration', () => {
    const config = testConfig()
    const state = new SessionState()
    mapEvent(SESSION, call('bash', { command: 'true' }), state, config)
    const mapping = mapEvent(SESSION, result('call-1', false), state, config)
    expect(mapping?.classUid).toBe(CLASS.processActivity)
    expect(mapping?.correlationUid).toBe(`${SESSION}:call-1`)
    expect(mapping?.statusId).toBe(STATUS.success)
    expect(mapping?.duration).toBe(250)
    expect(mapping?.startTime).toBe(1_000)
    expect(mapping?.attributes?.['tool']).toBe('bash')
  })

  it('reads the call id from the tool-result block when the source has none', () => {
    const config = testConfig()
    const state = new SessionState()
    mapEvent(SESSION, call('bash', { command: 'true' }), state, config)
    const mapping = mapEvent(SESSION, {
      type: 'tool/result',
      seq: 2,
      time: 1_100,
      data: { turn: 1, step: 0, message: { source: { kind: 'tool' }, content: [{ toolCallId: 'call-1' }] } },
    }, state, config)
    expect(mapping?.correlationUid).toBe(`${SESSION}:call-1`)
    expect(mapping?.duration).toBe(100)
  })

  it('grades an errored result as a failure', () => {
    const config = testConfig()
    const state = new SessionState()
    mapEvent(SESSION, call('bash', { command: 'false' }), state, config)
    const mapping = mapEvent(SESSION, result('call-1', true), state, config)
    expect(mapping?.statusId).toBe(STATUS.failure)
    expect(mapping?.severityId).toBe(SEVERITY.medium)
  })

  it('marks a result whose call was never observed', () => {
    const mapping = mapEvent(SESSION, result('orphan', false), new SessionState(), testConfig())
    expect(mapping?.attributes?.['unpaired']).toBe(true)
    expect(mapping?.duration).toBeUndefined()
  })

  it('carries the subject object its OCSF class requires on the settling record too', () => {
    const config = testConfig()
    const state = new SessionState()
    mapEvent(SESSION, call('bash', { command: 'ls -la /etc' }), state, config)
    expect(mapEvent(SESSION, result('call-1', false), state, config)?.process?.name).toBe('ls')

    mapEvent(SESSION, call('read', { file_path: '/srv/app/.env' }), state, config)
    expect(mapEvent(SESSION, result('call-1', false), state, config)?.file?.path).toBe('/srv/app/.env')

    mapEvent(SESSION, call('web_fetch', { url: 'https://example.test/a' }), state, config)
    expect(mapEvent(SESSION, result('call-1', false), state, config)?.httpRequest?.http_method).toBe('GET')
  })

  it('still names a subject when the settling record has no call to draw one from', () => {
    const config = testConfig()
    const mapping = mapEvent(SESSION, {
      type: 'tool/code-dispatch',
      seq: 6,
      time: 2_050,
      data: { subCallId: 'lost', name: 'write', isError: false },
    }, new SessionState(), config)
    expect(mapping?.classUid).toBe(CLASS.fileSystemActivity)
    expect(mapping?.file?.name).toBe('write')
  })

  it('does not let two sessions share a call id', () => {
    const config = testConfig()
    const first = new SessionState()
    const second = new SessionState()
    mapEvent('session-a', call('bash', { command: 'true' }), first, config)
    const mapping = mapEvent('session-b', result('call-1', false), second, config)
    expect(mapping?.attributes?.['unpaired']).toBe(true)
  })
})

describe('code-mode sub-dispatch', () => {
  it('classifies a sub-call by its own tool and links it to its parent', () => {
    const config = testConfig()
    const state = new SessionState()
    const start = mapEvent(SESSION, {
      type: 'tool/code-dispatch-start',
      seq: 5,
      time: 2_000,
      data: { rootCallId: 'root', parentCallId: 'parent', subCallId: 'sub-1', name: 'write', arguments: { file_path: '/tmp/x' } },
    }, state, config)
    expect(start?.classUid).toBe(CLASS.fileSystemActivity)
    expect(start?.attributes?.['parent_call_id']).toBe('parent')

    const settle = mapEvent(SESSION, {
      type: 'tool/code-dispatch',
      seq: 6,
      time: 2_050,
      data: { subCallId: 'sub-1', name: 'write', isError: true },
    }, state, config)
    expect(settle?.statusId).toBe(STATUS.failure)
    expect(settle?.duration).toBe(50)
  })
})

describe('unresolved calls', () => {
  it('flushes a call that never settled with an unknown status', () => {
    const mapping = mapUnresolvedCall(SESSION, {
      callId: 'call-9', name: 'bash', toolClass: 'process-launch', time: 10, seq: 3, turn: 1, step: 0,
      process: { name: 'sleep' },
    }, 60)
    expect(mapping.statusId).toBe(STATUS.unknown)
    expect(mapping.duration).toBe(50)
    expect(mapping.attributes?.['unresolved']).toBe(true)
    expect(mapping.process?.name).toBe('sleep')
  })

  it('names a subject even for a call whose arguments yielded none', () => {
    const mapping = mapUnresolvedCall(SESSION, {
      callId: 'call-9', name: 'read', toolClass: 'file-read', time: 10, seq: 3, turn: 1, step: 0,
    }, 60)
    expect(mapping.file?.name).toBe('read')
  })
})

describe('the composed record', () => {
  it('carries the OCSF identity, its declared profiles, and the extension object', () => {
    const config = testConfig()
    const env = testEnvironment(config)
    const state = new SessionState()
    state.aiModel = { name: 'deepseek-chat', ai_provider: 'deepseek' }
    const mapping = mapEvent(SESSION, call('bash', { command: 'id' }), state, config)
    const record = buildRecord(env, {
      sessionId: SESSION,
      seq: 1,
      time: 1_000,
      eventType: 'tool/call',
      replayed: false,
      aiModel: state.aiModel,
    }, mapping!)

    expect(record.class_uid).toBe(CLASS.processActivity)
    expect(record.category_uid).toBe(1)
    expect(record.type_uid).toBe(typeUid(CLASS.processActivity, 1))
    expect(record.metadata.version).toBe('1.9.0')
    expect(record.metadata.uid).toBe(`${SESSION}:1`)
    expect(record.ai_agent?.instance_uid).toBe(SESSION)
    expect(record.ai_agent?.ai_model?.name).toBe('deepseek-chat')
    expect(record.cloud).toEqual({ provider: 'Other' })
    expect(record.osint).toEqual([])
    const attributes = dshOf(record)
    expect(attributes['session_id']).toBe(SESSION)
    expect(attributes['event_type']).toBe('tool/call')
    expect(attributes['call_id']).toBe('call-1')
  })

  it('declares every profile whose attributes it carries', () => {
    const record = buildRecord(testEnvironment(), {
      sessionId: SESSION, seq: 1, time: 1, eventType: 'turn/start', replayed: false,
    }, mapEvent(SESSION, call('bash', { command: 'id' }), new SessionState(), testConfig())!)
    expect(record.metadata.profiles).toEqual(['ai_operation', 'cloud', 'osint'])
  })

  it('keeps the extension attributes out of the class namespace by default', () => {
    const record = buildRecord(testEnvironment(), {
      sessionId: SESSION, seq: 1, time: 1, eventType: 'tool/call', replayed: false,
    }, mapEvent(SESSION, call('bash', { command: 'id' }), new SessionState(), testConfig())!)
    expect(record['dsh']).toBeUndefined()
    expect((record.unmapped as Record<string, unknown>)['dsh']).toBeDefined()
  })

  it('names an extension only once a deployment supplies a registered uid', () => {
    const plain = buildRecord(testEnvironment(), {
      sessionId: SESSION, seq: 1, time: 1, eventType: 'tool/call', replayed: false,
    }, mapEvent(SESSION, call('bash', { command: 'id' }), new SessionState(), testConfig())!)
    expect(plain.metadata.extensions).toBeUndefined()

    const config = testConfig({ extension: { uid: 4242 } })
    const registered = buildRecord(testEnvironment(config), {
      sessionId: SESSION, seq: 1, time: 1, eventType: 'tool/call', replayed: false,
    }, mapEvent(SESSION, call('bash', { command: 'id' }), new SessionState(), config)!)
    expect(registered.metadata.extensions).toEqual([{ name: 'dsh', uid: 4242, version: '0.1.0-test' }])
  })

  it('places the extension object at the top level when the deployment asks', () => {
    const config = testConfig({ extension: { placement: 'attribute' } })
    const record = buildRecord(testEnvironment(config), {
      sessionId: SESSION, seq: 1, time: 1, eventType: 'tool/call', replayed: false,
    }, mapEvent(SESSION, call('bash', { command: 'id' }), new SessionState(), config)!)
    expect(record['dsh']).toBeDefined()
    expect(record.unmapped).toBeUndefined()
  })

  it('honours a synthetic idempotency key', () => {
    const env = testEnvironment()
    const record = buildRecord(env, {
      sessionId: SESSION, seq: 4, time: 1, eventType: 'tool/call', replayed: true, uid: 'custom',
    }, mapUnresolvedCall(SESSION, {
      callId: 'c', name: 'bash', toolClass: 'process-launch', time: 0, seq: 1, turn: 0, step: 0,
    }, 5))
    expect(record.metadata.uid).toBe('custom')
    expect(dshOf(record)['replayed']).toBe(true)
  })
})
