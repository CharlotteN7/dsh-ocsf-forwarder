/** Tool classification, call/result correlation, and the record fields each one produces. */
import { describe, expect, it } from 'vitest'
import { SessionState } from '../../src/correlate.ts'
import { mapEvent } from '../../src/map/index.ts'
import { mapUnresolvedCall } from '../../src/map/tool-events.ts'
import { classifyTool, parseArguments } from '../../src/map/tools.ts'
import { CLASS, OBSERVABLE, SEVERITY, STATUS, typeUid } from '../../src/ocsf/constants.ts'
import { buildRecord } from '../../src/ocsf/record.ts'
import type { OcsfObservable } from '../../src/ocsf/types.ts'
import { digest } from '../../src/privacy.ts'
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
    expect(mapping?.process?.uid).toBe(`${SESSION}:call-1`)
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
    expect(mapping?.observables).toEqual([])
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

describe('the observables a tool call emits', () => {
  /** The one observable of the given name, so a wrong type or value is not hidden by a sibling. */
  function observable(mapping: { observables?: readonly OcsfObservable[] } | undefined, name: string): OcsfObservable {
    const found = (mapping?.observables ?? []).filter(item => item.name === name)
    expect(found).toHaveLength(1)
    return found[0] as OcsfObservable
  }

  it('digests a command line and types it as a hash, not as a command line', () => {
    const config = testConfig()
    const command = 'psql "postgres://admin:hunter2@db.test/app"'
    const mapping = mapEvent(SESSION, call('bash', { command }), new SessionState(), config)
    const emitted = observable(mapping, 'process.cmd_line')
    expect(emitted.type_id).toBe(OBSERVABLE.hash)
    expect(emitted.value).toBe(digest(config.hmacKey, command))
    expect(emitted.value).not.toContain('hunter2')
  })

  it('carries the command line verbatim, typed as one, only when a deployment asked for that', () => {
    const config = testConfig({ privacy: { commandLine: 'full' } })
    const command = 'psql "postgres://admin:hunter2@db.test/app"'
    const emitted = observable(mapEvent(SESSION, call('bash', { command }), new SessionState(), config), 'process.cmd_line')
    expect(emitted.type_id).toBe(OBSERVABLE.commandLine)
    expect(emitted.value).toBe(command)
  })

  it('carries the file path itself, not the argument record it came from', () => {
    const mapping = mapEvent(
      SESSION,
      call('write', { file_path: '/srv/app/.env', content: 'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK' }),
      new SessionState(),
      testConfig(),
    )
    const emitted = observable(mapping, 'file.path')
    expect(emitted.type_id).toBe(OBSERVABLE.filePath)
    expect(emitted.value).toBe('/srv/app/.env')
    expect(emitted.value).not.toContain('wJalrXUtnFEMIK')
  })

  it('carries the redacted URL, not the one the model wrote', () => {
    const mapping = mapEvent(
      SESSION,
      call('web_fetch', { url: 'https://example.test/reset?token=sk-live-1#frag' }),
      new SessionState(),
      testConfig(),
    )
    const emitted = observable(mapping, 'http_request.url.url_string')
    expect(emitted.type_id).toBe(OBSERVABLE.url)
    expect(emitted.value).toBe('https://example.test')
    expect(emitted.value).not.toContain('sk-live-1')
  })

  it('follows the URL policy a deployment set, and never widens past it', () => {
    const sanitized = mapEvent(
      SESSION,
      call('web_fetch', { url: 'https://example.test/reset?token=sk-live-1' }),
      new SessionState(),
      testConfig({ privacy: { url: 'sanitized' } }),
    )
    expect(observable(sanitized, 'http_request.url.url_string').value).toBe('https://example.test/reset')

    const full = mapEvent(
      SESSION,
      call('web_fetch', { url: 'https://example.test/reset?token=sk-live-1' }),
      new SessionState(),
      testConfig({ privacy: { url: 'full' } }),
    )
    expect(observable(full, 'http_request.url.url_string').value).toBe('https://example.test/reset?token=sk-live-1')
  })

  it('emits no observable for a call that named no subject to observe', () => {
    expect(mapEvent(SESSION, call('bash', { description: 'nothing to run' }), new SessionState(), testConfig())?.observables)
      .toEqual([])
    expect(mapEvent(SESSION, call('read', { pattern: 'x' }), new SessionState(), testConfig())?.observables).toEqual([])
    expect(mapEvent(SESSION, call('web_fetch', { url: 'not-a-url' }), new SessionState(), testConfig())?.observables)
      .toEqual([])
    expect(mapEvent(SESSION, call('mystery_tool', { a: 1 }), new SessionState(), testConfig())?.observables).toEqual([])
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
    const settled = mapEvent(SESSION, result('call-1', false), state, config)
    expect(settled?.process?.name).toBe('ls')
    expect(settled?.process?.uid).toBe(`${SESSION}:call-1`)

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

  it('identifies a launched process the harness never reported an OS pid for', () => {
    const config = testConfig()
    const state = new SessionState()
    // `process` constrains `at_least_one: [pid, uid, cpid]`. No payload names
    // the child's pid, so every record about one subprocess carries the same
    // producer-assigned `uid`, and none carries an invented pid.
    const launch = mapEvent(SESSION, call('bash', { command: 'ls' }), state, config)
    expect(launch?.process?.pid).toBeUndefined()
    expect(launch?.process?.uid).toBe(`${SESSION}:call-1`)

    const unpaired = mapEvent(SESSION, result('never-seen', false), new SessionState(), config)
    expect(unpaired?.process).toBeUndefined()

    const delegation = mapEvent(SESSION, call('subagent_codex', { prompt: 'go' }), state, testConfig({
      delegationTools: { subagent_codex: 'codex' },
    }))
    expect(delegation?.process?.uid).toBe(`${SESSION}:call-1`)
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

  it('carries no subject object for a sub-call whose class defines none', () => {
    const mapping = mapEvent(SESSION, {
      type: 'tool/code-dispatch-start',
      seq: 5,
      time: 2_000,
      data: { subCallId: 'sub-1', name: 'mystery_tool', arguments: { a: 1 } },
    }, new SessionState(), testConfig())
    expect(mapping?.classUid).toBe(CLASS.apiActivity)
    expect(mapping?.process).toBeUndefined()
    expect(mapping?.file).toBeUndefined()
    expect(mapping?.httpRequest).toBeUndefined()
    expect(mapping?.api?.operation).toBe('tool:mystery_tool')
  })

  it('classifies a sub-call that hands the task to an external harness as one', () => {
    const config = testConfig({ delegationTools: { handoff: 'codex' } })
    const state = new SessionState()
    const start = mapEvent(SESSION, {
      type: 'tool/code-dispatch-start',
      seq: 5,
      time: 2_000,
      data: { subCallId: 'sub-1', name: 'handoff', arguments: { prompt: 'go' } },
    }, state, config)
    expect(start?.severityId).toBe(SEVERITY.high)
    expect(start?.process?.name).toBe('codex')

    const settle = mapEvent(SESSION, {
      type: 'tool/code-dispatch',
      seq: 6,
      time: 2_050,
      data: { subCallId: 'sub-1', isError: false },
    }, state, config)
    expect(settle?.attributes?.['delegation_provider']).toBe('codex')
  })

  it('names an unnamed sub-call unknown rather than dropping its settling record', () => {
    const mapping = mapEvent(SESSION, {
      type: 'tool/code-dispatch',
      seq: 6,
      time: 2_050,
      data: { subCallId: 'orphan', isError: false },
    }, new SessionState(), testConfig())
    expect(mapping?.attributes?.['tool']).toBe('unknown')
    expect(mapping?.attributes?.['unpaired']).toBe(true)
  })

  it('carries the http subject of a sub-call whose class defines one', () => {
    const mapping = mapEvent(SESSION, {
      type: 'tool/code-dispatch-start',
      seq: 5,
      time: 2_000,
      data: { subCallId: 'sub-1', name: 'web_fetch', arguments: { url: 'https://example.test/a' } },
    }, new SessionState(), testConfig())
    expect(mapping?.httpRequest?.url?.url_string).toBe('https://example.test')
  })
})

describe('payloads a mapper has to read defensively', () => {
  it('records that a sub-dispatch arrived with arguments that are not an object', () => {
    const mapping = mapEvent(SESSION, {
      type: 'tool/code-dispatch-start',
      seq: 5,
      time: 2_000,
      data: { subCallId: 'sub-1', name: 'write', arguments: 42 },
    }, new SessionState(), testConfig())
    expect(mapping?.attributes?.['arguments_parse_error']).toBe('tool arguments are not a JSON object')
    expect(mapping?.attributes?.['arguments']).toEqual([])
  })

  it('reports a sub-dispatch payload that names no sub-call, rather than inventing one', () => {
    const state = new SessionState()
    expect(mapEvent(SESSION, { type: 'tool/code-dispatch-start', seq: 1, time: 1, data: { name: 'write' } }, state, testConfig()))
      .toBeUndefined()
    expect(mapEvent(SESSION, { type: 'tool/code-dispatch', seq: 1, time: 1, data: { name: 'write' } }, state, testConfig()))
      .toBeUndefined()
    expect(mapEvent(SESSION, { type: 'tool/result', seq: 1, time: 1, data: {} }, state, testConfig())).toBeUndefined()
  })

  it('defaults a sub-dispatch that names no parent or root call, and takes the call ids as its own', () => {
    const mapping = mapEvent(SESSION, {
      type: 'tool/code-dispatch-start',
      seq: 5,
      time: 2_000,
      data: { subCallId: 'sub-1', name: 'read', arguments: { file_path: '/tmp/x' } },
    }, new SessionState(), testConfig())
    expect(mapping?.attributes?.['parent_call_id']).toBe('')
    expect(mapping?.attributes?.['root_call_id']).toBe('')
  })

  it('reads a tool call that names no turn or step as turn 0 step 0', () => {
    const mapping = mapEvent(
      SESSION,
      { type: 'tool/call', seq: 1, time: 1, data: { callId: 'c1', name: 'bash', arguments: '{}' } },
      new SessionState(),
      testConfig(),
    )
    expect(mapping?.attributes?.['turn']).toBe(0)
    expect(mapping?.attributes?.['step']).toBe(0)
  })

  it('carries the failure identity of a tool result that reported an error object', () => {
    const config = testConfig()
    const state = new SessionState()
    mapEvent(SESSION, call('bash', { command: 'false' }), state, config)
    const mapping = mapEvent(SESSION, {
      type: 'tool/result',
      seq: 2,
      time: 1_100,
      data: { message: { source: { callId: 'call-1' } }, error: { name: 'ToolError', code: 'ENOENT' } },
    }, state, config)
    expect(mapping?.statusDetail).toBe('ToolError: ENOENT')
  })

  it('gives a settling record with no call and no subject an http_request, so its class stays valid', () => {
    const mapping = mapEvent(SESSION, {
      type: 'tool/code-dispatch',
      seq: 6,
      time: 2_050,
      data: { subCallId: 'lost', name: 'web_fetch', isError: false },
    }, new SessionState(), testConfig())
    expect(mapping?.classUid).toBe(CLASS.httpActivity)
    expect(mapping?.httpRequest).toEqual({ http_method: 'GET' })
  })

  it('carries no api object on an unresolved call whose class defines none', () => {
    const mapping = mapUnresolvedCall(SESSION, {
      callId: 'c', name: 'bash', toolClass: 'process-launch', time: 0, seq: 1, turn: 0, step: 0,
    }, 5)
    expect(mapping.api).toBeUndefined()
    expect(mapUnresolvedCall(SESSION, {
      callId: 'c', name: 'mystery', toolClass: 'api', time: 0, seq: 1, turn: 0, step: 0,
    }, 5).api?.operation).toBe('tool:mystery')
  })
})

describe('unresolved calls', () => {
  it('flushes a call that never settled with an unknown status', () => {
    const mapping = mapUnresolvedCall(SESSION, {
      callId: 'call-9', name: 'bash', toolClass: 'process-launch', time: 10, seq: 3, turn: 1, step: 0,
      process: { name: 'sleep', uid: `${SESSION}:call-9` },
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

    const config = testConfig({ extension: { uid: '4242' } })
    const registered = buildRecord(testEnvironment(config), {
      sessionId: SESSION, seq: 1, time: 1, eventType: 'tool/call', replayed: false,
    }, mapEvent(SESSION, call('bash', { command: 'id' }), new SessionState(), config)!)
    expect(registered.metadata.extensions).toEqual([{ name: 'dsh', uid: '4242', version: '0.1.0-test' }])
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
