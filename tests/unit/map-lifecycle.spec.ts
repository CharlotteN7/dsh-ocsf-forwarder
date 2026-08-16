/** Turn, step, model, and lifecycle mapping, including the outcome grading of every turn end reason. */
import { describe, expect, it } from 'vitest'
import { SessionState } from '../../src/correlate.ts'
import { mapEvent } from '../../src/map/index.ts'
import { mapSeedBoundary } from '../../src/map/lifecycle.ts'
import { ACTIVITY, CLASS, SEVERITY, STATUS } from '../../src/ocsf/constants.ts'
import { testConfig } from './support.ts'

const SESSION = 'session-1'
const config = testConfig()

function event(type: string, data: unknown, time = 1_000, seq = 1): { type: string; seq: number; time: number; data: unknown } {
  return { type, seq, time, data }
}

describe('turns', () => {
  it('brackets a turn and reports its duration', () => {
    const state = new SessionState()
    const start = mapEvent(SESSION, event('turn/start', { turn: 3 }, 1_000), state, config)
    expect(start?.statusId).toBe(STATUS.unknown)
    expect(start?.correlationUid).toBe(`${SESSION}:turn:3`)

    const end = mapEvent(SESSION, event('turn/end', { turn: 3, reason: { kind: 'completed' } }, 4_000), state, config)
    expect(end?.statusId).toBe(STATUS.success)
    expect(end?.duration).toBe(3_000)
    expect(end?.correlationUid).toBe(`${SESSION}:turn:3`)
  })

  it('grades every shipped end reason', () => {
    const grade = (reason: unknown): { statusId: number | undefined; severityId: number | undefined; detail: string | undefined } => {
      const mapping = mapEvent(SESSION, event('turn/end', { turn: 1, reason }), new SessionState(), config)
      return { statusId: mapping?.statusId, severityId: mapping?.severityId, detail: mapping?.statusDetail }
    }
    expect(grade({ kind: 'completed' })).toMatchObject({ statusId: STATUS.success, severityId: SEVERITY.informational })
    expect(grade({ kind: 'max-tokens' })).toMatchObject({ statusId: STATUS.success, severityId: SEVERITY.low })
    expect(grade({ kind: 'aborted', reason: { kind: 'user' } })).toMatchObject({ statusId: STATUS.failure })
    expect(grade({ kind: 'blocked' })).toMatchObject({ statusId: STATUS.failure, severityId: SEVERITY.medium })
    expect(grade({ kind: 'interrupted' })).toMatchObject({ statusId: STATUS.failure, severityId: SEVERITY.medium })
    expect(grade({ kind: 'error', error: { code: 'RATE_LIMIT', message: 'slow down' } }))
      .toMatchObject({ statusId: STATUS.failure, severityId: SEVERITY.high, detail: 'error' })
  })

  it('falls through to unknown for a merged end reason it does not know', () => {
    const mapping = mapEvent(SESSION, event('turn/end', { turn: 1, reason: { kind: 'handed-off' } }), new SessionState(), config)
    expect(mapping?.statusId).toBe(STATUS.unknown)
    expect(mapping?.statusDetail).toBe('handed-off')
  })

  it('keeps the cancellation cause and the failure code', () => {
    const aborted = mapEvent(SESSION, event('turn/end', { turn: 1, reason: { kind: 'aborted', reason: { kind: 'hook' } } }), new SessionState(), config)
    expect(aborted?.attributes?.['cancel_cause']).toBe('hook')
    const failed = mapEvent(SESSION, event('turn/end', { turn: 1, reason: { kind: 'error', error: { code: 'RATE_LIMIT', message: 'slow down' } } }), new SessionState(), config)
    expect(failed?.attributes?.['error_code']).toBe('RATE_LIMIT')
  })

  it('digests a provider failure message rather than copying the error chain', () => {
    const mapping = mapEvent(SESSION, event('turn/end', {
      turn: 1,
      reason: { kind: 'error', error: { code: 'PROVIDER_ERROR', message: 'upstream 401 for key sk-live-SUPERSECRET' } },
    }), new SessionState(), config)
    expect(JSON.stringify(mapping)).not.toContain('sk-live-SUPERSECRET')
    expect(String(mapping?.attributes?.['error_message_digest'])).toMatch(/^hmac-sha256:/)
    expect(mapping?.attributes?.['error_message_length']).toBe('upstream 401 for key sk-live-SUPERSECRET'.length)
  })

  it('groups repeat failures by digesting the same message identically', () => {
    const grade = (message: string): unknown => mapEvent(SESSION, event('turn/end', {
      turn: 1, reason: { kind: 'error', error: { code: 'E', message } },
    }), new SessionState(), config)?.attributes?.['error_message_digest']
    expect(grade('boom')).toBe(grade('boom'))
    expect(grade('boom')).not.toBe(grade('bang'))
  })
})

describe('steps and model calls', () => {
  it('brackets a step', () => {
    const state = new SessionState()
    mapEvent(SESSION, event('step/start', { turn: 1, step: 2 }, 500), state, config)
    const end = mapEvent(SESSION, event('step/end', { turn: 1, step: 2 }, 900), state, config)
    expect(end?.duration).toBe(400)
    expect(end?.correlationUid).toBe(`${SESSION}:1:2`)
  })

  it('maps a completion with its token accounting and no text', () => {
    const mapping = mapEvent(SESSION, event('assistant/message', {
      turn: 1,
      step: 0,
      message: { role: 'assistant', content: [{ type: 'text', text: 'the key is hunter2' }] },
      usage: { inputTokens: 120, outputTokens: 30, reasoningTokens: 8 },
    }), new SessionState(), config)
    expect(mapping?.classUid).toBe(CLASS.apiActivity)
    expect(mapping?.messageContext).toMatchObject({ ai_role_id: 2, prompt_tokens: 120, completion_tokens: 30, total_tokens: 150 })
    expect(mapping?.attributes?.['reasoning_tokens']).toBe(8)
    expect(JSON.stringify(mapping)).not.toContain('hunter2')
    expect(String(mapping?.attributes?.['text_digest'])).toMatch(/^hmac-sha256:/)
  })

  it('maps a user-role message by source without its text', () => {
    const mapping = mapEvent(SESSION, event('user/message', {
      content: [{ type: 'text', text: 'delete production' }],
      source: { kind: 'user' },
    }), new SessionState(), config)
    expect(mapping?.messageContext?.ai_role_id).toBe(1)
    expect(mapping?.attributes?.['message_source']).toBe('user')
    expect(mapping?.attributes?.['text_length']).toBe('delete production'.length)
    expect(JSON.stringify(mapping)).not.toContain('delete production')
  })

  it('folds the model route so later records report the model', () => {
    const state = new SessionState()
    mapEvent(SESSION, event('request/context', { provider: 'deepseek', model: 'deepseek-chat', contextWindow: 128_000 }), state, config)
    expect(state.aiModel).toEqual({ name: 'deepseek-chat', ai_provider: 'deepseek' })
  })

  it('records the capability set without the prompt or the schemas', () => {
    const mapping = mapEvent(SESSION, event('request/header', {
      reason: 'initial',
      header: {
        config: { model: 'deepseek-chat' },
        system: 'you are a coding agent with SECRET instructions',
        tools: [{ name: 'bash', parameters: { properties: { command: {} } } }, { name: 'read' }],
      },
    }), new SessionState(), config)
    expect(mapping?.classUid).toBe(CLASS.applicationLifecycle)
    expect(mapping?.attributes?.['tools']).toEqual(['bash', 'read'])
    expect(mapping?.attributes?.['tool_count']).toBe(2)
    expect(JSON.stringify(mapping)).not.toContain('SECRET')
    expect(JSON.stringify(mapping)).not.toContain('properties')
  })
})

describe('hooks, subagents, workflows, compaction, schedules', () => {
  it('maps a hook invocation onto Process Activity and pairs its result', () => {
    const invoked = mapEvent(SESSION, event('hook/invoked', { turn: 1, point: 'PreToolUse', dialect: 'claude', handlerId: 'h1' }), new SessionState(), config)
    expect(invoked?.classUid).toBe(CLASS.processActivity)
    expect(invoked?.correlationUid).toBe(`${SESSION}:hook:h1`)

    const result = mapEvent(SESSION, event('hook/result', { turn: 1, point: 'PreToolUse', handlerId: 'h1', decision: 'deny', exitCode: 2, durationMs: 40 }), new SessionState(), config)
    expect(result?.activityId).toBe(ACTIVITY.process.terminate)
    expect(result?.statusId).toBe(STATUS.failure)
    expect(result?.duration).toBe(40)
    expect(result?.process?.exit_code).toBe(2)
  })

  it('reduces a hook decision to the protocol vocabulary', () => {
    const decide = (decision: string): Record<string, unknown> | undefined =>
      mapEvent(SESSION, event('hook/result', { turn: 1, point: 'PreToolUse', handlerId: 'h1', decision, exitCode: 0 }), new SessionState(), config)
        ?.attributes as Record<string, unknown> | undefined
    expect(decide('deny')?.['decision']).toBe('deny')
    expect(decide('allow')?.['decision']).toBe('allow')
    expect(decide('ask')?.['decision']).toBe('ask')
  })

  it('never copies a hook-authored finding out of the decision field', () => {
    const mapping = mapEvent(SESSION, event('hook/result', {
      turn: 1, point: 'PreToolUse', handlerId: 'h1',
      decision: 'deny: token ghp_AAAABBBBCCCC found in staged diff', exitCode: 2, durationMs: 12,
    }), new SessionState(), config)
    expect(JSON.stringify(mapping)).not.toContain('ghp_AAAABBBBCCCC')
    expect(mapping?.attributes?.['decision']).toBe('other')
    expect(mapping?.statusDetail).toBe('other')
    expect(String(mapping?.attributes?.['decision_digest'])).toMatch(/^hmac-sha256:/)
    expect(mapping?.statusId).toBe(STATUS.failure)
  })

  it('describes the child agent this session is, without inventing a child id', () => {
    const mapping = mapEvent(SESSION, event('subagent/descriptor', {
      version: 2, mode: 'continuable', provider: 'task', label: 'audit the repo',
    }, 7_000), new SessionState(), config)
    expect(mapping?.delegation).toBeUndefined()
    expect(mapping?.attributes?.['subagent_mode']).toBe('continuable')
    expect(mapping?.attributes?.['subagent_provider']).toBe('task')
    expect(mapping?.attributes?.['descriptor_version']).toBe(2)
    expect(JSON.stringify(mapping)).not.toContain('audit the repo')
  })

  it('maps workflow brackets onto application lifecycle', () => {
    const start = mapEvent(SESSION, event('tool-workflow/run-start', { runId: 'r1', name: 'review' }), new SessionState(), config)
    expect(start?.activityId).toBe(ACTIVITY.applicationLifecycle.start)
    const end = mapEvent(SESSION, event('tool-workflow/run-end', { runId: 'r1', stopReason: 'completed' }), new SessionState(), config)
    expect(end?.activityId).toBe(ACTIVITY.applicationLifecycle.stop)
    expect(end?.statusId).toBe(STATUS.success)
  })

  it('grades an aborted workflow run a failure, reading the reason the harness emits', () => {
    const end = mapEvent(SESSION, event('tool-workflow/run-end', { runId: 'wf1', stopReason: 'aborted' }), new SessionState(), config)
    expect(end?.statusId).toBe(STATUS.failure)
    expect(end?.statusDetail).toBe('aborted')

    const member = mapEvent(SESSION, event('tool-workflow/agent-end', { runId: 'wf1', seq: 0, outcome: 'failed' }), new SessionState(), config)
    expect(member?.statusId).toBe(STATUS.failure)
    expect(member?.attributes?.['member_seq']).toBe(0)
  })

  it('links a workflow member to its published child session', () => {
    const mapping = mapEvent(SESSION, event('tool-workflow/agent-start', {
      runId: 'wf1', seq: 0, label: 'reviewer', childId: 'CHILD1',
    }, 7_000), new SessionState(), config)
    expect(mapping?.delegation).toEqual({ uid: 'CHILD1', parent_uid: SESSION, created_time: 7_000 })
    expect(mapping?.attributes?.['child_session_id']).toBe('CHILD1')
  })

  it('records a prune as history deletion, identified by the range it replaced', () => {
    const mapping = mapEvent(SESSION, event('compaction/prune', {
      shadowedRange: { start: 4, end: 9 }, shadowedSeqs: [4, 5, 6], shadowedTokenCount: 900,
    }), new SessionState(), config)
    expect(mapping?.activityId).toBe(ACTIVITY.api.delete)
    expect(mapping?.attributes?.['shadowed_tokens']).toBe(900)
    expect(mapping?.attributes?.['shadowed_count']).toBe(3)
    expect(mapping?.attributes?.['shadowed_start']).toBe(4)
    expect(mapping?.attributes?.['compaction_id']).toBeUndefined()
    expect(mapping?.correlationUid).toBe(`${SESSION}:compaction:range:4-9`)
  })

  it('digests a compaction summary instead of carrying it', () => {
    const mapping = mapEvent(SESSION, event('compaction/summary', {
      compactionId: 'c1', summary: [{ type: 'text', text: 'the user pasted an API key' }],
    }), new SessionState(), config)
    expect(JSON.stringify(mapping)).not.toContain('API key')
    expect(mapping?.attributes?.['summary_digest']).toBeDefined()
  })

  it('reports a failed compaction', () => {
    const mapping = mapEvent(SESSION, event('compaction/end', { compactionId: 'c1', turn: 1, error: 'model refused' }), new SessionState(), config)
    expect(mapping?.statusId).toBe(STATUS.failure)
    expect(mapping?.statusDetail).toBe('model refused')
  })

  it('maps a schedule change onto Scheduled Job Activity, reading the durable payload', () => {
    const created = mapEvent(SESSION, event('schedule/change', {
      version: 1, operation: 'create', schedule: { id: 'sch_1', kind: 'every', prompt: 'nightly deploy' },
    }), new SessionState(), config)
    expect(created?.classUid).toBe(CLASS.scheduledJobActivity)
    expect(created?.activityId).toBe(ACTIVITY.scheduledJob.create)
    expect(created?.job).toEqual({ name: 'sch_1', uid: 'sch_1' })
    expect(created?.attributes?.['operation']).toBe('create')
    expect(JSON.stringify(created)).not.toContain('nightly deploy')

    const deleted = mapEvent(SESSION, event('schedule/change', { version: 1, operation: 'delete', id: 'sch_1' }), new SessionState(), config)
    expect(deleted?.activityId).toBe(ACTIVITY.scheduledJob.delete)

    const dispatched = mapEvent(SESSION, event('schedule/change', {
      version: 1, operation: 'dispatch', id: 'sch_1', acceptedAt: '2026-01-01',
    }), new SessionState(), config)
    expect(dispatched?.activityId).toBe(ACTIVITY.scheduledJob.update)

    const unknown = mapEvent(SESSION, event('schedule/change', { version: 1, operation: 'merged-later' }), new SessionState(), config)
    expect(unknown?.activityId).toBe(ACTIVITY.scheduledJob.other)
  })
})

describe('the generic fallback', () => {
  it('forwards an event type this build does not know as metadata', () => {
    const mapping = mapEvent(SESSION, event('acme/quarantine', { turn: 2, step: 1, secret: 'value' }), new SessionState(), config)
    expect(mapping?.classUid).toBe(CLASS.apiActivity)
    expect(mapping?.activityId).toBe(ACTIVITY.api.other)
    expect(mapping?.api?.operation).toBe('acme/quarantine')
    expect(mapping?.attributes?.['turn']).toBe(2)
    expect(JSON.stringify(mapping)).not.toContain('value')
  })

  it('announces an adopted session whose seed this process never saw', () => {
    const mapping = mapSeedBoundary(SESSION, 42, 'parent-1')
    expect(mapping.classUid).toBe(CLASS.applicationLifecycle)
    expect(mapping.attributes?.['seed_events']).toBe(42)
    expect(mapping.attributes?.['forked_from']).toBe('parent-1')
  })
})
