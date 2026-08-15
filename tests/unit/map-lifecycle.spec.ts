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

  it('maps a subagent descriptor onto the delegation object', () => {
    const mapping = mapEvent(SESSION, event('subagent/descriptor', { sessionId: 'child-1', kind: 'continuable' }, 7_000), new SessionState(), config)
    expect(mapping?.delegation).toEqual({ uid: 'child-1', parent_uid: SESSION, created_time: 7_000 })
  })

  it('maps workflow brackets onto application lifecycle', () => {
    const start = mapEvent(SESSION, event('tool-workflow/run-start', { runId: 'r1', name: 'review' }), new SessionState(), config)
    expect(start?.activityId).toBe(ACTIVITY.applicationLifecycle.start)
    const end = mapEvent(SESSION, event('tool-workflow/run-end', { runId: 'r1', reason: 'aborted' }), new SessionState(), config)
    expect(end?.activityId).toBe(ACTIVITY.applicationLifecycle.stop)
    expect(end?.statusId).toBe(STATUS.failure)
  })

  it('records a prune as history deletion', () => {
    const mapping = mapEvent(SESSION, event('compaction/prune', {
      shadowedRange: { start: 4, end: 9 }, shadowedSeqs: [4, 5, 6], shadowedTokenCount: 900,
    }), new SessionState(), config)
    expect(mapping?.activityId).toBe(ACTIVITY.api.delete)
    expect(mapping?.attributes?.['shadowed_tokens']).toBe(900)
    expect(mapping?.attributes?.['shadowed_count']).toBe(3)
    expect(mapping?.attributes?.['shadowed_start']).toBe(4)
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

  it('maps a schedule change onto Scheduled Job Activity', () => {
    const created = mapEvent(SESSION, event('schedule/change', { kind: 'create', id: 's1' }), new SessionState(), config)
    expect(created?.classUid).toBe(CLASS.scheduledJobActivity)
    expect(created?.activityId).toBe(ACTIVITY.scheduledJob.create)
    expect(created?.job).toEqual({ name: 's1', uid: 's1' })
    const removed = mapEvent(SESSION, event('schedule/change', { kind: 'remove', id: 's1' }), new SessionState(), config)
    expect(removed?.activityId).toBe(ACTIVITY.scheduledJob.delete)
    const changed = mapEvent(SESSION, event('schedule/change', { kind: 'reschedule', id: 's1' }), new SessionState(), config)
    expect(changed?.activityId).toBe(ACTIVITY.scheduledJob.update)
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
