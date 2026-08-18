/** Turn, step, model, and lifecycle mapping, including the outcome grading of every turn end reason. */
import { describe, expect, it } from 'vitest'
import { SessionState } from '../../src/correlate.ts'
import { mapEvent } from '../../src/map/index.ts'
import { mapSeedBoundary, mapWorkflow } from '../../src/map/lifecycle.ts'
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
    expect(result?.exitCode).toBe(2)
    expect(result?.process?.uid).toBe(`${SESSION}:hook:h1`)
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

  it('names the model that wrote a summary, which the compaction backend chose', () => {
    const named = mapEvent(SESSION, event('compaction/summary', {
      compactionId: 'c1', summary: [], provider: 'deepseek', model: 'deepseek-chat-lite',
    }), new SessionState(), config)
    expect(named?.aiModel).toEqual({ name: 'deepseek-chat-lite', ai_provider: 'deepseek' })

    // A summary that named only half the route claims neither: an `ai_model`
    // missing `name` or `ai_provider` is one the object's schema rejects.
    const half = mapEvent(SESSION, event('compaction/summary', {
      compactionId: 'c1', summary: [], provider: 'deepseek',
    }), new SessionState(), config)
    expect(half?.aiModel).toBeUndefined()

    // Only the summarizing event reports a model; the lock events have none.
    expect(mapEvent(SESSION, event('compaction/start', { compactionId: 'c1', model: 'x', provider: 'y' }), new SessionState(), config)?.aiModel)
      .toBeUndefined()
  })

  it('times how long a compaction held the lock, and reports none when it never saw the start', () => {
    const state = new SessionState()
    mapEvent(SESSION, event('compaction/start', { compactionId: 'c1', turn: 1 }, 2_000), state, config)
    const end = mapEvent(SESSION, event('compaction/end', { compactionId: 'c1', turn: 1 }, 2_900), state, config)
    expect(end?.startTime).toBe(2_000)
    expect(end?.duration).toBe(900)

    // A second end for the same id has nothing left to close.
    expect(mapEvent(SESSION, event('compaction/end', { compactionId: 'c1' }, 3_000), state, config)?.duration).toBeUndefined()
    // A resumed log can carry an end whose start this process never observed.
    expect(mapEvent(SESSION, event('compaction/end', { compactionId: 'other' }, 3_000), new SessionState(), config)?.duration)
      .toBeUndefined()
    // `compaction/prune` carries no id and opens nothing.
    expect(mapEvent(SESSION, event('compaction/prune', { shadowedRange: { start: 1, end: 2 } }, 4_000), state, config)?.duration)
      .toBeUndefined()
  })

  it('reports a failed compaction without copying the rendered failure into the record', () => {
    const mapping = mapEvent(SESSION, event('compaction/end', { compactionId: 'c1', turn: 1, error: 'model refused: found sk-live-1' }), new SessionState(), config)
    expect(mapping?.statusId).toBe(STATUS.failure)
    expect(mapping?.statusDetail).toBe('error')
    expect(JSON.stringify(mapping)).not.toContain('sk-live-1')
    expect(mapping?.attributes?.['error_digest']).toBeDefined()
    expect(mapping?.attributes?.['error_length']).toBe(30)
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

describe('optional attributes', () => {
  /** One mapping's extension attributes, which is where the optional fields land. */
  function attributes(type: string, data: unknown, state = new SessionState()): Readonly<Record<string, unknown>> {
    return mapEvent(SESSION, event(type, data), state, config)?.attributes ?? {}
  }

  it('omits a turn bracket a start was never seen for, and its cancel and failure fields', () => {
    const orphan = mapEvent(SESSION, event('turn/end', { turn: 9, reason: { kind: 'completed' } }), new SessionState(), config)
    expect(orphan?.startTime).toBeUndefined()
    expect(orphan?.duration).toBeUndefined()
    expect(orphan?.attributes?.['cancel_cause']).toBeUndefined()
    expect(orphan?.attributes?.['error_code']).toBeUndefined()
    expect(orphan?.attributes?.['error_message_digest']).toBeUndefined()
  })

  it('omits a step bracket a start was never seen for', () => {
    const orphan = mapEvent(SESSION, event('step/end', { turn: 1, step: 4 }), new SessionState(), config)
    expect(orphan?.startTime).toBeUndefined()
    expect(orphan?.duration).toBeUndefined()
  })

  it('reports only the token counts the usage block actually carried', () => {
    const none = mapEvent(SESSION, event('assistant/message', { turn: 1, step: 0 }), new SessionState(), config)
    expect(none?.messageContext).toEqual({ ai_role_id: 2 })
    expect(none?.attributes?.['reasoning_tokens']).toBeUndefined()

    const inputOnly = mapEvent(
      SESSION,
      event('assistant/message', { turn: 1, step: 0, usage: { inputTokens: 12 } }),
      new SessionState(),
      config,
    )
    expect(inputOnly?.messageContext).toEqual({ ai_role_id: 2, prompt_tokens: 12 })

    const reasoning = attributes('assistant/message', { turn: 1, step: 0, usage: { reasoningTokens: 7 } })
    expect(reasoning['reasoning_tokens']).toBe(7)
  })

  it('reads a message whose content is missing or holds no text blocks', () => {
    const noContent = attributes('user/message', { source: { kind: 'human' } })
    expect(noContent['text_length']).toBe(0)
    const noText = attributes('user/message', { source: { kind: 'human' }, content: [{ type: 'image' }] })
    expect(noText['text_length']).toBe(0)
  })

  it('reports a context window only when the route named one', () => {
    expect(attributes('request/context', { provider: 'p', model: 'm' })['context_window']).toBeUndefined()
    expect(attributes('request/context', { provider: 'p', model: 'm', contextWindow: 128_000 })['context_window'])
      .toBe(128_000)
  })

  it('reports an empty capability set for a header with no tools, and no digest with no prompt', () => {
    const bare = attributes('request/header', { reason: 'initial', header: {} })
    expect(bare['tool_count']).toBe(0)
    expect(bare['tools']).toEqual([])
    expect(bare['system_prompt_digest']).toBeUndefined()
    expect(bare['model']).toBeUndefined()

    const named = attributes('request/header', { header: { tools: [{}], config: { model: 'deepseek-chat' } } })
    expect(named['tools']).toEqual(['unknown'])
    expect(named['model']).toBe('deepseek-chat')
    expect(named['reason']).toBe('unknown')
  })

  it('reports a hook matcher, exit code and duration only when the payload carried them', () => {
    expect(attributes('hook/invoked', { point: 'PreToolUse', handlerId: 'h1' })['matcher']).toBeUndefined()
    expect(attributes('hook/invoked', { point: 'PreToolUse', handlerId: 'h1', matcher: 'Bash' })['matcher']).toBe('Bash')

    const bare = mapEvent(SESSION, event('hook/result', { point: 'PreToolUse', handlerId: 'h1', decision: 'allow' }), new SessionState(), config)
    expect(bare?.exitCode).toBeUndefined()
    expect(bare?.duration).toBeUndefined()

    const timed = mapEvent(
      SESSION,
      event('hook/result', { point: 'PreToolUse', handlerId: 'h1', decision: 'allow', exitCode: 0, durationMs: 12 }),
      new SessionState(),
      config,
    )
    expect(timed?.exitCode).toBe(0)
    expect(timed?.duration).toBe(12)
  })

  it('reports a descriptor version only when the descriptor carried one', () => {
    expect(attributes('subagent/descriptor', { mode: 'one-shot' })['descriptor_version']).toBeUndefined()
    expect(attributes('subagent/descriptor', { mode: 'one-shot', version: 2 })['descriptor_version']).toBe(2)
  })

  it('omits a workflow member seq, child id and name when the event names none', () => {
    const bare = mapEvent(SESSION, event('tool-workflow/run-start', { runId: 'w1' }), new SessionState(), config)
    expect(bare?.statusDetail).toBeUndefined()
    expect(bare?.delegation).toBeUndefined()
    expect(bare?.attributes?.['member_seq']).toBeUndefined()
    expect(bare?.attributes?.['child_session_id']).toBeUndefined()
    expect(bare?.attributes?.['name']).toBeUndefined()

    const full = attributes('tool-workflow/agent-end', { runId: 'w1', outcome: 'completed', seq: 2, name: 'reviewer' })
    expect(full['member_seq']).toBe(2)
    expect(full['name']).toBe('reviewer')
  })

  it('takes the lifecycle activity of a workflow event type it does not recognise', () => {
    const mapping = mapEvent(SESSION, event('tool-workflow/run-start', { runId: 'w1' }), new SessionState(), config)
    expect(mapping?.activityId).toBe(ACTIVITY.applicationLifecycle.start)
  })

  it('omits every compaction field the event did not carry, and correlates on nothing it cannot key', () => {
    const bare = mapEvent(SESSION, event('compaction/start', {}), new SessionState(), config)
    expect(bare?.correlationUid).toBeUndefined()
    expect(bare?.statusDetail).toBeUndefined()
    expect(bare?.attributes?.['compaction_id']).toBeUndefined()
    expect(bare?.attributes?.['shadowed_tokens']).toBeUndefined()
    expect(bare?.attributes?.['shadowed_count']).toBeUndefined()
    expect(bare?.attributes?.['shadowed_start']).toBeUndefined()
    expect(bare?.attributes?.['summary_digest']).toBeUndefined()

    const keyed = mapEvent(SESSION, event('compaction/end', { compactionId: 'k1' }), new SessionState(), config)
    expect(keyed?.correlationUid).toBe(`${SESSION}:compaction:k1`)

    const ranged = mapEvent(SESSION, event('compaction/prune', { shadowedRange: {} }), new SessionState(), config)
    expect(ranged?.correlationUid).toBe(`${SESSION}:compaction:range:0-0`)
    expect(ranged?.attributes?.['shadowed_start']).toBe(0)
  })

  it('reads a schedule id from the bare payload when there is no schedule record, and grades an unknown operation', () => {
    const dispatched = mapEvent(SESSION, event('schedule/change', { operation: 'dispatch', id: 's2' }), new SessionState(), config)
    expect(dispatched?.activityId).toBe(ACTIVITY.scheduledJob.update)
    expect(dispatched?.job).toEqual({ name: 's2', uid: 's2' })

    const unknown = mapEvent(SESSION, event('schedule/change', {}), new SessionState(), config)
    expect(unknown?.activityId).toBe(ACTIVITY.scheduledJob.other)
    expect(unknown?.job).toEqual({ name: 'unknown', uid: 'unknown' })
  })

  it('omits the turn and step of an unknown event that names neither', () => {
    const bare = attributes('someone-elses-plugin/event', {})
    expect(bare['turn']).toBeUndefined()
    expect(bare['step']).toBeUndefined()
  })

  it('names no fork on a seed boundary for a session that was not forked', () => {
    expect(mapSeedBoundary(SESSION, 4, undefined).attributes?.['forked_from']).toBeUndefined()
    expect(mapSeedBoundary(SESSION, 4, 'parent-1').attributes?.['forked_from']).toBe('parent-1')
  })
})

describe('payloads missing the fields a mapper reads', () => {
  /**
   * Every lifecycle event type, with an empty payload. None of these are
   * droppable: an event whose payload a future build reshapes must still
   * produce a record, with the documented default rather than a guess.
   */
  const bare: readonly [string, Record<string, unknown>][] = [
    ['turn/start', { turn: 0, phase: 'start' }],
    ['turn/end', { turn: 0, end_reason: 'unknown' }],
    ['step/start', { turn: 0, step: 0 }],
    ['step/end', { turn: 0, step: 0 }],
    ['assistant/message', { turn: 0, step: 0, text_length: 0 }],
    ['user/message', { message_source: 'unknown', text_length: 0 }],
    ['request/context', { provider: 'unknown', model: 'unknown' }],
    ['request/header', { reason: 'unknown', tool_count: 0 }],
    ['hook/invoked', { hook_point: 'unknown', handler_id: 'unknown', dialect: 'unknown', turn: 0 }],
    ['hook/result', { hook_point: 'unknown', handler_id: 'unknown', decision: 'unknown', turn: 0 }],
    ['subagent/descriptor', { subagent_mode: 'unknown', subagent_provider: 'unknown' }],
    ['tool-workflow/run-end', { run_id: 'unknown' }],
    ['schedule/change', { schedule_id: 'unknown', operation: 'unknown' }],
    ['compaction/prune', { event: 'compaction/prune' }],
  ]

  it.each(bare)('records %s with its documented defaults', (type, expected) => {
    const mapping = mapEvent(SESSION, event(type, {}), new SessionState(), config)
    expect(mapping).toBeDefined()
    expect(mapping?.attributes).toMatchObject(expected)
  })

  it('grades an unpaired turn end and an empty turn payload without inventing a duration', () => {
    const mapping = mapEvent(SESSION, event('turn/end', {}), new SessionState(), config)
    expect(mapping?.statusId).toBe(STATUS.unknown)
    expect(mapping?.severityId).toBe(SEVERITY.informational)
    expect(mapping?.correlationUid).toBe(`${SESSION}:turn:0`)
  })

  it('gives a workflow event type it does not know the update activity', () => {
    // `mapEvent` routes only the four shipped types here; this is the
    // merge-extensible fallthrough a plugin-added workflow event would take.
    expect(mapWorkflow('tool-workflow/step-retried', SESSION, { time: 1, data: { runId: 'w1' } }).activityId)
      .toBe(ACTIVITY.applicationLifecycle.update)
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
