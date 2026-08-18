/**
 * The interaction events: slash commands, plan and goal state, the agent
 * inbox, model-request retries, the agent preset, and the auxiliary search
 * request.
 *
 * Every one of these took the generic fallback before — API Activity 6003 /
 * activity `99 Other`, `unmapped.dsh.event` and nothing else — so each test
 * here asserts the field the fallback dropped, not only the class.
 */
import { describe, expect, it } from 'vitest'
import { SessionState } from '../../src/correlate.ts'
import { mapEvent } from '../../src/map/index.ts'
import { ACTIVITY, AI_ROLE, CLASS, SEVERITY, STATUS } from '../../src/ocsf/constants.ts'
import type { EventMapping } from '../../src/ocsf/record.ts'
import type { JsonValue } from '../../src/ocsf/types.ts'
import { digest } from '../../src/privacy.ts'
import { testConfig } from './support.ts'

const SESSION = 'session-1'
const config = testConfig()

function event(type: string, data: unknown, time = 1_000): { type: string; seq: number; time: number; data: unknown } {
  return { type, seq: 1, time, data }
}

function map(
  type: string,
  data: unknown,
  state: SessionState = new SessionState(),
  time = 1_000,
): EventMapping | undefined {
  return mapEvent(SESSION, event(type, data, time), state, config)
}

function attributes(mapping: EventMapping | undefined): Readonly<Record<string, JsonValue>> {
  return mapping?.attributes ?? {}
}

describe('agent/inbox/spliced', () => {
  it('counts what was inserted and removed, and digests what the messages said', () => {
    const mapping = map('agent/inbox/spliced', {
      target: 'next-turn',
      start: 2,
      removedCount: 1,
      inserted: [
        { content: [{ type: 'text', text: 'stop and ' }] },
        { content: [{ type: 'text', text: 'do this instead' }] },
      ],
    })
    expect(mapping?.classUid).toBe(CLASS.apiActivity)
    expect(mapping?.activityId).toBe(ACTIVITY.api.update)
    expect(mapping?.api?.operation).toBe('agent/inbox/spliced')
    const carried = attributes(mapping)
    expect(carried['inbox_target']).toBe('next-turn')
    expect(carried['splice_start']).toBe(2)
    expect(carried['removed_count']).toBe(1)
    expect(carried['inserted_count']).toBe(2)
    expect(carried['inserted_digest']).toBe(digest(config.hmacKey, 'stop and do this instead'))
    expect(carried['inserted_length']).toBe(24)
    expect(carried['splice_outcome']).toBeUndefined()
  })

  it('reads a cancellation and an empty splice without inventing counts', () => {
    const carried = attributes(map('agent/inbox/spliced', { outcome: 'canceled' }))
    expect(carried['inbox_target']).toBe('unknown')
    expect(carried['splice_start']).toBe(0)
    expect(carried['removed_count']).toBe(0)
    expect(carried['inserted_count']).toBe(0)
    expect(carried['inserted_length']).toBe(0)
    expect(carried['splice_outcome']).toBe('canceled')
  })
})

describe('agent-preset/selected', () => {
  it('records the composition later turns run under as a lifecycle update', () => {
    const mapping = map('agent-preset/selected', { agentPreset: 'reviewer' })
    expect(mapping?.classUid).toBe(CLASS.applicationLifecycle)
    expect(mapping?.activityId).toBe(ACTIVITY.applicationLifecycle.update)
    expect(mapping?.message).toBe('agent preset reviewer selected')
    expect(attributes(mapping)['agent_preset']).toBe('reviewer')
  })

  it('names the preset unknown rather than dropping the record', () => {
    expect(attributes(map('agent-preset/selected', {}))['agent_preset']).toBe('unknown')
  })
})

describe('a slash command', () => {
  it('names the command, digests what was typed after it, and times the pair', () => {
    const state = new SessionState()
    const run = map('command/run', { commandId: 'k1', name: 'compact', args: ' --hard now', source: 'user' }, state, 5_000)
    expect(run?.classUid).toBe(CLASS.apiActivity)
    expect(run?.activityId).toBe(ACTIVITY.api.create)
    expect(run?.statusId).toBe(STATUS.unknown)
    expect(run?.api?.operation).toBe('command:compact')
    expect(run?.correlationUid).toBe(`${SESSION}:command:k1`)
    expect(attributes(run)['command_source']).toBe('user')
    expect(attributes(run)['args_digest']).toBe(digest(config.hmacKey, ' --hard now'))
    expect(attributes(run)['args_length']).toBe(11)

    const done = map('command/done', { commandId: 'k1', kind: 'success', sourceEventSeq: 9 }, state, 5_250)
    expect(done?.activityId).toBe(ACTIVITY.api.update)
    expect(done?.statusId).toBe(STATUS.success)
    expect(done?.statusDetail).toBe('success')
    expect(done?.correlationUid).toBe(`${SESSION}:command:k1`)
    expect(done?.startTime).toBe(5_000)
    expect(done?.duration).toBe(250)
    expect(done?.api?.operation).toBe('command:compact')
    expect(attributes(done)['command']).toBe('compact')
    expect(attributes(done)['source_event_seq']).toBe(9)
    expect(attributes(done)['unpaired']).toBeUndefined()
  })

  it('grades a failed command as one, and digests the rendered failure', () => {
    const state = new SessionState()
    map('command/run', { commandId: 'k2', name: 'diff' }, state, 1_000)
    const done = map('command/done', { commandId: 'k2', kind: 'error', text: 'ENOENT: /srv/secret.env' }, state, 1_010)
    expect(done?.statusId).toBe(STATUS.failure)
    expect(done?.severityId).toBe(SEVERITY.low)
    expect(attributes(done)['outcome_digest']).toBe(digest(config.hmacKey, 'ENOENT: /srv/secret.env'))
    expect(attributes(done)['outcome_length']).toBe(23)
  })

  it('reports a settlement whose start this process never saw, without a duration', () => {
    const done = map('command/done', { commandId: 'orphan', kind: 'success' })
    expect(done?.duration).toBeUndefined()
    expect(done?.startTime).toBeUndefined()
    expect(done?.api?.operation).toBe('command:unknown')
    expect(attributes(done)['unpaired']).toBe(true)
  })

  it('reads a command that recorded no input and no id', () => {
    const run = map('command/run', {})
    expect(run?.api?.operation).toBe('command:unknown')
    expect(attributes(run)['command_id']).toBe('unknown')
    expect(attributes(run)['command_source']).toBe('unknown')
    expect(attributes(run)['args_digest']).toBeUndefined()

    const done = map('command/done', {})
    expect(attributes(done)['kind']).toBe('unknown')
    expect(attributes(done)['outcome_digest']).toBeUndefined()
    expect(attributes(done)['source_event_seq']).toBeUndefined()
  })

  it('does not let two sessions share a command id', () => {
    const first = new SessionState()
    const second = new SessionState()
    mapEvent('session-a', event('command/run', { commandId: 'k1', name: 'compact' }), first, config)
    const done = mapEvent('session-b', event('command/done', { commandId: 'k1', kind: 'success' }), second, config)
    expect(attributes(done)['unpaired']).toBe(true)
  })
})

describe('goal/change', () => {
  it('carries the mutation and the goal identity, and digests the objective', () => {
    const mapping = map('goal/change', {
      kind: 'goal/change',
      version: 1,
      operation: 'create',
      goal: { id: 'g1', revision: 1, objective: 'ship the audit lane', phase: 'active', maxGoalRounds: 8 },
      roundsStarted: 0,
    })
    expect(mapping?.classUid).toBe(CLASS.apiActivity)
    expect(mapping?.activityId).toBe(ACTIVITY.api.update)
    expect(mapping?.api?.operation).toBe('goal:create')
    const carried = attributes(mapping)
    expect(carried['goal_id']).toBe('g1')
    expect(carried['goal_revision']).toBe(1)
    expect(carried['goal_phase']).toBe('active')
    expect(carried['objective_digest']).toBe(digest(config.hmacKey, 'ship the audit lane'))
    expect(carried['objective_length']).toBe(19)
    expect(carried['rounds_started']).toBe(0)
    expect(carried['goal_blocked_code']).toBeUndefined()
  })

  it('reads a block reason code, which the blocking policy chose from a bounded set', () => {
    const carried = attributes(map('goal/change', {
      operation: 'block',
      goal: { id: 'g1', revision: 4, objective: 'x', phase: 'blocked', blockedReason: { code: 'awaiting-approval', message: 'needs a human' } },
    }))
    expect(carried['goal_blocked_code']).toBe('awaiting-approval')
    expect(carried['goal_phase']).toBe('blocked')
  })

  it('reads the tombstone a clear leaves, which names the goal but carries no snapshot', () => {
    const carried = attributes(map('goal/change', { operation: 'clear', cleared: { id: 'g1', revision: 5 }, clearedAt: 9 }))
    expect(carried['goal_operation']).toBe('clear')
    expect(carried['goal_id']).toBe('g1')
    expect(carried['goal_revision']).toBe(5)
    expect(carried['objective_digest']).toBeUndefined()
    expect(carried['goal_phase']).toBeUndefined()
    expect(carried['rounds_started']).toBeUndefined()
  })

  it('reads a payload naming no goal at all', () => {
    const carried = attributes(map('goal/change', {}))
    expect(carried['goal_operation']).toBe('unknown')
    expect(carried['goal_id']).toBe('unknown')
    expect(carried['goal_revision']).toBe(0)
  })
})

describe('a model-request retry', () => {
  it('reports the failure code as the status detail and digests the provider message', () => {
    const mapping = map('llm/retry', {
      retryId: 'r1',
      turn: 2,
      step: 1,
      provider: 'deepseek',
      mode: 'normal',
      policyKey: 'default',
      retry: 1,
      maxRetries: 3,
      delayMs: 500,
      failure: { code: 'ETIMEDOUT', message: 'upstream timed out after 30s', status: 504 },
    })
    expect(mapping?.classUid).toBe(CLASS.apiActivity)
    expect(mapping?.activityId).toBe(ACTIVITY.api.read)
    expect(mapping?.statusId).toBe(STATUS.failure)
    expect(mapping?.severityId).toBe(SEVERITY.low)
    expect(mapping?.statusDetail).toBe('ETIMEDOUT')
    expect(mapping?.correlationUid).toBe(`${SESSION}:retry:r1`)
    const carried = attributes(mapping)
    expect(carried['provider']).toBe('deepseek')
    expect(carried['retry_mode']).toBe('normal')
    expect(carried['policy_key']).toBe('default')
    expect(carried['retry']).toBe(1)
    expect(carried['max_retries']).toBe(3)
    expect(carried['delay_ms']).toBe(500)
    expect(carried['failure_code']).toBe('ETIMEDOUT')
    expect(carried['failure_status']).toBe(504)
    expect(carried['failure_digest']).toBe(digest(config.hmacKey, 'upstream timed out after 30s'))
    expect(carried['failure_length']).toBe(28)
  })

  it('reads an always-retry attempt, which carries no cap and may carry no HTTP status', () => {
    const carried = attributes(map('llm/retry', {
      retryId: 'r2', turn: 1, step: 0, provider: 'deepseek', mode: 'always', policyKey: 'k', retry: 7, delayMs: 100,
      failure: { code: 'ECONNRESET', message: 'socket hang up' },
    }))
    expect(carried['max_retries']).toBeUndefined()
    expect(carried['failure_status']).toBeUndefined()
    expect(carried['retry_mode']).toBe('always')
  })

  it('reads a retry whose payload named no failure', () => {
    const mapping = map('llm/retry', {})
    expect(mapping?.statusDetail).toBe('unknown')
    expect(attributes(mapping)['failure_length']).toBe(0)
    expect(attributes(mapping)['provider']).toBe('unknown')
    expect(attributes(mapping)['retry_id']).toBe('unknown')
  })

  it('pairs the wait completing with the retry that scheduled it', () => {
    const mapping = map('llm/retry-started', { retryId: 'r1', turn: 2, step: 1, retry: 1 })
    expect(mapping?.activityId).toBe(ACTIVITY.api.read)
    expect(mapping?.statusId).toBe(STATUS.unknown)
    expect(mapping?.correlationUid).toBe(`${SESSION}:retry:r1`)
    expect(attributes(mapping)['retry']).toBe(1)
    expect(attributes(mapping)['turn']).toBe(2)
    expect(attributes(mapping)['step']).toBe(1)

    const bare = map('llm/retry-started', {})
    expect(bare?.correlationUid).toBe(`${SESSION}:retry:unknown`)
    expect(attributes(bare)['retry']).toBe(0)
  })
})

describe('plan/mode', () => {
  it('says which way the mode went', () => {
    expect(map('plan/mode', { active: true })?.message).toBe('plan mode on')
    expect(attributes(map('plan/mode', { active: true }))['plan_mode_active']).toBe(true)
    expect(map('plan/mode', { active: false })?.message).toBe('plan mode off')
    expect(attributes(map('plan/mode', {}))['plan_mode_active']).toBe(false)
  })
})

describe('web/deepseek-search-llm-request', () => {
  it('names the search service and the model that saw the query, and digests the query', () => {
    const mapping = map('web/deepseek-search-llm-request', {
      apiVersion: '2024-10-01',
      body: {
        model: 'deepseek-search-1',
        max_tokens: 1024,
        messages: [{ role: 'user', content: [{ type: 'text', text: 'who owns example.test' }] }],
      },
    })
    expect(mapping?.classUid).toBe(CLASS.apiActivity)
    expect(mapping?.activityId).toBe(ACTIVITY.api.read)
    expect(mapping?.api?.service?.name).toBe('deepseek-search')
    expect(mapping?.api?.version).toBe('2024-10-01')
    // Not the session's route: this request went to the search provider's model.
    expect(mapping?.aiModel).toEqual({ name: 'deepseek-search-1', ai_provider: 'deepseek' })
    expect(mapping?.messageContext?.ai_role_id).toBe(AI_ROLE.user)
    const carried = attributes(mapping)
    expect(carried['query_digest']).toBe(digest(config.hmacKey, 'who owns example.test'))
    expect(carried['query_length']).toBe(21)
    expect(carried['max_tokens']).toBe(1024)
  })

  it('reads a request with no body, claiming no model rather than inventing one', () => {
    const mapping = map('web/deepseek-search-llm-request', {})
    expect(mapping?.aiModel).toBeUndefined()
    expect(mapping?.api?.version).toBeUndefined()
    expect(mapping?.api?.service?.name).toBe('deepseek-search')
    expect(attributes(mapping)['query_length']).toBe(0)
    expect(attributes(mapping)['max_tokens']).toBeUndefined()
  })

  it('reads a body whose messages are not a list', () => {
    expect(attributes(map('web/deepseek-search-llm-request', { body: { messages: 'nope' } }))['query_length']).toBe(0)
  })
})
