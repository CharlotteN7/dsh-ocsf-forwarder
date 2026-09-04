/**
 * The two events that decide which model endpoint a session and its children
 * talk to: `model/selection` and `subagent/model-selection-policy`.
 *
 * `request/context` records the route a request actually used. These two are
 * earlier and different: one is a validated selection committed for the next
 * request, the other is the enumerated set of provider/model routes this
 * session is permitted to hand to a child agent. Both are decisions about where
 * conversation content is sent, and both used to reach the SOC lane as the
 * generic fallback — API Activity 99 Other, with no provider and no model.
 */
import { describe, expect, it } from 'vitest'
import { SessionState } from '../../src/correlate.ts'
import { mapEvent } from '../../src/map/index.ts'
import { ACTIVITY, CLASS, SEVERITY, STATUS } from '../../src/ocsf/constants.ts'
import { testConfig } from './support.ts'

const SESSION = 'session-1'
const config = testConfig()

/** One event of the given type. */
function event(type: string, data: unknown): { type: string; seq: number; time: number; data: unknown } {
  return { type, seq: 4, time: 5_000, data }
}

describe('model/selection', () => {
  it('names the provider and model the next request will use', () => {
    const mapping = mapEvent(
      SESSION,
      event('model/selection', { provider: 'deepseek-official', model: 'deepseek-reasoner' }),
      new SessionState(),
      config,
    )
    expect(mapping?.classUid).toBe(CLASS.applicationLifecycle)
    expect(mapping?.activityId).toBe(ACTIVITY.applicationLifecycle.update)
    expect(mapping?.statusId).toBe(STATUS.success)
    expect(mapping?.severityId).toBe(SEVERITY.low)
    expect(mapping?.aiModel).toEqual({ name: 'deepseek-reasoner', ai_provider: 'deepseek-official' })
    expect(mapping?.attributes?.['provider']).toBe('deepseek-official')
    expect(mapping?.attributes?.['model']).toBe('deepseek-reasoner')
    expect(mapping?.attributes?.['phase']).toBe('selected')
  })

  it('carries the reasoning effort when the selection pinned one', () => {
    const mapping = mapEvent(
      SESSION,
      event('model/selection', { provider: 'deepseek-official', model: 'deepseek-reasoner', reasoningEffort: 'high' }),
      new SessionState(),
      config,
    )
    expect(mapping?.attributes?.['reasoning_effort']).toBe('high')
  })

  it('does not move the session route, which only a recorded request does', () => {
    const state = new SessionState()
    mapEvent(SESSION, event('request/context', { provider: 'deepseek-official', model: 'deepseek-chat' }), state, config)
    const selection = mapEvent(SESSION, event('model/selection', { provider: 'other-vendor', model: 'gpt-x' }), state, config)
    // The record names the route that was selected...
    expect(selection?.aiModel).toEqual({ name: 'gpt-x', ai_provider: 'other-vendor' })
    // ...and the session route stays on the model that has actually served a
    // request. A selection is what the NEXT request should use; folding it in
    // here would attribute every record between this event and the next
    // `request/context` to a model that has served nothing.
    expect(state.aiModel).toEqual({ name: 'deepseek-chat', ai_provider: 'deepseek-official' })
  })

  it('reports a selection missing either half of the route as unreadable', () => {
    const state = new SessionState()
    expect(mapEvent(SESSION, event('model/selection', { provider: 'deepseek-official' }), state, config)).toBeUndefined()
    expect(mapEvent(SESSION, event('model/selection', { model: 'deepseek-chat' }), state, config)).toBeUndefined()
  })
})

describe('subagent/model-selection-policy', () => {
  it('records the authorized child routes as the privileges they are', () => {
    const mapping = mapEvent(
      SESSION,
      event('subagent/model-selection-policy', {
        allowedModels: [
          { provider: 'deepseek-official', model: 'deepseek-chat' },
          { provider: 'deepseek-official', model: 'deepseek-reasoner' },
        ],
      }),
      new SessionState(),
      config,
    )
    expect(mapping?.classUid).toBe(CLASS.authorizeSession)
    expect(mapping?.activityId).toBe(ACTIVITY.authorizeSession.assignPrivileges)
    expect(mapping?.statusId).toBe(STATUS.success)
    // Same grade as every other setting later decisions are judged against.
    expect(mapping?.severityId).toBe(SEVERITY.medium)
    expect(mapping?.privileges).toEqual([
      'subagent-model:deepseek-official/deepseek-chat',
      'subagent-model:deepseek-official/deepseek-reasoner',
    ])
    expect(mapping?.attributes?.['setting']).toBe('subagent/model-selection-policy')
    expect(mapping?.attributes?.['allowed_model_count']).toBe(2)
  })

  it('refuses a record with no privilege on it, which Authorize Session forbids', () => {
    // OCSF 1.9.0 constrains the class `at_least_one: [privileges, groups,
    // iam_roles]`, and this plugin emits none of the other two. A policy that
    // authorizes nothing is reported unreadable rather than as an empty grant.
    const state = new SessionState()
    expect(mapEvent(SESSION, event('subagent/model-selection-policy', { allowedModels: [] }), state, config)).toBeUndefined()
    expect(mapEvent(SESSION, event('subagent/model-selection-policy', {}), state, config)).toBeUndefined()
    expect(mapEvent(SESSION, event('subagent/model-selection-policy', { allowedModels: [{ provider: 'p' }] }), state, config))
      .toBeUndefined()
  })
})
