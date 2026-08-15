/** Approval pairing, decision latency, and the authorization-state records. */
import { describe, expect, it } from 'vitest'
import { SessionState } from '../../src/correlate.ts'
import { mapEvent } from '../../src/map/index.ts'
import { mapUnresolvedApproval } from '../../src/map/authorization.ts'
import { CLASS, SEVERITY, STATUS } from '../../src/ocsf/constants.ts'
import { testConfig } from './support.ts'

const SESSION = 'session-1'
const config = testConfig()

function asked(id: string, time: number, extra: Record<string, unknown> = {}): { type: string; seq: number; time: number; data: unknown } {
  return { type: 'approval/asked', seq: 10, time, data: { id, toolName: 'bash', ...extra } }
}

function decided(id: string, outcome: string, time: number): { type: string; seq: number; time: number; data: unknown } {
  return { type: 'approval/decided', seq: 11, time, data: { id, outcome } }
}

describe('approval/asked', () => {
  it('records a pending authorization naming the privilege at stake', () => {
    const mapping = mapEvent(SESSION, asked('a-1', 5_000, { callId: 'call-7', reason: 'escalate sandbox' }), new SessionState(), config)
    expect(mapping?.classUid).toBe(CLASS.authorizeSession)
    expect(mapping?.activityId).toBe(1)
    expect(mapping?.statusId).toBe(STATUS.unknown)
    expect(mapping?.privileges).toEqual(['tool:bash'])
    expect(mapping?.correlationUid).toBe(`${SESSION}:approval:a-1`)
    expect(mapping?.attributes?.['call_id']).toBe('call-7')
    expect(mapping?.attributes?.['reason']).toBe('escalate sandbox')
  })

  it('reports a payload with no request id', () => {
    expect(mapEvent(SESSION, { type: 'approval/asked', seq: 1, time: 1, data: {} }, new SessionState(), config))
      .toBeUndefined()
  })
})

describe('approval/decided', () => {
  it('pairs with its question and emits the decision latency', () => {
    const state = new SessionState()
    mapEvent(SESSION, asked('a-1', 5_000, { callId: 'call-7' }), state, config)
    const mapping = mapEvent(SESSION, decided('a-1', 'allowed-once', 12_500), state, config)
    expect(mapping?.statusId).toBe(STATUS.success)
    expect(mapping?.duration).toBe(7_500)
    expect(mapping?.attributes?.['approval_latency_ms']).toBe(7_500)
    expect(mapping?.attributes?.['asked_seq']).toBe(10)
    expect(mapping?.attributes?.['call_id']).toBe('call-7')
    expect(mapping?.correlationUid).toBe(`${SESSION}:approval:a-1`)
  })

  it('grades every outcome of the closed vocabulary', () => {
    const grade = (outcome: string): { statusId: number | undefined; severityId: number } => {
      const state = new SessionState()
      mapEvent(SESSION, asked('a', 0), state, config)
      const mapping = mapEvent(SESSION, decided('a', outcome, 10), state, config)
      return { statusId: mapping?.statusId, severityId: mapping?.severityId ?? -1 }
    }
    expect(grade('allowed-once').statusId).toBe(STATUS.success)
    expect(grade('rejected').statusId).toBe(STATUS.failure)
    expect(grade('cancelled').statusId).toBe(STATUS.failure)
    expect(grade('unavailable')).toEqual({ statusId: STATUS.failure, severityId: SEVERITY.medium })
    expect(grade('something-new').statusId).toBe(STATUS.other)
  })

  it('marks a decision whose question was never observed', () => {
    const mapping = mapEvent(SESSION, decided('ghost', 'rejected', 10), new SessionState(), config)
    expect(mapping?.attributes?.['unpaired']).toBe(true)
    expect(mapping?.duration).toBeUndefined()
  })

  it('never reports a negative latency when clocks disagree', () => {
    const state = new SessionState()
    mapEvent(SESSION, asked('a', 5_000), state, config)
    const mapping = mapEvent(SESSION, decided('a', 'rejected', 4_000), state, config)
    expect(mapping?.duration).toBe(0)
  })
})

describe('unresolved approvals', () => {
  it('flushes a question that never got an answer', () => {
    const mapping = mapUnresolvedApproval(SESSION, { id: 'a-2', toolName: 'write', time: 100, seq: 4 }, 900)
    expect(mapping.statusId).toBe(STATUS.unknown)
    expect(mapping.duration).toBe(800)
    expect(mapping.attributes?.['unresolved']).toBe(true)
  })
})

describe('authorization state', () => {
  it('records a sandbox switch as a privilege assignment', () => {
    const mapping = mapEvent(SESSION, { type: 'sandbox/mode', seq: 1, time: 1, data: { mode: 'danger-full-access' } }, new SessionState(), config)
    expect(mapping?.classUid).toBe(CLASS.authorizeSession)
    expect(mapping?.privileges).toEqual(['sandbox:danger-full-access'])
    expect(mapping?.severityId).toBe(SEVERITY.medium)
  })

  it('records an approval-policy switch and its delegation source', () => {
    const mapping = mapEvent(SESSION, { type: 'approval/policy', seq: 1, time: 1, data: { policy: 'never', source: 'delegation' } }, new SessionState(), config)
    expect(mapping?.privileges).toEqual(['approval-policy:never'])
    expect(mapping?.attributes?.['source']).toBe('delegation')
  })

  it('records a permission preset', () => {
    const mapping = mapEvent(SESSION, { type: 'permission/preset', seq: 1, time: 1, data: { preset: 'read-only' } }, new SessionState(), config)
    expect(mapping?.privileges).toEqual(['preset:read-only'])
  })
})
