/**
 * `session-log-deepseek/delivery-accepted`: the session log itself leaving the
 * host.
 *
 * `@deepseek-ai/dsh-session-log-deepseek` contributes a `dsh_session_log` field
 * to every official DeepSeek model request, carrying the complete canonical
 * event envelopes from the last accepted watermark through the log's current
 * end — every tool argument, every tool result, every prompt. When the endpoint
 * accepts the request the plugin appends this event to record the new
 * watermark. It is the one session event that says the audit subject was
 * copied off the host, and it names how much of it went.
 */
import { describe, expect, it } from 'vitest'
import { SessionState } from '../../src/correlate.ts'
import { mapEvent } from '../../src/map/index.ts'
import { ACTIVITY, CLASS, SEVERITY, STATUS } from '../../src/ocsf/constants.ts'
import { testConfig } from './support.ts'

const SESSION = 'session-1'
const config = testConfig()

/** One acceptance event. */
function accepted(seq: number, time: number, data: unknown): { type: string; seq: number; time: number; data: unknown } {
  return { type: 'session-log-deepseek/delivery-accepted', seq, time, data }
}

describe('session-log-deepseek/delivery-accepted', () => {
  it('reports the delivery as an API call to the provider that took the log', () => {
    const mapping = mapEvent(
      SESSION,
      accepted(40, 5_000, { sessionId: SESSION, throughSeq: 39 }),
      new SessionState(),
      config,
    )
    expect(mapping?.classUid).toBe(CLASS.apiActivity)
    expect(mapping?.activityId).toBe(ACTIVITY.api.create)
    expect(mapping?.statusId).toBe(STATUS.success)
    // Routine once the row is enabled — one per successful model request — so
    // the record's existence and its service name carry the signal, not a
    // severity that would flood the index.
    expect(mapping?.severityId).toBe(SEVERITY.low)
    expect(mapping?.api).toEqual({
      operation: 'session-log/deliver',
      service: { name: 'deepseek-llm-api' },
    })
    expect(mapping?.correlationUid).toBe(`${SESSION}:session-log-delivery`)
    expect(mapping?.attributes?.['delivered_through_seq']).toBe(39)
    expect(mapping?.attributes?.['delivered_session_id']).toBe(SESSION)
  })

  it('counts what left the host, from the watermark of the delivery before it', () => {
    const state = new SessionState()
    mapEvent(SESSION, accepted(12, 5_000, { sessionId: SESSION, throughSeq: 11 }), state, config)
    const second = mapEvent(SESSION, accepted(30, 6_000, { sessionId: SESSION, throughSeq: 29 }), state, config)
    // Events 12 through 29 inclusive: everything appended after the previous
    // watermark, up to and including the new one.
    expect(second?.attributes?.['delivered_after_seq']).toBe(11)
    expect(second?.attributes?.['delivered_event_count']).toBe(18)
    expect(second?.attributes?.['first_observed_delivery']).toBeUndefined()
  })

  it('claims no count for the first delivery it observes, whose predecessor it never saw', () => {
    // A plugin mounted mid-session, or a session adopted without full seed
    // replay, has no watermark to subtract. Reporting -1 would claim the whole
    // log went in this one delivery.
    const mapping = mapEvent(
      SESSION,
      accepted(40, 5_000, { sessionId: SESSION, throughSeq: 39 }),
      new SessionState(),
      config,
    )
    expect(mapping?.attributes?.['first_observed_delivery']).toBe(true)
    expect(mapping?.attributes?.['delivered_after_seq']).toBeUndefined()
    expect(mapping?.attributes?.['delivered_event_count']).toBeUndefined()
  })

  it('grades a fork-inherited marker as nothing having left this session', () => {
    // The harness's own invariant: a marker naming a session other than its
    // container was inherited through a fork seed. It records a delivery the
    // PARENT made, and nothing left the host on this session's account.
    const mapping = mapEvent(
      SESSION,
      accepted(3, 5_000, { sessionId: 'parent-session', throughSeq: 2 }),
      new SessionState(),
      config,
    )
    expect(mapping?.attributes?.['inherited_marker']).toBe(true)
    expect(mapping?.attributes?.['delivered_session_id']).toBe('parent-session')
    expect(mapping?.severityId).toBe(SEVERITY.informational)
  })

  it('keeps each delivered session id on its own watermark', () => {
    const state = new SessionState()
    mapEvent(SESSION, accepted(12, 5_000, { sessionId: 'parent-session', throughSeq: 11 }), state, config)
    const own = mapEvent(SESSION, accepted(20, 6_000, { sessionId: SESSION, throughSeq: 19 }), state, config)
    // The parent's inherited watermark says nothing about this session's own
    // first delivery.
    expect(own?.attributes?.['first_observed_delivery']).toBe(true)
    expect(own?.attributes?.['delivered_after_seq']).toBeUndefined()
  })

  it('reports a payload without the two fields it is made of as unreadable', () => {
    const state = new SessionState()
    expect(mapEvent(SESSION, accepted(40, 5_000, { throughSeq: 39 }), state, config)).toBeUndefined()
    expect(mapEvent(SESSION, accepted(40, 5_000, { sessionId: SESSION }), state, config)).toBeUndefined()
    expect(mapEvent(SESSION, accepted(40, 5_000, { sessionId: SESSION, throughSeq: 'nope' }), state, config)).toBeUndefined()
  })
})
