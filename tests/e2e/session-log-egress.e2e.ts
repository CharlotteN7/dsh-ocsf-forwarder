/**
 * The session log leaving the host, driven end to end.
 *
 * `@deepseek-ai/dsh-session-log-deepseek` is a row of the base bundle, off
 * unless a deployment enables it. Enabled, it attaches the session's own
 * canonical event envelopes to every model request as `dsh_session_log` and
 * appends `session-log-deepseek/delivery-accepted` when the endpoint takes
 * them. The mock stands in for the endpoint, so the upload really happens over
 * a socket and the captured request body is the evidence that it did.
 *
 * The assertions join the two: the bytes the mock received, and the OCSF
 * records the forwarder wrote about them.
 */

import { describe, expect, it } from 'vitest'
import { dshOf, runAgent, type OcsfLine } from './harness.ts'

/** The incremental session-log field an official DeepSeek request carries. */
interface SessionLogField {
  readonly version: number
  readonly session: { readonly id: string }
  readonly afterSeq: number
  readonly throughSeq: number
  readonly events: readonly { readonly type: string }[]
}

/** The `dsh_session_log` field of one captured request body, when it carried one. */
function sessionLogOf(body: unknown): SessionLogField | undefined {
  const field = (body as Record<string, unknown> | null)?.['dsh_session_log']
  return field === undefined ? undefined : field as SessionLogField
}

describe('session-log delivery', () => {
  it('records each upload of the log, with the count of what left the host', async ({ skip }) => {
    const result = await runAgent({
      task: 'print a marker',
      sequence: ['tool_call_success', 'success', 'success'],
      toolName: 'bash',
      toolArguments: JSON.stringify({ command: 'printf MARKER', description: 'Print a marker' }),
      successText: 'done',
      extraProfilePatch: ['- id: session-log-deepseek', '  config:', '    enabled: true'].join('\n'),
    })

    expect(result.code, result.stderr).toBe(0)

    const uploads = result.modelRequests
      .map(request => sessionLogOf(request.body))
      .filter((field): field is SessionLogField => field !== undefined)

    if (uploads.length === 0) {
      // `@deepseek-ai/dsh-session-log-deepseek` is a `0.1.2` package: on an
      // older CLI the profile patch names a row that does not exist and the
      // boot ignores it. The absence is total rather than partial — nothing
      // uploaded AND nothing recorded — which is asserted here so a harness
      // that uploaded without the forwarder noticing fails instead of skipping.
      expect(result.sessionLog.some(row => row['type'] === 'session-log-deepseek/delivery-accepted')).toBe(false)
      skip('this harness has no session-log-deepseek row; the upload cannot happen')
      return
    }

    // At least two requests carried the field, so there is a second delivery
    // whose predecessor the forwarder observed.
    expect(uploads.length).toBeGreaterThanOrEqual(2)
    // What went is the log itself, not a summary of it.
    expect(uploads[0]?.events.some(event => event.type === 'user/message')).toBe(true)

    const records = result.ocsfRecords
      .filter(record => dshOf(record)['event_type'] === 'session-log-deepseek/delivery-accepted')
    // One acceptance per accepted upload, minus the last one if the run ended
    // before its response arrived.
    expect(records.length).toBeGreaterThanOrEqual(1)

    const first = records[0] as OcsfLine
    expect(first.class_uid).toBe(6003)
    expect(first.activity_id).toBe(1)
    expect(first.type_uid).toBe(600301)
    expect(first.status_id).toBe(1)
    expect(first.severity_id).toBe(2)
    expect(first.api).toEqual({ operation: 'session-log/deliver', service: { name: 'deepseek-llm-api' } })
    expect(String(first.metadata.correlation_uid)).toContain(':session-log-delivery')

    // The first acceptance this process observes has no predecessor to
    // subtract, and says so rather than reporting a count it cannot know.
    expect(dshOf(first)['first_observed_delivery']).toBe(true)
    expect(dshOf(first)['delivered_event_count']).toBeUndefined()
    expect(dshOf(first)['inherited_marker']).toBeUndefined()

    // The watermark is the one the session log itself recorded.
    const accepted = result.sessionLog
      .filter(row => row['type'] === 'session-log-deepseek/delivery-accepted')
      .map(row => (row['data'] as { throughSeq: number }).throughSeq)
    expect(accepted.length).toBeGreaterThanOrEqual(1)
    expect(dshOf(first)['delivered_through_seq']).toBe(accepted[0])
    expect(dshOf(first)['delivered_session_id']).toBe(dshOf(first)['session_id'])

    // Every acceptance after the first counts the events that went with it,
    // from the watermark of the one before.
    for (const [index, record] of records.slice(1).entries()) {
      const previous = accepted[index] as number
      expect(dshOf(record)['delivered_after_seq']).toBe(previous)
      expect(dshOf(record)['delivered_event_count']).toBe((accepted[index + 1] as number) - previous)
      expect(dshOf(record)['first_observed_delivery']).toBeUndefined()
    }
  }, 120_000)

  it('writes no delivery record when the row is left off, which is its default', async () => {
    const result = await runAgent({
      task: 'print a marker',
      sequence: ['success'],
      successText: 'done',
    })

    expect(result.code, result.stderr).toBe(0)
    expect(result.modelRequests.every(request => sessionLogOf(request.body) === undefined)).toBe(true)
    expect(result.sessionLog.some(row => row['type'] === 'session-log-deepseek/delivery-accepted')).toBe(false)
    expect(result.ocsfRecords.some(record => dshOf(record)['event_type'] === 'session-log-deepseek/delivery-accepted'))
      .toBe(false)
  }, 120_000)
})
