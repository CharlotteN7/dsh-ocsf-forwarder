/**
 * The approval path, driven end to end without a fixture plugin: under the
 * base bundle's `workspace-write` mode the approval policy is `ask`, and a
 * model-requested sandbox escalation makes `dsh-tool-bash` call
 * `ctx.approval.request(...)` before anything executes. The headless profile
 * composes no answerer, so the ask fails closed to `unavailable` — which is
 * itself the SOC signal worth having.
 */

import { describe, expect, it } from 'vitest'
import { dshOf, runAgent, type OcsfLine } from './harness.ts'

/** Records of one event type, in spool order. */
function ofType(records: readonly OcsfLine[], type: string): OcsfLine[] {
  return records.filter(record => dshOf(record)['event_type'] === type)
}

describe('approval events', () => {
  it('pairs the ask with its decision and computes the decision latency', async () => {
    const result = await runAgent({
      task: 'read the protected file',
      sequence: ['tool_call_success', 'success', 'success'],
      toolName: 'bash',
      toolArguments: JSON.stringify({
        command: 'printf ESCALATED',
        description: 'Print a marker with wider access',
        sandbox_permissions: 'danger-full-access',
        justification: 'the marker must be written outside the workspace',
      }),
      successText: 'escalation attempt finished',
      permissionMode: 'workspace-write',
    })

    expect(result.code, result.stderr).toBe(0)

    const asked = ofType(result.ocsfRecords, 'approval/asked')
    const decided = ofType(result.ocsfRecords, 'approval/decided')
    expect(asked).toHaveLength(1)
    expect(decided).toHaveLength(1)

    const question = asked[0] as OcsfLine
    const decision = decided[0] as OcsfLine

    // Authorize Session / Assign Privileges, with the privilege at stake named.
    expect(question.class_uid).toBe(3003)
    expect(question.category_uid).toBe(3)
    expect(question.activity_id).toBe(1)
    expect(question.type_uid).toBe(300301)
    expect(question.privileges).toEqual(['tool:bash'])
    expect(question.status_id).toBe(0)
    expect(question.user).toMatchObject({ type_id: 1 })

    // Paired by the approval request id, repeated verbatim in the decision.
    expect(dshOf(decision)['approval_id']).toBe(dshOf(question)['approval_id'])
    expect(decision.metadata.correlation_uid).toBe(question.metadata.correlation_uid)
    expect(String(question.metadata.correlation_uid)).toContain(':approval:')

    // The fail-closed outcome, graded as a failure with the latency attached.
    expect(dshOf(decision)['outcome']).toBe('unavailable')
    expect(decision.status_id).toBe(2)
    expect(decision.status_detail).toBe('unavailable')
    expect(decision.severity_id).toBe(3)
    expect(typeof dshOf(decision)['approval_latency_ms']).toBe('number')
    expect(dshOf(decision)['approval_latency_ms'] as number).toBeGreaterThanOrEqual(0)
    expect(decision.duration).toBe(dshOf(decision)['approval_latency_ms'])
    expect(decision.start_time).toBe(question.time)
    expect(dshOf(decision)['asked_seq']).toBe(dshOf(question)['seq'])
    expect(dshOf(decision)['unpaired']).toBeUndefined()

    // The question names the tool call it is about, so the authorization joins
    // to the Process Activity records of the same call.
    const callId = dshOf(question)['call_id']
    expect(typeof callId).toBe('string')
    const call = ofType(result.ocsfRecords, 'tool/call')[0] as OcsfLine
    expect(dshOf(call)['call_id']).toBe(callId)

    // The escalation was refused, so the tool call settled as an error and the
    // marker never ran.
    const settled = ofType(result.ocsfRecords, 'tool/result')[0] as OcsfLine
    expect(settled.status_id).toBe(2)
    expect(dshOf(settled)['is_error']).toBe(true)

    // The approval prompt quotes the action being approved, so the SOC lane
    // carries its digest and length rather than its text.
    expect(dshOf(question)['reason']).toBeUndefined()
    expect(String(dshOf(question)['reason_digest'])).toMatch(/^hmac-sha256:/)
    expect(dshOf(question)['reason_length'] as number).toBeGreaterThan(0)
    expect(JSON.stringify(result.ocsfRecords)).not.toContain('escalate sandbox to danger-full-access')
  }, 120_000)
})
