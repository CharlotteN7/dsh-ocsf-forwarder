/**
 * The evidence bar from CONVENTIONS.md §5: a booted harness, this plugin
 * mounted, a mock model driving a real tool call, and an assertion on what the
 * forwarder produced from the resulting session log.
 */

import { describe, expect, it } from 'vitest'
import { dshOf, isHeartbeat, runAgent, type OcsfLine } from './harness.ts'

/** Records of one event type, in spool order. */
function ofType(records: readonly OcsfLine[], type: string): OcsfLine[] {
  return records.filter(record => dshOf(record)['event_type'] === type)
}

describe('a real agent run, normalised to OCSF', () => {
  it('produces correlated Process Activity records for a bash call and its result', async () => {
    const result = await runAgent({
      task: 'print the round-trip marker',
      // One request per entry: the model asks for a tool, then answers. The
      // session-title provider issues a third request, so the script carries
      // a spare success.
      sequence: ['tool_call_success', 'success', 'success'],
      toolName: 'bash',
      toolArguments: JSON.stringify({
        command: 'printf E2E_ROUND_TRIP',
        description: 'Print the round-trip marker',
      }),
      successText: 'round trip complete',
    })

    expect(result.code, result.stderr).toBe(0)
    expect(result.ocsfRecords.length).toBeGreaterThan(0)

    const calls = ofType(result.ocsfRecords, 'tool/call')
    const results = ofType(result.ocsfRecords, 'tool/result')
    expect(calls).toHaveLength(1)
    expect(results).toHaveLength(1)

    const call = calls[0] as OcsfLine
    const settled = results[0] as OcsfLine

    // Process Activity / Launch, with the derived type_uid.
    expect(call.class_uid).toBe(1007)
    expect(call.category_uid).toBe(1)
    expect(call.activity_id).toBe(1)
    expect(call.type_uid).toBe(100701)
    expect(call.metadata.version).toBe('1.9.0')
    expect(call.metadata.profiles).toEqual(['ai_operation', 'cloud', 'osint', 'record_integrity'])

    // Correlated by callId, through a correlation id both records carry.
    expect(call.metadata.correlation_uid).toBe(settled.metadata.correlation_uid)
    expect(String(call.metadata.correlation_uid)).toContain(String(dshOf(call)['call_id']))
    expect(dshOf(settled)['call_id']).toBe(dshOf(call)['call_id'])
    expect(dshOf(call)['phase']).toBe('invoke')
    expect(dshOf(settled)['phase']).toBe('complete')

    // The result closed the pair, so it carries an outcome and a duration.
    expect(settled.status_id).toBe(1)
    expect(dshOf(settled)['is_error']).toBe(false)
    expect(typeof settled.duration).toBe('number')
    expect(settled.duration as number).toBeGreaterThanOrEqual(0)
    expect(settled.start_time).toBe(call.time)

    // Session identity comes from the Session object, never from the envelope.
    expect(String(dshOf(call)['session_id']).length).toBeGreaterThan(0)
    expect(call.ai_agent).toMatchObject({ instance_uid: dshOf(call)['session_id'], type_id: 1 })
    expect(call.metadata.uid).toBe(`${String(dshOf(call)['session_id'])}:${String(dshOf(call)['seq'])}`)

    // The SOC lane classifies the command without carrying it.
    expect(call.process).toMatchObject({ name: 'printf' })
    expect(String((call.process as { cmd_line: string }).cmd_line)).toMatch(/^hmac-sha256:/)
    expect(JSON.stringify(result.ocsfRecords)).not.toContain('E2E_ROUND_TRIP')

    // The real tool still ran: the plugin is read-side and changed nothing.
    const toolResults = result.sessionLog.filter(row => row['type'] === 'tool/result')
    expect(JSON.stringify(toolResults)).toContain('E2E_ROUND_TRIP')

    // Turn and model activity are covered too, and the model route was folded
    // into every record's ai_model.
    expect(ofType(result.ocsfRecords, 'turn/start')).toHaveLength(1)
    expect(ofType(result.ocsfRecords, 'turn/end')[0]?.status_id).toBe(1)
    expect(call.ai_model).toMatchObject({ ai_provider: expect.any(String), name: expect.any(String) })

    // Dropped by policy: the stream deltas never reach the spool.
    expect(ofType(result.ocsfRecords, 'assistant/chunk')).toHaveLength(0)
    expect(result.sessionLog.some(row => row['type'] === 'assistant/chunk')).toBe(true)
  }, 120_000)

  it('records a turn with no tool call and leaves the agent output alone', async () => {
    const result = await runAgent({
      task: 'just answer',
      sequence: ['success', 'success'],
      successText: 'answered without tools',
    })

    expect(result.code, result.stderr).toBe(0)
    expect(result.stdout.trim()).toBe('answered without tools')
    expect(ofType(result.ocsfRecords, 'tool/call')).toHaveLength(0)

    const turnEnd = ofType(result.ocsfRecords, 'turn/end')[0] as OcsfLine
    expect(turnEnd.class_uid).toBe(6003)
    expect(turnEnd.status_id).toBe(1)
    expect(dshOf(turnEnd)['end_reason']).toBe('completed')

    // Every record is one JSON object per line carrying the required OCSF fields.
    for (const record of result.ocsfRecords) {
      expect(record.type_uid).toBe(record.class_uid * 100 + record.activity_id)
      expect(record.cloud).toEqual({ provider: 'Other' })
      expect(record.osint).toEqual([])
      expect(record.metadata.profiles).toEqual(['ai_operation', 'cloud', 'osint', 'record_integrity'])
      // No extension uid is claimed, and nothing sits outside the class's own
      // attributes: every OCSF class is `additionalProperties: false`.
      expect(record.metadata.extension).toBeUndefined()
      expect(record.metadata.extensions).toBeUndefined()
      expect(record['dsh']).toBeUndefined()
      // A heartbeat reports on the forwarder, not on a session, so it is the
      // one record with no session id to carry.
      if (!isHeartbeat(record)) expect(dshOf(record)['session_id']).toBeDefined()
    }
  }, 120_000)
})
