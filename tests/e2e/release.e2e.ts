/**
 * The 0.2 surfaces on a booted harness: the heartbeat that makes a silent host
 * detectable, the fleet identity a multi-team SOC filters on, and the
 * delegation record that says telemetry coverage ends at a tool call.
 */

import { describe, expect, it } from 'vitest'
import { dshOf, isHeartbeat, runAgent, type OcsfLine } from './harness.ts'

/** Records of one event type, in spool order. */
function ofType(records: readonly OcsfLine[], type: string): OcsfLine[] {
  return records.filter(record => dshOf(record)['event_type'] === type)
}

/**
 * A profile patch restating the forwarder row. A patch layer replaces a row's
 * whole `config`, so the spool path the bundle defaulted has to be restated —
 * `dshHomePath` resolves it to the same throwaway home the harness reads.
 */
function forwarderRow(extra: readonly string[]): string {
  return [
    '- id: dsh-ocsf-forwarder',
    '  config:',
    "    spoolPath: !!js dshHomePath('ocsf/session.ocsf.jsonl')",
    ...extra,
  ].join('\n')
}

describe('the forwarder reporting on itself', () => {
  it('spools a heartbeat carrying its counters, the spool size, and the fleet identity', async () => {
    const result = await runAgent({
      task: 'just answer',
      sequence: ['success', 'success'],
      successText: 'answered',
      extraProfilePatch: forwarderRow([
        '    fleet:',
        '      tenantUid: acme-soc',
        '      labels: [prod, eu-west]',
        '      tags:',
        '        owner: platform',
      ]),
    })

    expect(result.code, result.stderr).toBe(0)

    const beats = result.ocsfRecords.filter(isHeartbeat)
    expect(beats.length).toBeGreaterThan(0)
    const beat = beats[beats.length - 1] as OcsfLine
    // Application Lifecycle / Other: OCSF names no liveness activity.
    expect(beat.class_uid).toBe(6002)
    expect(beat.activity_id).toBe(99)
    expect(beat['activity_name']).toBe('Heartbeat')
    expect(beat['application']).toMatchObject({ name: 'deepseek-harness' })
    expect(dshOf(beat)['final']).toBe(true)
    expect(dshOf(beat)['forwarded']).toBeGreaterThan(0)
    expect(dshOf(beat)['spool_bytes']).toBeGreaterThan(0)
    expect(dshOf(beat)['spool_pressure']).toBe(false)
    expect(dshOf(beat)['session_id']).toBeUndefined()
    expect(beat.metadata.uid).toMatch(/:heartbeat:\d+$/)

    // Fleet identity is on every record, heartbeat included.
    const installUid = beat['device'] as { uid?: string }
    expect(installUid.uid).toMatch(/^[0-9a-f-]{36}$/)
    for (const record of result.ocsfRecords) {
      expect(record.metadata['tenant_uid']).toBe('acme-soc')
      expect(record.metadata['labels']).toEqual(['prod', 'eu-west'])
      expect(record.metadata['tags']).toEqual([{ name: 'owner', value: 'platform' }])
      expect((record['device'] as { uid?: string }).uid).toBe(installUid.uid)
    }

    // A collected event passes its log time through; the generated heartbeat
    // has no source time to pass through and omits the attribute.
    const turnStart = ofType(result.ocsfRecords, 'turn/start')[0] as OcsfLine
    expect(turnStart.metadata['original_time']).toBe(String(turnStart['time']))
    expect(beat.metadata['original_time']).toBeUndefined()
  }, 120_000)
})

describe('a tool call that leaves this session', () => {
  it('is graded high and states that coverage ends at the boundary', async () => {
    const result = await runAgent({
      task: 'hand the task over',
      sequence: ['tool_call_success', 'success', 'success'],
      toolName: 'subagent_codex',
      toolArguments: JSON.stringify({ prompt: 'E2E_DELEGATED_PROMPT' }),
      successText: 'handed over',
      extraProfilePatch: forwarderRow([
        '    delegationTools:',
        '      subagent_codex: codex',
      ]),
    })

    const calls = ofType(result.ocsfRecords, 'tool/call')
      .filter(record => dshOf(record)['tool'] === 'subagent_codex')
    expect(calls.length, result.stderr).toBeGreaterThan(0)

    const call = calls[0] as OcsfLine
    expect(call.class_uid).toBe(1007)
    expect(call.severity_id).toBe(4)
    expect(String(call['message'])).toContain('coverage ends at this boundary')
    expect(call['process']).toMatchObject({ name: 'codex' })
    expect(dshOf(call)['delegation_provider']).toBe('codex')
    expect(dshOf(call)['delegation_boundary']).toBe(true)
    expect(dshOf(call)['delegation_coverage']).toBe('none')

    // Metadata only: the prompt handed to the other harness is not disclosed.
    expect(JSON.stringify(result.ocsfRecords)).not.toContain('E2E_DELEGATED_PROMPT')
  }, 120_000)
})

describe('an MCP tool call', () => {
  it('names the server the agent talked to, so a SOC can pivot on it', async () => {
    const result = await runAgent({
      task: 'reach the external server',
      sequence: ['tool_call_success', 'success', 'success'],
      toolName: 'mcp__acme_tickets__create_issue',
      toolArguments: JSON.stringify({ title: 'E2E_MCP_TITLE' }),
      successText: 'reached',
    })

    const calls = ofType(result.ocsfRecords, 'tool/call')
      .filter(record => dshOf(record)['mcp_server'] !== undefined)
    expect(calls.length, result.stderr).toBeGreaterThan(0)

    const call = calls[0] as OcsfLine
    expect(call.class_uid).toBe(6003)
    expect(call['api']).toMatchObject({ service: { name: 'mcp:acme_tickets' } })
    expect(dshOf(call)['mcp_server']).toBe('acme_tickets')
    expect(dshOf(call)['mcp_tool']).toBe('create_issue')
    expect(JSON.stringify(result.ocsfRecords)).not.toContain('E2E_MCP_TITLE')
  }, 120_000)
})
