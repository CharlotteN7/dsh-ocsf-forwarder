/**
 * The two classification changes a SOC sees, and the delegation boundary
 * record: `cordis_*` graded as process activity, MCP calls attributed to the
 * server that offers them, and a call to an external harness graded high with
 * a statement that coverage ends there.
 */
import { describe, expect, it } from 'vitest'
import { SessionState } from '../../src/correlate.ts'
import { discoverDelegationTools, mergeDelegationTools, type RegistryLike } from '../../src/delegation.ts'
import { mapEvent } from '../../src/map/index.ts'
import { classifyTool, parseMcpToolName } from '../../src/map/tools.ts'
import { CLASS, SEVERITY } from '../../src/ocsf/constants.ts'
import { buildRecord, type EventMapping } from '../../src/ocsf/record.ts'
import type { ResolvedConfig } from '../../src/config.ts'
import type { OcsfRecord } from '../../src/ocsf/types.ts'
import { dshOf, testConfig, testEnvironment } from './support.ts'

const SESSION = 'session-1'

/** One `tool/call`, mapped and composed the way the forwarder composes one. */
function callRecord(name: string, config: ResolvedConfig, args: unknown = {}): OcsfRecord {
  const state = new SessionState()
  const event = {
    type: 'tool/call',
    seq: 1,
    time: 1_000,
    data: { turn: 1, step: 0, callId: 'call-1', name, arguments: JSON.stringify(args) },
  }
  const mapping = mapEvent(SESSION, event, state, config) as EventMapping
  return buildRecord(testEnvironment(config), {
    sessionId: SESSION, seq: 1, time: 1_000, eventType: 'tool/call', replayed: false,
  }, mapping)
}

/** One `tool/result` closing the call above. */
function resultRecord(name: string, config: ResolvedConfig): OcsfRecord {
  const state = new SessionState()
  const call = {
    type: 'tool/call',
    seq: 1,
    time: 1_000,
    data: { turn: 1, step: 0, callId: 'call-1', name, arguments: '{}' },
  }
  mapEvent(SESSION, call, state, config)
  const event = {
    type: 'tool/result',
    seq: 2,
    time: 1_200,
    data: { message: { source: { callId: 'call-1' } } },
  }
  const mapping = mapEvent(SESSION, event, state, config) as EventMapping
  return buildRecord(testEnvironment(config), {
    sessionId: SESSION, seq: 2, time: 1_200, eventType: 'tool/result', replayed: false,
  }, mapping)
}

describe('cordis tool classification', () => {
  it('grades cordis_define and cordis_run as process activity, where process detections fire', () => {
    const config = testConfig()
    expect(classifyTool('cordis_define', config)).toBe('process-launch')
    expect(classifyTool('cordis_run', config)).toBe('process-launch')

    const record = callRecord('cordis_run', config, { pluginId: 'p', packageId: 'k' })
    expect(record.class_uid).toBe(CLASS.processActivity)
    expect(record.type_uid).toBe(CLASS.processActivity * 100 + 1)
    expect(record.process?.name).toBe('cordis_run')
  })

  it('leaves the read-only cordis tool an API call', () => {
    expect(classifyTool('cordis_inspect_self', testConfig())).toBe('api')
  })
})

describe('MCP server attribution', () => {
  it('splits the public tool name back into the server and the tool', () => {
    expect(parseMcpToolName('mcp__github__create_issue')).toEqual({ server: 'github', tool: 'create_issue' })
    expect(parseMcpToolName('mcp__github__a__b')).toEqual({ server: 'github', tool: 'a__b' })
    expect(parseMcpToolName('bash')).toBeUndefined()
    expect(parseMcpToolName('mcp__github')).toBeUndefined()
    expect(parseMcpToolName('mcp____tool')).toBeUndefined()
    expect(parseMcpToolName('mcp__github__')).toBeUndefined()
  })

  it('names the external server on the call, so a SOC can pivot on it', () => {
    const record = callRecord('mcp__github__create_issue', testConfig(), { title: 'x' })
    expect(record.class_uid).toBe(CLASS.apiActivity)
    expect(record.api?.service?.name).toBe('mcp:github')
    expect(record.api?.operation).toBe('tool:mcp__github__create_issue')
    expect(dshOf(record)['mcp_server']).toBe('github')
    expect(dshOf(record)['mcp_tool']).toBe('create_issue')
  })

  it('repeats the attribution on the result, so both records filter alike', () => {
    const record = resultRecord('mcp__github__create_issue', testConfig())
    expect(record.api?.service?.name).toBe('mcp:github')
    expect(dshOf(record)['mcp_server']).toBe('github')
  })

  it('carries no service name for a tool that is not an MCP one', () => {
    expect(callRecord('todo_write', testConfig()).api?.service).toBeUndefined()
  })

  it('carries the server name only, never an argument value', () => {
    const record = callRecord('mcp__github__create_issue', testConfig(), { title: 'CVE-2026-1 exploit', token: 'sk-live-1' })
    const serialized = JSON.stringify(record)
    expect(serialized).not.toContain('sk-live-1')
    expect(serialized).not.toContain('CVE-2026-1')
  })
})

describe('external-harness delegation', () => {
  const config = testConfig({ delegationTools: { subagent_claude_code: 'claude-code' } })

  it('grades a delegation call high and says coverage ends at the boundary', () => {
    const record = callRecord('subagent_claude_code', config, { prompt: 'do the thing' })
    expect(record.severity_id).toBe(SEVERITY.high)
    expect(record.class_uid).toBe(CLASS.processActivity)
    expect(record.message).toContain('coverage ends at this boundary')
    expect(record.process?.name).toBe('claude-code')
    expect(dshOf(record)['delegation_provider']).toBe('claude-code')
    expect(dshOf(record)['delegation_boundary']).toBe(true)
    expect(dshOf(record)['delegation_coverage']).toBe('none')
    expect(dshOf(record)['tool_class']).toBe('delegation-external')
  })

  it('carries the boundary attributes onto the result as well', () => {
    const record = resultRecord('subagent_claude_code', config)
    expect(dshOf(record)['delegation_boundary']).toBe(true)
    expect(dshOf(record)['delegation_provider']).toBe('claude-code')
  })

  it('carries no prompt into the SOC lane, only the tool and provider names', () => {
    const record = callRecord('subagent_claude_code', config, { prompt: 'exfiltrate /etc/shadow' })
    expect(JSON.stringify(record)).not.toContain('exfiltrate')
  })

  it('leaves an in-process subagent tool alone, so the two that matter stay visible', () => {
    const record = callRecord('subagent', testConfig(), { prompt: 'x' })
    expect(record.severity_id).toBe(SEVERITY.informational)
    expect(dshOf(record)['delegation_boundary']).toBeUndefined()
  })
})

describe('delegation discovery', () => {
  /** A registry holding the plugin rows a composed profile would have mounted. */
  function registry(rows: readonly { name?: string; config?: unknown }[]): RegistryLike {
    const runtimes = new Map<string, { name?: string; fibers: { config?: unknown }[] }>()
    for (const row of rows) {
      const key = row.name ?? '<anonymous>'
      const existing = runtimes.get(key) ?? { ...row.name === undefined ? {} : { name: row.name }, fibers: [] }
      existing.fibers.push({ config: row.config })
      runtimes.set(key, existing)
    }
    return { values: () => runtimes.values() }
  }

  it('finds the delegation tools whose provider leaves this session', () => {
    const discovered = discoverDelegationTools(registry([
      { name: 'tool-subagent', config: { provider: 'spawn', toolName: 'subagent' } },
      { name: 'tool-subagent', config: { provider: 'claude-code', toolName: 'subagent_claude_code' } },
      { name: 'tool-subagent', config: { provider: 'codex', toolName: 'delegate_codex' } },
      { name: 'tool-subagent', config: { provider: 'fork', toolName: 'subagent_fork' } },
      { name: 'session-persistence-jsonl', config: { root: '/tmp' } },
    ]))
    expect(discovered).toEqual({ subagent_claude_code: 'claude-code', delegate_codex: 'codex' })
  })

  it('reads a row that names no tool or no provider as no delegation tool', () => {
    expect(discoverDelegationTools(registry([
      { name: 'tool-subagent', config: { provider: 'claude-code' } },
      { name: 'tool-subagent', config: { toolName: 'orphan' } },
      { name: 'tool-subagent' },
    ]))).toEqual({})
  })

  it('lets configuration add a name discovery cannot see', () => {
    expect(mergeDelegationTools({ a: 'codex' }, { b: 'claude-code' }))
      .toEqual({ a: 'codex', b: 'claude-code' })
  })

  it('refuses to let configuration un-name a discovered delegation tool', () => {
    expect(mergeDelegationTools({ a: 'claude-code' }, { a: 'spawn' })).toEqual({ a: 'claude-code' })
  })
})
