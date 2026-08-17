/**
 * The SOC lane's one privacy invariant, tested as an invariant.
 *
 * `privacy.ts` states it: a raw argument value, message text, or command line
 * never reaches the SOC lane unless a deployment has explicitly opted that
 * whole category in. Asserting it one call site at a time leaves every site
 * nobody thought of unguarded — `observables[]` was entirely unguarded, and a
 * mutation putting the raw URL there passed the whole suite. So a distinct
 * sentinel goes into every payload field a session event can carry text in, a
 * full forwarder run is driven over them, and the serialized records are
 * searched for all of them at once. A new leak fails this whether or not
 * anyone remembers to write a test for the field that leaked.
 */
import { describe, expect, it } from 'vitest'
import { Forwarder, type ForwardableSession } from '../../src/forwarder.ts'
import type { MappableEvent } from '../../src/map/index.ts'
import type { OcsfRecord } from '../../src/ocsf/types.ts'
import type { Sink } from '../../src/sink/spool.ts'
import { testConfig, testEnvironment } from './support.ts'
import type { Config } from '../../src/config.ts'

/**
 * One secret per surface, so a failure names the surface that leaked. Each is
 * a value a real deployment would call a secret and none is a substring of
 * another.
 */
const SENTINELS: Readonly<Record<string, string>> = Object.freeze({
  command: 'SENTINEL-shell-AKIAIOSFODNN7EXAMPLE',
  code: 'SENTINEL-runcode-ghp0123456789abcdef',
  urlQuery: 'SENTINEL-urltoken-sk-live-9f2a',
  fileBody: 'SENTINEL-filebody-BEGIN-RSA-PRIVATE-KEY',
  grepPattern: 'SENTINEL-grep-hunter2',
  apiArgument: 'SENTINEL-apiarg-xoxb-11-22-33',
  mcpArgument: 'SENTINEL-mcparg-glpat-AAAA',
  malformed: 'SENTINEL-malformed-psql-W-hunter3',
  prompt: 'SENTINEL-prompt-my-password-is-swordfish',
  completion: 'SENTINEL-completion-here-is-the-key-abc',
  systemPrompt: 'SENTINEL-system-internal-runbook-url',
  approvalReason: 'SENTINEL-approval-rm-rf-slash-home-secret',
  turnError: 'SENTINEL-turnerror-x-api-key-header-echo',
  hookDecision: 'SENTINEL-hook-matched-value-4111111111111111',
  summary: 'SENTINEL-summary-the-user-said-swordfish',
  scheduleId: 'SENTINEL-notasecret-schedule-id',
})

/**
 * Every text-bearing surface a session event offers, each carrying its own
 * sentinel. Mirrors the mapper dispatch: a type this omits is a surface the
 * invariant is not being tested on.
 */
function events(): MappableEvent[] {
  return [
    { type: 'turn/start', seq: 0, time: 1_000, data: { turn: 1 } },
    { type: 'request/context', seq: 1, time: 1_001, data: { provider: 'deepseek', model: 'deepseek-chat' } },
    {
      type: 'request/header',
      seq: 2,
      time: 1_002,
      data: { reason: 'initial', header: { system: SENTINELS['systemPrompt'], tools: [{ name: 'bash' }] } },
    },
    { type: 'step/start', seq: 3, time: 1_003, data: { turn: 1, step: 0 } },
    {
      type: 'user/message',
      seq: 4,
      time: 1_004,
      data: { source: { kind: 'human' }, content: [{ type: 'text', text: SENTINELS['prompt'] }] },
    },
    {
      type: 'assistant/message',
      seq: 5,
      time: 1_005,
      data: { turn: 1, step: 0, message: { content: [{ type: 'text', text: SENTINELS['completion'] }] } },
    },
    {
      type: 'tool/call',
      seq: 6,
      time: 1_006,
      data: {
        turn: 1,
        step: 0,
        callId: 'c1',
        name: 'bash',
        arguments: JSON.stringify({ command: `curl -H "Authorization: Bearer ${SENTINELS['command']}" https://x.test` }),
      },
    },
    { type: 'tool/result', seq: 7, time: 1_007, data: { message: { source: { callId: 'c1' } } } },
    {
      type: 'tool/call',
      seq: 8,
      time: 1_008,
      data: {
        turn: 1,
        step: 0,
        callId: 'c2',
        name: 'write',
        arguments: JSON.stringify({ file_path: '/srv/app/.env', content: SENTINELS['fileBody'] }),
      },
    },
    { type: 'tool/result', seq: 9, time: 1_009, data: { message: { source: { callId: 'c2' } } } },
    {
      type: 'tool/call',
      seq: 10,
      time: 1_010,
      data: {
        turn: 1,
        step: 0,
        callId: 'c3',
        name: 'web_fetch',
        arguments: JSON.stringify({ url: `https://example.test/reset?token=${SENTINELS['urlQuery']}` }),
      },
    },
    { type: 'tool/result', seq: 11, time: 1_011, data: { message: { source: { callId: 'c3' } } } },
    {
      type: 'tool/call',
      seq: 12,
      time: 1_012,
      data: { turn: 1, step: 0, callId: 'c4', name: 'grep', arguments: JSON.stringify({ pattern: SENTINELS['grepPattern'] }) },
    },
    { type: 'tool/result', seq: 13, time: 1_013, data: { message: { source: { callId: 'c4' } } } },
    {
      type: 'tool/call',
      seq: 14,
      time: 1_014,
      data: { turn: 1, step: 0, callId: 'c5', name: 'mystery_tool', arguments: JSON.stringify({ token: SENTINELS['apiArgument'] }) },
    },
    { type: 'tool/result', seq: 15, time: 1_015, data: { message: { source: { callId: 'c5' } } } },
    {
      type: 'tool/call',
      seq: 16,
      time: 1_016,
      data: {
        turn: 1,
        step: 0,
        callId: 'c6',
        name: 'mcp__github__create_issue',
        arguments: JSON.stringify({ body: SENTINELS['mcpArgument'] }),
      },
    },
    { type: 'tool/result', seq: 17, time: 1_017, data: { message: { source: { callId: 'c6' } } } },
    // Malformed argument JSON: the parser's own message quotes a window of the
    // text it choked on, which here is raw model output.
    {
      type: 'tool/call',
      seq: 18,
      time: 1_018,
      data: { turn: 1, step: 0, callId: 'c7', name: 'bash', arguments: `{"command": ${SENTINELS['malformed']}}` },
    },
    { type: 'tool/result', seq: 19, time: 1_019, data: { message: { source: { callId: 'c7' } } } },
    {
      type: 'tool/code-dispatch-start',
      seq: 20,
      time: 1_020,
      data: {
        rootCallId: 'root',
        parentCallId: 'c1',
        subCallId: 'sub-1',
        name: 'run_code',
        // A program body rather than a bare token: `process.name` is the
        // leading executable token of a command line, emitted verbatim as
        // metadata by `commandName`, and a payload that is nothing but a
        // secret would be testing that documented exception instead of this
        // invariant.
        arguments: {
          code: `const token = "${SENTINELS['code']}"\nawait fetch("https://x.test", { headers: { authorization: token } })`,
        },
      },
    },
    { type: 'tool/code-dispatch', seq: 21, time: 1_021, data: { subCallId: 'sub-1', name: 'run_code', isError: false } },
    {
      type: 'approval/asked',
      seq: 22,
      time: 1_022,
      data: { id: 'a1', toolName: 'bash', callId: 'c8', reason: SENTINELS['approvalReason'] },
    },
    { type: 'approval/decided', seq: 23, time: 1_023, data: { id: 'a1', outcome: 'allowed-once' } },
    { type: 'sandbox/mode', seq: 24, time: 1_024, data: { mode: 'danger-full-access' } },
    { type: 'hook/invoked', seq: 25, time: 1_025, data: { turn: 1, point: 'PreToolUse', handlerId: 'h1' } },
    {
      type: 'hook/result',
      seq: 26,
      time: 1_026,
      data: { turn: 1, point: 'PreToolUse', handlerId: 'h1', decision: SENTINELS['hookDecision'], exitCode: 0 },
    },
    {
      type: 'compaction/summary',
      seq: 27,
      time: 1_027,
      data: { compactionId: 'k1', summary: { text: SENTINELS['summary'] } },
    },
    { type: 'schedule/change', seq: 28, time: 1_028, data: { version: 1, operation: 'create', schedule: { id: SENTINELS['scheduleId'] } } },
    {
      type: 'turn/end',
      seq: 29,
      time: 1_029,
      data: { turn: 1, reason: { kind: 'error', error: { code: 'ETIMEDOUT', message: SENTINELS['turnError'] } } },
    },
    // A type this build has no mapper for takes the generic fallback, which
    // must read the payload's shape and never its content.
    { type: 'someone-elses-plugin/event', seq: 30, time: 1_030, data: { turn: 1, note: SENTINELS['prompt'] } },
  ]
}

/** Drive one full forwarder run and return the records each lane received. */
function run(overrides: Partial<Config> = {}): { soc: OcsfRecord[]; restricted: OcsfRecord[] } {
  const config = testConfig(overrides)
  const soc: OcsfRecord[] = []
  const restricted: OcsfRecord[] = []
  const socSink: Sink = { write: record => { soc.push(record) }, close: () => {} }
  const restrictedSink: Sink = { write: record => { restricted.push(record) }, close: () => {} }
  const log = events()
  const session: ForwardableSession = { id: 'S1', firstLiveSeq: 0, seq: log.length, events: log, header: { cwd: '/srv' } }
  const forwarder = new Forwarder(testEnvironment(config), config, socSink, restrictedSink, error => { throw error })
  forwarder.adopt(session)
  for (const event of log) forwarder.observe(session, event)
  forwarder.dispose(session)
  return { soc, restricted }
}

/** Every sentinel that appears anywhere in a lane's serialized records. */
function leaked(records: readonly OcsfRecord[]): string[] {
  const serialized = records.map(record => JSON.stringify(record)).join('\n')
  return Object.entries(SENTINELS)
    .filter(([, value]) => serialized.includes(value))
    .map(([surface]) => surface)
}

describe('the SOC lane privacy invariant', () => {
  it('carries no raw argument value, message text, or command line from any surface', () => {
    // The schedule id is a durable record identifier a SOC pivots on, not
    // content, and is emitted verbatim by design; it is in the table so that
    // this assertion is a list of deliberate exceptions rather than a bare set.
    expect(leaked(run().soc)).toEqual(['scheduleId'])
  })

  it('puts every one of those values in front of the lane, so the search is not searching for nothing', () => {
    // The restricted lane is the same records plus the verbatim payload. If a
    // sentinel is missing here, the event carrying it never reached a mapper
    // and the SOC-lane assertion above proved nothing about that surface.
    expect(leaked(run().restricted).sort()).toEqual(Object.keys(SENTINELS).sort())
  })

  it('holds when a deployment opens one category, and opens only that one', () => {
    // `commandLine` covers both surfaces a command line arrives on: a shell
    // tool's `command` and a code tool's `code`.
    expect(leaked(run({ privacy: { commandLine: 'full' } }).soc).sort()).toEqual(['code', 'command', 'scheduleId'])
    expect(leaked(run({ privacy: { url: 'full' } }).soc).sort()).toEqual(['scheduleId', 'urlQuery'])
  })

  it('carries the whole argument record only under the argument policy that says so', () => {
    const opened = leaked(run({ privacy: { argumentValues: 'full' } }).soc).sort()
    expect(opened).toEqual([
      'apiArgument', 'code', 'command', 'fileBody', 'grepPattern', 'mcpArgument', 'scheduleId', 'urlQuery',
    ])
    // Opening the argument record does not open the command-line surfaces it
    // overlaps: `process.cmd_line` and its observable stay digested.
    const processRecords = run({ privacy: { argumentValues: 'full' } }).soc
      .filter(record => record.process?.cmd_line !== undefined)
    expect(processRecords.length).toBeGreaterThan(0)
    for (const record of processRecords) {
      expect(record.process?.cmd_line).toMatch(/^hmac-sha256:/)
      for (const item of record.observables ?? []) {
        if (item.name === 'process.cmd_line') expect(item.value).toMatch(/^hmac-sha256:/)
      }
    }
  })
})
