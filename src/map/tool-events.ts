/**
 * Mapping of the four tool events, and the correlation that joins each call to
 * its result.
 *
 * A `tool/result` carries no top-level call id, and the message it does carry
 * changed shape inside the supported peer range. Through the `0.1.5` line the
 * result message was a user-role message whose single content block held
 * `toolCallId` and `isError`; from `0.1.7` it is a tool-role message carrying
 * both at the top of the message. Every reader here checks both placements,
 * because the range admits builds on either side and a resumed log can carry
 * events written by either.
 * @module map/tool-events
 */

import type { ResolvedConfig } from '../config.ts'
import type { SessionState, PendingCall } from '../correlate.ts'
import { SEVERITY, STATUS } from '../ocsf/constants.ts'
import type { EventMapping } from '../ocsf/record.ts'
import type { JsonValue } from '../ocsf/types.ts'
import { readNested, readNumber, readRecord, readString } from '../read.ts'
import {
  DELEGATION_COVERAGE,
  apiOf,
  classifyTool,
  ocsfClassOf,
  parseArguments,
  RUNTIME_INSTALL_APPLICATION,
  parseMcpToolName,
  runtimeInstallDetails,
  toolDetails,
  type ParsedArguments,
  type ToolClass,
} from './tools.ts'

/**
 * The correlation id joining every record of one tool call.
 *
 * It is also the `process.uid` of a call that launches or ends a process: the
 * OCSF `process` object constrains `at_least_one: [pid, uid, cpid]`, and the
 * harness never reports the child's OS pid, so the identifier is the one the
 * schema defines for a producer to assign — "a unique identifier for this
 * process assigned by the producer (tool)", which the launch and the settlement
 * records both carry.
 */
export function callCorrelationUid(sessionId: string, callId: string): string {
  return `${sessionId}:${callId}`
}

/** Arguments of a PTC-mode sub-dispatch arrive already parsed, not as a JSON string. */
function argumentsOf(data: unknown): ParsedArguments {
  const raw = readRecord(data)?.['arguments']
  if (typeof raw === 'string') return parseArguments(raw)
  const record = readRecord(raw)
  return record === undefined ? { error: 'tool arguments are not a JSON object' } : { record }
}

/**
 * The extension attributes every record of one tool call repeats, so a
 * `tool/result` is filterable on the same keys as its `tool/call`.
 * @param toolClass - the tool's class.
 * @param toolName - the tool name the model called.
 * @param delegationProvider - the harness a delegation tool hands the task to.
 * @returns MCP attribution and delegation attributes, where they apply.
 */
function identityAttributes(
  toolClass: ToolClass,
  toolName: string,
  delegationProvider: string | undefined,
): Readonly<Record<string, JsonValue>> {
  const mcp = parseMcpToolName(toolName)
  return {
    ...mcp === undefined ? {} : { mcp_server: mcp.server, mcp_tool: mcp.tool },
    ...toolClass !== 'delegation-external' ? {} : {
      delegation_provider: delegationProvider ?? 'unknown',
      delegation_boundary: true,
      delegation_coverage: DELEGATION_COVERAGE,
    },
  }
}

/**
 * The class-required object a settled or abandoned call carries.
 *
 * Every OCSF class this plugin emits requires its own subject object on every
 * record of that class, so a `tool/result` needs the `process`, `file`, or
 * `http_request` its `tool/call` built. The call's object is reused when the
 * pair is intact; a result whose call was never observed still gets a
 * name-only object, because a record missing it is not a valid record.
 * @param toolClass - the tool's class.
 * @param name - the tool name.
 * @param call - the paired call, when it was observed.
 * @param processUid - `process.uid` when the call's own object is unavailable.
 * @returns the `process`, `file`, or `httpRequest` field for the mapping.
 */
function subjectOf(
  toolClass: ToolClass,
  name: string,
  call: PendingCall | undefined,
  processUid: string,
): Pick<EventMapping, 'process' | 'file' | 'httpRequest'> {
  if (toolClass === 'process-launch' || toolClass === 'process-terminate' || toolClass === 'delegation-external') {
    return { process: call?.process ?? { name, uid: processUid } }
  }
  if (toolClass === 'file-read' || toolClass === 'file-write' || toolClass === 'file-update') {
    return { file: call?.file ?? { name, type_id: 1 } }
  }
  if (toolClass === 'http') {
    return { httpRequest: call?.httpRequest ?? { http_method: 'GET' } }
  }
  return {}
}

/**
 * Map a `tool/call`, opening the correlation entry its result will close.
 * @param sessionId - the session the event belongs to.
 * @param event - the event's `seq`, `time`, and payload.
 * @param state - the session's correlation state.
 * @param config - the resolved configuration.
 * @returns the record mapping, or `undefined` when the payload has no tool name.
 */
export function mapToolCall(
  sessionId: string,
  event: { seq: number; time: number; data: unknown },
  state: SessionState,
  config: ResolvedConfig,
): EventMapping | undefined {
  const name = readString(event.data, 'name')
  const callId = readString(event.data, 'callId')
  if (name === undefined || callId === undefined) return undefined
  const toolClass = classifyTool(name, config)
  const { classUid, activityId } = ocsfClassOf(toolClass)
  const turn = readNumber(event.data, 'turn') ?? 0
  const step = readNumber(event.data, 'step') ?? 0
  const correlationUid = callCorrelationUid(sessionId, callId)
  const details = toolDetails(name, toolClass, argumentsOf(event.data), config, correlationUid)
  const api = apiOf(toolClass, name)
  state.openCall({
    callId, name, toolClass, time: event.time, seq: event.seq, turn, step,
    ...config.delegationTools[name] === undefined ? {} : { delegationProvider: config.delegationTools[name] },
    ...details.process === undefined ? {} : { process: details.process },
    ...details.file === undefined ? {} : { file: details.file },
    ...details.httpRequest === undefined ? {} : { httpRequest: details.httpRequest },
  })
  const delegating = toolClass === 'delegation-external'
  return {
    classUid,
    activityId,
    // A delegation call is the last thing this plugin will see of the work it
    // starts, so it is graded high rather than left to look like any other call.
    severityId: delegating ? SEVERITY.high : SEVERITY.informational,
    statusId: STATUS.unknown,
    message: delegating
      ? `tool call ${name} delegates to ${config.delegationTools[name] ?? 'an external harness'}; `
        + 'session telemetry coverage ends at this boundary'
      : `tool call ${name}`,
    correlationUid,
    ...details.process === undefined ? {} : { process: details.process },
    ...details.file === undefined ? {} : { file: details.file },
    ...details.httpRequest === undefined ? {} : { httpRequest: details.httpRequest },
    ...api === undefined ? {} : { api },
    ...toolClass !== 'runtime-install' ? {} : { application: RUNTIME_INSTALL_APPLICATION },
    observables: details.observables,
    attributes: { ...details.attributes, turn, step, call_id: callId, phase: 'invoke' },
  }
}

/** Read a tool result's call id from any of the three places it lives. */
export function resultCallId(data: unknown): string | undefined {
  const message = readNested(data, 'message')
  const fromSource = readString(readNested(message, 'source'), 'callId')
  if (fromSource !== undefined) return fromSource
  const fromMessage = readString(message, 'toolCallId')
  if (fromMessage !== undefined) return fromMessage
  const content = readRecord(message)?.['content']
  const first = Array.isArray(content) ? content[0] : undefined
  return readString(first, 'toolCallId')
}

/**
 * Whether a tool result reported failure.
 *
 * `isError` moved from the result block to the message itself between the
 * `0.1.5` and `0.1.7` lines, both of which the peer range admits. Reading only
 * the older placement graded every failed tool call on a newer harness a
 * success — a refused sandbox escalation among them — so both are read and
 * either one saying so is a failure.
 * @param data - the `tool/result` payload.
 * @returns true when the invocation failed.
 */
function resultIsError(data: unknown): boolean {
  const message = readNested(data, 'message')
  if (readRecord(message)?.['isError'] === true) return true
  const content = readRecord(message)?.['content']
  const first = Array.isArray(content) ? content[0] : undefined
  return readRecord(first)?.['isError'] === true
}

/** The closed-call fields shared by `tool/result` and `tool/ptc-dispatch`. */
function settle(
  sessionId: string,
  event: { seq: number; time: number; data: unknown },
  call: PendingCall | undefined,
  callId: string,
  isError: boolean,
  fallbackName: string,
  config: ResolvedConfig,
  extra: Readonly<Record<string, JsonValue>>,
): EventMapping {
  const toolClass = call?.toolClass ?? classifyTool(fallbackName, config)
  const { classUid, activityId } = ocsfClassOf(toolClass)
  const name = call?.name ?? fallbackName
  const error = readNested(event.data, 'error')
  const api = apiOf(toolClass, name)
  const correlationUid = callCorrelationUid(sessionId, callId)
  // A runtime install reports what it installed in its result rather than in
  // its arguments, which the tool declares as empty.
  const install = toolClass === 'runtime-install' ? runtimeInstallDetails(event.data, isError) : undefined
  return {
    classUid,
    activityId,
    severityId: isError ? SEVERITY.medium : SEVERITY.informational,
    statusId: isError ? STATUS.failure : STATUS.success,
    ...error === undefined ? {} : { statusDetail: `${String(error['name'])}: ${String(error['code'])}` },
    message: `tool result ${name}`,
    correlationUid,
    ...call === undefined ? {} : { startTime: call.time, duration: Math.max(0, event.time - call.time) },
    ...api === undefined ? {} : { api },
    ...install?.application === undefined ? {} : { application: install.application },
    ...install === undefined ? {} : { observables: install.observables },
    ...subjectOf(toolClass, name, call, correlationUid),
    attributes: {
      tool: name,
      tool_class: toolClass,
      call_id: callId,
      phase: 'complete',
      is_error: isError,
      turn: readNumber(event.data, 'turn') ?? call?.turn ?? 0,
      step: readNumber(event.data, 'step') ?? call?.step ?? 0,
      ...identityAttributes(toolClass, name, call?.delegationProvider ?? config.delegationTools[name]),
      ...call === undefined ? { unpaired: true } : { call_seq: call.seq },
      ...install?.attributes,
      ...extra,
    },
  }
}

/**
 * Map a `tool/result`, closing the correlation entry its call opened.
 * @param sessionId - the session the event belongs to.
 * @param event - the event's `seq`, `time`, and payload.
 * @param state - the session's correlation state.
 * @param config - the resolved configuration.
 * @returns the record mapping, or `undefined` when no call id can be read.
 */
export function mapToolResult(
  sessionId: string,
  event: { seq: number; time: number; data: unknown },
  state: SessionState,
  config: ResolvedConfig,
): EventMapping | undefined {
  const callId = resultCallId(event.data)
  if (callId === undefined) return undefined
  const call = state.closeCall(callId)
  return settle(sessionId, event, call, callId, resultIsError(event.data), 'unknown', config, {})
}

/**
 * Map a `tool/ptc-dispatch-start`: one tool call issued from inside a
 * `run_code` program.
 *
 * The harness renamed this type from `tool/code-dispatch-start` in the
 * session format's v3-to-v4 migration; the dispatcher routes both names here
 * because the peer range admits builds on either side of that rename, and the
 * payload fields are unchanged.
 * @param sessionId - the session the event belongs to.
 * @param event - the event's `seq`, `time`, and payload.
 * @param state - the session's correlation state.
 * @param config - the resolved configuration.
 * @returns the record mapping, or `undefined` when the payload has no sub-call id.
 */
export function mapPtcDispatchStart(
  sessionId: string,
  event: { seq: number; time: number; data: unknown },
  state: SessionState,
  config: ResolvedConfig,
): EventMapping | undefined {
  const name = readString(event.data, 'name')
  const subCallId = readString(event.data, 'subCallId')
  if (name === undefined || subCallId === undefined) return undefined
  const toolClass = classifyTool(name, config)
  const { classUid, activityId } = ocsfClassOf(toolClass)
  const correlationUid = callCorrelationUid(sessionId, subCallId)
  const details = toolDetails(name, toolClass, argumentsOf(event.data), config, correlationUid)
  const api = apiOf(toolClass, name)
  state.openCall({
    callId: subCallId, name, toolClass, time: event.time, seq: event.seq, turn: 0, step: 0,
    ...config.delegationTools[name] === undefined ? {} : { delegationProvider: config.delegationTools[name] },
    ...details.process === undefined ? {} : { process: details.process },
    ...details.file === undefined ? {} : { file: details.file },
    ...details.httpRequest === undefined ? {} : { httpRequest: details.httpRequest },
  })
  return {
    classUid,
    activityId,
    severityId: toolClass === 'delegation-external' ? SEVERITY.high : SEVERITY.informational,
    statusId: STATUS.unknown,
    message: `ptc-mode sub-call ${name}`,
    correlationUid,
    ...details.process === undefined ? {} : { process: details.process },
    ...details.file === undefined ? {} : { file: details.file },
    ...details.httpRequest === undefined ? {} : { httpRequest: details.httpRequest },
    ...api === undefined ? {} : { api },
    ...toolClass !== 'runtime-install' ? {} : { application: RUNTIME_INSTALL_APPLICATION },
    observables: details.observables,
    attributes: {
      ...details.attributes,
      call_id: subCallId,
      phase: 'invoke',
      parent_call_id: readString(event.data, 'parentCallId') ?? '',
      root_call_id: readString(event.data, 'rootCallId') ?? '',
    },
  }
}

/**
 * Map a `tool/ptc-dispatch`: one PTC-mode sub-call settling.
 *
 * Renamed from `tool/code-dispatch` by the same migration as its start event.
 * @param sessionId - the session the event belongs to.
 * @param event - the event's `seq`, `time`, and payload.
 * @param state - the session's correlation state.
 * @param config - the resolved configuration.
 * @returns the record mapping, or `undefined` when the payload has no sub-call id.
 */
export function mapPtcDispatch(
  sessionId: string,
  event: { seq: number; time: number; data: unknown },
  state: SessionState,
  config: ResolvedConfig,
): EventMapping | undefined {
  const subCallId = readString(event.data, 'subCallId')
  if (subCallId === undefined) return undefined
  const call = state.closeCall(subCallId)
  return settle(
    sessionId,
    event,
    call,
    subCallId,
    readRecord(event.data)?.['isError'] === true,
    readString(event.data, 'name') ?? 'unknown',
    config,
    { parent_call_id: readString(event.data, 'parentCallId') ?? '' },
  )
}

/**
 * Map one tool call that never settled, flushed when the session is disposed.
 * @param sessionId - the session the call belongs to.
 * @param call - the pending call.
 * @param time - when the flush happens.
 * @returns a record mapping with an unknown status.
 */
export function mapUnresolvedCall(sessionId: string, call: PendingCall, time: number): EventMapping {
  const { classUid, activityId } = ocsfClassOf(call.toolClass)
  const api = apiOf(call.toolClass, call.name)
  const correlationUid = callCorrelationUid(sessionId, call.callId)
  return {
    classUid,
    activityId,
    severityId: SEVERITY.low,
    statusId: STATUS.unknown,
    message: `tool call ${call.name} never settled`,
    correlationUid,
    startTime: call.time,
    duration: Math.max(0, time - call.time),
    ...api === undefined ? {} : { api },
    ...call.toolClass !== 'runtime-install' ? {} : { application: RUNTIME_INSTALL_APPLICATION },
    ...subjectOf(call.toolClass, call.name, call, correlationUid),
    attributes: {
      tool: call.name,
      tool_class: call.toolClass,
      call_id: call.callId,
      phase: 'unresolved',
      unresolved: true,
      turn: call.turn,
      step: call.step,
      call_seq: call.seq,
      ...identityAttributes(call.toolClass, call.name, call.delegationProvider),
    },
  }
}
