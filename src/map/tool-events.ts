/**
 * Mapping of the four tool events, and the correlation that joins each call to
 * its result.
 *
 * A `tool/result` carries no top-level call id: it is read from
 * `data.message.source.callId`, with `data.message.content[0].toolCallId` as
 * the fallback. Both are checked because either can be the only one present in
 * a replayed log written by a different build.
 * @module map/tool-events
 */

import type { ResolvedConfig } from '../config.ts'
import type { SessionState, PendingCall } from '../correlate.ts'
import { SEVERITY, STATUS } from '../ocsf/constants.ts'
import type { EventMapping } from '../ocsf/record.ts'
import type { JsonValue } from '../ocsf/types.ts'
import { readNested, readNumber, readRecord, readString } from '../read.ts'
import { classifyTool, ocsfClassOf, parseArguments, toolDetails, type ParsedArguments, type ToolClass } from './tools.ts'

/** The correlation id joining every record of one tool call. */
export function callCorrelationUid(sessionId: string, callId: string): string {
  return `${sessionId}:${callId}`
}

/** Arguments of a code-mode sub-dispatch arrive already parsed, not as a JSON string. */
function argumentsOf(data: unknown): ParsedArguments {
  const raw = readRecord(data)?.['arguments']
  if (typeof raw === 'string') return parseArguments(raw)
  const record = readRecord(raw)
  return record === undefined ? { error: 'tool arguments are not a JSON object' } : { record }
}

/** The `api` object for tools that map to API Activity; other classes carry none. */
function apiOf(toolClass: ToolClass, toolName: string): { operation: string } | undefined {
  return toolClass === 'api' ? { operation: `tool:${toolName}` } : undefined
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
  const details = toolDetails(name, toolClass, argumentsOf(event.data), config)
  const api = apiOf(toolClass, name)
  state.openCall({ callId, name, toolClass, time: event.time, seq: event.seq, turn, step })
  return {
    classUid,
    activityId,
    severityId: SEVERITY.informational,
    statusId: STATUS.unknown,
    message: `tool call ${name}`,
    correlationUid: callCorrelationUid(sessionId, callId),
    ...details.process === undefined ? {} : { process: details.process },
    ...details.file === undefined ? {} : { file: details.file },
    ...details.httpRequest === undefined ? {} : { httpRequest: details.httpRequest },
    ...api === undefined ? {} : { api },
    observables: details.observables,
    attributes: { ...details.attributes, turn, step, call_id: callId, phase: 'invoke' },
  }
}

/** Read a tool result's call id from either of the two places it lives. */
export function resultCallId(data: unknown): string | undefined {
  const message = readNested(data, 'message')
  const fromSource = readString(readNested(message, 'source'), 'callId')
  if (fromSource !== undefined) return fromSource
  const content = readRecord(message)?.['content']
  const first = Array.isArray(content) ? content[0] : undefined
  return readString(first, 'toolCallId')
}

/** Whether a tool result reported failure. */
function resultIsError(data: unknown): boolean {
  const content = readRecord(readNested(data, 'message'))?.['content']
  const first = Array.isArray(content) ? content[0] : undefined
  return readRecord(first)?.['isError'] === true
}

/** The closed-call fields shared by `tool/result` and `tool/code-dispatch`. */
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
  return {
    classUid,
    activityId,
    severityId: isError ? SEVERITY.medium : SEVERITY.informational,
    statusId: isError ? STATUS.failure : STATUS.success,
    ...error === undefined ? {} : { statusDetail: `${String(error['name'])}: ${String(error['code'])}` },
    message: `tool result ${name}`,
    correlationUid: callCorrelationUid(sessionId, callId),
    ...call === undefined ? {} : { startTime: call.time, duration: Math.max(0, event.time - call.time) },
    ...toolClass === 'api' ? { api: { operation: `tool:${name}` } } : {},
    attributes: {
      tool: name,
      tool_class: toolClass,
      call_id: callId,
      phase: 'complete',
      is_error: isError,
      turn: readNumber(event.data, 'turn') ?? call?.turn ?? 0,
      step: readNumber(event.data, 'step') ?? call?.step ?? 0,
      ...call === undefined ? { unpaired: true } : { call_seq: call.seq },
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
 * Map a `tool/code-dispatch-start`: one tool call issued from inside a
 * `run_code` program.
 * @param sessionId - the session the event belongs to.
 * @param event - the event's `seq`, `time`, and payload.
 * @param state - the session's correlation state.
 * @param config - the resolved configuration.
 * @returns the record mapping, or `undefined` when the payload has no sub-call id.
 */
export function mapCodeDispatchStart(
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
  const details = toolDetails(name, toolClass, argumentsOf(event.data), config)
  state.openCall({ callId: subCallId, name, toolClass, time: event.time, seq: event.seq, turn: 0, step: 0 })
  return {
    classUid,
    activityId,
    severityId: SEVERITY.informational,
    statusId: STATUS.unknown,
    message: `code-mode sub-call ${name}`,
    correlationUid: callCorrelationUid(sessionId, subCallId),
    ...details.process === undefined ? {} : { process: details.process },
    ...details.file === undefined ? {} : { file: details.file },
    ...details.httpRequest === undefined ? {} : { httpRequest: details.httpRequest },
    ...toolClass === 'api' ? { api: { operation: `tool:${name}` } } : {},
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
 * Map a `tool/code-dispatch`: one code-mode sub-call settling.
 * @param sessionId - the session the event belongs to.
 * @param event - the event's `seq`, `time`, and payload.
 * @param state - the session's correlation state.
 * @param config - the resolved configuration.
 * @returns the record mapping, or `undefined` when the payload has no sub-call id.
 */
export function mapCodeDispatch(
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
  return {
    classUid,
    activityId,
    severityId: SEVERITY.low,
    statusId: STATUS.unknown,
    message: `tool call ${call.name} never settled`,
    correlationUid: callCorrelationUid(sessionId, call.callId),
    startTime: call.time,
    duration: Math.max(0, time - call.time),
    ...call.toolClass === 'api' ? { api: { operation: `tool:${call.name}` } } : {},
    attributes: {
      tool: call.name,
      tool_class: call.toolClass,
      call_id: call.callId,
      phase: 'unresolved',
      unresolved: true,
      turn: call.turn,
      step: call.step,
      call_seq: call.seq,
    },
  }
}
