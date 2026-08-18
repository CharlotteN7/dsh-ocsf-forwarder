/**
 * Mapping of the agent-loop, model, and lifecycle events: turns, steps,
 * messages, request routing, hooks, subagents, workflows, compaction, and
 * scheduled jobs — plus the generic fallback every remaining event type takes.
 * @module map/lifecycle
 */

import type { ResolvedConfig } from '../config.ts'
import type { SessionState } from '../correlate.ts'
import { ACTIVITY, AI_ROLE, CLASS, SEVERITY, STATUS } from '../ocsf/constants.ts'
import type { EventMapping } from '../ocsf/record.ts'
import type { JsonValue } from '../ocsf/types.ts'
import { readArrayLength, readNested, readNumber, readRecord, readString } from '../read.ts'
import { summariseText } from '../privacy.ts'

/** How a turn's end reason grades as an OCSF outcome. */
const TURN_END_OUTCOMES: Readonly<Record<string, { statusId: number; severityId: number }>> = Object.freeze({
  completed: { statusId: STATUS.success, severityId: SEVERITY.informational },
  'max-tokens': { statusId: STATUS.success, severityId: SEVERITY.low },
  aborted: { statusId: STATUS.failure, severityId: SEVERITY.low },
  blocked: { statusId: STATUS.failure, severityId: SEVERITY.medium },
  interrupted: { statusId: STATUS.failure, severityId: SEVERITY.medium },
  error: { statusId: STATUS.failure, severityId: SEVERITY.high },
})

/** The correlation id joining a turn's start and end. */
export function turnCorrelationUid(sessionId: string, turn: number): string {
  return `${sessionId}:turn:${turn}`
}

/** The correlation id joining a step's start and end. */
export function stepCorrelationUid(sessionId: string, turn: number, step: number): string {
  return `${sessionId}:${turn}:${step}`
}

/**
 * Concatenated text of a message's content blocks; other block types contribute
 * nothing.
 * @param message - a message-shaped payload, or anything else.
 * @returns the concatenated text, empty when the value carries none.
 */
export function messageText(message: unknown): string {
  const content = readRecord(message)?.['content']
  if (!Array.isArray(content)) return ''
  return content.map(block => readString(block, 'text') ?? '').join('')
}

/**
 * Map `turn/start`.
 * @param sessionId - the session the event belongs to.
 * @param event - the event's `time` and payload.
 * @param state - the session's correlation state.
 * @returns the record mapping.
 */
export function mapTurnStart(
  sessionId: string,
  event: { time: number; data: unknown },
  state: SessionState,
): EventMapping {
  const turn = readNumber(event.data, 'turn') ?? 0
  state.openTurn(turn, event.time)
  return {
    classUid: CLASS.apiActivity,
    activityId: ACTIVITY.api.create,
    severityId: SEVERITY.informational,
    statusId: STATUS.unknown,
    message: `turn ${turn} started`,
    correlationUid: turnCorrelationUid(sessionId, turn),
    api: { operation: 'turn' },
    attributes: { turn, phase: 'start' },
  }
}

/**
 * Map `turn/end`, taking the outcome from the merge-extensible
 * {@link TurnEndReason} discriminant.
 * @param sessionId - the session the event belongs to.
 * @param event - the event's `time` and payload.
 * @param state - the session's correlation state.
 * @param config - the resolved configuration, for the failure-message digest.
 * @returns the record mapping.
 */
export function mapTurnEnd(
  sessionId: string,
  event: { time: number; data: unknown },
  state: SessionState,
  config: ResolvedConfig,
): EventMapping {
  const turn = readNumber(event.data, 'turn') ?? 0
  const reason = readNested(event.data, 'reason')
  const kind = readString(reason, 'kind') ?? 'unknown'
  // `TurnEndReasonMap` is merge-extensible: an unrecognized kind is graded
  // unknown rather than rejected.
  const graded = TURN_END_OUTCOMES[kind] ?? { statusId: STATUS.unknown, severityId: SEVERITY.informational }
  const started = state.closeTurn(turn)
  const failure = readNested(reason, 'error')
  const cancelCause = readString(readNested(reason, 'reason'), 'kind')
  // A provider failure message is a flattened error chain: URLs, request ids,
  // file paths, and whatever the far end echoed back of the request. Only its
  // code is a bounded value, so the text is reduced to a digest that still
  // groups repeat failures.
  const failureText = failure === undefined ? undefined : summariseText(String(failure['message'] ?? ''), config)
  return {
    classUid: CLASS.apiActivity,
    activityId: ACTIVITY.api.create,
    severityId: graded.severityId,
    statusId: graded.statusId,
    statusDetail: kind,
    message: `turn ${turn} ended: ${kind}`,
    correlationUid: turnCorrelationUid(sessionId, turn),
    api: { operation: 'turn' },
    ...started === undefined ? {} : { startTime: started, duration: Math.max(0, event.time - started) },
    attributes: {
      turn,
      phase: 'end',
      end_reason: kind,
      ...cancelCause === undefined ? {} : { cancel_cause: cancelCause },
      ...failure === undefined || failureText === undefined ? {} : {
        error_code: String(failure['code'] ?? 'UNKNOWN'),
        error_message_digest: failureText.digest,
        error_message_length: failureText.length,
      },
    },
  }
}

/**
 * Map `step/start`.
 * @param sessionId - the session the event belongs to.
 * @param event - the event's `time` and payload.
 * @param state - the session's correlation state.
 * @returns the record mapping.
 */
export function mapStepStart(
  sessionId: string,
  event: { time: number; data: unknown },
  state: SessionState,
): EventMapping {
  const turn = readNumber(event.data, 'turn') ?? 0
  const step = readNumber(event.data, 'step') ?? 0
  state.openStep(turn, step, event.time)
  return {
    classUid: CLASS.apiActivity,
    activityId: ACTIVITY.api.read,
    severityId: SEVERITY.informational,
    statusId: STATUS.unknown,
    message: `step ${turn}:${step} started`,
    correlationUid: stepCorrelationUid(sessionId, turn, step),
    api: { operation: 'llm.step' },
    attributes: { turn, step, phase: 'start' },
  }
}

/**
 * Map `step/end`.
 * @param sessionId - the session the event belongs to.
 * @param event - the event's `time` and payload.
 * @param state - the session's correlation state.
 * @returns the record mapping.
 */
export function mapStepEnd(
  sessionId: string,
  event: { time: number; data: unknown },
  state: SessionState,
): EventMapping {
  const turn = readNumber(event.data, 'turn') ?? 0
  const step = readNumber(event.data, 'step') ?? 0
  const started = state.closeStep(turn, step)
  return {
    classUid: CLASS.apiActivity,
    activityId: ACTIVITY.api.read,
    severityId: SEVERITY.informational,
    statusId: STATUS.success,
    message: `step ${turn}:${step} ended`,
    correlationUid: stepCorrelationUid(sessionId, turn, step),
    api: { operation: 'llm.step' },
    ...started === undefined ? {} : { startTime: started, duration: Math.max(0, event.time - started) },
    attributes: { turn, step, phase: 'end' },
  }
}

/**
 * Map `assistant/message`: one model completion, with its token accounting.
 * @param sessionId - the session the event belongs to.
 * @param event - the event's payload.
 * @param config - the resolved configuration, for the text digest.
 * @returns the record mapping.
 */
export function mapAssistantMessage(
  sessionId: string,
  event: { data: unknown },
  config: ResolvedConfig,
): EventMapping {
  const turn = readNumber(event.data, 'turn') ?? 0
  const step = readNumber(event.data, 'step') ?? 0
  const usage = readNested(event.data, 'usage')
  const input = readNumber(usage, 'inputTokens')
  const output = readNumber(usage, 'outputTokens')
  const text = summariseText(messageText(readNested(event.data, 'message')), config)
  return {
    classUid: CLASS.apiActivity,
    activityId: ACTIVITY.api.read,
    severityId: SEVERITY.informational,
    statusId: STATUS.success,
    message: 'model completion',
    correlationUid: stepCorrelationUid(sessionId, turn, step),
    api: { operation: 'llm.completion' },
    messageContext: {
      ai_role_id: AI_ROLE.assistant,
      ...input === undefined ? {} : { prompt_tokens: input },
      ...output === undefined ? {} : { completion_tokens: output },
      ...input === undefined || output === undefined ? {} : { total_tokens: input + output },
    },
    attributes: {
      turn,
      step,
      text_digest: text.digest,
      text_length: text.length,
      ...readNumber(usage, 'reasoningTokens') === undefined ? {} : { reasoning_tokens: readNumber(usage, 'reasoningTokens') as number },
    },
  }
}

/**
 * Map `user/message`: a human prompt or an injected context, distinguished by
 * the message source.
 * @param event - the event's payload.
 * @param config - the resolved configuration, for the text digest.
 * @returns the record mapping.
 */
export function mapUserMessage(event: { data: unknown }, config: ResolvedConfig): EventMapping {
  const source = readString(readNested(event.data, 'source'), 'kind') ?? 'unknown'
  const text = summariseText(messageText(event.data), config)
  return {
    classUid: CLASS.apiActivity,
    activityId: ACTIVITY.api.create,
    severityId: SEVERITY.informational,
    statusId: STATUS.success,
    message: `user-role message (${source})`,
    api: { operation: 'llm.prompt' },
    messageContext: { ai_role_id: AI_ROLE.user },
    attributes: {
      message_source: source,
      text_digest: text.digest,
      text_length: text.length,
    },
  }
}

/**
 * Map `request/context`, folding the session's model route so every later
 * record reports the model that produced it.
 * @param event - the event's payload.
 * @param state - the session's correlation state.
 * @returns the record mapping.
 */
export function mapRequestContext(event: { data: unknown }, state: SessionState): EventMapping {
  const provider = readString(event.data, 'provider') ?? 'unknown'
  const model = readString(event.data, 'model') ?? 'unknown'
  state.aiModel = { name: model, ai_provider: provider }
  return {
    classUid: CLASS.applicationLifecycle,
    activityId: ACTIVITY.applicationLifecycle.update,
    severityId: SEVERITY.informational,
    statusId: STATUS.success,
    message: `model route ${provider}/${model}`,
    attributes: {
      provider,
      model,
      ...readNumber(event.data, 'contextWindow') === undefined ? {} : { context_window: readNumber(event.data, 'contextWindow') as number },
    },
  }
}

/**
 * Map `request/header`: the agent's capability set for the next request. Tool
 * *names* and a system-prompt digest are recorded; the prompt text and the
 * tool schemas are not.
 * @param event - the event's payload.
 * @param config - the resolved configuration, for the prompt digest.
 * @returns the record mapping.
 */
export function mapRequestHeader(event: { data: unknown }, config: ResolvedConfig): EventMapping {
  const header = readNested(event.data, 'header')
  const tools = readRecord(header)?.['tools']
  const names = Array.isArray(tools)
    ? tools.map(tool => readString(tool, 'name') ?? 'unknown')
    : []
  const system = readString(header, 'system')
  const prompt = system === undefined ? undefined : summariseText(system, config)
  const model = readString(readNested(header, 'config'), 'model')
  return {
    classUid: CLASS.applicationLifecycle,
    activityId: ACTIVITY.applicationLifecycle.update,
    severityId: SEVERITY.informational,
    statusId: STATUS.success,
    message: 'request header snapshot',
    attributes: {
      reason: readString(event.data, 'reason') ?? 'unknown',
      tool_count: names.length,
      tools: names as JsonValue,
      ...model === undefined ? {} : { model },
      ...prompt === undefined ? {} : { system_prompt_digest: prompt.digest, system_prompt_length: prompt.length },
    },
  }
}

/** The correlation id joining one hook's invocation and its result. */
export function hookCorrelationUid(sessionId: string, handlerId: string): string {
  return `${sessionId}:hook:${handlerId}`
}

/**
 * Map `hook/invoked`: a hook command is a subprocess the harness launched on
 * the agent's behalf.
 *
 * The payload never carries the child's OS pid, and the `process` object
 * constrains `at_least_one: [pid, uid, cpid]`, so `process.uid` is the
 * correlation id — the producer-assigned identifier the schema defines, shared
 * with the `hook/result` record describing the same subprocess.
 * @param sessionId - the session the event belongs to.
 * @param event - the event's payload.
 * @returns the record mapping.
 */
export function mapHookInvoked(sessionId: string, event: { data: unknown }): EventMapping {
  const handlerId = readString(event.data, 'handlerId') ?? 'unknown'
  const point = readString(event.data, 'point') ?? 'unknown'
  return {
    classUid: CLASS.processActivity,
    activityId: ACTIVITY.process.launch,
    severityId: SEVERITY.informational,
    statusId: STATUS.unknown,
    message: `hook ${point} invoked`,
    correlationUid: hookCorrelationUid(sessionId, handlerId),
    process: { name: point, uid: hookCorrelationUid(sessionId, handlerId) },
    attributes: {
      hook_point: point,
      handler_id: handlerId,
      dialect: readString(event.data, 'dialect') ?? 'unknown',
      turn: readNumber(event.data, 'turn') ?? 0,
      phase: 'invoked',
      ...readString(event.data, 'matcher') === undefined ? {} : { matcher: readString(event.data, 'matcher') as string },
    },
  }
}

/**
 * Blocking decisions the hook protocol defines. `hook/result.decision` is
 * typed `string` because it is folded from hook-authored JSON, so anything
 * outside this set is recorded as `other` rather than copied.
 */
const HOOK_DECISIONS: ReadonlySet<string> = new Set(['approve', 'allow', 'block', 'deny', 'ask'])

/** One hook decision reduced to the protocol's vocabulary. */
function hookDecision(reported: string | undefined): string {
  if (reported === undefined) return 'unknown'
  return HOOK_DECISIONS.has(reported) ? reported : 'other'
}

/**
 * Map `hook/result`: the paired hook outcome.
 * @param sessionId - the session the event belongs to.
 * @param event - the event's payload.
 * @param config - the resolved configuration, for the decision digest.
 * @returns the record mapping.
 */
export function mapHookResult(sessionId: string, event: { data: unknown }, config: ResolvedConfig): EventMapping {
  const handlerId = readString(event.data, 'handlerId') ?? 'unknown'
  const point = readString(event.data, 'point') ?? 'unknown'
  const reported = readString(event.data, 'decision')
  const decision = hookDecision(reported)
  const exitCode = readNumber(event.data, 'exitCode')
  const failed = decision === 'deny' || decision === 'block' || (exitCode !== undefined && exitCode !== 0)
  // A hook that reports what it found — a DLP hook naming the secret it
  // matched, for instance — writes that finding into `decision`, which the
  // protocol types as a free string.
  const detail = reported === undefined || decision !== 'other' ? undefined : summariseText(reported, config)
  return {
    classUid: CLASS.processActivity,
    activityId: ACTIVITY.process.terminate,
    severityId: failed ? SEVERITY.medium : SEVERITY.informational,
    statusId: failed ? STATUS.failure : STATUS.success,
    statusDetail: decision,
    message: `hook ${point} decided ${decision}`,
    correlationUid: hookCorrelationUid(sessionId, handlerId),
    process: { name: point, uid: hookCorrelationUid(sessionId, handlerId) },
    // `exit_code` is a Process Activity attribute, not a `process` one.
    ...exitCode === undefined ? {} : { exitCode },
    ...readNumber(event.data, 'durationMs') === undefined ? {} : { duration: readNumber(event.data, 'durationMs') as number },
    attributes: {
      hook_point: point,
      handler_id: handlerId,
      decision,
      turn: readNumber(event.data, 'turn') ?? 0,
      phase: 'result',
      ...detail === undefined ? {} : { decision_digest: detail.digest, decision_length: detail.length },
    },
  }
}

/**
 * Map `subagent/descriptor`: this session is itself a child agent, established
 * under another session's authority.
 *
 * The descriptor is appended to the child's own log and names no session id;
 * the record's own `session_id` is the child, and `dsh.parent_session_id`
 * carries the lineage. `tool-workflow/agent-start` is where a parent names its
 * children, so that is where {@link mapWorkflow} builds the delegation link.
 * @param sessionId - the session the event belongs to, which is the child.
 * @param event - the event's payload.
 * @returns the record mapping.
 */
export function mapSubagentDescriptor(sessionId: string, event: { data: unknown }): EventMapping {
  const mode = readString(event.data, 'mode') ?? 'unknown'
  const provider = readString(event.data, 'provider') ?? 'unknown'
  return {
    classUid: CLASS.applicationLifecycle,
    activityId: ACTIVITY.applicationLifecycle.start,
    // Delegation widens the blast radius of one prompt: a child agent runs
    // its own tools under the parent's authority.
    severityId: SEVERITY.low,
    statusId: STATUS.success,
    message: `subagent established (${mode})`,
    correlationUid: `${sessionId}:subagent`,
    attributes: {
      subagent_mode: mode,
      subagent_provider: provider,
      phase: 'start',
      ...readNumber(event.data, 'version') === undefined ? {} : { descriptor_version: readNumber(event.data, 'version') as number },
    },
  }
}

/** Workflow event types and the lifecycle activity each one records. */
const WORKFLOW_ACTIVITIES: Readonly<Record<string, number>> = Object.freeze({
  'tool-workflow/run-start': ACTIVITY.applicationLifecycle.start,
  'tool-workflow/agent-start': ACTIVITY.applicationLifecycle.start,
  'tool-workflow/run-end': ACTIVITY.applicationLifecycle.stop,
  'tool-workflow/agent-end': ACTIVITY.applicationLifecycle.stop,
})

/**
 * Map one `tool-workflow/*` event.
 * @param eventType - the session event type.
 * @param sessionId - the session the event belongs to.
 * @param event - the event's payload.
 * @returns the record mapping.
 */
export function mapWorkflow(
  eventType: string,
  sessionId: string,
  event: { time: number; data: unknown },
): EventMapping {
  const runId = readString(event.data, 'runId') ?? 'unknown'
  // A run settles with `stopReason`, a member with `outcome`; neither is
  // called `reason`, so reading that name graded every aborted run a success.
  const reason = readString(event.data, 'stopReason') ?? readString(event.data, 'outcome')
  const childId = readString(event.data, 'childId')
  const member = readNumber(event.data, 'seq')
  return {
    classUid: CLASS.applicationLifecycle,
    activityId: WORKFLOW_ACTIVITIES[eventType] ?? ACTIVITY.applicationLifecycle.update,
    severityId: reason !== undefined && reason !== 'completed' ? SEVERITY.low : SEVERITY.informational,
    statusId: reason === undefined || reason === 'completed' ? STATUS.success : STATUS.failure,
    ...reason === undefined ? {} : { statusDetail: reason },
    message: eventType,
    correlationUid: `${sessionId}:workflow:${runId}`,
    ...childId === undefined ? {} : { delegation: { uid: childId, parent_uid: sessionId, created_time: event.time } },
    attributes: {
      run_id: runId,
      event: eventType,
      ...member === undefined ? {} : { member_seq: member },
      ...childId === undefined ? {} : { child_session_id: childId },
      ...readString(event.data, 'name') === undefined ? {} : { name: readString(event.data, 'name') as string },
    },
  }
}

/**
 * Map one `compaction/*` event. `compaction/prune` is recorded as a delete
 * because it removes model-visible history.
 * @param eventType - the session event type.
 * @param sessionId - the session the event belongs to.
 * @param event - the event's `time` and payload.
 * @param state - the session's correlation state, holding the open compaction.
 * @param config - the resolved configuration, for the summary digest.
 * @returns the record mapping.
 */
export function mapCompaction(
  eventType: string,
  sessionId: string,
  event: { time: number; data: unknown },
  state: SessionState,
  config: ResolvedConfig,
): EventMapping {
  const compactionId = readString(event.data, 'compactionId')
  const error = readString(event.data, 'error')
  const shadowed = readNested(event.data, 'shadowedRange')
  const summary = eventType === 'compaction/summary'
    ? summariseText(JSON.stringify(readRecord(event.data)?.['summary'] ?? ''), config)
    : undefined
  if (eventType === 'compaction/start' && compactionId !== undefined) state.openCompaction(compactionId, event.time)
  // How long the compaction lock was held. `compaction/end` is the only event
  // that closes one, and a resumed log can carry an end whose start this
  // process never saw.
  const started = eventType === 'compaction/end' && compactionId !== undefined
    ? state.closeCompaction(compactionId)
    : undefined
  // The summarize call's own route, reported by the backend that made it: the
  // model that wrote a replacement for history is not always the session's.
  const provider = eventType === 'compaction/summary' ? readString(event.data, 'provider') : undefined
  const model = eventType === 'compaction/summary' ? readString(event.data, 'model') : undefined
  // `compaction/prune` carries no compaction id — it is a standalone shadow
  // price, identified by the surface range it replaced.
  const correlationUid = compactionId !== undefined
    ? `${sessionId}:compaction:${compactionId}`
    : shadowed === undefined
      ? undefined
      : `${sessionId}:compaction:range:${String(shadowed['start'] ?? 0)}-${String(shadowed['end'] ?? 0)}`
  return {
    classUid: CLASS.apiActivity,
    activityId: eventType === 'compaction/prune' ? ACTIVITY.api.delete : ACTIVITY.api.update,
    severityId: eventType === 'compaction/prune' ? SEVERITY.low : SEVERITY.informational,
    statusId: error === undefined ? STATUS.success : STATUS.failure,
    ...error === undefined ? {} : { statusDetail: error },
    message: eventType,
    ...correlationUid === undefined ? {} : { correlationUid },
    ...started === undefined ? {} : { startTime: started, duration: Math.max(0, event.time - started) },
    ...provider === undefined || model === undefined ? {} : { aiModel: { name: model, ai_provider: provider } },
    api: { operation: eventType },
    attributes: {
      ...compactionId === undefined ? {} : { compaction_id: compactionId },
      event: eventType,
      ...readNumber(event.data, 'shadowedTokenCount') === undefined ? {} : { shadowed_tokens: readNumber(event.data, 'shadowedTokenCount') as number },
      ...readArrayLength(event.data, 'shadowedSeqs') === undefined ? {} : { shadowed_count: readArrayLength(event.data, 'shadowedSeqs') as number },
      ...shadowed === undefined ? {} : { shadowed_start: Number(shadowed['start'] ?? 0), shadowed_end: Number(shadowed['end'] ?? 0) },
      ...summary === undefined ? {} : { summary_digest: summary.digest, summary_length: summary.length },
    },
  }
}

/** The Scheduled Job activity each durable `ScheduleChange.operation` records. */
const SCHEDULE_ACTIVITIES: Readonly<Record<string, number>> = Object.freeze({
  create: ACTIVITY.scheduledJob.create,
  delete: ACTIVITY.scheduledJob.delete,
  // A dispatch advances the record's durable state rather than removing it.
  dispatch: ACTIVITY.scheduledJob.update,
})

/**
 * Map `schedule/change` onto Scheduled Job Activity.
 * @param sessionId - the session the event belongs to.
 * @param event - the event's payload.
 * @returns the record mapping.
 */
export function mapScheduleChange(sessionId: string, event: { data: unknown }): EventMapping {
  // `ScheduleChange` is a strict discriminated union on `operation`; a create
  // names its record under `schedule`, the other two carry a bare `id`.
  const operation = readString(event.data, 'operation') ?? 'unknown'
  const id = readString(readNested(event.data, 'schedule'), 'id') ?? readString(event.data, 'id') ?? 'unknown'
  const activityId = SCHEDULE_ACTIVITIES[operation] ?? ACTIVITY.scheduledJob.other
  return {
    classUid: CLASS.scheduledJobActivity,
    activityId,
    severityId: SEVERITY.low,
    statusId: STATUS.success,
    statusDetail: operation,
    message: `schedule ${operation}`,
    correlationUid: `${sessionId}:schedule:${id}`,
    job: { name: id, uid: id },
    attributes: { schedule_id: id, operation },
  }
}

/**
 * Map any event type without a specialised mapper — including types merged by
 * plugins this build does not know. Metadata only: the payload is not read.
 * @param eventType - the session event type.
 * @param event - the event's payload.
 * @returns the record mapping.
 */
export function mapGeneric(eventType: string, event: { data: unknown }): EventMapping {
  const turn = readNumber(event.data, 'turn')
  const step = readNumber(event.data, 'step')
  return {
    classUid: CLASS.apiActivity,
    activityId: ACTIVITY.api.other,
    severityId: SEVERITY.informational,
    statusId: STATUS.unknown,
    message: eventType,
    api: { operation: eventType },
    attributes: {
      event: eventType,
      ...turn === undefined ? {} : { turn },
      ...step === undefined ? {} : { step },
    },
  }
}

/**
 * The record announcing that a resumed or forked session arrived with prior
 * history this process never observed.
 * @param sessionId - the adopted session.
 * @param seedLength - how many events entered through the constructor seed.
 * @param parentSessionId - the session this one was forked from, when any.
 * @returns the record mapping.
 */
export function mapSeedBoundary(
  sessionId: string,
  seedLength: number,
  parentSessionId: string | undefined,
): EventMapping {
  return {
    classUid: CLASS.applicationLifecycle,
    activityId: ACTIVITY.applicationLifecycle.start,
    severityId: SEVERITY.low,
    statusId: STATUS.unknown,
    message: `session adopted with ${seedLength} seed events not observed live`,
    attributes: {
      phase: 'adopted',
      first_live_seq: seedLength,
      seed_events: seedLength,
      ...parentSessionId === undefined ? {} : { forked_from: parentSessionId },
    },
  }
}
