/**
 * Mapping of the interaction events: slash commands, plan and goal state, the
 * agent inbox, model-request retries, the agent preset, and the auxiliary
 * search request.
 *
 * Each of these took the generic fallback — API Activity 6003 / activity
 * `99 Other`, metadata only — which forwards that an event happened and drops
 * every field in it. A slash command lost its name and its arguments, a retry
 * lost the provider failure code, an inbox splice lost how many messages were
 * inserted into the agent's pending list. Those are the facts a SOC reads these
 * events for.
 * @module map/interaction
 */

import type { ResolvedConfig } from '../config.ts'
import type { SessionState } from '../correlate.ts'
import { ACTIVITY, AI_ROLE, CLASS, SEVERITY, STATUS } from '../ocsf/constants.ts'
import type { EventMapping } from '../ocsf/record.ts'
import type { JsonValue } from '../ocsf/types.ts'
import { readArrayLength, readBoolean, readNested, readNumber, readRecord, readString } from '../read.ts'
import { summariseText } from '../privacy.ts'
import { messageText } from './lifecycle.ts'

/** The correlation id joining a slash command's start and its settlement. */
export function commandCorrelationUid(sessionId: string, commandId: string): string {
  return `${sessionId}:command:${commandId}`
}

/**
 * Map `agent/inbox/spliced`: messages inserted into or removed from the agent's
 * durable pending list.
 *
 * The inserted messages are steering text a user or a plugin composed, so the
 * record carries how many there were and one digest of them, never the text.
 * @param event - the event's payload.
 * @param config - the resolved configuration, for the text digest.
 * @returns the record mapping.
 */
export function mapInboxSpliced(event: { data: unknown }, config: ResolvedConfig): EventMapping {
  const target = readString(event.data, 'target') ?? 'unknown'
  const outcome = readString(event.data, 'outcome')
  const inserted = readRecord(event.data)?.['inserted']
  const text = summariseText(
    Array.isArray(inserted) ? inserted.map(message => messageText(message)).join('') : '',
    config,
  )
  return {
    classUid: CLASS.apiActivity,
    activityId: ACTIVITY.api.update,
    severityId: SEVERITY.informational,
    statusId: STATUS.success,
    message: `agent inbox spliced at ${target}`,
    api: { operation: 'agent/inbox/spliced' },
    attributes: {
      event: 'agent/inbox/spliced',
      inbox_target: target,
      splice_start: readNumber(event.data, 'start') ?? 0,
      removed_count: readNumber(event.data, 'removedCount') ?? 0,
      inserted_count: readArrayLength(event.data, 'inserted') ?? 0,
      inserted_digest: text.digest,
      inserted_length: text.length,
      ...outcome === undefined ? {} : { splice_outcome: outcome },
    },
  }
}

/**
 * Map `agent-preset/selected`: the session's composition was chosen after
 * creation, which changes the tools and permissions later turns run under.
 * @param event - the event's payload.
 * @returns the record mapping.
 */
export function mapAgentPresetSelected(event: { data: unknown }): EventMapping {
  const preset = readString(event.data, 'agentPreset') ?? 'unknown'
  return {
    classUid: CLASS.applicationLifecycle,
    activityId: ACTIVITY.applicationLifecycle.update,
    severityId: SEVERITY.informational,
    statusId: STATUS.success,
    message: `agent preset ${preset} selected`,
    attributes: { event: 'agent-preset/selected', agent_preset: preset },
  }
}

/**
 * Map `command/run`: a resolved slash command entered its handler.
 * @param sessionId - the session the event belongs to.
 * @param event - the event's `time` and payload.
 * @param state - the session's correlation state.
 * @param config - the resolved configuration, for the argument digest.
 * @returns the record mapping.
 */
export function mapCommandRun(
  sessionId: string,
  event: { time: number; data: unknown },
  state: SessionState,
  config: ResolvedConfig,
): EventMapping {
  const commandId = readString(event.data, 'commandId') ?? 'unknown'
  const name = readString(event.data, 'name') ?? 'unknown'
  const args = readString(event.data, 'args')
  state.openCommand({ id: commandId, name, time: event.time })
  return {
    classUid: CLASS.apiActivity,
    activityId: ACTIVITY.api.create,
    severityId: SEVERITY.informational,
    statusId: STATUS.unknown,
    message: `command ${name} started`,
    correlationUid: commandCorrelationUid(sessionId, commandId),
    api: { operation: `command:${name}` },
    attributes: {
      event: 'command/run',
      command: name,
      command_id: commandId,
      command_source: readString(event.data, 'source') ?? 'unknown',
      phase: 'start',
      // `args` is `parseCommand`'s verbatim rest of the line: whatever the user
      // typed after the command name.
      ...args === undefined ? {} : {
        args_digest: summariseText(args, config).digest,
        args_length: args.length,
      },
    },
  }
}

/**
 * Map `command/done`: the paired command settled.
 * @param sessionId - the session the event belongs to.
 * @param event - the event's `time` and payload.
 * @param state - the session's correlation state.
 * @param config - the resolved configuration, for the outcome digest.
 * @returns the record mapping.
 */
export function mapCommandDone(
  sessionId: string,
  event: { time: number; data: unknown },
  state: SessionState,
  config: ResolvedConfig,
): EventMapping {
  const commandId = readString(event.data, 'commandId') ?? 'unknown'
  const kind = readString(event.data, 'kind') ?? 'unknown'
  const failed = kind === 'error'
  const run = state.closeCommand(commandId)
  // The handler's own outcome text, which for a failure is a rendered error and
  // for a success is whatever the command chose to say.
  const text = readString(event.data, 'text')
  const sourceEventSeq = readNumber(event.data, 'sourceEventSeq')
  return {
    classUid: CLASS.apiActivity,
    activityId: ACTIVITY.api.update,
    severityId: failed ? SEVERITY.low : SEVERITY.informational,
    statusId: failed ? STATUS.failure : STATUS.success,
    statusDetail: kind,
    message: `command ${run?.name ?? 'unknown'} ${kind}`,
    correlationUid: commandCorrelationUid(sessionId, commandId),
    ...run === undefined ? {} : { startTime: run.time, duration: Math.max(0, event.time - run.time) },
    api: { operation: `command:${run?.name ?? 'unknown'}` },
    attributes: {
      event: 'command/done',
      command: run?.name ?? 'unknown',
      command_id: commandId,
      kind,
      phase: 'done',
      ...run === undefined ? { unpaired: true } : {},
      ...text === undefined ? {} : {
        outcome_digest: summariseText(text, config).digest,
        outcome_length: text.length,
      },
      ...sourceEventSeq === undefined ? {} : { source_event_seq: sourceEventSeq },
    },
  }
}

/**
 * Map `goal/change`: the durable completion objective this session runs under.
 * @param event - the event's payload.
 * @param config - the resolved configuration, for the objective digest.
 * @returns the record mapping.
 */
export function mapGoalChange(event: { data: unknown }, config: ResolvedConfig): EventMapping {
  const operation = readString(event.data, 'operation') ?? 'unknown'
  // A non-clear mutation carries the whole post-mutation snapshot; a clear
  // carries a tombstone naming the goal it removed.
  const goal = readNested(event.data, 'goal') ?? readNested(event.data, 'cleared')
  const objective = readString(goal, 'objective')
  const phase = readString(goal, 'phase')
  const blocked = readString(readNested(goal, 'blockedReason'), 'code')
  return {
    classUid: CLASS.apiActivity,
    activityId: ACTIVITY.api.update,
    severityId: SEVERITY.informational,
    statusId: STATUS.success,
    message: `goal ${operation}`,
    api: { operation: `goal:${operation}` },
    attributes: {
      event: 'goal/change',
      goal_operation: operation,
      goal_id: readString(goal, 'id') ?? 'unknown',
      goal_revision: readNumber(goal, 'revision') ?? 0,
      // A human-written objective is free text; only its digest and length reach
      // the SOC lane.
      ...objective === undefined ? {} : {
        objective_digest: summariseText(objective, config).digest,
        objective_length: objective.length,
      },
      ...phase === undefined ? {} : { goal_phase: phase },
      ...blocked === undefined ? {} : { goal_blocked_code: blocked },
      ...readNumber(event.data, 'roundsStarted') === undefined
        ? {}
        : { rounds_started: readNumber(event.data, 'roundsStarted') as number },
    },
  }
}

/**
 * Map `llm/retry`: one model request failed and a retry was scheduled.
 * @param sessionId - the session the event belongs to.
 * @param event - the event's payload.
 * @param config - the resolved configuration, for the failure-message digest.
 * @returns the record mapping.
 */
export function mapLlmRetry(
  sessionId: string,
  event: { data: unknown },
  config: ResolvedConfig,
): EventMapping {
  const turn = readNumber(event.data, 'turn') ?? 0
  const step = readNumber(event.data, 'step') ?? 0
  const failure = readNested(event.data, 'failure')
  const code = readString(failure, 'code') ?? 'unknown'
  // A provider failure message is provider-composed free text and has carried
  // echoed request headers; the code is the bounded routing value.
  const detail = summariseText(readString(failure, 'message') ?? '', config)
  const maxRetries = readNumber(event.data, 'maxRetries')
  const status = readNumber(failure, 'status')
  return {
    classUid: CLASS.apiActivity,
    activityId: ACTIVITY.api.read,
    severityId: SEVERITY.low,
    statusId: STATUS.failure,
    statusDetail: code,
    message: `model request failed with ${code}; retry scheduled`,
    correlationUid: retryCorrelationUid(sessionId, readString(event.data, 'retryId') ?? 'unknown'),
    api: { operation: 'llm.retry' },
    attributes: {
      event: 'llm/retry',
      turn,
      step,
      retry_id: readString(event.data, 'retryId') ?? 'unknown',
      provider: readString(event.data, 'provider') ?? 'unknown',
      retry_mode: readString(event.data, 'mode') ?? 'unknown',
      policy_key: readString(event.data, 'policyKey') ?? 'unknown',
      retry: readNumber(event.data, 'retry') ?? 0,
      delay_ms: readNumber(event.data, 'delayMs') ?? 0,
      failure_code: code,
      failure_digest: detail.digest,
      failure_length: detail.length,
      phase: 'scheduled',
      ...maxRetries === undefined ? {} : { max_retries: maxRetries },
      ...status === undefined ? {} : { failure_status: status },
    },
  }
}

/** The correlation id joining one retry's scheduling and its start. */
export function retryCorrelationUid(sessionId: string, retryId: string): string {
  return `${sessionId}:retry:${retryId}`
}

/**
 * Map `llm/retry-started`: the retry wait completed and the next attempt is
 * about to be dispatched.
 * @param sessionId - the session the event belongs to.
 * @param event - the event's payload.
 * @returns the record mapping.
 */
export function mapLlmRetryStarted(sessionId: string, event: { data: unknown }): EventMapping {
  const retryId = readString(event.data, 'retryId') ?? 'unknown'
  return {
    classUid: CLASS.apiActivity,
    activityId: ACTIVITY.api.read,
    severityId: SEVERITY.informational,
    statusId: STATUS.unknown,
    message: 'model request retry starting',
    correlationUid: retryCorrelationUid(sessionId, retryId),
    api: { operation: 'llm.retry-started' },
    attributes: {
      event: 'llm/retry-started',
      turn: readNumber(event.data, 'turn') ?? 0,
      step: readNumber(event.data, 'step') ?? 0,
      retry_id: retryId,
      retry: readNumber(event.data, 'retry') ?? 0,
      phase: 'started',
    },
  }
}

/**
 * Map `plan/mode`: whether the agent is confined to planning from here on.
 * @param event - the event's payload.
 * @returns the record mapping.
 */
export function mapPlanMode(event: { data: unknown }): EventMapping {
  const active = readBoolean(event.data, 'active') ?? false
  return {
    classUid: CLASS.apiActivity,
    activityId: ACTIVITY.api.update,
    severityId: SEVERITY.informational,
    statusId: STATUS.success,
    message: `plan mode ${active ? 'on' : 'off'}`,
    api: { operation: 'plan/mode' },
    attributes: { event: 'plan/mode', plan_mode_active: active },
  }
}

/** Concatenated text of the messages one search request body carries. */
function requestText(body: Readonly<Record<string, unknown>> | undefined): string {
  const messages = body?.['messages']
  return Array.isArray(messages) ? messages.map(message => messageText(message)).join('') : ''
}

/**
 * Map `web/deepseek-search-llm-request`: an auxiliary model request the search
 * provider makes outside the agent's own model route.
 * @param event - the event's payload.
 * @param config - the resolved configuration, for the query digest.
 * @returns the record mapping.
 */
export function mapDeepSeekSearchRequest(event: { data: unknown }, config: ResolvedConfig): EventMapping {
  const body = readNested(event.data, 'body')
  const model = readString(body, 'model')
  const apiVersion = readString(event.data, 'apiVersion')
  const query = summariseText(requestText(body), config)
  const attributes: Record<string, JsonValue> = {
    event: 'web/deepseek-search-llm-request',
    query_digest: query.digest,
    query_length: query.length,
    ...readNumber(body, 'max_tokens') === undefined
      ? {}
      : { max_tokens: readNumber(body, 'max_tokens') as number },
  }
  return {
    classUid: CLASS.apiActivity,
    activityId: ACTIVITY.api.read,
    severityId: SEVERITY.informational,
    statusId: STATUS.unknown,
    message: 'auxiliary search model request',
    api: {
      operation: 'web/deepseek-search-llm-request',
      service: { name: 'deepseek-search' },
      ...apiVersion === undefined ? {} : { version: apiVersion },
    },
    // The search provider's own model, which is not the session's route: the
    // record says which model saw the query.
    ...model === undefined ? {} : { aiModel: { name: model, ai_provider: 'deepseek' } },
    messageContext: { ai_role_id: AI_ROLE.user },
    attributes,
  }
}
