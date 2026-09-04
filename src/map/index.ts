/**
 * The event-type dispatcher: one session event in, one OCSF mapping out.
 *
 * `SessionEventMap` is merge-extensible, so this switch ends in a documented
 * default rather than an exhaustiveness assertion — an out-of-repo plugin can
 * add event types at any time, and an unknown type must be forwarded as
 * metadata rather than dropped or thrown on.
 * @module map
 */

import type { ResolvedConfig } from '../config.ts'
import type { SessionState } from '../correlate.ts'
import type { EventMapping } from '../ocsf/record.ts'
import {
  mapApprovalAsked,
  mapApprovalDecided,
  mapAuthorizationState,
  mapSubagentModelPolicy,
} from './authorization.ts'
import { mapSessionLogDelivery } from './egress.ts'
import {
  mapAssistantMessage,
  mapCompaction,
  mapGeneric,
  mapHookInvoked,
  mapHookResult,
  mapModelSelection,
  mapRequestContext,
  mapRequestHeader,
  mapScheduleChange,
  mapStepEnd,
  mapStepStart,
  mapSubagentDescriptor,
  mapTurnEnd,
  mapTurnStart,
  mapUserMessage,
  mapWorkflow,
} from './lifecycle.ts'
import {
  mapAgentPresetSelected,
  mapCommandDone,
  mapCommandRun,
  mapDeepSeekSearchRequest,
  mapGoalChange,
  mapInboxSpliced,
  mapLlmRetry,
  mapLlmRetryStarted,
  mapPlanMode,
} from './interaction.ts'
import {
  mapTeamMember,
  mapTeamMessageDelivered,
  mapTeamMessageQueued,
  mapTeamTask,
} from './team.ts'
import {
  mapCodeDispatch,
  mapCodeDispatchStart,
  mapToolCall,
  mapToolResult,
} from './tool-events.ts'

/** One session event, reduced to what a mapper needs. */
export interface MappableEvent {
  readonly type: string
  readonly seq: number
  readonly time: number
  readonly data: unknown
}

/**
 * Map one session event to its OCSF record fields.
 * @param sessionId - the session the event belongs to; it is never in the payload.
 * @param event - the appended event, exactly as recorded.
 * @param state - the session's correlation state, read and updated here.
 * @param config - the resolved configuration.
 * @returns the mapping, or `undefined` when the payload lacks the identity the
 *   record needs (an unreadable event is reported by the caller, not dropped
 *   silently).
 */
export function mapEvent(
  sessionId: string,
  event: MappableEvent,
  state: SessionState,
  config: ResolvedConfig,
): EventMapping | undefined {
  switch (event.type) {
    case 'tool/call': return mapToolCall(sessionId, event, state, config)
    case 'tool/result': return mapToolResult(sessionId, event, state, config)
    case 'tool/code-dispatch-start': return mapCodeDispatchStart(sessionId, event, state, config)
    case 'tool/code-dispatch': return mapCodeDispatch(sessionId, event, state, config)
    case 'approval/asked': return mapApprovalAsked(sessionId, event, state, config)
    case 'approval/decided': return mapApprovalDecided(sessionId, event, state)
    case 'approval/policy':
    case 'sandbox/mode':
    case 'permission/preset': return mapAuthorizationState(event.type, event)
    case 'subagent/model-selection-policy': return mapSubagentModelPolicy(event)
    case 'turn/start': return mapTurnStart(sessionId, event, state)
    case 'turn/end': return mapTurnEnd(sessionId, event, state, config)
    case 'step/start': return mapStepStart(sessionId, event, state)
    case 'step/end': return mapStepEnd(sessionId, event, state)
    case 'assistant/message': return mapAssistantMessage(sessionId, event, config)
    case 'user/message': return mapUserMessage(event, config)
    case 'request/context': return mapRequestContext(event, state)
    case 'model/selection': return mapModelSelection(event)
    case 'request/header': return mapRequestHeader(event, config)
    case 'hook/invoked': return mapHookInvoked(sessionId, event)
    case 'hook/result': return mapHookResult(sessionId, event, config)
    case 'subagent/descriptor': return mapSubagentDescriptor(sessionId, event)
    case 'tool-workflow/run-start':
    case 'tool-workflow/run-end':
    case 'tool-workflow/agent-start':
    case 'tool-workflow/agent-end': return mapWorkflow(event.type, sessionId, event)
    case 'compaction/start':
    case 'compaction/end':
    case 'compaction/prune':
    case 'compaction/summary': return mapCompaction(event.type, sessionId, event, state, config)
    case 'schedule/change': return mapScheduleChange(sessionId, event)
    case 'agent/inbox/spliced': return mapInboxSpliced(event, config)
    case 'agent-preset/selected': return mapAgentPresetSelected(event)
    case 'command/run': return mapCommandRun(sessionId, event, state, config)
    case 'command/done': return mapCommandDone(sessionId, event, state, config)
    case 'goal/change': return mapGoalChange(event, config)
    case 'llm/retry': return mapLlmRetry(sessionId, event, config)
    case 'llm/retry-started': return mapLlmRetryStarted(sessionId, event)
    case 'plan/mode': return mapPlanMode(event)
    case 'web/deepseek-search-llm-request': return mapDeepSeekSearchRequest(event, config)
    case 'session-log-deepseek/delivery-accepted': return mapSessionLogDelivery(sessionId, event, state)
    case 'team/member': return mapTeamMember(sessionId, event, config)
    case 'team/message/queued': return mapTeamMessageQueued(sessionId, event, state, config)
    case 'team/message/delivered': return mapTeamMessageDelivered(sessionId, event, state)
    case 'team/task': return mapTeamTask(sessionId, event, config)
    // Every remaining type — including plugin-merged types this build does not
    // know — is forwarded as metadata.
    default: return mapGeneric(event.type, event)
  }
}
