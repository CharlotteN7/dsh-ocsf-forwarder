/**
 * Authorization mapping: approval questions and decisions, approval policy,
 * sandbox mode, and permission presets — everything that changes what the
 * agent is allowed to do.
 *
 * The decision latency computed here is the approval-fatigue signal: a human
 * who answers in 300 ms is not reading the prompt, and an `unavailable`
 * outcome returned in under a millisecond is a deployment with no approval
 * channel at all.
 * @module map/authorization
 */

import type { ResolvedConfig } from '../config.ts'
import type { SessionState } from '../correlate.ts'
import { ACTIVITY, CLASS, SEVERITY, STATUS } from '../ocsf/constants.ts'
import type { EventMapping } from '../ocsf/record.ts'
import { summariseText } from '../privacy.ts'
import { readRecord, readString } from '../read.ts'

/** The correlation id joining an approval question to its decision. */
export function approvalCorrelationUid(sessionId: string, id: string): string {
  return `${sessionId}:approval:${id}`
}

/** `status_id` and `severity_id` for each approval outcome. */
const OUTCOMES: Readonly<Record<string, { statusId: number; severityId: number }>> = Object.freeze({
  'allowed-once': { statusId: STATUS.success, severityId: SEVERITY.medium },
  rejected: { statusId: STATUS.failure, severityId: SEVERITY.informational },
  cancelled: { statusId: STATUS.failure, severityId: SEVERITY.low },
  // A fail-closed ask means no approval channel was reachable: the deployment
  // cannot answer questions it is configured to ask.
  unavailable: { statusId: STATUS.failure, severityId: SEVERITY.medium },
})

/**
 * Map an `approval/asked`, opening the pairing entry its decision closes.
 * @param sessionId - the session the event belongs to.
 * @param event - the event's `seq`, `time`, and payload.
 * @param state - the session's correlation state.
 * @param config - the resolved configuration, for the prompt digest.
 * @returns the record mapping, or `undefined` when the payload has no request id.
 */
export function mapApprovalAsked(
  sessionId: string,
  event: { seq: number; time: number; data: unknown },
  state: SessionState,
  config: ResolvedConfig,
): EventMapping | undefined {
  const id = readString(event.data, 'id')
  if (id === undefined) return undefined
  const toolName = readString(event.data, 'toolName') ?? 'unknown'
  const callId = readString(event.data, 'callId')
  // An approval prompt explains itself by quoting the action being approved —
  // the command, the path, the URL — so it is a rendering of the request, not
  // a label for it.
  const askedReason = readString(event.data, 'reason')
  const reason = askedReason === undefined ? undefined : summariseText(askedReason, config)
  state.openApproval({ id, toolName, time: event.time, seq: event.seq, ...callId === undefined ? {} : { callId } })
  return {
    classUid: CLASS.authorizeSession,
    activityId: ACTIVITY.authorizeSession.assignPrivileges,
    severityId: SEVERITY.low,
    statusId: STATUS.unknown,
    message: `approval asked for tool ${toolName}`,
    correlationUid: approvalCorrelationUid(sessionId, id),
    privileges: [`tool:${toolName}`],
    attributes: {
      approval_id: id,
      tool: toolName,
      phase: 'asked',
      ...callId === undefined ? {} : { call_id: callId },
      ...reason === undefined ? {} : { reason_digest: reason.digest, reason_length: reason.length },
    },
  }
}

/**
 * Map an `approval/decided`, closing the pairing entry and emitting the
 * decision latency.
 * @param sessionId - the session the event belongs to.
 * @param event - the event's `seq`, `time`, and payload.
 * @param state - the session's correlation state.
 * @returns the record mapping, or `undefined` when the payload has no request id.
 */
export function mapApprovalDecided(
  sessionId: string,
  event: { seq: number; time: number; data: unknown },
  state: SessionState,
): EventMapping | undefined {
  const id = readString(event.data, 'id')
  if (id === undefined) return undefined
  const outcome = readString(event.data, 'outcome') ?? 'unknown'
  const asked = state.closeApproval(id)
  const latency = asked === undefined ? undefined : Math.max(0, event.time - asked.time)
  const graded = OUTCOMES[outcome] ?? { statusId: STATUS.other, severityId: SEVERITY.unknown }
  const toolName = asked?.toolName ?? 'unknown'
  return {
    classUid: CLASS.authorizeSession,
    activityId: ACTIVITY.authorizeSession.assignPrivileges,
    severityId: graded.severityId,
    statusId: graded.statusId,
    statusDetail: outcome,
    message: `approval ${outcome} for tool ${toolName}`,
    correlationUid: approvalCorrelationUid(sessionId, id),
    privileges: [`tool:${toolName}`],
    ...asked === undefined ? {} : { startTime: asked.time },
    ...latency === undefined ? {} : { duration: latency },
    attributes: {
      approval_id: id,
      outcome,
      tool: toolName,
      phase: 'decided',
      ...latency === undefined ? { unpaired: true } : { approval_latency_ms: latency, asked_seq: asked?.seq ?? 0 },
      ...asked?.callId === undefined ? {} : { call_id: asked.callId },
    },
  }
}

/**
 * Map one approval question that never received its decision in this process.
 * @param sessionId - the session the question belongs to.
 * @param approval - the pending question.
 * @param time - when the flush happens.
 * @returns a record mapping with an unknown status.
 */
export function mapUnresolvedApproval(
  sessionId: string,
  approval: { id: string; toolName: string; time: number; seq: number },
  time: number,
): EventMapping {
  return {
    classUid: CLASS.authorizeSession,
    activityId: ACTIVITY.authorizeSession.assignPrivileges,
    severityId: SEVERITY.medium,
    statusId: STATUS.unknown,
    message: `approval for tool ${approval.toolName} never decided`,
    correlationUid: approvalCorrelationUid(sessionId, approval.id),
    startTime: approval.time,
    duration: Math.max(0, time - approval.time),
    privileges: [`tool:${approval.toolName}`],
    attributes: {
      approval_id: approval.id,
      tool: approval.toolName,
      phase: 'unresolved',
      unresolved: true,
      asked_seq: approval.seq,
    },
  }
}

/**
 * Map `subagent/model-selection-policy`: the exact provider and model routes
 * this session may hand to a child agent.
 *
 * It is a grant of a set of external endpoints, so it is recorded as the
 * privileges it is rather than as a settings change. OCSF 1.9.0 constrains
 * Authorize Session `at_least_one: [privileges, groups, iam_roles]` and this
 * plugin emits neither of the other two, so a policy that names no usable
 * route produces no record at all instead of an empty grant.
 * @param event - the event's payload.
 * @returns the record mapping, or `undefined` when no complete route is readable.
 */
export function mapSubagentModelPolicy(event: { data: unknown }): EventMapping | undefined {
  const routes = readRecord(event.data)?.['allowedModels']
  if (!Array.isArray(routes)) return undefined
  const privileges = routes
    .map((route) => {
      const provider = readString(route, 'provider')
      const model = readString(route, 'model')
      return provider === undefined || model === undefined ? undefined : `subagent-model:${provider}/${model}`
    })
    .filter((privilege): privilege is string => privilege !== undefined)
  if (privileges.length === 0) return undefined
  return {
    classUid: CLASS.authorizeSession,
    activityId: ACTIVITY.authorizeSession.assignPrivileges,
    // The same grade as every other setting later decisions are judged
    // against: it is the list a child route is checked for membership in.
    severityId: SEVERITY.medium,
    statusId: STATUS.success,
    message: `subagent model selection limited to ${String(privileges.length)} route(s)`,
    privileges,
    attributes: {
      setting: 'subagent/model-selection-policy',
      allowed_model_count: privileges.length,
    },
  }
}

/**
 * Map a policy-bearing authorization event: `approval/policy`, `sandbox/mode`,
 * or `permission/preset`.
 * @param eventType - the session event type.
 * @param event - the event's payload.
 * @returns the record mapping.
 */
export function mapAuthorizationState(
  eventType: string,
  event: { data: unknown },
): EventMapping {
  const value = readString(event.data, 'policy')
    ?? readString(event.data, 'mode')
    ?? readString(event.data, 'preset')
    ?? 'unknown'
  const privilege = eventType === 'sandbox/mode'
    ? `sandbox:${value}`
    : eventType === 'permission/preset' ? `preset:${value}` : `approval-policy:${value}`
  return {
    classUid: CLASS.authorizeSession,
    activityId: ACTIVITY.authorizeSession.assignPrivileges,
    // A confinement or approval-policy change is the setting every later
    // decision is judged against, so it is never merely informational.
    severityId: SEVERITY.medium,
    statusId: STATUS.success,
    message: `${eventType} set to ${value}`,
    privileges: [privilege],
    attributes: {
      setting: eventType,
      value,
      ...readString(event.data, 'source') === undefined ? {} : { source: readString(event.data, 'source') as string },
    },
  }
}
