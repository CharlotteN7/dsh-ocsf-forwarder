/**
 * The `team/*` events: several agents sharing one team, messaging each other,
 * and holding tasks that carry write scopes.
 *
 * `team/message/queued` is one agent putting text into another agent's inbox.
 * It names the sender's session, the target's session, and whether the delivery
 * wakes the target or waits for its next turn — the multi-agent equivalent of
 * lateral movement, and the reason these four types are worth reading by name
 * rather than forwarding as metadata.
 *
 * The payload fields are those of the merged `SessionEventMap` the harness
 * compiles its own session vocabulary against. They are read defensively like
 * every other payload here, so a build whose emitter writes something else
 * yields absent attributes rather than wrong ones.
 * @module map/team
 */

import type { ResolvedConfig } from '../config.ts'
import type { SessionState } from '../correlate.ts'
import { ACTIVITY, AI_ROLE, CLASS, SEVERITY, STATUS } from '../ocsf/constants.ts'
import type { EventMapping } from '../ocsf/record.ts'
import type { JsonValue } from '../ocsf/types.ts'
import { summariseText } from '../privacy.ts'
import { readArrayLength, readNested, readNumber, readString, readStringArray } from '../read.ts'
import { messageText } from './lifecycle.ts'

/** How a member's provisioning phase grades as an OCSF outcome. */
const MEMBER_PHASES: Readonly<Record<string, { statusId: number; severityId: number }>> = Object.freeze({
  active: { statusId: STATUS.success, severityId: SEVERITY.low },
  failed: { statusId: STATUS.failure, severityId: SEVERITY.medium },
  provisioning: { statusId: STATUS.unknown, severityId: SEVERITY.low },
})

/** The correlation id joining every record of one team message. */
export function teamMessageCorrelationUid(sessionId: string, messageId: string): string {
  return `${sessionId}:team-message:${messageId}`
}

/**
 * Map `team/member`: an agent joined this session's team.
 *
 * This is the second event type that names a child session by id — the first
 * being `tool-workflow/agent-start` — so it builds the same `delegation` link.
 * @param sessionId - the session the event belongs to.
 * @param event - the event's `time` and payload.
 * @param config - the resolved configuration, for the description digest.
 * @returns the record mapping, or `undefined` when the member has no session id.
 */
export function mapTeamMember(
  sessionId: string,
  event: { time: number; data: unknown },
  config: ResolvedConfig,
): EventMapping | undefined {
  const member = readNested(event.data, 'member')
  const memberId = readString(member, 'id')
  if (memberId === undefined) return undefined
  const teamId = readString(event.data, 'teamId') ?? 'unknown'
  const phase = readString(member, 'phase') ?? 'unknown'
  const graded = MEMBER_PHASES[phase] ?? { statusId: STATUS.other, severityId: SEVERITY.unknown }
  const name = readString(member, 'name')
  // The description is the brief the child acts on: prose a user or a model
  // wrote, so the SOC lane takes its digest. The name is the identifier
  // `team/message/queued` repeats as `senderName`, and a digest of it would
  // join nothing.
  const description = readString(member, 'description')
  const summary = description === undefined ? undefined : summariseText(description, config)
  const error = readString(member, 'error')
  const failure = error === undefined ? undefined : summariseText(error, config)
  return {
    classUid: CLASS.applicationLifecycle,
    activityId: ACTIVITY.applicationLifecycle.start,
    severityId: graded.severityId,
    statusId: graded.statusId,
    statusDetail: phase,
    message: `team member ${name ?? memberId} ${phase}`,
    correlationUid: `${sessionId}:team:${teamId}`,
    delegation: { uid: memberId, parent_uid: sessionId, created_time: event.time },
    attributes: {
      team_id: teamId,
      member_session_id: memberId,
      member_phase: phase,
      ...name === undefined ? {} : { member_name: name },
      ...readString(member, 'provider') === undefined ? {} : { member_provider: readString(member, 'provider') as string },
      ...readString(member, 'context') === undefined ? {} : { member_context: readString(member, 'context') as string },
      ...summary === undefined ? {} : { member_description_digest: summary.digest, member_description_length: summary.length },
      ...failure === undefined ? {} : { member_error_digest: failure.digest, member_error_length: failure.length },
    },
  }
}

/**
 * Map `team/message/queued`: one agent addressed another.
 * @param sessionId - the session the event belongs to.
 * @param event - the event's `time` and payload.
 * @param state - the session's correlation state, opening the delivery pairing.
 * @param config - the resolved configuration, for the content digest.
 * @returns the record mapping, or `undefined` when the message has no id.
 */
export function mapTeamMessageQueued(
  sessionId: string,
  event: { time: number; data: unknown },
  state: SessionState,
  config: ResolvedConfig,
): EventMapping | undefined {
  const message = readNested(event.data, 'message')
  const messageId = readString(message, 'id')
  if (messageId === undefined) return undefined
  const delivery = readString(message, 'delivery') ?? 'unknown'
  const content = summariseText(messageText(message), config)
  state.openTeamMessage(messageId, event.time)
  return {
    classUid: CLASS.apiActivity,
    activityId: ACTIVITY.api.create,
    // A wakeup makes the target act on the text now; a quiet message waits for
    // the target's own next turn.
    severityId: delivery === 'wakeup' ? SEVERITY.medium : SEVERITY.low,
    statusId: STATUS.unknown,
    message: `team message queued (${delivery})`,
    api: { operation: 'team:message-queued' },
    correlationUid: teamMessageCorrelationUid(sessionId, messageId),
    messageContext: { ai_role_id: AI_ROLE.agent },
    attributes: {
      team_id: readString(event.data, 'teamId') ?? 'unknown',
      message_id: messageId,
      delivery,
      phase: 'queued',
      content_digest: content.digest,
      content_length: content.length,
      ...readString(message, 'senderId') === undefined ? {} : { sender_session_id: readString(message, 'senderId') as string },
      ...readString(message, 'senderName') === undefined ? {} : { sender_name: readString(message, 'senderName') as string },
      ...readString(message, 'targetId') === undefined ? {} : { target_session_id: readString(message, 'targetId') as string },
    },
  }
}

/**
 * Map `team/message/delivered`, closing the pairing its queueing opened.
 * @param sessionId - the session the event belongs to.
 * @param event - the event's `time` and payload.
 * @param state - the session's correlation state.
 * @returns the record mapping, or `undefined` when the payload has no message id.
 */
export function mapTeamMessageDelivered(
  sessionId: string,
  event: { time: number; data: unknown },
  state: SessionState,
): EventMapping | undefined {
  const messageId = readString(event.data, 'messageId')
  if (messageId === undefined) return undefined
  const queued = state.closeTeamMessage(messageId)
  const latency = queued === undefined ? undefined : Math.max(0, event.time - queued)
  return {
    classUid: CLASS.apiActivity,
    activityId: ACTIVITY.api.update,
    severityId: SEVERITY.informational,
    statusId: STATUS.success,
    message: 'team message delivered',
    api: { operation: 'team:message-delivered' },
    correlationUid: teamMessageCorrelationUid(sessionId, messageId),
    ...queued === undefined ? {} : { startTime: queued },
    ...latency === undefined ? {} : { duration: latency },
    attributes: {
      team_id: readString(event.data, 'teamId') ?? 'unknown',
      message_id: messageId,
      phase: 'delivered',
      ...readString(event.data, 'targetId') === undefined ? {} : { target_session_id: readString(event.data, 'targetId') as string },
      ...latency === undefined ? { unpaired: true } : { delivery_latency_ms: latency },
    },
  }
}

/** How a task's status grades as an OCSF outcome. */
const TASK_STATUSES: Readonly<Record<string, { activityId: number; statusId: number }>> = Object.freeze({
  pending: { activityId: ACTIVITY.api.update, statusId: STATUS.unknown },
  in_progress: { activityId: ACTIVITY.api.update, statusId: STATUS.unknown },
  completed: { activityId: ACTIVITY.api.update, statusId: STATUS.success },
  deleted: { activityId: ACTIVITY.api.delete, statusId: STATUS.success },
})

/**
 * Map `team/task`: one revision of a shared task.
 *
 * The `create` activity is deliberately not emitted. The payload is a snapshot
 * carrying a revision number whose origin this plugin cannot read, so calling
 * one of them the creation would be a guess; every non-delete revision is an
 * update.
 * @param sessionId - the session the event belongs to.
 * @param event - the event's payload.
 * @param config - the resolved configuration, for the text digests.
 * @returns the record mapping, or `undefined` when the task has no id.
 */
export function mapTeamTask(
  sessionId: string,
  event: { data: unknown },
  config: ResolvedConfig,
): EventMapping | undefined {
  const task = readNested(event.data, 'task')
  const taskId = readString(task, 'id')
  if (taskId === undefined) return undefined
  const status = readString(task, 'status') ?? 'unknown'
  const graded = TASK_STATUSES[status] ?? { activityId: ACTIVITY.api.update, statusId: STATUS.other }
  const subject = readString(task, 'subject')
  const subjectSummary = subject === undefined ? undefined : summariseText(subject, config)
  const description = readString(task, 'description')
  const descriptionSummary = description === undefined ? undefined : summariseText(description, config)
  // A write scope is a path pattern: the security signal itself, carried
  // verbatim on the same reasoning as `file.path`.
  const writeScopes = readStringArray(task, 'writeScopes')
  return {
    classUid: CLASS.apiActivity,
    activityId: graded.activityId,
    severityId: SEVERITY.low,
    statusId: graded.statusId,
    statusDetail: status,
    message: `team task ${status}`,
    api: { operation: 'team:task' },
    correlationUid: `${sessionId}:team-task:${taskId}`,
    attributes: {
      team_id: readString(event.data, 'teamId') ?? 'unknown',
      task_id: taskId,
      task_status: status,
      ...readNumber(task, 'revision') === undefined ? {} : { task_revision: readNumber(task, 'revision') as number },
      ...readString(task, 'ownerId') === undefined ? {} : { owner_session_id: readString(task, 'ownerId') as string },
      ...readArrayLength(task, 'blockedBy') === undefined ? {} : { blocked_by_count: readArrayLength(task, 'blockedBy') as number },
      ...writeScopes === undefined ? {} : { write_scopes: writeScopes as JsonValue },
      ...subjectSummary === undefined ? {} : { subject_digest: subjectSummary.digest, subject_length: subjectSummary.length },
      ...descriptionSummary === undefined
        ? {}
        : { description_digest: descriptionSummary.digest, description_length: descriptionSummary.length },
    },
  }
}
