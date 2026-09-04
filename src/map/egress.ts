/**
 * The session log leaving the host.
 *
 * `@deepseek-ai/dsh-session-log-deepseek` contributes a `dsh_session_log` field
 * to every official DeepSeek model request. The field carries the complete
 * canonical event envelopes from the last accepted watermark through the log's
 * current end — tool arguments, tool results and prompts included — and when
 * the endpoint accepts the request the plugin appends
 * `session-log-deepseek/delivery-accepted` with the new watermark.
 *
 * That is the only session event saying the audit subject itself was copied to
 * a third party, so it gets a record that names the destination service and
 * how many events went, rather than the metadata-only generic fallback.
 * @module map/egress
 */

import type { SessionState } from '../correlate.ts'
import { ACTIVITY, CLASS, SEVERITY, STATUS } from '../ocsf/constants.ts'
import type { EventMapping } from '../ocsf/record.ts'
import { readNumber, readString } from '../read.ts'

/** The service the accepted delivery went to; the plugin registers for no other. */
const DELIVERY_SERVICE = 'deepseek-llm-api'

/**
 * Map `session-log-deepseek/delivery-accepted`.
 *
 * The severity is deliberately low rather than high. Acceptance is appended
 * once per successful model request, so grading each one as an incident would
 * bury the index; what a SOC acts on is that these records exist at all on a
 * host whose policy forbids the upload, which the record's presence and its
 * `api.service.name` already say.
 * @param sessionId - the session the event belongs to.
 * @param event - the event's payload.
 * @param state - the session's correlation state, holding the previous watermark.
 * @returns the record mapping, or `undefined` when the payload carries neither
 *   of the two fields the record is made of.
 */
export function mapSessionLogDelivery(
  sessionId: string,
  event: { data: unknown },
  state: SessionState,
): EventMapping | undefined {
  const deliveredSessionId = readString(event.data, 'sessionId')
  const throughSeq = readNumber(event.data, 'throughSeq')
  if (deliveredSessionId === undefined || throughSeq === undefined) return undefined
  // The harness's own invariant: a marker naming a session other than the one
  // containing it was inherited through a fork seed, and records a delivery
  // the parent made. Nothing left the host on this session's account.
  const inherited = deliveredSessionId !== sessionId
  const previous = state.advanceDelivery(deliveredSessionId, throughSeq)
  return {
    classUid: CLASS.apiActivity,
    activityId: ACTIVITY.api.create,
    severityId: inherited ? SEVERITY.informational : SEVERITY.low,
    statusId: STATUS.success,
    message: inherited
      ? `inherited session-log delivery marker for ${deliveredSessionId} through seq ${String(throughSeq)}`
      : `session log delivered to ${DELIVERY_SERVICE} through seq ${String(throughSeq)}`,
    api: { operation: 'session-log/deliver', service: { name: DELIVERY_SERVICE } },
    correlationUid: `${sessionId}:session-log-delivery`,
    attributes: {
      event: 'session-log-deepseek/delivery-accepted',
      delivered_session_id: deliveredSessionId,
      delivered_through_seq: throughSeq,
      ...inherited ? { inherited_marker: true } : {},
      // Without the preceding watermark the size of this delivery is unknown:
      // a plugin mounted mid-session, or a session adopted without full seed
      // replay, never saw it. Reporting a count from an assumed `-1` would
      // claim the whole log went in this one delivery.
      ...previous === undefined
        ? { first_observed_delivery: true }
        : { delivered_after_seq: previous, delivered_event_count: Math.max(0, throughSeq - previous) },
    },
  }
}
