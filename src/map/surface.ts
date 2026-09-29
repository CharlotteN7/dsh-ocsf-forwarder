/**
 * Mapping of the four event types that change what the model sees without
 * being a user prompt or a model completion: the rendered system prompt, the
 * developer-role capability deltas, an attempt that committed no message, and
 * the permanent removal of images from later requests.
 *
 * All four entered `KNOWN_SESSION_EVENT_TYPES` after the `0.1.2` line the
 * mapper was first written against, and all four were reaching `mapGeneric`,
 * which reads no field of a payload.
 * @module map/surface
 */

import type { ResolvedConfig } from '../config.ts'
import { ACTIVITY, AI_ROLE, CLASS, SEVERITY, STATUS } from '../ocsf/constants.ts'
import type { EventMapping } from '../ocsf/record.ts'
import type { JsonValue } from '../ocsf/types.ts'
import { readArrayLength, readNested, readNumber, readRecord, readString } from '../read.ts'
import { summariseText } from '../privacy.ts'
import { messageText, stepCorrelationUid } from './lifecycle.ts'

/**
 * Map `system/message`: the rendered system prompt as it stands on the
 * model-visible surface.
 *
 * This is the same category of fact `request/header` already carries a digest
 * of — the instructions the model runs under — so it takes the same class and
 * the same redaction: a keyed digest and a length, never the prompt text in
 * the SOC lane. The digest is what a detection compares against a fleet
 * baseline, and the `message.id` is what identifies the surface node a later
 * replacement rewrites.
 * @param event - the event's payload.
 * @param config - the resolved configuration, for the prompt digest.
 * @returns the record mapping.
 */
export function mapSystemMessage(event: { data: unknown }, config: ResolvedConfig): EventMapping {
  const message = readNested(event.data, 'message')
  const prompt = summariseText(messageText(message), config)
  const messageId = readString(message, 'id')
  return {
    classUid: CLASS.applicationLifecycle,
    activityId: ACTIVITY.applicationLifecycle.update,
    severityId: SEVERITY.informational,
    statusId: STATUS.success,
    message: 'system prompt committed to the model surface',
    attributes: {
      turn: readNumber(event.data, 'turn') ?? 0,
      step: readNumber(event.data, 'step') ?? 0,
      system_prompt_digest: prompt.digest,
      system_prompt_length: prompt.length,
      // An empty rendering clears every active system node, which is a
      // different fact from a prompt that happens to hash to something new.
      system_prompt_empty: prompt.length === 0,
      ...messageId === undefined ? {} : { message_id: messageId },
    },
  }
}

/**
 * Map `developer/message`: an incremental change to the agent's session,
 * which the harness documents as tool additions and removals.
 *
 * A tool admitted mid-session widens what one prompt can reach, so this is
 * graded like `model/selection` rather than as routine bookkeeping. The
 * payload's `headerSeq` names the earlier `request/header` that defines every
 * added tool, and is recorded so a reader can reach the names from here.
 * @param event - the event's payload.
 * @param config - the resolved configuration, for the text digest.
 * @returns the record mapping.
 */
export function mapDeveloperMessage(event: { data: unknown }, config: ResolvedConfig): EventMapping {
  const message = readNested(event.data, 'message')
  const text = summariseText(messageText(message), config)
  const headerSeq = readNumber(event.data, 'headerSeq')
  const messageId = readString(message, 'id')
  return {
    classUid: CLASS.applicationLifecycle,
    activityId: ACTIVITY.applicationLifecycle.update,
    severityId: SEVERITY.low,
    statusId: STATUS.success,
    message: 'developer-role session change on the model surface',
    messageContext: {
      // OCSF 1.9.0 `message_context.ai_role_id` has no developer member; 99 is
      // its `Other`, and the `ai_role` sibling is where the schema puts the
      // value the enum does not spell.
      ai_role_id: AI_ROLE.other,
      ai_role: 'developer',
    },
    attributes: {
      turn: readNumber(event.data, 'turn') ?? 0,
      step: readNumber(event.data, 'step') ?? 0,
      text_digest: text.digest,
      text_length: text.length,
      ...messageId === undefined ? {} : { message_id: messageId },
      ...headerSeq === undefined ? {} : { header_seq: headerSeq },
    },
  }
}

/**
 * Map `assistant/attempt`: one model attempt that reached settlement without
 * committing a surface message — a failure, a retry, a cancellation, or a
 * stream error.
 *
 * The embedded `stream` is the model's own partial output and is never read;
 * only how many records it holds, which distinguishes an attempt that produced
 * nothing from one cut off part-way.
 * @param sessionId - the session the event belongs to.
 * @param event - the event's payload.
 * @returns the record mapping.
 */
export function mapAssistantAttempt(sessionId: string, event: { data: unknown }): EventMapping {
  const turn = readNumber(event.data, 'turn') ?? 0
  const step = readNumber(event.data, 'step') ?? 0
  return {
    classUid: CLASS.apiActivity,
    activityId: ACTIVITY.api.read,
    severityId: SEVERITY.low,
    statusId: STATUS.failure,
    statusDetail: 'no-surface-message',
    message: 'model attempt committed no message',
    correlationUid: stepCorrelationUid(sessionId, turn, step),
    api: { operation: 'llm.completion' },
    messageContext: { ai_role_id: AI_ROLE.assistant },
    attributes: {
      turn,
      step,
      stream_records: readArrayLength(event.data, 'stream') ?? 0,
    },
  }
}

/**
 * Map `image/offload`: input images permanently omitted from every later model
 * request.
 *
 * It removes model-visible content the log keeps, which is the same
 * tamper-relevant shape as `compaction/prune`, so it takes the same activity.
 * The event names the surface nodes it edits by `seq`, and those numbers are
 * recorded: a range a reader can check against the log is the whole signal.
 * @param event - the event's payload.
 * @returns the record mapping.
 */
export function mapImageOffload(event: { data: unknown }): EventMapping {
  const targets = readRecord(event.data)?.['targets']
  const list = Array.isArray(targets) ? targets : []
  const seqs = list
    .map(target => readNumber(target, 'seq'))
    .filter((seq): seq is number => seq !== undefined)
  const images = list.reduce((total: number, target) => total + (readArrayLength(target, 'imageIndexes') ?? 0), 0)
  return {
    classUid: CLASS.apiActivity,
    activityId: ACTIVITY.api.delete,
    severityId: SEVERITY.low,
    statusId: STATUS.success,
    message: `image offload over ${String(list.length)} surface node(s)`,
    api: { operation: 'image/offload' },
    attributes: {
      offload_target_count: list.length,
      offload_image_count: images,
      offload_seqs: seqs as JsonValue,
    },
  }
}
