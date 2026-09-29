/**
 * Mapping of `deliverables/presented`: the files a turn declared as its
 * deliverables.
 *
 * The event names filesystem paths the agent handed to the user, which is the
 * one durable record of what left the workspace through the `present` tool. A
 * path is the security signal rather than a secret — the same rule the file
 * tools' `file.path` observable already follows — so the paths are emitted
 * verbatim and the model-written `description` is not read at all.
 * @module map/deliverables
 */

import { ACTIVITY, CLASS, OBSERVABLE, SEVERITY, STATUS } from '../ocsf/constants.ts'
import type { EventMapping } from '../ocsf/record.ts'
import type { JsonValue, OcsfObservable } from '../ocsf/types.ts'
import { readNumber, readRecord, readString } from '../read.ts'

/**
 * The file name at the end of a POSIX or Windows path.
 * @param path - the declared path, absolute or relative.
 * @returns the last segment, or the whole value when it has no separator.
 */
function baseName(path: string): string {
  return path.slice(Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\')) + 1)
}

/**
 * Map `deliverables/presented`.
 *
 * File System Activity requires one `file`, and the event can name several. The
 * first declared path fills the required object, every path is listed in the
 * extension attributes, and each contributes its own `file.path` observable, so
 * a SIEM matching on observables sees all of them rather than only the first.
 * @param sessionId - the session the event belongs to.
 * @param event - the event's payload.
 * @returns the record mapping, or `undefined` when the payload declares no file
 *   with a readable path: File System Activity has no valid record without one.
 */
export function mapPresentedDeliverables(
  sessionId: string,
  event: { data: unknown },
): EventMapping | undefined {
  const files = readRecord(event.data)?.['files']
  const paths = (Array.isArray(files) ? files : [])
    .map(file => readString(file, 'path'))
    .filter((path): path is string => path !== undefined)
  const first = paths[0]
  if (first === undefined) return undefined
  const callId = readString(event.data, 'callId')
  const observables: readonly OcsfObservable[] = paths.map(path => ({
    name: 'file.path',
    type_id: OBSERVABLE.filePath,
    value: path,
  }))
  return {
    classUid: CLASS.fileSystemActivity,
    activityId: ACTIVITY.fileSystem.read,
    // Files leaving the workspace to the user is the deliverable path a data
    // detection watches; it is not an incident by itself.
    severityId: SEVERITY.low,
    statusId: STATUS.success,
    message: `${String(paths.length)} file(s) presented as deliverables`,
    // The same key the `present` tool call's own records carry, so the
    // declaration joins the invocation that produced it.
    ...callId === undefined ? {} : { correlationUid: `${sessionId}:${callId}` },
    file: { name: baseName(first), type_id: 1, path: first },
    observables,
    attributes: {
      turn: readNumber(event.data, 'turn') ?? 0,
      presented_count: paths.length,
      presented_paths: paths as JsonValue,
      ...callId === undefined ? {} : { call_id: callId },
    },
  }
}
