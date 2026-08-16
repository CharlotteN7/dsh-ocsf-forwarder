/**
 * The heartbeat: a periodic record saying the forwarder is alive, what it has
 * counted, and how far delivery has got.
 *
 * OCSF 1.9.0 has **no** heartbeat, liveness, health-check, keepalive or
 * checkpoint class. Enumerating every class at
 * `https://schema.ocsf.io/api/1.9.0/classes` (87 entries) and searching name,
 * caption and description for those words returns nothing, so there is no slot
 * to map onto and this is not a standard mapping. Application Lifecycle (6002)
 * is the nearest home; the activity is `Other` (99) rather than `Start`,
 * because the record reports that the application is still running rather than
 * that it started, and `unmapped.dsh.kind` says what it actually is.
 *
 * A `metadata.sequence` gap is only detectable inside a session, so a host that
 * goes quiet is invisible without this. Detection is well-trodden on the SIEM
 * side and is documented in the README rather than shipped here.
 * @module map/heartbeat
 */

import { ACTIVITY, CLASS, SEVERITY, STATUS } from '../ocsf/constants.ts'
import type { EventMapping } from '../ocsf/record.ts'
import type { ForwarderStats } from '../forwarder.ts'

/** `unmapped.dsh.kind` of a heartbeat, since OCSF names no class for one. */
export const HEARTBEAT_KIND = 'heartbeat'

/** `activity_name` accompanying the `Other` activity id. */
const HEARTBEAT_ACTIVITY_NAME = 'Heartbeat'

/** Everything one heartbeat reports. */
export interface HeartbeatState {
  /** Sessions the store held when the heartbeat was taken. */
  readonly liveSessions: number
  /** The forwarder's counters. */
  readonly stats: ForwarderStats
  /** Bytes the spool occupies across its live file and every rotated generation. */
  readonly spoolBytes: number
  /** Total spool bytes at which this heartbeat is raised to `severity_id: 4`. */
  readonly spoolHighWaterBytes: number
  /** True once a stop condition has held rotation and the live file is growing. */
  readonly rotationStopped: boolean
  /** Byte offset delivery has reached in the live spool, absent when no shipper is configured. */
  readonly cursor?: number
  /** Records this process has set aside as refused, absent when no shipper is configured. */
  readonly quarantined?: number
  /** How long this forwarder has been mounted, in milliseconds. */
  readonly uptimeMs: number
  /** Which destination the shipper posts to, absent when no shipper is configured. */
  readonly destination?: string
  /** True when the heartbeat is the last one, emitted as the plugin unloads. */
  readonly final: boolean
}

/**
 * Map one heartbeat.
 *
 * The spool crossing its high-water mark is the one condition that raises the
 * severity: a spool that is filling is an outage the SOC should learn about
 * from the SIEM rather than from a full disk, and rotation refusing to run is
 * the same condition one step later.
 * @param state - what this heartbeat reports.
 * @returns the record mapping.
 */
export function mapHeartbeat(state: HeartbeatState): EventMapping {
  const pressured = state.rotationStopped || state.spoolBytes >= state.spoolHighWaterBytes
  return {
    classUid: CLASS.applicationLifecycle,
    activityId: ACTIVITY.applicationLifecycle.other,
    activityName: HEARTBEAT_ACTIVITY_NAME,
    severityId: pressured ? SEVERITY.high : SEVERITY.informational,
    statusId: STATUS.success,
    message: pressured
      ? `ocsf-forwarder heartbeat: spool at ${String(state.spoolBytes)} bytes, `
        + `high-water mark ${String(state.spoolHighWaterBytes)}`
      : 'ocsf-forwarder heartbeat',
    attributes: {
      kind: HEARTBEAT_KIND,
      live_sessions: state.liveSessions,
      forwarded: state.stats.forwarded,
      dropped: state.stats.dropped,
      unreadable: state.stats.unreadable,
      failed: state.stats.failed,
      spool_bytes: state.spoolBytes,
      spool_high_water_bytes: state.spoolHighWaterBytes,
      spool_pressure: pressured,
      rotation_stopped: state.rotationStopped,
      uptime_ms: state.uptimeMs,
      final: state.final,
      ...state.cursor === undefined ? {} : { shipper_cursor: state.cursor },
      ...state.quarantined === undefined ? {} : { shipper_quarantined: state.quarantined },
      ...state.destination === undefined ? {} : { shipper_destination: state.destination },
    },
  }
}
