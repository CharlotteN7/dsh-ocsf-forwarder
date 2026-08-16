/**
 * OCSF identifiers pinned to schema version 1.9.0.
 *
 * Every value here was read from `https://schema.ocsf.io/api/1.9.0/...` and is
 * an external specification, not a deployment choice: none of it is
 * configurable. `type_uid` is derived, never stored — see {@link typeUid}.
 * @module ocsf/constants
 */

/** The OCSF schema version every emitted record declares in `metadata.version`. */
export const OCSF_VERSION = '1.9.0'

/** This plugin's name, reported in `metadata.product.name` and to a destination as the producing service. */
export const PRODUCT_NAME = 'dsh-ocsf-forwarder'

/** Event classes this plugin emits, as `class_uid` values. */
export const CLASS = {
  /** System Activity / File System Activity. */
  fileSystemActivity: 1001,
  /** System Activity / Scheduled Job Activity. */
  scheduledJobActivity: 1006,
  /** System Activity / Process Activity. */
  processActivity: 1007,
  /** Identity & Access Management / Authorize Session. */
  authorizeSession: 3003,
  /** Network Activity / HTTP Activity. */
  httpActivity: 4002,
  /** Application Activity / Application Lifecycle. */
  applicationLifecycle: 6002,
  /** Application Activity / API Activity. */
  apiActivity: 6003,
} as const

/** One of the {@link CLASS} values. */
export type ClassUid = typeof CLASS[keyof typeof CLASS]

/** `category_uid` for each class we emit; OCSF derives it from the class's first digit. */
export const CATEGORY_OF_CLASS: Readonly<Record<ClassUid, number>> = Object.freeze({
  [CLASS.fileSystemActivity]: 1,
  [CLASS.scheduledJobActivity]: 1,
  [CLASS.processActivity]: 1,
  [CLASS.authorizeSession]: 3,
  [CLASS.httpActivity]: 4,
  [CLASS.applicationLifecycle]: 6,
  [CLASS.apiActivity]: 6,
})

/**
 * OCSF's own `name` for each class we emit, which is not always the caption
 * lower-cased: 1001 is captioned "File System Activity" and named
 * `file_activity`. Read from `https://schema.ocsf.io/api/1.9.0/classes`.
 * A destination that groups by class — a Splunk `sourcetype`, for one — uses
 * these so a search matches the schema rather than our wording.
 */
export const CLASS_NAME: Readonly<Record<ClassUid, string>> = Object.freeze({
  [CLASS.fileSystemActivity]: 'file_activity',
  [CLASS.scheduledJobActivity]: 'scheduled_job_activity',
  [CLASS.processActivity]: 'process_activity',
  [CLASS.authorizeSession]: 'authorize_session',
  [CLASS.httpActivity]: 'http_activity',
  [CLASS.applicationLifecycle]: 'application_lifecycle',
  [CLASS.apiActivity]: 'api_activity',
})

/** Class-specific `activity_id` values, grouped by the class that defines them. */
export const ACTIVITY = {
  fileSystem: { create: 1, read: 2, update: 3, delete: 4, other: 99 },
  scheduledJob: { create: 1, update: 2, delete: 3, other: 99 },
  process: { launch: 1, terminate: 2, other: 99 },
  authorizeSession: { assignPrivileges: 1, other: 99 },
  http: { get: 3, post: 6, other: 99 },
  applicationLifecycle: { install: 1, remove: 2, start: 3, stop: 4, restart: 5, update: 8, other: 99 },
  api: { create: 1, read: 2, update: 3, delete: 4, other: 99 },
} as const

/** `severity_id` values of the base event. */
export const SEVERITY = {
  unknown: 0,
  informational: 1,
  low: 2,
  medium: 3,
  high: 4,
  critical: 5,
} as const

/** `status_id` values of the base event. */
export const STATUS = {
  unknown: 0,
  success: 1,
  failure: 2,
  other: 99,
} as const

/** `observable.type_id` values this plugin emits. */
export const OBSERVABLE = {
  hostname: 1,
  userName: 4,
  url: 6,
  hash: 8,
  commandLine: 13,
  filePath: 45,
} as const

/** `ai_agent.type_id`: the harness is a first-party ("Native") agent runtime. */
export const AI_AGENT_TYPE_NATIVE = 1

/** `message_context.ai_role_id` values. */
export const AI_ROLE = {
  unknown: 0,
  user: 1,
  assistant: 2,
  tool: 3,
  agent: 4,
} as const

/** `user.type_id` for a human account. */
export const USER_TYPE_USER = 1

/**
 * The OCSF `type_uid` of one record.
 * @param classUid - the event class.
 * @param activityId - the class-specific activity.
 * @returns `class_uid * 100 + activity_id`, per the OCSF base-event definition.
 */
export function typeUid(classUid: number, activityId: number): number {
  return classUid * 100 + activityId
}
