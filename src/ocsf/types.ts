/**
 * The subset of the OCSF 1.9.0 object model this plugin produces.
 *
 * These are output types: they describe what we serialize, not the whole
 * schema. Optional members are omitted from a record rather than set to
 * `undefined`, so JSON output never carries null-ish placeholders.
 * @module ocsf/types
 */

/** A JSON value, as it appears in a serialized OCSF record. */
export type JsonValue =
  | string
  | number
  | boolean
  | null
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue }

/** `metadata.product` — the software that produced the record. */
export interface OcsfProduct {
  readonly name: string
  readonly vendor_name: string
  readonly version: string
}

/** `metadata.extension` — the schema extension an record's extra attributes belong to. */
export interface OcsfExtension {
  readonly name: string
  readonly uid: number
  readonly version: string
}

/** `metadata` — required on every OCSF event. */
export interface OcsfMetadata {
  readonly product: OcsfProduct
  readonly version: string
  readonly profiles?: readonly string[]
  readonly extension?: OcsfExtension
  readonly log_provider?: string
  readonly log_name?: string
  /** Idempotency key: `<session id>:<event seq>`. */
  readonly uid?: string
  /** Joins the records of one tool call, approval, turn, or step. */
  readonly correlation_uid?: string
  /** The session-log sequence number, so a consumer can detect gaps. */
  readonly sequence?: number
  /** When this plugin produced the record, as opposed to when the activity happened. */
  readonly logged_time?: number
}

/** One typed observable extracted from a record. */
export interface OcsfObservable {
  readonly name: string
  readonly type_id: number
  readonly value?: string
}

/** `ai_model` of the `ai_operation` profile. */
export interface OcsfAiModel {
  readonly name: string
  readonly ai_provider: string
}

/** `ai_agent` of the `ai_operation` profile. */
export interface OcsfAiAgent {
  readonly name: string
  readonly type_id: number
  readonly version: string
  readonly instance_uid: string
  readonly uid?: string
  readonly ai_model?: OcsfAiModel
}

/** `message_context` of the `ai_operation` profile. */
export interface OcsfMessageContext {
  readonly ai_role_id: number
  readonly uid?: string
  readonly prompt_text?: string
  readonly response_text?: string
  readonly prompt_tokens?: number
  readonly completion_tokens?: number
  readonly total_tokens?: number
}

/** `delegation` of the `ai_operation` profile — one link of the authority chain. */
export interface OcsfDelegation {
  readonly uid: string
  readonly parent_uid?: string
  readonly created_time?: number
}

/** A `process` object; also used for `actor.process`. */
export interface OcsfProcess {
  readonly name?: string
  readonly pid?: number
  readonly cmd_line?: string
  readonly uid?: string
  readonly exit_code?: number
}

/** A `user` object. */
export interface OcsfUser {
  readonly name: string
  readonly type_id: number
}

/** An `actor` object. */
export interface OcsfActor {
  readonly process?: OcsfProcess
  readonly user?: OcsfUser
}

/** A `device` object. */
export interface OcsfDevice {
  readonly type_id: number
  readonly hostname: string
  readonly os?: { readonly name: string; readonly type_id: number }
}

/** A `file` object. */
export interface OcsfFile {
  readonly name: string
  readonly path?: string
  readonly type_id: number
}

/** An `api` object; `operation` is required by the class. */
export interface OcsfApi {
  readonly operation: string
  readonly service?: { readonly name: string }
  readonly version?: string
}

/** An `http_request` object. */
export interface OcsfHttpRequest {
  readonly http_method: string
  readonly url?: { readonly url_string: string; readonly hostname?: string }
}

/** A `job` object. */
export interface OcsfJob {
  readonly name: string
  readonly uid?: string
}

/**
 * The extension-owned object carrying agent-loop semantics OCSF has no home
 * for, stored under the configured extension name so a consumer can strip or
 * index it wholesale. Every instance carries at least `v` (this object's own
 * payload version), `session_id`, `event_type`, and `seq`.
 */
export type DshAttributes = Readonly<Record<string, JsonValue>>

/** One complete OCSF record, as this plugin serializes it. */
export interface OcsfRecord {
  readonly class_uid: number
  readonly category_uid: number
  readonly type_uid: number
  readonly activity_id: number
  readonly severity_id: number
  readonly time: number
  readonly metadata: OcsfMetadata
  /** Required by every class we emit and meaningless on a host agent; see README. */
  readonly cloud: { readonly provider: string }
  /** Required by every class we emit; always empty for a first-party producer. */
  readonly osint: readonly JsonValue[]
  readonly status_id?: number
  readonly status_detail?: string
  readonly message?: string
  readonly start_time?: number
  readonly end_time?: number
  readonly duration?: number
  readonly observables?: readonly OcsfObservable[]
  readonly ai_agent?: OcsfAiAgent
  readonly ai_model?: OcsfAiModel
  readonly message_context?: OcsfMessageContext
  readonly delegation?: OcsfDelegation
  readonly actor?: OcsfActor
  readonly device?: OcsfDevice
  readonly process?: OcsfProcess
  readonly file?: OcsfFile
  readonly user?: OcsfUser
  readonly api?: OcsfApi
  readonly http_request?: OcsfHttpRequest
  readonly job?: OcsfJob
  readonly privileges?: readonly string[]
  /** The verbatim session-event payload; restricted lane only. */
  readonly raw_data?: string
  readonly unmapped?: { readonly [key: string]: JsonValue }
  /** The extension object lives here, under its configured name. */
  readonly [key: string]: unknown
}
