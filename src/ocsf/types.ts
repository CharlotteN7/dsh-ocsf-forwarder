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

/** One entry of `metadata.extensions` — a schema extension the record uses. */
export interface OcsfExtension {
  readonly name: string
  readonly uid: number
  readonly version: string
}

/** One `key_value_object` entry, as `metadata.tags` requires. */
export interface OcsfKeyValue {
  readonly name: string
  readonly value: string
}

/**
 * An `application` object. Application Lifecycle constrains
 * `at_least_one: [app, application]` and deprecated `app` in 1.9.0, so every
 * record of that class carries this.
 */
export interface OcsfApplication {
  readonly name: string
  readonly uid?: string
}

/** `metadata` — required on every OCSF event. */
export interface OcsfMetadata {
  readonly product: OcsfProduct
  readonly version: string
  readonly profiles?: readonly string[]
  /** The org or business-unit key a multi-team SOC filters on. */
  readonly tenant_uid?: string
  /** Free tags, typically the deployment environment. */
  readonly labels?: readonly string[]
  /** Name/value pairs; OCSF types this as an array of `key_value_object`, not a map. */
  readonly tags?: readonly OcsfKeyValue[]
  /** The event's time as the session log recorded it, passed through unnormalised. */
  readonly original_time?: string
  /** `metadata.extension` has been deprecated since OCSF 1.1.0 in favour of this list. */
  readonly extensions?: readonly OcsfExtension[]
  readonly log_provider?: string
  readonly log_name?: string
  /**
   * Idempotency key: `<session id>:<event seq>`. Required rather than optional
   * because a chained record's successor references it as `prev_event.uid`, and
   * a link to nothing is not a link.
   */
  readonly uid: string
  /** Joins the records of one tool call, approval, turn, or step. */
  readonly correlation_uid?: string
  /** The session-log sequence number, so a consumer can detect gaps. */
  readonly sequence?: number
  /** When this plugin produced the record, as opposed to when the activity happened. */
  readonly logged_time?: number
}

/**
 * A `fingerprint` object: a hash over some canonical serialization, with the
 * algorithm and the encoding of `value` named by their OCSF enum ids.
 *
 * The `algorithm` and `encoding` string siblings are omitted. Both are defined
 * as the caption of their id, so they carry no information a reader holding the
 * schema does not have, and every record carries two of these objects.
 */
export interface OcsfFingerprint {
  readonly value: string
  readonly algorithm_id: number
  readonly encoding_id: number
}

/** A `prev_event` reference: the previous entry of a tamper-evident chain. */
export interface OcsfPrevEvent {
  /** The previous record's `metadata.uid`. */
  readonly uid: string
  /** The previous record's `type_uid`, which names the class it is stored under. */
  readonly type_uid: number
  readonly fingerprint: OcsfFingerprint
}

/**
 * One `attestation` of the `record_integrity` profile.
 *
 * `signatures` and `authority_uid` are deliberately absent: this producer holds
 * no signing credential, so there is no identity to bind and none to name. The
 * class constraint `at_least_one: [fingerprint, signatures]` is met by the
 * fingerprint.
 */
export interface OcsfAttestation {
  /** This entry's position in its chain, as `<chain_uid>:<index>`. */
  readonly uid: string
  /** The chain this entry belongs to: one spool file written by one process. */
  readonly chain_uid: string
  /** Absent on the genesis entry of a chain. */
  readonly prev_event?: OcsfPrevEvent
  /** Hash of this record's canonical serialization, less this field. */
  readonly fingerprint: OcsfFingerprint
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

/**
 * A `network_endpoint` object. API Activity requires `src_endpoint`: for an
 * on-host agent the caller is the host itself.
 */
export interface OcsfNetworkEndpoint {
  readonly hostname: string
  readonly svc_name?: string
}

/** A `device` object. */
export interface OcsfDevice {
  readonly type_id: number
  readonly hostname: string
  /** The stable install uid, so a renamed host is still the same device. */
  readonly uid?: string
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
  /** Set alongside an `activity_id` of 99, which OCSF leaves to the producer to name. */
  readonly activity_name?: string
  readonly severity_id: number
  readonly time: number
  readonly metadata: OcsfMetadata
  /** Required by Application Lifecycle's `at_least_one: [app, application]` constraint. */
  readonly application?: OcsfApplication
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
  /** The `record_integrity` profile's attestations; present when attesting is on. */
  readonly attestation_list?: readonly OcsfAttestation[]
  readonly ai_agent?: OcsfAiAgent
  readonly ai_model?: OcsfAiModel
  readonly message_context?: OcsfMessageContext
  readonly delegation?: OcsfDelegation
  readonly actor?: OcsfActor
  readonly device?: OcsfDevice
  /** Required by API Activity; the host the agent runs on. */
  readonly src_endpoint?: OcsfNetworkEndpoint
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
