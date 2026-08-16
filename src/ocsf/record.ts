/**
 * Composition of one OCSF record from the per-process identity, the session
 * subject, and a mapper's per-event result.
 *
 * The split exists because the mappers must stay pure functions of one event:
 * everything that is the same for every record in a process (product, device,
 * actor) is resolved once here.
 * @module ocsf/record
 */

import { hostname, platform, userInfo } from 'node:os'
import type { ResolvedConfig } from '../config.ts'
import {
  AI_AGENT_TYPE_NATIVE,
  CATEGORY_OF_CLASS,
  CLASS,
  OCSF_VERSION,
  USER_TYPE_USER,
  type ClassUid,
  typeUid,
} from './constants.ts'
import type {
  DshAttributes,
  JsonValue,
  OcsfActor,
  OcsfAiModel,
  OcsfApi,
  OcsfDelegation,
  OcsfDevice,
  OcsfFile,
  OcsfHttpRequest,
  OcsfJob,
  OcsfMessageContext,
  OcsfNetworkEndpoint,
  OcsfObservable,
  OcsfProcess,
  OcsfRecord,
  OcsfUser,
} from './types.ts'

/** Version of the extension-owned attribute object, independent of the harness log format. */
export const DSH_ATTRIBUTES_VERSION = 1

/** Name reported as the agent runtime in `ai_agent.name`. */
const AGENT_NAME = 'deepseek-harness'

/** Profiles every record declares, one per profile-owned attribute it carries. */
const RECORD_PROFILES: readonly string[] = Object.freeze(['ai_operation', 'cloud', 'osint'])

/** Per-process identity shared by every record. */
export interface RecordEnvironment {
  readonly config: ResolvedConfig
  readonly productName: string
  readonly productVersion: string
  readonly device: OcsfDevice
  readonly actor: OcsfActor
  readonly user: OcsfUser
  /** `src_endpoint` of the API Activity records; the host the agent runs on. */
  readonly srcEndpoint: OcsfNetworkEndpoint
  /** Injectable so tests get deterministic `metadata.logged_time`. */
  readonly now: () => number
}

/**
 * Build the per-process identity every record shares.
 * @param config - the resolved configuration.
 * @param productVersion - this plugin's version, reported in `metadata.product`.
 * @param now - clock used for `metadata.logged_time`.
 * @returns the shared record environment.
 */
export function createEnvironment(
  config: ResolvedConfig,
  productVersion: string,
  now: () => number = Date.now,
): RecordEnvironment {
  const user: OcsfUser = { name: userInfo().username, type_id: USER_TYPE_USER }
  const host = hostname()
  return {
    config,
    productName: 'dsh-ocsf-forwarder',
    productVersion,
    device: { type_id: 0, hostname: host, os: { name: platform(), type_id: 0 } },
    actor: { process: { pid: process.pid, name: 'dsh' }, user },
    user,
    srcEndpoint: { hostname: host, svc_name: AGENT_NAME },
    now,
  }
}

/** The session-level facts a record needs beyond the event itself. */
export interface RecordSubject {
  readonly sessionId: string
  readonly seq: number
  readonly time: number
  readonly eventType: string
  /** True when the record was produced by seed replay rather than the live firehose. */
  readonly replayed: boolean
  /** Overrides the default `<session id>:<seq>` idempotency key for synthetic records. */
  readonly uid?: string
  readonly parentSessionId?: string
  readonly seedLength?: number
  readonly agentPreset?: string
  readonly cwd?: string
  /** The session's current model route, folded from `request/context`. */
  readonly aiModel?: OcsfAiModel
  /** Verbatim event payload for the restricted lane; never set for the SOC lane. */
  readonly rawData?: string
}

/** One mapper's result: everything about a record that depends on the event. */
export interface EventMapping {
  readonly classUid: ClassUid
  readonly activityId: number
  readonly severityId: number
  readonly statusId?: number
  readonly statusDetail?: string
  readonly message?: string
  readonly correlationUid?: string
  readonly startTime?: number
  readonly duration?: number
  readonly process?: OcsfProcess
  readonly file?: OcsfFile
  readonly api?: OcsfApi
  readonly httpRequest?: OcsfHttpRequest
  readonly job?: OcsfJob
  readonly privileges?: readonly string[]
  readonly messageContext?: OcsfMessageContext
  readonly delegation?: OcsfDelegation
  readonly observables?: readonly OcsfObservable[]
  /** Extension-owned attributes, merged with the identity ones added here. */
  readonly attributes?: Readonly<Record<string, JsonValue>>
}

/** Drop `undefined`-valued keys so the serialized record has no empty slots. */
function compact(value: Readonly<Record<string, unknown>>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(value).filter(([, item]) => item !== undefined))
}

/**
 * Compose one OCSF record.
 * @param env - the per-process identity.
 * @param subject - the session-level facts.
 * @param mapping - the mapper's per-event result.
 * @returns a complete OCSF 1.9.0 record, ready to serialize.
 */
export function buildRecord(
  env: RecordEnvironment,
  subject: RecordSubject,
  mapping: EventMapping,
): OcsfRecord {
  const { config } = env
  const attributes: DshAttributes = {
    v: DSH_ATTRIBUTES_VERSION,
    session_id: subject.sessionId,
    event_type: subject.eventType,
    seq: subject.seq,
    replayed: subject.replayed,
    ...subject.parentSessionId === undefined ? {} : { parent_session_id: subject.parentSessionId },
    ...subject.seedLength === undefined ? {} : { seed_length: subject.seedLength },
    ...subject.agentPreset === undefined ? {} : { agent_preset: subject.agentPreset },
    ...subject.cwd === undefined ? {} : { cwd: subject.cwd },
    ...mapping.attributes,
  }
  const record: Record<string, unknown> = {
    class_uid: mapping.classUid,
    category_uid: CATEGORY_OF_CLASS[mapping.classUid],
    type_uid: typeUid(mapping.classUid, mapping.activityId),
    activity_id: mapping.activityId,
    severity_id: mapping.severityId,
    status_id: mapping.statusId,
    status_detail: mapping.statusDetail,
    message: mapping.message,
    time: subject.time,
    start_time: mapping.startTime,
    end_time: mapping.duration === undefined ? undefined : subject.time,
    duration: mapping.duration,
    metadata: compact({
      product: {
        name: env.productName,
        vendor_name: config.vendorName,
        version: env.productVersion,
      },
      version: OCSF_VERSION,
      // `cloud` and `osint` are declared because the record carries those
      // objects; under `additionalProperties: false` an undeclared profile's
      // attribute is exactly the validation failure it was meant to avoid.
      profiles: RECORD_PROFILES,
      // `metadata.extension` is deprecated since 1.9.0's 1.1.0 predecessor.
      // The list is omitted entirely until a deployment supplies a uid the
      // OCSF registry assigned it.
      extensions: config.extensionUid === undefined ? undefined : [{
        name: config.extensionName,
        uid: config.extensionUid,
        version: env.productVersion,
      }],
      log_provider: AGENT_NAME,
      log_name: 'session',
      uid: subject.uid ?? `${subject.sessionId}:${subject.seq}`,
      correlation_uid: mapping.correlationUid,
      sequence: subject.seq,
      logged_time: env.now(),
    }),
    // Required by the declared `cloud` and `osint` profiles and meaningless for
    // a host agent; emitted so records validate rather than fail ingestion.
    cloud: { provider: 'Other' },
    osint: [],
    // API Activity requires a source endpoint. Other classes do not define the
    // attribute, and every class is `additionalProperties: false`.
    src_endpoint: mapping.classUid === CLASS.apiActivity ? env.srcEndpoint : undefined,
    ai_agent: compact({
      name: AGENT_NAME,
      type_id: AI_AGENT_TYPE_NATIVE,
      version: env.productVersion,
      instance_uid: subject.sessionId,
      uid: subject.agentPreset,
      ai_model: subject.aiModel,
    }),
    ai_model: subject.aiModel,
    message_context: mapping.messageContext,
    delegation: mapping.delegation,
    actor: env.actor,
    device: env.device,
    user: env.user,
    process: mapping.process,
    file: mapping.file,
    api: mapping.api,
    http_request: mapping.httpRequest,
    job: mapping.job,
    privileges: mapping.privileges,
    observables: mapping.observables,
    raw_data: subject.rawData,
    ...config.extensionPlacement === 'unmapped'
      ? { unmapped: { [config.extensionName]: attributes } }
      : { [config.extensionName]: attributes },
  }
  return compact(record) as OcsfRecord
}
