/**
 * Validated plugin configuration and its resolution into runtime values.
 *
 * Everything a deployment can vary lives here; OCSF identifiers and the tool
 * classification table do not, because they are an external specification and
 * a security invariant respectively. Misconfiguration fails at load: a missing
 * HMAC key variable or an unacknowledged restricted lane throws before any
 * listener is registered.
 * @module config
 */

import { randomBytes } from 'node:crypto'
import z from '@deepseek-ai/schemastery'

/** How much of a tool argument value reaches the SOC lane. */
export type ArgumentPolicy = 'omit' | 'digest' | 'full'

/** How much of a command line reaches the SOC lane. */
export type CommandLinePolicy = 'digest' | 'full'

/** How much of a URL reaches the SOC lane. */
export type UrlPolicy = 'host' | 'sanitized' | 'full'

/** What happens to a resumed or forked session's constructor seed. */
export type SeedReplay = 'none' | 'boundary' | 'full'

/** Where the extension-owned attributes are attached. */
export type ExtensionPlacement = 'attribute' | 'unmapped'

/** Where the digest key comes from. */
export type HmacKeySource = 'ephemeral' | 'env' | 'literal'

/**
 * Classes a deployment may assign to a tool the built-in table does not know.
 * The built-in classifications themselves are not overridable.
 */
export type ConfigurableToolClass =
  | 'process-launch'
  | 'process-terminate'
  | 'file-read'
  | 'file-write'
  | 'file-update'
  | 'http'
  | 'api'

/** Every {@link ConfigurableToolClass}, for schema validation. */
const CONFIGURABLE_TOOL_CLASSES = [
  'process-launch', 'process-terminate', 'file-read', 'file-write', 'file-update', 'http', 'api',
] as const

/** Plugin configuration, as written in `cordis.yml`. */
export interface Config {
  /** Absolute path of the append-only SOC-lane spool (newline-delimited OCSF JSON). */
  spoolPath: string
  /** Rotate the spool once it reaches this many bytes. */
  spoolMaxBytes?: number
  /**
   * How many rotated generations may await the shipper. Rotation stops at this
   * count and the live file grows past `spoolMaxBytes` rather than a
   * generation being deleted unshipped.
   */
  spoolMaxGenerations?: number
  /** How often the forwarder logs its counters. `0` turns the report off. */
  statsIntervalMs?: number
  /** Restricted lane: full event payloads, written only when acknowledged. */
  restricted?: {
    /** Absolute path of the restricted spool; the file is created with mode 0600. */
    path?: string
    /** Must be `true` for the restricted lane to open. Guards against enabling full-body capture by accident. */
    acknowledged?: boolean
  }
  /** OTLP/HTTP log shipper. Disabled when `endpoint` is absent. */
  otlp?: {
    /** Collector base URL; `/v1/logs` is appended when the URL has no path. */
    endpoint?: string
    /** Extra request headers, typically authorization. */
    headers?: Record<string, string>
    /** Records per POST. */
    batchSize?: number
    /** How often the shipper drains the spool. */
    flushIntervalMs?: number
    /** Per-request timeout. */
    timeoutMs?: number
    /** Path of the durable byte cursor; defaults to `<spoolPath>.cursor`. */
    cursorPath?: string
    /** Largest spool region read into memory in one pass. */
    maxReadBytes?: number
    /** Ceiling of the exponential backoff applied after a transient failure. */
    maxBackoffMs?: number
    /** Where batches the collector refuses on content are set aside; defaults to `<spoolPath>.quarantine`. */
    quarantinePath?: string
  }
  /** Redaction policy for the SOC lane. */
  privacy?: {
    argumentValues?: ArgumentPolicy
    commandLine?: CommandLinePolicy
    url?: UrlPolicy
    hmacKey?: {
      source?: HmacKeySource
      /** Environment variable holding the key; required when `source` is `env`. */
      variable?: string
      /** Literal key; required when `source` is `literal`. */
      value?: string
    }
  }
  /** How a resumed or forked session's prior log is treated. */
  seedReplay?: SeedReplay
  /** Session event types never forwarded, in addition to the built-in drops. */
  dropEventTypes?: string[]
  /** Session event types forwarded even though they are dropped by default. */
  includeEventTypes?: string[]
  /** Additional tool names classified as a process, file, http, or api activity. */
  toolClasses?: Record<string, ConfigurableToolClass>
  /** Identity written into `metadata.extensions[]`; the attributes object uses `name` as its key. */
  extension?: {
    name?: string
    /**
     * OCSF extension uid, as assigned by the OCSF extension registry. There is
     * no default: `metadata.extensions` is omitted until a deployment has an
     * assigned uid, because every unassigned value collides with somebody.
     */
    uid?: number
    placement?: ExtensionPlacement
  }
  /** Vendor name written into `metadata.product`. */
  vendorName?: string
}

/** Rotation threshold of the SOC-lane spool. */
const DEFAULT_SPOOL_MAX_BYTES = 256 * 1024 * 1024

/** Rotated generations kept before rotation stops and the live file grows instead. */
const DEFAULT_SPOOL_MAX_GENERATIONS = 16

/** How often the forwarder's counters reach the log. */
const DEFAULT_STATS_INTERVAL_MS = 300_000

/** Records per OTLP POST. */
const DEFAULT_BATCH_SIZE = 256

/** How often the shipper drains the spool. */
const DEFAULT_FLUSH_INTERVAL_MS = 5_000

/** Per-request timeout of one OTLP POST. */
const DEFAULT_TIMEOUT_MS = 10_000

/** Largest spool region the shipper reads into memory in one pass. */
const DEFAULT_MAX_READ_BYTES = 8 * 1024 * 1024

/** Ceiling of the shipper's exponential backoff. */
const DEFAULT_MAX_BACKOFF_MS = 300_000

/** Vendor reported in `metadata.product.vendor_name`. */
const DEFAULT_VENDOR_NAME = 'dsh-security-plugins'

/** Schemastery validator for {@link Config}. */
export const Config: z<Config> = z.object({
  spoolPath: z.string().required(),
  spoolMaxBytes: z.number().default(DEFAULT_SPOOL_MAX_BYTES),
  spoolMaxGenerations: z.number().default(DEFAULT_SPOOL_MAX_GENERATIONS),
  statsIntervalMs: z.number().default(DEFAULT_STATS_INTERVAL_MS),
  restricted: z.object({
    path: z.string(),
    acknowledged: z.boolean().default(false),
  }),
  otlp: z.object({
    endpoint: z.string(),
    headers: z.dict(z.string()).default({}),
    batchSize: z.number().default(DEFAULT_BATCH_SIZE),
    flushIntervalMs: z.number().default(DEFAULT_FLUSH_INTERVAL_MS),
    timeoutMs: z.number().default(DEFAULT_TIMEOUT_MS),
    cursorPath: z.string(),
    maxReadBytes: z.number().default(DEFAULT_MAX_READ_BYTES),
    maxBackoffMs: z.number().default(DEFAULT_MAX_BACKOFF_MS),
    quarantinePath: z.string(),
  }),
  privacy: z.object({
    argumentValues: z.union(['omit', 'digest', 'full'] as const).default('digest'),
    commandLine: z.union(['digest', 'full'] as const).default('digest'),
    // `sanitized` keeps the path, and a path is where a reset or invite token
    // rides as often as a query string does.
    url: z.union(['host', 'sanitized', 'full'] as const).default('host'),
    hmacKey: z.object({
      source: z.union(['ephemeral', 'env', 'literal'] as const).default('ephemeral'),
      variable: z.string(),
      value: z.string(),
    }),
  }),
  seedReplay: z.union(['none', 'boundary', 'full'] as const).default('full'),
  dropEventTypes: z.array(z.string()).default([]),
  includeEventTypes: z.array(z.string()).default([]),
  toolClasses: z.dict(z.union(CONFIGURABLE_TOOL_CLASSES)).default({}),
  extension: z.object({
    name: z.string().default('dsh'),
    uid: z.number(),
    // Every OCSF class is `additionalProperties: false`, so a top-level
    // extension key makes the record fail validation. `unmapped` is the slot
    // the schema provides for exactly this.
    placement: z.union(['attribute', 'unmapped'] as const).default('unmapped'),
  }),
  vendorName: z.string().default(DEFAULT_VENDOR_NAME),
})

/** Event types never forwarded unless `includeEventTypes` names them. */
export const DEFAULT_DROPPED_EVENT_TYPES: readonly string[] = [
  // Token-level stream deltas: the highest-volume type in the log and pure
  // model content. The assembled `assistant/message` is byte-complete.
  'assistant/chunk',
  // Construction marker; the seed-replay boundary record carries its meaning.
  'session/end-seed',
  // Model-written restatements of the user's prompt, and the prompt itself.
  'session/title',
  'session/title-llm-request',
  // A free-text human remark about the session: no security value, high privacy cost.
  'feedback/record',
  // UI state made of user and model task text.
  'todo/write',
]

/** The complete, defaulted configuration the runtime uses. */
export interface ResolvedConfig {
  readonly spoolPath: string
  readonly spoolMaxBytes: number
  readonly spoolMaxGenerations: number
  readonly statsIntervalMs: number
  readonly restrictedPath: string | undefined
  readonly otlp: ResolvedOtlp | undefined
  readonly argumentValues: ArgumentPolicy
  readonly commandLine: CommandLinePolicy
  readonly url: UrlPolicy
  readonly hmacKey: Buffer
  readonly seedReplay: SeedReplay
  readonly forwarded: (eventType: string) => boolean
  readonly toolClasses: Readonly<Record<string, ConfigurableToolClass>>
  readonly extensionName: string
  /** Absent until a deployment configures a uid the OCSF registry assigned it. */
  readonly extensionUid: number | undefined
  readonly extensionPlacement: ExtensionPlacement
  readonly vendorName: string
}

/** The resolved OTLP shipper settings; present only when an endpoint is configured. */
export interface ResolvedOtlp {
  readonly url: string
  readonly headers: Readonly<Record<string, string>>
  readonly batchSize: number
  readonly flushIntervalMs: number
  readonly timeoutMs: number
  readonly cursorPath: string
  readonly maxReadBytes: number
  readonly maxBackoffMs: number
  readonly quarantinePath: string
}

/** Minimum accepted length of a configured HMAC key, in bytes. */
const MIN_HMAC_KEY_BYTES = 32

/**
 * Resolve the digest key. Deployment-supplied keys are validated here so a
 * weak or absent key fails at load rather than producing guessable digests.
 * @param config - the validated configuration.
 * @param env - the process environment to read an `env`-sourced key from.
 * @returns the key bytes used for every HMAC in this process.
 */
function resolveHmacKey(config: Config, env: NodeJS.ProcessEnv): Buffer {
  const source = config.privacy?.hmacKey?.source ?? 'ephemeral'
  if (source === 'ephemeral') return randomBytes(MIN_HMAC_KEY_BYTES)
  if (source === 'literal') {
    const value = config.privacy?.hmacKey?.value
    if (value === undefined || Buffer.byteLength(value) < MIN_HMAC_KEY_BYTES) {
      throw new Error(`ocsf-forwarder: privacy.hmacKey.value must be at least ${MIN_HMAC_KEY_BYTES} bytes for source "literal"`)
    }
    return Buffer.from(value)
  }
  const variable = config.privacy?.hmacKey?.variable
  if (variable === undefined) {
    throw new Error('ocsf-forwarder: privacy.hmacKey.variable is required for source "env"')
  }
  const value = env[variable]
  if (value === undefined || Buffer.byteLength(value) < MIN_HMAC_KEY_BYTES) {
    throw new Error(`ocsf-forwarder: environment variable "${variable}" must hold an HMAC key of at least ${MIN_HMAC_KEY_BYTES} bytes`)
  }
  return Buffer.from(value)
}

/**
 * Resolve the restricted lane. Naming a path is not enough: the lane carries
 * verbatim event payloads, so it also requires an explicit acknowledgement.
 * @param config - the validated configuration.
 * @returns the restricted spool path, or `undefined` when the lane is closed.
 */
function resolveRestrictedPath(config: Config): string | undefined {
  const path = config.restricted?.path
  if (path === undefined) return undefined
  if (config.restricted?.acknowledged !== true) {
    throw new Error('ocsf-forwarder: restricted.path writes verbatim session payloads; set restricted.acknowledged: true to open that lane')
  }
  return path
}

/**
 * Resolve the OTLP endpoint into the exact URL the shipper posts to.
 * @param config - the validated configuration.
 * @returns the shipper settings, or `undefined` when no endpoint is configured.
 */
function resolveOtlp(config: Config): ResolvedOtlp | undefined {
  const endpoint = config.otlp?.endpoint
  if (endpoint === undefined) return undefined
  let url: URL
  try {
    url = new URL(endpoint)
  } catch {
    // URL parse failure only; the message names the offending value.
    throw new Error(`ocsf-forwarder: otlp.endpoint is not a valid URL: ${endpoint}`)
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error(`ocsf-forwarder: otlp.endpoint must be an http or https URL, got "${endpoint}"`)
  }
  const target = url.pathname === '/' ? new URL('/v1/logs', url).href : url.href
  return {
    url: target,
    headers: { ...config.otlp?.headers },
    batchSize: config.otlp?.batchSize ?? DEFAULT_BATCH_SIZE,
    flushIntervalMs: config.otlp?.flushIntervalMs ?? DEFAULT_FLUSH_INTERVAL_MS,
    timeoutMs: config.otlp?.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    cursorPath: config.otlp?.cursorPath ?? `${config.spoolPath}.cursor`,
    maxReadBytes: config.otlp?.maxReadBytes ?? DEFAULT_MAX_READ_BYTES,
    maxBackoffMs: config.otlp?.maxBackoffMs ?? DEFAULT_MAX_BACKOFF_MS,
    quarantinePath: config.otlp?.quarantinePath ?? `${config.spoolPath}.quarantine`,
  }
}

/**
 * Turn validated configuration into the runtime values the forwarder uses,
 * failing loud on anything that cannot be resolved.
 * @param config - the validated configuration.
 * @param env - the process environment, read for an `env`-sourced HMAC key.
 * @returns the complete resolved configuration.
 */
export function resolveConfig(config: Config, env: NodeJS.ProcessEnv = process.env): ResolvedConfig {
  const dropped = new Set([...DEFAULT_DROPPED_EVENT_TYPES, ...config.dropEventTypes ?? []])
  for (const type of config.includeEventTypes ?? []) dropped.delete(type)
  return {
    spoolPath: config.spoolPath,
    spoolMaxBytes: config.spoolMaxBytes ?? DEFAULT_SPOOL_MAX_BYTES,
    spoolMaxGenerations: config.spoolMaxGenerations ?? DEFAULT_SPOOL_MAX_GENERATIONS,
    statsIntervalMs: config.statsIntervalMs ?? DEFAULT_STATS_INTERVAL_MS,
    restrictedPath: resolveRestrictedPath(config),
    otlp: resolveOtlp(config),
    argumentValues: config.privacy?.argumentValues ?? 'digest',
    commandLine: config.privacy?.commandLine ?? 'digest',
    url: config.privacy?.url ?? 'host',
    hmacKey: resolveHmacKey(config, env),
    seedReplay: config.seedReplay ?? 'full',
    forwarded: (eventType: string): boolean => !dropped.has(eventType),
    toolClasses: { ...config.toolClasses },
    extensionName: config.extension?.name ?? 'dsh',
    extensionUid: config.extension?.uid,
    extensionPlacement: config.extension?.placement ?? 'unmapped',
    vendorName: config.vendorName ?? DEFAULT_VENDOR_NAME,
  }
}
