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

import { randomBytes, randomUUID } from 'node:crypto'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { hostname as osHostname } from 'node:os'
import { dirname } from 'node:path'
import z from '@deepseek-ai/schemastery'
import { PRODUCT_NAME } from './ocsf/constants.ts'
import { createOtlpTransport } from './sink/otlp.ts'
import { HEC_EVENT_PATH, createSplunkTransport } from './sink/splunk.ts'
import type { Transport } from './sink/transport.ts'

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

/** Where the Splunk HEC token comes from. There is no ephemeral option: a token is issued, not generated. */
export type HecTokenSource = 'env' | 'literal'

/**
 * Delivery settings every shipper shares. They describe the drain, not the
 * wire, so a new destination inherits them unchanged.
 */
export interface ShipperConfig {
  /** Extra request headers. */
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
  /** Where batches the destination refuses on content are set aside; defaults to `<spoolPath>.quarantine`. */
  quarantinePath?: string
}

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
  /**
   * Second stop condition on rotation, in bytes across the live spool and every
   * rotated generation. Rotation stops here on the same refuse-to-rotate terms
   * as `spoolMaxGenerations`: this is a disk bound, never a delete policy.
   */
  spoolMaxTotalBytes?: number
  /**
   * Total spool bytes at which the heartbeat is raised to `severity_id: 4`, so
   * the SOC learns from the SIEM rather than from a full disk. Must not exceed
   * `spoolMaxTotalBytes`.
   */
  spoolHighWaterBytes?: number
  /**
   * How often the forwarder logs its counters and emits a heartbeat record.
   * `0` reports and heartbeats only at unload.
   */
  statsIntervalMs?: number
  /** Restricted lane: full event payloads, written only when acknowledged. */
  restricted?: {
    /** Absolute path of the restricted spool; the file is created with mode 0600. */
    path?: string
    /** Must be `true` for the restricted lane to open. Guards against enabling full-body capture by accident. */
    acknowledged?: boolean
  }
  /** OTLP/HTTP log shipper. Disabled when `endpoint` is absent. */
  otlp?: ShipperConfig & {
    /** Collector base URL; `/v1/logs` is appended when the URL has no path. */
    endpoint?: string
  }
  /**
   * Splunk HTTP Event Collector shipper. Disabled when `endpoint` is absent.
   * At most one shipper may be configured; two endpoints fail at load.
   */
  splunk?: ShipperConfig & {
    /** HEC base URL, typically `https://<host>:8088`. The collector path is appended. */
    endpoint?: string
    /** The HEC token. Read from the environment unless a literal is configured. */
    token?: {
      source?: HecTokenSource
      /** Environment variable holding the token; required when `source` is `env`. */
      variable?: string
      /** Literal token; required when `source` is `literal`. */
      value?: string
    }
    /** `index` stamped on every event; omitted so the token's default index applies. */
    index?: string
    /** `host` stamped on every event; defaults to this machine's hostname. */
    host?: string
    /** `source` stamped on every event. */
    source?: string
    /** `sourcetype` is `<prefix>:<class name>`, so one search matches every OCSF class. */
    sourcetypePrefix?: string
  }
  /** Fleet identity stamped into `metadata` and `device` on every record. */
  fleet?: {
    /** `metadata.tenant_uid`: the org or business-unit key a multi-team SOC filters on. */
    tenantUid?: string
    /** `metadata.labels`: free tags, typically an environment such as `prod` or `ci`. */
    labels?: string[]
    /** `metadata.tags`: name/value pairs, rendered as OCSF `key_value_object` entries. */
    tags?: Record<string, string>
    /** `device.uid`: an explicit install uid, which wins over the persisted one. */
    installUid?: string
    /**
     * Where the generated install uid is persisted, so a renamed host keeps its
     * identity. Defaults to `<spoolPath>.install-uid`.
     */
    installUidPath?: string
  }
  /**
   * Tool names that hand the task to a harness outside this session, mapped to
   * the provider that runs it. Composed `tool-subagent` rows naming an external
   * provider are discovered at mount; entries here add names that discovery
   * cannot see. An entry may not un-name a discovered tool.
   */
  delegationTools?: Record<string, string>
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

/**
 * Bytes across the live spool and every rotated generation before rotation
 * stops. Sized to the count bound it complements: sixteen generations of
 * 256 MiB each.
 */
const DEFAULT_SPOOL_MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024

/** Total spool bytes at which the heartbeat is raised to `severity_id: 4`. */
const DEFAULT_SPOOL_HIGH_WATER_BYTES = 3 * 1024 * 1024 * 1024

/** Records per POST. */
const DEFAULT_BATCH_SIZE = 256

/** How often the shipper drains the spool. */
const DEFAULT_FLUSH_INTERVAL_MS = 5_000

/** Per-request timeout of one POST. */
const DEFAULT_TIMEOUT_MS = 10_000

/** `sourcetype` prefix of every Splunk event; the OCSF class name follows it. */
const DEFAULT_SOURCETYPE_PREFIX = 'ocsf'

/** `source` stamped on every Splunk event. */
const DEFAULT_SPLUNK_SOURCE = 'dsh:session'

/** Largest spool region the shipper reads into memory in one pass. */
const DEFAULT_MAX_READ_BYTES = 8 * 1024 * 1024

/** Ceiling of the shipper's exponential backoff. */
const DEFAULT_MAX_BACKOFF_MS = 300_000

/** Vendor reported in `metadata.product.vendor_name`. */
const DEFAULT_VENDOR_NAME = 'dsh-security-plugins'

/** The delivery fields every shipper block carries, declared once. */
const SHIPPER_FIELDS = {
  headers: z.dict(z.string()).default({}),
  batchSize: z.number().default(DEFAULT_BATCH_SIZE),
  flushIntervalMs: z.number().default(DEFAULT_FLUSH_INTERVAL_MS),
  timeoutMs: z.number().default(DEFAULT_TIMEOUT_MS),
  cursorPath: z.string(),
  maxReadBytes: z.number().default(DEFAULT_MAX_READ_BYTES),
  maxBackoffMs: z.number().default(DEFAULT_MAX_BACKOFF_MS),
  quarantinePath: z.string(),
} as const

/** Schemastery validator for {@link Config}. */
export const Config: z<Config> = z.object({
  spoolPath: z.string().required(),
  spoolMaxBytes: z.number().default(DEFAULT_SPOOL_MAX_BYTES),
  spoolMaxGenerations: z.number().default(DEFAULT_SPOOL_MAX_GENERATIONS),
  spoolMaxTotalBytes: z.number().default(DEFAULT_SPOOL_MAX_TOTAL_BYTES),
  spoolHighWaterBytes: z.number().default(DEFAULT_SPOOL_HIGH_WATER_BYTES),
  statsIntervalMs: z.number().default(DEFAULT_STATS_INTERVAL_MS),
  restricted: z.object({
    path: z.string(),
    acknowledged: z.boolean().default(false),
  }),
  otlp: z.object({
    endpoint: z.string(),
    ...SHIPPER_FIELDS,
  }),
  splunk: z.object({
    endpoint: z.string(),
    token: z.object({
      source: z.union(['env', 'literal'] as const).default('env'),
      variable: z.string(),
      value: z.string(),
    }),
    index: z.string(),
    host: z.string(),
    source: z.string().default(DEFAULT_SPLUNK_SOURCE),
    sourcetypePrefix: z.string().default(DEFAULT_SOURCETYPE_PREFIX),
    ...SHIPPER_FIELDS,
  }),
  fleet: z.object({
    tenantUid: z.string(),
    labels: z.array(z.string()).default([]),
    tags: z.dict(z.string()).default({}),
    installUid: z.string(),
    installUidPath: z.string(),
  }),
  delegationTools: z.dict(z.string()).default({}),
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

/** The fleet identity every record carries, resolved once per process. */
export interface ResolvedFleet {
  /** `metadata.tenant_uid`; absent unless configured. */
  readonly tenantUid: string | undefined
  /** `metadata.labels`; absent when the list is empty. */
  readonly labels: readonly string[] | undefined
  /** `metadata.tags`, already in OCSF's `key_value_object` shape. */
  readonly tags: readonly { readonly name: string; readonly value: string }[] | undefined
  /** `device.uid`: stable across a rename of the host. */
  readonly installUid: string
}

/** The complete, defaulted configuration the runtime uses. */
export interface ResolvedConfig {
  readonly spoolPath: string
  readonly spoolMaxBytes: number
  readonly spoolMaxGenerations: number
  readonly spoolMaxTotalBytes: number
  readonly spoolHighWaterBytes: number
  readonly statsIntervalMs: number
  readonly restrictedPath: string | undefined
  readonly shipper: ResolvedShipper | undefined
  readonly fleet: ResolvedFleet
  readonly argumentValues: ArgumentPolicy
  readonly commandLine: CommandLinePolicy
  readonly url: UrlPolicy
  readonly hmacKey: Buffer
  readonly seedReplay: SeedReplay
  readonly forwarded: (eventType: string) => boolean
  readonly toolClasses: Readonly<Record<string, ConfigurableToolClass>>
  /** Tool names that hand the task to an unobserved harness, mapped to its provider. */
  readonly delegationTools: Readonly<Record<string, string>>
  readonly extensionName: string
  /** Absent until a deployment configures a uid the OCSF registry assigned it. */
  readonly extensionUid: number | undefined
  readonly extensionPlacement: ExtensionPlacement
  readonly vendorName: string
}

/**
 * The resolved shipper settings; present only when exactly one destination is
 * configured. The transport holds everything wire-specific, so nothing below it
 * varies by destination.
 */
export interface ResolvedShipper {
  readonly transport: Transport
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
 * Validate one positive finite limit.
 *
 * The schema types these fields as numbers and nothing more, so `0` reaches the
 * runtime: as a batch size it is an infinite loop in the shipper, as a timeout
 * it is a request that can never complete, and as a rotation bound it is a
 * spool that refuses to rotate for the life of the process. Misconfiguration
 * fails at load instead.
 * @param name - the configuration key, named in the failure message.
 * @param value - the configured value.
 * @returns the value, once it is usable.
 */
function assertPositive(name: string, value: number): number {
  if (!Number.isFinite(value) || value <= 0) throw new Error(`ocsf-forwarder: ${name} must be a positive finite number`)
  return value
}

/** Validate one count of records or files, which a fraction cannot express. */
function assertPositiveInteger(name: string, value: number): number {
  if (!Number.isInteger(value) || value <= 0) throw new Error(`ocsf-forwarder: ${name} must be a positive integer`)
  return value
}

/** Validate one interval whose zero has a documented meaning of its own. */
function assertNonNegative(name: string, value: number): number {
  if (!Number.isFinite(value) || value < 0) throw new Error(`ocsf-forwarder: ${name} must be zero or a positive finite number`)
  return value
}

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
 * Parse and validate one configured destination URL.
 * @param key - the configuration key, named in any failure message.
 * @param endpoint - the URL as configured.
 * @param defaultPath - the path appended when the URL carries none.
 * @returns the exact URL the shipper posts to.
 */
function destinationUrl(key: string, endpoint: string, defaultPath: string): string {
  let url: URL
  try {
    url = new URL(endpoint)
  } catch {
    // URL parse failure only; the message names the offending value.
    throw new Error(`ocsf-forwarder: ${key} is not a valid URL: ${endpoint}`)
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error(`ocsf-forwarder: ${key} must be an http or https URL, got "${endpoint}"`)
  }
  return url.pathname === '/' ? new URL(defaultPath, url).href : url.href
}

/**
 * The delivery settings shared by every destination, with the spool-derived
 * defaults applied.
 * @param config - the validated configuration, read for the spool-derived paths.
 * @param key - the configuration block these settings came from, named in any failure.
 * @param block - the block itself.
 * @returns the resolved delivery settings.
 */
function shipperDefaults(config: Config, key: string, block: ShipperConfig): Omit<ResolvedShipper, 'transport'> {
  return {
    batchSize: assertPositiveInteger(`${key}.batchSize`, block.batchSize ?? DEFAULT_BATCH_SIZE),
    flushIntervalMs: assertPositive(`${key}.flushIntervalMs`, block.flushIntervalMs ?? DEFAULT_FLUSH_INTERVAL_MS),
    timeoutMs: assertPositive(`${key}.timeoutMs`, block.timeoutMs ?? DEFAULT_TIMEOUT_MS),
    cursorPath: block.cursorPath ?? `${config.spoolPath}.cursor`,
    maxReadBytes: assertPositive(`${key}.maxReadBytes`, block.maxReadBytes ?? DEFAULT_MAX_READ_BYTES),
    maxBackoffMs: assertPositive(`${key}.maxBackoffMs`, block.maxBackoffMs ?? DEFAULT_MAX_BACKOFF_MS),
    quarantinePath: block.quarantinePath ?? `${config.spoolPath}.quarantine`,
  }
}

/**
 * Resolve the Splunk HEC token. A token is issued rather than generated, so an
 * absent or empty one fails at load rather than producing a shipper that will
 * be refused on every batch.
 * @param config - the validated configuration.
 * @param env - the process environment to read an `env`-sourced token from.
 * @returns the token placed in the authorization header.
 */
function resolveHecToken(config: Config, env: NodeJS.ProcessEnv): string {
  const token = config.splunk?.token
  if ((token?.source ?? 'env') === 'literal') {
    const value = token?.value
    if (value === undefined || value.length === 0) {
      throw new Error('ocsf-forwarder: splunk.token.value is required for source "literal"')
    }
    return value
  }
  const variable = token?.variable
  if (variable === undefined) {
    throw new Error('ocsf-forwarder: splunk.token.variable is required for source "env"')
  }
  const value = env[variable]
  if (value === undefined || value.length === 0) {
    throw new Error(`ocsf-forwarder: environment variable "${variable}" must hold the Splunk HEC token`)
  }
  return value
}

/**
 * Resolve the one configured destination into a shipper.
 *
 * Two destinations share one cursor file by default and would each step it past
 * the other's deliveries, so naming both fails at load rather than losing
 * records to whichever drained second.
 * @param config - the validated configuration.
 * @param env - the process environment, read for an `env`-sourced HEC token.
 * @param hostname - this machine's hostname, the default Splunk `host`.
 * @returns the shipper settings, or `undefined` when no destination is configured.
 */
function resolveShipper(
  config: Config,
  env: NodeJS.ProcessEnv,
  hostname: string,
): ResolvedShipper | undefined {
  const otlpEndpoint = config.otlp?.endpoint
  const splunkEndpoint = config.splunk?.endpoint
  if (otlpEndpoint !== undefined && splunkEndpoint !== undefined) {
    throw new Error(
      'ocsf-forwarder: otlp.endpoint and splunk.endpoint are both set; one spool has one shipper, '
      + 'so configure exactly one destination',
    )
  }
  if (otlpEndpoint !== undefined) {
    return {
      transport: createOtlpTransport(
        destinationUrl('otlp.endpoint', otlpEndpoint, '/v1/logs'),
        { ...config.otlp?.headers },
        PRODUCT_NAME,
      ),
      ...shipperDefaults(config, 'otlp', config.otlp ?? {}),
    }
  }
  if (splunkEndpoint === undefined) return undefined
  return {
    transport: createSplunkTransport(
      destinationUrl('splunk.endpoint', splunkEndpoint, HEC_EVENT_PATH),
      resolveHecToken(config, env),
      { ...config.splunk?.headers },
      {
        host: config.splunk?.host ?? hostname,
        source: config.splunk?.source ?? DEFAULT_SPLUNK_SOURCE,
        sourcetypePrefix: config.splunk?.sourcetypePrefix ?? DEFAULT_SOURCETYPE_PREFIX,
        ...config.splunk?.index === undefined ? {} : { index: config.splunk.index },
      },
    ),
    ...shipperDefaults(config, 'splunk', config.splunk ?? {}),
  }
}

/**
 * Resolve the fleet identity, generating and persisting an install uid the
 * first time one is needed.
 *
 * A hostname is not an identity: it changes when a laptop is renamed and
 * collides across a fleet built from one image. The uid is written beside the
 * spool so the same installation keeps it across restarts.
 * @param config - the validated configuration.
 * @returns the identity stamped onto every record.
 */
function resolveFleet(config: Config): ResolvedFleet {
  const labels = config.fleet?.labels ?? []
  const tags = Object.entries(config.fleet?.tags ?? {}).map(([name, value]) => ({ name, value }))
  return {
    tenantUid: config.fleet?.tenantUid,
    labels: labels.length === 0 ? undefined : [...labels],
    tags: tags.length === 0 ? undefined : tags,
    installUid: config.fleet?.installUid
      ?? readOrCreateInstallUid(config.fleet?.installUidPath ?? `${config.spoolPath}.install-uid`),
  }
}

/**
 * Read the persisted install uid, minting one on first run.
 * @param path - where the uid is kept.
 * @returns the uid this installation reports as `device.uid`.
 */
function readOrCreateInstallUid(path: string): string {
  try {
    const existing = readFileSync(path, 'utf8').trim()
    if (existing.length > 0) return existing
  } catch {
    // ENOENT only: this installation has not minted a uid yet.
  }
  const minted = randomUUID()
  mkdirSync(dirname(path), { recursive: true })
  writeFileSync(path, `${minted}\n`, { mode: 0o640 })
  return minted
}

/**
 * Turn validated configuration into the runtime values the forwarder uses,
 * failing loud on anything that cannot be resolved.
 * @param config - the validated configuration.
 * @param env - the process environment, read for an `env`-sourced HMAC key.
 * @returns the complete resolved configuration.
 */
export function resolveConfig(
  config: Config,
  env: NodeJS.ProcessEnv = process.env,
  hostname: string = osHostname(),
): ResolvedConfig {
  const dropped = new Set([...DEFAULT_DROPPED_EVENT_TYPES, ...config.dropEventTypes ?? []])
  for (const type of config.includeEventTypes ?? []) dropped.delete(type)
  const maxTotalBytes = assertPositive(
    'spoolMaxTotalBytes',
    config.spoolMaxTotalBytes ?? DEFAULT_SPOOL_MAX_TOTAL_BYTES,
  )
  const highWaterBytes = assertPositive(
    'spoolHighWaterBytes',
    config.spoolHighWaterBytes ?? DEFAULT_SPOOL_HIGH_WATER_BYTES,
  )
  if (highWaterBytes > maxTotalBytes) {
    throw new Error(
      `ocsf-forwarder: spoolHighWaterBytes (${String(highWaterBytes)}) exceeds spoolMaxTotalBytes `
      + `(${String(maxTotalBytes)}), so the alarm would never fire before rotation stopped`,
    )
  }
  return {
    spoolPath: config.spoolPath,
    spoolMaxBytes: assertPositive('spoolMaxBytes', config.spoolMaxBytes ?? DEFAULT_SPOOL_MAX_BYTES),
    spoolMaxGenerations: assertPositiveInteger(
      'spoolMaxGenerations',
      config.spoolMaxGenerations ?? DEFAULT_SPOOL_MAX_GENERATIONS,
    ),
    spoolMaxTotalBytes: maxTotalBytes,
    spoolHighWaterBytes: highWaterBytes,
    statsIntervalMs: assertNonNegative('statsIntervalMs', config.statsIntervalMs ?? DEFAULT_STATS_INTERVAL_MS),
    restrictedPath: resolveRestrictedPath(config),
    shipper: resolveShipper(config, env, hostname),
    fleet: resolveFleet(config),
    argumentValues: config.privacy?.argumentValues ?? 'digest',
    commandLine: config.privacy?.commandLine ?? 'digest',
    url: config.privacy?.url ?? 'host',
    hmacKey: resolveHmacKey(config, env),
    seedReplay: config.seedReplay ?? 'full',
    forwarded: (eventType: string): boolean => !dropped.has(eventType),
    toolClasses: { ...config.toolClasses },
    delegationTools: { ...config.delegationTools },
    extensionName: config.extension?.name ?? 'dsh',
    extensionUid: config.extension?.uid === undefined
      ? undefined
      : assertPositiveInteger('extension.uid', config.extension.uid),
    extensionPlacement: config.extension?.placement ?? 'unmapped',
    vendorName: config.vendorName ?? DEFAULT_VENDOR_NAME,
  }
}
