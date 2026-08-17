/**
 * A read-side SIEM forwarder for DeepSeek Harness: it observes the session
 * event firehose, normalises every event to OCSF 1.9.0, and ships the result
 * to a local append-only spool and an optional OTLP/HTTP collector.
 *
 * The plugin never writes to the session log. `Session.append()` cannot set
 * the envelope's `ignorable` flag, so a plugin-owned event type makes the next
 * resume refuse the whole session; all durable output goes to our own sink.
 * It also registers no waterfall listener, so it cannot change a tool call, an
 * approval decision, or a model request.
 * @module dsh-ocsf-forwarder
 */

import { randomUUID } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { hostname } from 'node:os'
import type { Context } from '@deepseek-ai/cordis'
import type { Session, SessionEvent } from '@deepseek-ai/dsh-session'
import { resolveConfig, type Config } from './config.ts'
import { discoverDelegationTools, mergeDelegationTools, type RegistryLike } from './delegation.ts'
import { Forwarder } from './forwarder.ts'
import { AttestingSink } from './integrity/attest.ts'
import { createEnvironment } from './ocsf/record.ts'
import { Shipper } from './sink/shipper.ts'
import { FanOutSink, SpoolSink, type Sink } from './sink/spool.ts'

export { Config } from './config.ts'
export type {
  ArgumentPolicy,
  CommandLinePolicy,
  ConfigurableToolClass,
  ExtensionPlacement,
  HecTokenSource,
  HmacKeySource,
  ResolvedConfig,
  ResolvedShipper,
  SeedReplay,
  ShipperConfig,
  UrlPolicy,
} from './config.ts'
export type { OcsfAttestation, OcsfFingerprint, OcsfPrevEvent, OcsfRecord } from './ocsf/types.ts'
export type { Transport, BatchOutcome } from './sink/transport.ts'
export { Forwarder } from './forwarder.ts'
export { AttestingSink, RECORD_INTEGRITY_PROFILE, attestRecord, canonicalJson, fingerprintOf } from './integrity/attest.ts'
export { formatReport, spoolFiles, verifyRecords } from './integrity/verify.ts'
export type { ChainFinding, ChainSummary, FindingKind, SpoolSource, VerifyReport } from './integrity/verify.ts'

/** Display metadata; labels the plugin in Cordis diagnostics. */
export const name = 'dsh-ocsf-forwarder'

/**
 * The session store must exist before the forwarder mounts: without it no
 * `session/event` is ever emitted and the plugin would sit silent.
 */
export const inject = ['sessions']

/** Mode of the SOC-lane spool: readable by the operator's group, not by the world. */
const SOC_SPOOL_MODE = 0o640

/** Mode of the restricted spool: verbatim payloads, owner-only. */
const RESTRICTED_SPOOL_MODE = 0o600

/** This package's version, reported in `metadata.product.version`. */
const PLUGIN_VERSION = (JSON.parse(
  readFileSync(new URL('../package.json', import.meta.url), 'utf8'),
) as { version: string }).version

/**
 * Mount the forwarder.
 * @param ctx - the plugin's context; every registration is undone on unload.
 * @param config - validated `cordis.yml` configuration.
 */
export function apply(ctx: Context, config: Config): void {
  const report = (error: unknown): void => {
    ctx.logger.warn(`ocsf-forwarder: ${error instanceof Error ? error.message : String(error)}`)
  }
  const base = resolveConfig(config, process.env, hostname(), report)
  // The provider a delegation tool starts runs on is fixed per plugin row and
  // absent from the tool-call payload, so the composed rows are read here —
  // the earliest point the registry is populated — rather than guessed later.
  const resolved = {
    ...base,
    delegationTools: mergeDelegationTools(
      discoverDelegationTools(ctx.registry as unknown as RegistryLike),
      base.delegationTools,
    ),
  }
  const env = createEnvironment(resolved, PLUGIN_VERSION)

  const warn = (message: string): void => { ctx.logger.warn(`ocsf-forwarder: ${message}`) }
  const soc = new SpoolSink({
    path: resolved.spoolPath,
    maxBytes: resolved.spoolMaxBytes,
    maxGenerations: resolved.spoolMaxGenerations,
    maxTotalBytes: resolved.spoolMaxTotalBytes,
    mode: SOC_SPOOL_MODE,
    onWarn: warn,
  })
  const restricted = resolved.restrictedPath === undefined
    ? undefined
    : new SpoolSink({
      path: resolved.restrictedPath,
      maxBytes: resolved.spoolMaxBytes,
      maxGenerations: resolved.spoolMaxGenerations,
      maxTotalBytes: resolved.spoolMaxTotalBytes,
      mode: RESTRICTED_SPOOL_MODE,
      onWarn: warn,
    })
  const sinks: Sink[] = restricted === undefined ? [soc] : [soc, restricted]
  const closing = new FanOutSink(sinks, report)

  const shipper = resolved.shipper === undefined
    ? undefined
    : new Shipper(resolved.shipper, resolved.spoolPath, undefined, report)
  shipper?.start()

  // One chain per lane: the two lanes are different files carrying different
  // records, and a link that points into the other file cannot be checked from
  // the file it is in. A fresh uid per process is what makes a chain's genesis
  // record mean "this writer started here" rather than "everything before this
  // was deleted".
  const chained = (sink: Sink): Sink => (resolved.attestRecords ? new AttestingSink(sink, randomUUID()) : sink)
  const forwarder = new Forwarder(
    env,
    resolved,
    chained(soc),
    restricted === undefined ? undefined : chained(restricted),
    report,
  )

  // Observation only: `session/event` is `@mode emit`, so nothing here can
  // change the outcome of the append it reports.
  ctx.on('session/created', (session: Session) => {
    forwarder.adopt(session)
  })
  ctx.on('session/event', (session: Session, event: SessionEvent) => {
    forwarder.observe(session, event)
  })
  ctx.on('session/disposed', (session: Session) => {
    forwarder.dispose(session)
  })

  // `session/created` is not replayed on reload, so a mount mid-run adopts
  // whatever is already live.
  for (const session of ctx.sessions.list()) {
    forwarder.adopt(session)
  }

  // Counters nobody reads are counters nobody acts on: a forwarder that has
  // been failing every write since mount looks exactly like an idle one until
  // this line appears in the log. The heartbeat carries the same counters to
  // the SIEM, where "this host went quiet" is detectable and a log line is not.
  const mountedAt = Date.now()
  const tick = (final: boolean): void => {
    const stats = forwarder.stats()
    ctx.logger.info(
      `ocsf-forwarder: forwarded=${String(stats.forwarded)} dropped=${String(stats.dropped)} `
      + `unreadable=${String(stats.unreadable)} failed=${String(stats.failed)}`,
    )
    const pressure = soc.pressure()
    forwarder.heartbeat({
      liveSessions: ctx.sessions.list().length,
      stats,
      spoolBytes: pressure.totalBytes,
      spoolHighWaterBytes: resolved.spoolHighWaterBytes,
      rotationStopped: pressure.rotationStopped,
      sinkFailed: pressure.sinkFailed,
      droppedRecords: pressure.droppedRecords,
      uptimeMs: Date.now() - mountedAt,
      final,
      ...shipper === undefined || resolved.shipper === undefined ? {} : {
        cursor: shipper.cursor(),
        quarantined: shipper.quarantinedCount(),
        destination: resolved.shipper.transport.kind,
      },
    })
  }
  const statsTimer = resolved.statsIntervalMs > 0
    ? setInterval(() => { tick(false) }, resolved.statsIntervalMs)
    : undefined
  statsTimer?.unref()

  ctx.effect(() => async () => {
    if (statsTimer !== undefined) clearInterval(statsTimer)
    // The final heartbeat is written before the shipper stops, so the record
    // that says this forwarder went away can still leave the host.
    tick(true)
    shipper?.stop()
    if (shipper !== undefined) await shipper.drain()
    closing.close()
  }, 'ocsf forwarder')
}
