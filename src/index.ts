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

import { readFileSync } from 'node:fs'
import type { Context } from '@deepseek-ai/cordis'
import type { Session, SessionEvent } from '@deepseek-ai/dsh-session'
import { resolveConfig, type Config } from './config.ts'
import { Forwarder } from './forwarder.ts'
import { createEnvironment } from './ocsf/record.ts'
import { OtlpShipper } from './sink/otlp.ts'
import { FanOutSink, SpoolSink, type Sink } from './sink/spool.ts'

export { Config } from './config.ts'
export type {
  ArgumentPolicy,
  CommandLinePolicy,
  ConfigurableToolClass,
  ExtensionPlacement,
  HmacKeySource,
  ResolvedConfig,
  SeedReplay,
  UrlPolicy,
} from './config.ts'
export type { OcsfRecord } from './ocsf/types.ts'
export { Forwarder } from './forwarder.ts'

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
  const resolved = resolveConfig(config)
  const env = createEnvironment(resolved, PLUGIN_VERSION)
  const report = (error: unknown): void => {
    ctx.logger.warn(`ocsf-forwarder: ${error instanceof Error ? error.message : String(error)}`)
  }

  const soc = new SpoolSink({ path: resolved.spoolPath, maxBytes: resolved.spoolMaxBytes, mode: SOC_SPOOL_MODE })
  const restricted = resolved.restrictedPath === undefined
    ? undefined
    : new SpoolSink({ path: resolved.restrictedPath, maxBytes: resolved.spoolMaxBytes, mode: RESTRICTED_SPOOL_MODE })
  const sinks: Sink[] = restricted === undefined ? [soc] : [soc, restricted]
  const closing = new FanOutSink(sinks, report)

  const shipper = resolved.otlp === undefined
    ? undefined
    : new OtlpShipper(resolved.otlp, resolved.spoolPath, env.productName, undefined, report)
  shipper?.start()

  const forwarder = new Forwarder(env, resolved, soc, restricted, report)

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

  ctx.effect(() => async () => {
    shipper?.stop()
    if (shipper !== undefined) await shipper.drain()
    closing.close()
  }, 'ocsf forwarder')
}
