/**
 * Which composed tools hand the task to a harness this plugin cannot observe.
 *
 * `subagent-claude-code` and `subagent-codex` resolve a real external CLI and
 * spawn it in the parent session's workspace. No DSH session exists for the
 * child, so no session event describes anything it does: telemetry coverage
 * ends at the tool call. That boundary is worth a record of its own, and this
 * module works out which tool names cross it.
 *
 * The provider name is fixed per plugin row and is **not** in the tool-call
 * payload, so a record cannot name the destination harness from the event
 * alone. What the payload does carry is the tool name, and a `tool-subagent`
 * row pairs a tool name with the provider it starts runs on. Reading those rows
 * out of `ctx.registry` at mount recovers the mapping.
 *
 * It is best-effort by construction: `toolName` is a deployment choice, a row
 * may be composed after this plugin mounts, and a deployment may reach an
 * external harness through a plugin this build has never heard of. The
 * `delegationTools` configuration key exists for exactly those cases.
 * @module delegation
 */

import { readString } from './read.ts'

/**
 * Subagent providers that run the task outside this session.
 *
 * `spawn` and `fork` are in-process and fully observed, so they are absent:
 * grading them as unobserved boundaries would bury the two that are. This is a
 * classification, not a tunable — a deployment may add names through
 * `delegationTools` but may not remove one, on the same reasoning as the tool
 * classification table.
 */
export const EXTERNAL_HARNESS_PROVIDERS: ReadonlySet<string> = new Set(['claude-code', 'codex'])

/** Cordis display name of the plugin that registers one delegation tool per row. */
const DELEGATION_PLUGIN_NAME = 'tool-subagent'

/** The part of `ctx.registry` this module reads. */
export interface RegistryLike {
  /** Every registered plugin runtime. */
  values(): Iterable<{ readonly name?: string | undefined; readonly fibers: Iterable<{ readonly config?: unknown }> }>
}

/**
 * The delegation tools a composed profile offers, from its mounted plugin rows.
 * @param registry - the plugin registry, read at mount.
 * @returns tool name to provider name, for providers that leave this session.
 */
export function discoverDelegationTools(registry: RegistryLike): Record<string, string> {
  const discovered: Record<string, string> = {}
  for (const runtime of registry.values()) {
    if (runtime.name !== DELEGATION_PLUGIN_NAME) continue
    for (const fiber of runtime.fibers) {
      const provider = readString(fiber.config, 'provider')
      const toolName = readString(fiber.config, 'toolName')
      if (provider === undefined || toolName === undefined) continue
      if (!EXTERNAL_HARNESS_PROVIDERS.has(provider)) continue
      discovered[toolName] = provider
    }
  }
  return discovered
}

/**
 * Merge the discovered map with the configured one.
 *
 * Configuration may name a tool discovery cannot see; it may not un-name one
 * discovery found. Repo-local configuration is attacker-controlled, and letting
 * it point a discovered delegation tool at a benign provider would silence the
 * loudest record this plugin emits.
 * @param discovered - what the registry reported at mount.
 * @param configured - the `delegationTools` configuration entries.
 * @returns the effective tool name to provider map.
 */
export function mergeDelegationTools(
  discovered: Readonly<Record<string, string>>,
  configured: Readonly<Record<string, string>>,
): Record<string, string> {
  return { ...configured, ...discovered }
}
