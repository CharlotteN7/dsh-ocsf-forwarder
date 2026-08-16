/**
 * The SOC lane's redaction rules: keyed digests, value classification, and URL
 * sanitisation.
 *
 * The invariant this module exists to hold: a raw argument value, message
 * text, or command line never reaches the SOC lane unless a deployment has
 * explicitly opted that whole category in. Correlation is preserved through
 * `HMAC-SHA256(key, value)` — the same value digests identically everywhere in
 * a process (and across processes when the key is configured), so a SIEM can
 * still join on it.
 * @module privacy
 */

import { createHmac } from 'node:crypto'
import type { ArgumentPolicy, CommandLinePolicy, ResolvedConfig, UrlPolicy } from './config.ts'
import type { JsonValue } from './ocsf/types.ts'

/** Hex characters kept from each digest. 128 bits is far beyond collision reach here. */
const DIGEST_HEX_CHARS = 32

/** What a tool-argument value looks like, without disclosing it. */
export type ValueClass = 'path' | 'url' | 'command' | 'number' | 'boolean' | 'json' | 'text' | 'empty'

/** One redacted tool-argument entry. */
export interface RedactedArgument {
  /** The argument name the model used. */
  readonly key: string
  readonly class: ValueClass
  /** Character length of the value as the model wrote it. */
  readonly length: number
  /** Keyed digest, present unless the policy is `omit`. */
  readonly digest?: string
  /** The verbatim value; present only under the `full` policy. */
  readonly value?: JsonValue
}

/**
 * Keyed digest of one value.
 * @param key - the process's HMAC key.
 * @param value - the value to digest.
 * @returns the truncated hex digest, prefixed with its algorithm.
 */
export function digest(key: Buffer, value: string): string {
  return `hmac-sha256:${createHmac('sha256', key).update(value).digest('hex').slice(0, DIGEST_HEX_CHARS)}`
}

/**
 * Classify a value by what it looks like, so an analyst can filter on shape
 * without seeing content.
 * @param value - the parsed argument value.
 * @returns the value's class.
 */
export function classifyValue(value: unknown): ValueClass {
  if (typeof value === 'number') return 'number'
  if (typeof value === 'boolean') return 'boolean'
  if (typeof value !== 'string') return 'json'
  if (value.length === 0) return 'empty'
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) return 'url'
  if (/^(?:[a-zA-Z]:[\\/]|[\\/~])/.test(value) || /^\.{1,2}[\\/]/.test(value)) return 'path'
  if (/[|;&><$`]/.test(value) || /^\S+\s+-{1,2}\S/.test(value)) return 'command'
  return 'text'
}

/** Render a value as the string that gets digested and measured. */
function stringify(value: unknown): string {
  return typeof value === 'string' ? value : JSON.stringify(value) ?? ''
}

/**
 * Redact one parsed tool-argument record under the configured policy.
 * @param args - the parsed top-level argument record, or `undefined` when the
 *   raw JSON did not parse into an object.
 * @param policy - the argument-value policy.
 * @param key - the process's HMAC key.
 * @returns one entry per top-level argument, in the model's own key order.
 */
export function redactArguments(
  args: Readonly<Record<string, unknown>> | undefined,
  policy: ArgumentPolicy,
  key: Buffer,
): readonly RedactedArgument[] {
  if (args === undefined) return []
  return Object.entries(args).map(([name, value]): RedactedArgument => {
    const text = stringify(value)
    return {
      key: name,
      class: classifyValue(value),
      length: text.length,
      ...policy === 'omit' ? {} : { digest: digest(key, text) },
      ...policy === 'full' ? { value: value as JsonValue } : {},
    }
  })
}

/**
 * The command line as it may appear in the SOC lane.
 * @param command - the verbatim command the tool was asked to run.
 * @param policy - the command-line policy.
 * @param key - the process's HMAC key.
 * @returns the command under `full`, otherwise its keyed digest.
 */
export function redactCommandLine(command: string, policy: CommandLinePolicy, key: Buffer): string {
  return policy === 'full' ? command : digest(key, command)
}

/**
 * Leading `NAME=VALUE` assignments of a command line, with quoted values.
 *
 * `SECRET=… cmd` is the ordinary way to hand a credential to one process, so
 * the first whitespace-delimited token of a command line is a secret at least
 * as often as it is an executable.
 */
const LEADING_ASSIGNMENTS = /^\s*(?:[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|'[^']*'|\S*)\s+)*/

/**
 * The executable name of a command, which is metadata rather than content and
 * is safe in every lane.
 * @param command - the verbatim command.
 * @returns the executable token, or `undefined` when the command is empty or
 *   its leading token still carries a value.
 */
export function commandName(command: string): string | undefined {
  const [first] = command.replace(LEADING_ASSIGNMENTS, '').trim().split(/\s+/, 1)
  if (first === undefined || first.length === 0) return undefined
  // An executable path never contains `=`; anything that does is a value the
  // assignment strip did not recognise, so it is withheld rather than guessed.
  return first.includes('=') ? undefined : first
}

/**
 * A URL as it may appear in the SOC lane. Query strings and fragments are
 * dropped by default because that is where credentials and tokens ride.
 * @param raw - the URL the model supplied.
 * @param policy - the URL policy.
 * @returns the URL under the policy, or `undefined` when `raw` does not parse.
 */
export function redactUrl(raw: string, policy: UrlPolicy): string | undefined {
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    // URL parse failure only: the model supplied a non-URL, which the tool
    // itself will reject; there is nothing to disclose.
    return undefined
  }
  if (policy === 'full') return url.href
  if (policy === 'host') return `${url.protocol}//${url.host}`
  return `${url.protocol}//${url.host}${url.pathname}`
}

/**
 * Digest of a text body (a prompt, a completion, a summary, a goal). The SOC
 * lane never carries the text itself.
 * @param text - the body.
 * @param config - the resolved configuration, for the HMAC key.
 * @returns the digest and the character count.
 */
export function summariseText(text: string, config: ResolvedConfig): { digest: string; length: number } {
  return { digest: digest(config.hmacKey, text), length: text.length }
}
