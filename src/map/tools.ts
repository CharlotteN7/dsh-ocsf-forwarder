/**
 * Tool classification: which OCSF class a tool invocation belongs to, and the
 * class-specific objects built from its arguments.
 *
 * The built-in table is a security invariant, not a tunable. Classifying
 * `bash` as an API call on a deployment's say-so would break every
 * process-based detection downstream, so `toolClasses` config entries may only
 * add names the table does not know.
 * @module map/tools
 */

import type { ResolvedConfig } from '../config.ts'
import { ACTIVITY, CLASS, OBSERVABLE, type ClassUid } from '../ocsf/constants.ts'
import type { JsonValue, OcsfFile, OcsfHttpRequest, OcsfObservable, OcsfProcess } from '../ocsf/types.ts'
import { commandName, redactArguments, redactCommandLine, redactUrl } from '../privacy.ts'

/** The activity a tool performs, in OCSF terms. */
export type ToolClass =
  | 'process-launch'
  | 'process-terminate'
  | 'file-read'
  | 'file-write'
  | 'file-update'
  | 'http'
  | 'api'

/** Tool names this build ships, mapped to the activity they perform. */
export const TOOL_CLASSES: Readonly<Record<string, ToolClass>> = Object.freeze({
  bash: 'process-launch',
  pwsh: 'process-launch',
  run_code: 'process-launch',
  terminal_open: 'process-launch',
  terminal_send: 'process-launch',
  terminal_close: 'process-terminate',
  terminal_signal: 'process-terminate',
  job_kill: 'process-terminate',
  read: 'file-read',
  read_image: 'file-read',
  glob: 'file-read',
  grep: 'file-read',
  write: 'file-write',
  edit: 'file-update',
  str_replace_editor: 'file-update',
  web_fetch: 'http',
  web_search: 'http',
})

/** The OCSF class and activity one {@link ToolClass} maps to. */
const CLASS_OF_TOOL_CLASS: Readonly<Record<ToolClass, { classUid: ClassUid; activityId: number }>> = Object.freeze({
  'process-launch': { classUid: CLASS.processActivity, activityId: ACTIVITY.process.launch },
  'process-terminate': { classUid: CLASS.processActivity, activityId: ACTIVITY.process.terminate },
  'file-read': { classUid: CLASS.fileSystemActivity, activityId: ACTIVITY.fileSystem.read },
  'file-write': { classUid: CLASS.fileSystemActivity, activityId: ACTIVITY.fileSystem.create },
  'file-update': { classUid: CLASS.fileSystemActivity, activityId: ACTIVITY.fileSystem.update },
  http: { classUid: CLASS.httpActivity, activityId: ACTIVITY.http.get },
  api: { classUid: CLASS.apiActivity, activityId: ACTIVITY.api.read },
})

/**
 * Classify one tool by name.
 * @param name - the tool name the model called.
 * @param config - the resolved configuration, for deployment-added names.
 * @returns the tool's class; unknown tools are API activity.
 */
export function classifyTool(name: string, config: ResolvedConfig): ToolClass {
  const known = TOOL_CLASSES[name]
  if (known !== undefined) return known
  return config.toolClasses[name] ?? 'api'
}

/**
 * The OCSF class and activity for one tool.
 * @param toolClass - the tool's class.
 * @returns the `class_uid` and `activity_id` to record.
 */
export function ocsfClassOf(toolClass: ToolClass): { classUid: ClassUid; activityId: number } {
  return CLASS_OF_TOOL_CLASS[toolClass]
}

/** Tool arguments after defensive parsing of the model's raw JSON string. */
export interface ParsedArguments {
  /** The parsed top-level record, absent when the raw string was not a JSON object. */
  readonly record?: Readonly<Record<string, unknown>>
  /** Why parsing failed, when it did. */
  readonly error?: string
}

/**
 * Parse a tool call's raw `arguments` string. This is model output crossing
 * into our code, so it is validated rather than trusted.
 * @param raw - the unparsed JSON string exactly as the model produced it.
 * @returns the parsed record, or the parse failure.
 */
export function parseArguments(raw: string): ParsedArguments {
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    // The parser's own message quotes a window of the offending text, which
    // for a malformed tool call is the raw model output — the one thing this
    // lane may not carry. Only the fact of the failure is recorded.
    return { error: 'tool arguments are not valid JSON' }
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { error: 'tool arguments are not a JSON object' }
  }
  return { record: parsed as Record<string, unknown> }
}

/** Read one string-valued argument, if present. */
function stringArg(args: Readonly<Record<string, unknown>> | undefined, key: string): string | undefined {
  const value = args?.[key]
  return typeof value === 'string' ? value : undefined
}

/** The class-specific objects and observables one tool call contributes. */
export interface ToolDetails {
  readonly process?: OcsfProcess
  readonly file?: OcsfFile
  readonly httpRequest?: OcsfHttpRequest
  readonly observables: readonly OcsfObservable[]
  readonly attributes: Readonly<Record<string, JsonValue>>
}

/**
 * Build the class-specific objects for one tool call under the SOC lane's
 * redaction policy.
 * @param toolName - the tool the model called.
 * @param toolClass - its class.
 * @param args - its parsed arguments.
 * @param config - the resolved configuration.
 * @returns objects, observables, and extension attributes for the record.
 */
export function toolDetails(
  toolName: string,
  toolClass: ToolClass,
  args: ParsedArguments,
  config: ResolvedConfig,
): ToolDetails {
  const observables: OcsfObservable[] = []
  const redacted = redactArguments(args.record, config.argumentValues, config.hmacKey)
  const attributes: Record<string, JsonValue> = {
    tool: toolName,
    tool_class: toolClass,
    arguments: redacted as unknown as JsonValue,
    ...args.error === undefined ? {} : { arguments_parse_error: args.error },
  }

  if (toolClass === 'process-launch' || toolClass === 'process-terminate') {
    const command = stringArg(args.record, 'command') ?? stringArg(args.record, 'code') ?? ''
    const rendered = redactCommandLine(command, config.commandLine, config.hmacKey)
    if (command.length > 0) {
      observables.push({ name: 'process.cmd_line', type_id: config.commandLine === 'full' ? OBSERVABLE.commandLine : OBSERVABLE.hash, value: rendered })
    }
    return {
      process: {
        name: commandName(command) ?? toolName,
        ...command.length === 0 ? {} : { cmd_line: rendered },
      },
      observables,
      attributes,
    }
  }

  if (toolClass === 'file-read' || toolClass === 'file-write' || toolClass === 'file-update') {
    // `pattern` is deliberately not a path fallback: a search expression is a
    // query the model composed, not a location, and it routinely contains the
    // very value it is hunting for.
    const path = stringArg(args.record, 'file_path') ?? stringArg(args.record, 'path')
    if (path !== undefined) observables.push({ name: 'file.path', type_id: OBSERVABLE.filePath, value: path })
    return {
      // A path is the security signal, not a secret, so it is emitted verbatim.
      file: { name: path === undefined ? toolName : path.split(/[\\/]/).pop() ?? path, type_id: 1, ...path === undefined ? {} : { path } },
      observables,
      attributes,
    }
  }

  if (toolClass === 'http') {
    const raw = stringArg(args.record, 'url')
    const url = raw === undefined ? undefined : redactUrl(raw, config.url)
    if (url !== undefined) observables.push({ name: 'http_request.url.url_string', type_id: OBSERVABLE.url, value: url })
    return {
      httpRequest: {
        http_method: 'GET',
        ...url === undefined ? {} : { url: { url_string: url } },
      },
      observables,
      attributes,
    }
  }

  return { observables, attributes }
}
