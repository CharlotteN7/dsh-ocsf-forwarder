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
import type { JsonValue, OcsfApi, OcsfFile, OcsfHttpRequest, OcsfObservable, OcsfProcess } from '../ocsf/types.ts'
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
  /** Hands the task to a harness this plugin cannot observe; see {@link DELEGATION_COVERAGE}. */
  | 'delegation-external'

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
  // `cordis_define` compiles and `cordis_run` evaluates a plugin body inside
  // the harness process, under the agent's own uid and with the agent's own
  // service graph in reach. The tool's own README says to treat the toolset
  // like bash access, so it is graded where a SOC's process detections can see
  // it rather than as an opaque API call.
  cordis_define: 'process-launch',
  cordis_run: 'process-launch',
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
  // The external harness is a real child process launched in the parent
  // session's workspace, so Process Activity is the honest class as well as the
  // one a SOC already writes detections against.
  'delegation-external': { classUid: CLASS.processActivity, activityId: ACTIVITY.process.launch },
})

/** Value of `unmapped.dsh.delegation_coverage` on every delegation record. */
export const DELEGATION_COVERAGE = 'none'

/**
 * Classify one tool by name.
 *
 * Delegation is checked first: a tool that hands the task to an unobserved
 * harness is that before it is anything else, and the classification is
 * strictly louder than the one it displaces.
 * @param name - the tool name the model called.
 * @param config - the resolved configuration, for deployment-added names.
 * @returns the tool's class; unknown tools are API activity.
 */
export function classifyTool(name: string, config: ResolvedConfig): ToolClass {
  if (config.delegationTools[name] !== undefined) return 'delegation-external'
  const known = TOOL_CLASSES[name]
  if (known !== undefined) return known
  return config.toolClasses[name] ?? 'api'
}

/** Prefix the MCP client gives every tool it registers on behalf of a server. */
const MCP_NAME_PREFIX = 'mcp__'

/** Separator between the server namespace and the server's own tool name. */
const MCP_NAME_SEPARATOR = '__'

/** An MCP tool name split back into the server that offers it and the tool itself. */
export interface McpIdentity {
  /** The deployment's local namespace for the MCP server. */
  readonly server: string
  /** The tool name as the MCP server publishes it. */
  readonly tool: string
}

/**
 * Split `mcp__<server>__<tool>` back into its two parts.
 *
 * The harness composes the public name as `mcp__${serverName}__${rawName}`,
 * replacing characters outside `[A-Za-z0-9_-]` with `_` and, when that
 * substitution or the 64-character cap changes the name, appending a hash of
 * the identity. So the split is exact for the clean case and best-effort
 * otherwise: the first `__` after the prefix is taken as the separator, because
 * a server namespace is a short deployment-chosen key and a tool name is not.
 * Only the two names are read — never an argument.
 * @param name - the model-facing tool name.
 * @returns the server and tool names, or `undefined` when the name is not an MCP one.
 */
export function parseMcpToolName(name: string): McpIdentity | undefined {
  if (!name.startsWith(MCP_NAME_PREFIX)) return undefined
  const rest = name.slice(MCP_NAME_PREFIX.length)
  const cut = rest.indexOf(MCP_NAME_SEPARATOR)
  if (cut <= 0) return undefined
  const tool = rest.slice(cut + MCP_NAME_SEPARATOR.length)
  if (tool.length === 0) return undefined
  return { server: rest.slice(0, cut), tool }
}

/**
 * The `api` object for one tool call.
 *
 * An MCP tool names the external server in `api.service.name`, which is what
 * lets a SOC pivot on which server an agent talked to; classes other than API
 * Activity define no `api` attribute and every OCSF class is
 * `additionalProperties: false`, so they carry none.
 * @param toolClass - the tool's class.
 * @param toolName - the tool name the model called.
 * @returns the `api` object, or `undefined` for a non-API class.
 */
export function apiOf(toolClass: ToolClass, toolName: string): OcsfApi | undefined {
  if (toolClass !== 'api') return undefined
  const mcp = parseMcpToolName(toolName)
  return {
    operation: `tool:${toolName}`,
    ...mcp === undefined ? {} : { service: { name: `mcp:${mcp.server}` } },
  }
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
  const mcp = parseMcpToolName(toolName)
  const attributes: Record<string, JsonValue> = {
    tool: toolName,
    tool_class: toolClass,
    arguments: redacted as unknown as JsonValue,
    ...args.error === undefined ? {} : { arguments_parse_error: args.error },
    // Metadata only: which server, which tool. An MCP call's arguments follow
    // the same redaction policy as any other tool's and are never widened here.
    ...mcp === undefined ? {} : { mcp_server: mcp.server, mcp_tool: mcp.tool },
  }

  if (toolClass === 'delegation-external') {
    const provider = config.delegationTools[toolName] ?? 'unknown'
    return {
      // The subject of the launch is the external harness, named by the
      // provider that spawns it; the tool name is a deployment choice.
      process: { name: provider },
      observables,
      attributes: {
        ...attributes,
        delegation_provider: provider,
        delegation_boundary: true,
        delegation_coverage: DELEGATION_COVERAGE,
      },
    }
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
