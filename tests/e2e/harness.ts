/**
 * Keyless end-to-end harness: boot a real `dsh` agent with this plugin mounted
 * into a throwaway profile, drive it with scripted mock-model responses, and
 * hand the test everything the run produced.
 *
 * No API key is involved anywhere. `@deepseek-ai/dsh-llm-mock-server` speaks the
 * OpenAI-compatible wire protocol the shipped DeepSeek adapter already talks to,
 * so the adapter, the agent loop, the tool pipeline, and persistence are all the
 * real ones; only the far side of the socket is scripted.
 * @module tests/e2e/harness
 */

import { spawn } from 'node:child_process'
import { cpSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  startMockLlmServer,
  type MockLlmBehavior,
  type MockLlmRequestRecord,
  type MockLlmServer,
} from '@deepseek-ai/dsh-llm-mock-server'

/** Package root of the plugin under test. */
const PLUGIN_ROOT = fileURLToPath(new URL('../../', import.meta.url))

/** This package's own manifest, read once for its name and runtime dependencies. */
const PLUGIN_MANIFEST = JSON.parse(
  readFileSync(join(PLUGIN_ROOT, 'package.json'), 'utf8'),
) as { name: string; dependencies?: Record<string, string> }

/** Package name the profile mounts; must match this package's `package.json` name. */
const PLUGIN_PACKAGE = PLUGIN_MANIFEST.name

/**
 * Harness checkout used to launch the agent, defaulting to `../dsh` beside
 * this repository. Point `DSH_REPO` at a checkout whose
 * `pnpm run build:lib:host` has run at least once; without those Typert host
 * artifacts profile boot fails with module-resolution errors.
 */
const DSH_REPO = process.env.DSH_REPO ?? fileURLToPath(new URL('../../../dsh', import.meta.url))

/**
 * Which `dsh` entry the agent boots from. `src` runs `apps/cli/src/bin.ts`
 * under tsx and needs only `pnpm run build:lib:host` in the checkout. `lib`
 * runs the built `apps/cli/lib/bin.js` under plain Node — the installed form,
 * which resolves this plugin through its real package `exports` into `lib/`
 * and is therefore the mode that catches export-shape mistakes. `lib` needs a
 * full `pnpm run build`.
 */
const LAUNCH_MODE = process.env.DSH_EXAMPLE_MODE === 'lib' ? 'lib' : 'src'

/**
 * Absolute path to an installed `dsh` bin, used instead of a harness checkout.
 * Set this to `node_modules/@deepseek-ai/dsh/lib/bin.js` to run against the
 * published CLI, which is what CI does: the published package needs no
 * monorepo, no `build:lib:host`, and resolves its own bundles. Requires
 * `autoInstallPeers: true`, because `@deepseek-ai/dsh-app-boot` declares the
 * vendored cordis plugins as required peers.
 */
const DSH_CLI = process.env.DSH_CLI

/** Directory the CLI subprocess starts in; the agent records it as the session cwd. */
const DSH_CWD = DSH_CLI === undefined ? DSH_REPO : dirname(DSH_CLI)

/** Command and leading arguments that boot the CLI in the selected mode. */
function launchArgv(): readonly string[] {
  if (DSH_CLI !== undefined) return [DSH_CLI]
  return LAUNCH_MODE === 'lib'
    ? [join(DSH_REPO, 'apps/cli/lib/bin.js')]
    : ['--import', import.meta.resolve('tsx'), join(DSH_REPO, 'apps/cli/src/bin.ts')]
}

/** One end-to-end run's inputs. */
export interface AgentRunOptions {
  /** The task string handed to `dsh --profile <name>`. */
  readonly task: string
  /** Ordered mock behaviors, one per accepted chat-completions request. */
  readonly sequence: readonly MockLlmBehavior[]
  /** Tool name emitted by every `tool_call_success` entry. */
  readonly toolName?: string
  /** Raw JSON arguments emitted by every `tool_call_success` entry. */
  readonly toolArguments?: string
  /** Complete text returned by success-shaped behaviors. */
  readonly successText?: string
  /** Extra rows appended to the profile's own patch layer. */
  readonly extraProfilePatch?: string
  /**
   * `DSH_PERMISSION_MODE` for the run. The default keeps tools unattended;
   * `workspace-write` leaves the base bundle's approval policy at `ask`, which
   * is what an approval-path test needs.
   */
  readonly permissionMode?: string
  /** Milliseconds before the agent process is killed. */
  readonly timeoutMs?: number
  /**
   * Prepare the filesystem the run will use, after the profile is materialised
   * and before the agent is launched.
   *
   * The returned function runs once the agent has exited and before the
   * throwaway home is removed, so a test that changed a filesystem attribute
   * can put it back — a file left append-only makes the cleanup fail.
   */
  readonly prepareRun?: (paths: RunPaths) => () => void
}

/** Paths a run will use, handed to {@link AgentRunOptions.prepareRun}. */
export interface RunPaths {
  /** The throwaway `$DSH_HOME`. */
  readonly home: string
  /** Where the bundle patch's default puts the SOC spool. Its directory does not exist yet. */
  readonly spoolPath: string
}

/** Everything one end-to-end run produced. */
export interface AgentRunResult {
  readonly code: number
  readonly stdout: string
  readonly stderr: string
  /** OCSF records the forwarder spooled, in order. */
  readonly ocsfRecords: readonly OcsfLine[]
  /**
   * The spool's lines exactly as they were written, byte for byte. The
   * integrity chain covers the serialized record, so a test that re-serializes
   * the parsed form is not verifying what the forwarder wrote.
   */
  readonly ocsfSpoolLines: readonly string[]
  /** The persisted session log, one parsed JSONL row per element. */
  readonly sessionLog: readonly Record<string, unknown>[]
  /** Wire requests the agent made, as captured by the mock. */
  readonly modelRequests: readonly MockLlmRequestRecord[]
}

/** One spooled OCSF record, read back as plain JSON. */
export interface OcsfLine extends Record<string, unknown> {
  readonly class_uid: number
  readonly activity_id: number
  readonly metadata: Record<string, unknown> & { readonly uid?: string; readonly correlation_uid?: string }
  /** The extension attributes, under the `unmapped` slot the schema provides. */
  readonly unmapped: { readonly dsh: Record<string, unknown> }
}

/**
 * The extension-owned attributes of one spooled record.
 * @param record - the record read back from the spool.
 * @returns the `dsh` attribute object.
 */
export function dshOf(record: OcsfLine): Record<string, unknown> {
  return record.unmapped.dsh
}

/**
 * Whether one record is the forwarder reporting on itself rather than on a
 * session. A heartbeat belongs to no session, so it carries no session id.
 * @param record - the record read back from the spool.
 * @returns true for a heartbeat.
 */
export function isHeartbeat(record: OcsfLine): boolean {
  return dshOf(record)['kind'] === 'heartbeat'
}

/** Recursively collect every file under `dir`; missing directories yield nothing. */
function filesUnder(dir: string): string[] {
  let entries: string[]
  try {
    entries = readdirSync(dir)
  } catch {
    // ENOENT only: the run may legitimately have persisted nothing.
    return []
  }
  return entries.flatMap((entry) => {
    const full = join(dir, entry)
    return statSync(full).isDirectory() ? filesUnder(full) : [full]
  })
}

/** Read a JSONL file's lines; a missing file yields none. */
function readLines(file: string): string[] {
  let text: string
  try {
    text = readFileSync(file, 'utf8')
  } catch {
    // ENOENT only: the plugin writes lazily and a run may observe nothing.
    return []
  }
  return text.split('\n').filter(line => line.length > 0)
}

/** Parse a JSONL file into rows; a missing file yields an empty list. */
function readJsonl(file: string): Record<string, unknown>[] {
  return readLines(file).map(line => JSON.parse(line) as Record<string, unknown>)
}

/**
 * Directory of one installed package, resolved the way Node's own lookup
 * would. The real path is searched as well as the given one: under pnpm a
 * package directory is a symlink into the store, and a dependency of that
 * package lives beside its real location, not beside the link.
 * @param name - the package to locate.
 * @param fromDir - the directory whose resolution paths are searched.
 * @returns the located package directory.
 */
function packageDir(name: string, fromDir: string): string {
  const bases = new Set([fromDir, realpathSync(fromDir)])
  for (const base of bases) {
    const require = createRequire(join(base, 'package.json'))
    for (const searchPath of require.resolve.paths(name) ?? []) {
      const candidate = join(searchPath, name)
      try {
        statSync(join(candidate, 'package.json'))
        return candidate
      } catch {
        // ENOENT only: keep walking the resolution paths.
        continue
      }
    }
  }
  throw new Error(`e2e harness: cannot resolve ${name} from ${fromDir}`)
}

/**
 * Copy this plugin's runtime dependency closure into a flat `node_modules`
 * beside the installed plugin.
 *
 * The plugin is copied, not symlinked, into the profile tree, so its own pnpm
 * store is out of Node's reach from there. Without this the run only works
 * because the launcher's resolution happens to reach the harness checkout's
 * own copy of `@deepseek-ai/schemastery`, which is not what an installed
 * profile looks like. Peer dependencies are deliberately absent: every harness
 * type this package uses is imported with `import type`, so nothing from
 * `@deepseek-ai/cordis` or the `dsh-*` packages is emitted as a runtime
 * import, and Cordis must come from the running installation rather than a
 * copy.
 * @param installDir - the plugin's directory inside the profile's node_modules.
 */
function copyRuntimeDependencies(installDir: string): void {
  const copied = new Set<string>()
  const queue: { name: string; fromDir: string }[] = Object.keys(PLUGIN_MANIFEST.dependencies ?? {})
    .map(name => ({ name, fromDir: PLUGIN_ROOT }))
  while (queue.length > 0) {
    const next = queue.pop()
    if (next === undefined) continue
    if (copied.has(next.name)) continue
    copied.add(next.name)
    const source = packageDir(next.name, next.fromDir)
    const target = join(installDir, 'node_modules', next.name)
    mkdirSync(dirname(target), { recursive: true })
    cpSync(source, target, { recursive: true, dereference: true })
    const manifest = JSON.parse(readFileSync(join(source, 'package.json'), 'utf8')) as {
      dependencies?: Record<string, string>
    }
    for (const name of Object.keys(manifest.dependencies ?? {})) {
      queue.push({ name, fromDir: source })
    }
  }
  // Prove the installed copy is self-sufficient rather than leaning on the
  // launcher reaching the harness checkout: every package in the closure must
  // now resolve from inside the profile tree.
  for (const name of copied) {
    statSync(join(installDir, 'node_modules', name, 'package.json'))
  }
}

/**
 * Materialize a throwaway `$DSH_HOME` holding one profile that mounts this
 * plugin, then boot the agent against a freshly scripted mock model.
 *
 * The plugin is COPIED (never symlinked) into
 * `$DSH_HOME/profiles/e2e/node_modules/<name>`: Node resolves a symlink to its
 * real path, which would move the parent walk off the profile tree and out of
 * reach of the installation's flat module fallback at
 * `$DSH_HOME/profiles/node_modules`.
 * @param options - the task, the model script, and optional profile overrides.
 * @returns process output, plugin observations, the session log, and mock request records.
 */
export async function runAgent(options: AgentRunOptions): Promise<AgentRunResult> {
  const home = mkdtempSync(join(tmpdir(), 'dsh-plugin-e2e-'))
  const profileDir = join(home, 'profiles', 'e2e')
  const installDir = join(profileDir, 'node_modules', PLUGIN_PACKAGE)
  const sessionsRoot = join(home, 'sessions')
  // The bundle patch defaults this to dshHomePath(...), so the throwaway home
  // isolates it without the test overriding the row.
  const spoolPath = join(home, 'ocsf', 'session.ocsf.jsonl')
  let server: MockLlmServer | undefined
  let restore: (() => void) | undefined

  try {
    mkdirSync(installDir, { recursive: true })
    // The `"type": "module"` manifest is load-bearing: without it tsx compiles
    // the plugin as CommonJS and the loader fails with ERR_REQUIRE_CYCLE_MODULE.
    for (const entry of ['package.json', 'cordis.patch.yml', 'src', 'lib']) {
      try {
        cpSync(join(PLUGIN_ROOT, entry), join(installDir, entry), { recursive: true })
      } catch {
        // ENOENT only: `lib` is absent until `pnpm run build` has run.
      }
    }
    copyRuntimeDependencies(installDir)

    writeFileSync(join(profileDir, 'package.json'), `${JSON.stringify({
      name: 'dsh-profile-e2e',
      private: true,
      dependencies: {},
      dsh: { profile: { bundles: ['@deepseek-ai/dsh-base', '@deepseek-ai/dsh-headless', PLUGIN_PACKAGE] } },
    }, undefined, 2)}\n`)

    // Later layers win per row, and a patch REPLACES a row's whole `config`,
    // so the persistence override restates `root`.
    writeFileSync(join(profileDir, 'cordis.patch.yml'), [
      '- id: session-persistence-jsonl',
      '  config:',
      `    root: '${sessionsRoot}'`,
      '    compression: none',
      '    packChunks: false',
      options.extraProfilePatch ?? '',
      '',
    ].join('\n'))

    restore = options.prepareRun?.({ home, spoolPath })

    server = await startMockLlmServer({
      sequence: options.sequence,
      apiKey: 'mock-key',
      ...options.toolName === undefined ? {} : { toolName: options.toolName },
      ...options.toolArguments === undefined ? {} : { toolArguments: options.toolArguments },
      ...options.successText === undefined ? {} : { successText: options.successText },
    })

    const child = spawn(process.execPath, [
      ...launchArgv(),
      '--profile', 'e2e',
      options.task,
    ], {
      cwd: DSH_CWD,
      env: {
        ...process.env,
        DSH_HOME: home,
        DSH_TELEMETRY_DISABLED: '1',
        DSH_PERMISSION_MODE: options.permissionMode ?? 'danger-full-access',
        DEEPSEEK_API_KEY: 'mock-key',
        DEEPSEEK_BASE_URL: server.baseURL,
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    })

    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (chunk: Buffer) => { stdout += chunk.toString() })
    child.stderr.on('data', (chunk: Buffer) => { stderr += chunk.toString() })

    const code = await new Promise<number>((resolve, reject) => {
      const timer = setTimeout(() => {
        child.kill('SIGKILL')
        reject(new Error(`dsh did not exit within ${options.timeoutMs ?? 90_000}ms\nstdout:\n${stdout}\nstderr:\n${stderr}`))
      }, options.timeoutMs ?? 90_000)
      child.on('error', reject)
      child.on('close', (exitCode) => {
        clearTimeout(timer)
        resolve(exitCode ?? -1)
      })
    })

    const logFile = filesUnder(sessionsRoot).find(file => file.endsWith('.jsonl'))

    return {
      code,
      stdout,
      stderr,
      ocsfRecords: readJsonl(spoolPath) as OcsfLine[],
      ocsfSpoolLines: readLines(spoolPath),
      sessionLog: logFile === undefined ? [] : readJsonl(logFile),
      modelRequests: [...server.requests],
    }
  } finally {
    restore?.()
    await server?.close()
    rmSync(home, { recursive: true, force: true })
  }
}
