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
import { cpSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  startMockLlmServer,
  type MockLlmBehavior,
  type MockLlmRequestRecord,
  type MockLlmServer,
} from '@deepseek-ai/dsh-llm-mock-server'

/** Package root of the plugin under test. */
const PLUGIN_ROOT = fileURLToPath(new URL('../../', import.meta.url))

/** Package name the profile mounts; must match this package's `package.json` name. */
const PLUGIN_PACKAGE = (JSON.parse(
  readFileSync(join(PLUGIN_ROOT, 'package.json'), 'utf8'),
) as { name: string }).name

/**
 * Harness checkout used to launch the agent. Point `DSH_REPO` at a checkout
 * whose `pnpm run build:lib:host` has run at least once; without those Typert
 * host artifacts profile boot fails with module-resolution errors.
 */
const DSH_REPO = process.env.DSH_REPO ?? '/path/to/workspace/dsh'

/**
 * Which `dsh` entry the agent boots from. `src` runs `apps/cli/src/bin.ts`
 * under tsx and needs only `pnpm run build:lib:host` in the checkout. `lib`
 * runs the built `apps/cli/lib/bin.js` under plain Node — the installed form,
 * which resolves this plugin through its real package `exports` into `lib/`
 * and is therefore the mode that catches export-shape mistakes. `lib` needs a
 * full `pnpm run build`.
 */
const LAUNCH_MODE = process.env.DSH_EXAMPLE_MODE === 'lib' ? 'lib' : 'src'

/** Command and leading arguments that boot the CLI in the selected mode. */
function launchArgv(): readonly string[] {
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
  /** Milliseconds before the agent process is killed. */
  readonly timeoutMs?: number
}

/** Everything one end-to-end run produced. */
export interface AgentRunResult {
  readonly code: number
  readonly stdout: string
  readonly stderr: string
  /** Records the plugin's `tools/pre-execute` listener appended, in order. */
  readonly observations: readonly Record<string, unknown>[]
  /** The persisted session log, one parsed JSONL row per element. */
  readonly sessionLog: readonly Record<string, unknown>[]
  /** Wire requests the agent made, as captured by the mock. */
  readonly modelRequests: readonly MockLlmRequestRecord[]
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

/** Parse a JSONL file into rows; a missing file yields an empty list. */
function readJsonl(file: string): Record<string, unknown>[] {
  let text: string
  try {
    text = readFileSync(file, 'utf8')
  } catch {
    // ENOENT only: the plugin writes lazily and a run may observe nothing.
    return []
  }
  return text.split('\n').filter(line => line.length > 0).map(line => JSON.parse(line) as Record<string, unknown>)
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
  const observationLog = join(home, 'dsh-plugin-template.observations.jsonl')
  let server: MockLlmServer | undefined

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
      cwd: DSH_REPO,
      env: {
        ...process.env,
        DSH_HOME: home,
        DSH_TELEMETRY_DISABLED: '1',
        DSH_PERMISSION_MODE: 'danger-full-access',
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
      observations: readJsonl(observationLog),
      sessionLog: logFile === undefined ? [] : readJsonl(logFile),
      modelRequests: [...server.requests],
    }
  } finally {
    await server?.close()
    rmSync(home, { recursive: true, force: true })
  }
}


