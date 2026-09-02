/**
 * A booted agent writing into a spool an operator hardened with `chattr +a`.
 *
 * This is the half of the append-only story that only a real run can show: the
 * plugin mounts, the sink is constructed against a file whose mode the kernel
 * will not let it re-assert, and records still reach disk. Setting the
 * attribute needs `CAP_LINUX_IMMUTABLE`, so the test runs where this process
 * can take it and skips elsewhere rather than pretending with a stub.
 */

import { spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { dshOf, runAgent, type OcsfLine } from './harness.ts'

/**
 * Run `chattr <flag> <path>`, escalating once through `sudo -n`.
 *
 * `-n` never prompts, so this is silent where the escalation is not granted.
 * @param flag - `+a` or `-a`.
 * @param path - the file to change.
 * @returns whether the attribute was changed.
 */
function chattr(flag: string, path: string): boolean {
  if (spawnSync('chattr', [flag, path], { stdio: 'ignore' }).status === 0) return true
  return spawnSync('sudo', ['-n', 'chattr', flag, path], { stdio: 'ignore' }).status === 0
}

/** Whether this process can set the append-only attribute on a temporary file. */
function canSetAppendOnly(): boolean {
  if (process.platform !== 'linux') return false
  const dir = mkdtempSync(join(tmpdir(), 'dsh-ocsf-chattr-'))
  const probe = join(dir, 'probe')
  writeFileSync(probe, '')
  const set = chattr('+a', probe)
  if (set) chattr('-a', probe)
  rmSync(dir, { recursive: true, force: true })
  return set
}

/** The attribute letters `lsattr` reports for one path. */
function attributes(path: string): string {
  return spawnSync('lsattr', ['-d', path], { encoding: 'utf8' }).stdout.split(' ')[0] ?? ''
}

describe('a spool an operator made append-only', () => {
  it.runIf(canSetAppendOnly())('takes a whole agent run despite a chmod the kernel refuses', async () => {
    let attributesAfterRun = ''
    let modeAfterRun = 0

    const result = await runAgent({
      task: 'print the append-only marker',
      sequence: ['tool_call_success', 'success', 'success'],
      toolName: 'bash',
      toolArguments: JSON.stringify({
        command: 'printf E2E_APPEND_ONLY',
        description: 'Print the append-only marker',
      }),
      successText: 'append-only run complete',
      prepareRun: ({ spoolPath }) => {
        // The operator's own preparation, in the order the documentation gives
        // it: create the file at the mode you want, then take away the ability
        // to change it. The plugin's own mkdir would come too late.
        mkdirSync(dirname(spoolPath), { recursive: true })
        writeFileSync(spoolPath, '', { mode: 0o640 })
        expect(chattr('+a', spoolPath)).toBe(true)
        // Read back before the attribute is cleared and before the throwaway
        // home is removed: this is the only window in which the file the agent
        // actually wrote to can be inspected.
        return () => {
          attributesAfterRun = attributes(spoolPath)
          modeAfterRun = statSync(spoolPath).mode & 0o7777
          chattr('-a', spoolPath)
        }
      },
    })

    expect(result.code, result.stderr).toBe(0)
    // The attribute was still set while the agent was writing, so these records
    // went into a file the kernel would not let anyone truncate or rename.
    expect(attributesAfterRun).toContain('a')
    expect(modeAfterRun).toBe(0o640)

    expect(result.ocsfRecords.length).toBeGreaterThan(0)
    const toolCalls = result.ocsfRecords.filter(record => dshOf(record)['event_type'] === 'tool/call')
    expect(toolCalls).toHaveLength(1)
    expect(dshOf(toolCalls[0] as OcsfLine)['tool']).toBe('bash')
    // Nothing rotated: renaming an append-only file is refused too, so the run
    // left one live file and no generation.
    expect(result.ocsfSpoolLines.length).toBe(result.ocsfRecords.length)
  })
})
