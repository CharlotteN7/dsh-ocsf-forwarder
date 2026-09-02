/**
 * The tamper-evidence claim, checked the way an auditor would: a real agent
 * run, the spool it left, and the **published** verifier command run against
 * that file as a subprocess.
 *
 * Nothing here reaches into the plugin's state. `bin/dsh-ocsf-verify.mjs` is
 * the file `package.json` links, it reads only the spool, and its exit status
 * is what a scheduled integrity check would act on.
 */

import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { runAgent } from './harness.ts'

/** The verifier as it ships: the linked bin, running against the built `lib/`. */
const VERIFIER = fileURLToPath(new URL('../../bin/dsh-ocsf-verify.mjs', import.meta.url))

let dir: string
let spooled: readonly string[]

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), 'dsh-ocsf-integrity-'))
  const result = await runAgent({
    task: 'print the integrity marker',
    sequence: ['tool_call_success', 'success', 'success'],
    toolName: 'bash',
    toolArguments: JSON.stringify({ command: 'printf E2E_INTEGRITY', description: 'Print the marker' }),
    successText: 'done',
  })
  expect(result.code, result.stderr).toBe(0)
  spooled = result.ocsfSpoolLines
  expect(spooled.length).toBeGreaterThan(3)
}, 180_000)

afterAll(() => { rmSync(dir, { recursive: true, force: true }) })

/**
 * Write one spool and run the shipped verifier over it.
 * @param name - file name inside this suite's temporary directory.
 * @param lines - the spool's contents.
 * @param options - further arguments, placed before the spool path.
 * @returns the exit status and everything the command printed.
 */
function verify(name: string, lines: readonly string[], ...options: readonly string[]): { status: number; output: string } {
  const path = join(dir, name)
  writeFileSync(path, `${lines.join('\n')}\n`)
  try {
    return { status: 0, output: execFileSync(process.execPath, [VERIFIER, ...options, path], { encoding: 'utf8' }) }
  } catch (error: unknown) {
    const failure = error as { status: number; stdout: string }
    return { status: failure.status, output: failure.stdout }
  }
}

describe('the record_integrity chain of a real run', () => {
  it('is complete from its genesis entry, and the shipped verifier says so', () => {
    const clean = verify('clean.jsonl', spooled)
    expect(clean.status, clean.output).toBe(0)
    expect(clean.output).toContain('INTACT')
    expect(clean.output).toContain('from its genesis entry')
    expect(clean.output).toContain(`${String(spooled.length)} record(s)`)
  })

  it('catches a record edited in place, naming the line it is on', () => {
    const target = spooled.findIndex(line => line.includes('"class_uid":1007'))
    expect(target).toBeGreaterThanOrEqual(0)
    const edited = JSON.parse(spooled[target] as string) as Record<string, unknown>
    // The edit an insider would make: downgrade the record that says a shell
    // command ran, leaving everything else as it was.
    edited['severity_id'] = 1
    edited['message'] = 'routine activity'
    const tampered = [...spooled]
    tampered[target] = JSON.stringify(edited)

    const result = verify('edited.jsonl', tampered)
    expect(result.status).toBe(1)
    expect(result.output).toContain('BROKEN')
    expect(result.output).toContain(`altered ${join(dir, 'edited.jsonl')}:${String(target + 1)}`)
  })

  it('catches a record deleted from the middle of the spool', () => {
    const tampered = [...spooled]
    tampered.splice(2, 1)
    const result = verify('deleted.jsonl', tampered)
    expect(result.status).toBe(1)
    expect(result.output).toContain('missing-records')
  })

  it('catches the whole spool being replaced with a plausible-looking one', () => {
    // Records with no chain at all: the shape a hand-written replacement has.
    const stripped = spooled.map((line) => {
      const record = JSON.parse(line) as Record<string, unknown>
      delete record['attestation_list']
      return JSON.stringify(record)
    })
    const result = verify('stripped.jsonl', stripped)
    expect(result.status).toBe(1)
    expect(result.output).toContain('unattested')
  })

  it('catches the end of the spool being cut off, against the heartbeat that had already shipped', () => {
    // The heartbeat is a chain entry like any other, so the copy the SIEM holds
    // states how far the chain had got. That is the one fact the surviving
    // records cannot supply.
    const anchorAt = spooled.findLastIndex(line => line.includes('"kind":"heartbeat"'))
    expect(anchorAt).toBeGreaterThan(0)
    const cut = spooled.slice(0, anchorAt)

    // Erasing the most recent activity: the chain that is left still verifies.
    const bare = verify('truncated.jsonl', cut)
    expect(bare.status, bare.output).toBe(0)
    expect(bare.output).toContain('INTACT')
    expect(bare.output).toContain('no anchor')

    const shipped = join(dir, 'shipped.jsonl')
    writeFileSync(shipped, `${spooled[anchorAt] as string}\n`)
    const anchored = verify('truncated.jsonl', cut, '--anchor', shipped)
    expect(anchored.status, anchored.output).toBe(1)
    expect(anchored.output).toContain('truncated')
  })
})
