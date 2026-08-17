/**
 * The verifying half: what an independent reader of a spool can tell about it.
 *
 * Every case here is a spool a tamperer could produce — an edited record, a
 * deleted one, a re-hashed one, a spliced head — and the assertion is that the
 * report names it and where it is.
 */
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { AttestingSink, attestRecord, canonicalJson, fingerprintOf } from '../../src/integrity/attest.ts'
import { formatReport, main, spoolFiles, verifyRecords, type SpoolSource } from '../../src/integrity/verify.ts'
import type { OcsfRecord } from '../../src/ocsf/types.ts'
import type { Sink } from '../../src/sink/spool.ts'

let dir: string

beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'dsh-ocsf-verify-')) })
afterEach(() => { rmSync(dir, { recursive: true, force: true }) })

/** A record shaped like the ones the forwarder spools. */
function record(uid: string, extra: Record<string, unknown> = {}): OcsfRecord {
  return {
    class_uid: 6003,
    category_uid: 6,
    type_uid: 600301,
    activity_id: 1,
    severity_id: 1,
    time: 1_000,
    cloud: { provider: 'Other' },
    osint: [],
    metadata: {
      product: { name: 'p', vendor_name: 'v', version: '0' },
      version: '1.9.0',
      profiles: ['ai_operation', 'cloud', 'osint'],
      uid,
    },
    ...extra,
  }
}

/** One chain of `count` attested records, as the lines a spool would hold. */
function chainLines(count: number, chainUid = 'chain-1'): string[] {
  const lines: string[] = []
  const sink: Sink = { write: item => { lines.push(JSON.stringify(item)) }, close: () => {} }
  const chained = new AttestingSink(sink, chainUid)
  for (let index = 0; index < count; index += 1) chained.write(record(`S1:${String(index)}`, { message: `event ${String(index)}` }))
  return lines
}

/** Verify one file's worth of lines under a fixed name. */
function verify(lines: readonly string[], path = 'spool.jsonl'): ReturnType<typeof verifyRecords> {
  return verifyRecords([{ path, lines } satisfies SpoolSource])
}

/** Every finding kind a report holds, in order. */
function kinds(report: ReturnType<typeof verifyRecords>): string[] {
  return report.findings.map(finding => finding.kind)
}

describe('an untampered chain', () => {
  it('verifies clean, and says the chain is whole from its genesis entry', () => {
    const report = verify(chainLines(5))
    expect(report.findings).toEqual([])
    expect(report.intact).toBe(true)
    expect(report.records).toBe(5)
    expect(report.attested).toBe(5)
    expect(report.chains).toEqual([{ chainUid: 'chain-1', records: 5, firstIndex: 0, lastIndex: 4, complete: true }])
    expect(formatReport(report).at(-1)).toContain('INTACT')
  })

  it('runs through a rotation: the generations and the live file are one chain', () => {
    const lines = chainLines(6)
    const spool = join(dir, 'ocsf.jsonl')
    writeFileSync(`${spool}.2026-08-17T10-00-00.000Z-000`, `${lines.slice(0, 2).join('\n')}\n`)
    writeFileSync(`${spool}.2026-08-17T10-00-01.000Z-000`, `${lines.slice(2, 4).join('\n')}\n`)
    writeFileSync(spool, `${lines.slice(4).join('\n')}\n`)

    expect(spoolFiles(spool)).toHaveLength(3)
    const output: string[] = []
    expect(main([spool], line => output.push(line))).toBe(0)
    expect(output.join('\n')).toContain('6 record(s) in 3 file(s)')
    expect(output.join('\n')).toContain('INTACT')
  })

  it('reads a spool holding the chains of two runs, one after the other', () => {
    const report = verify([...chainLines(3, 'chain-a'), ...chainLines(2, 'chain-b')])
    expect(report.findings).toEqual([])
    expect(report.chains.map(chain => chain.chainUid)).toEqual(['chain-a', 'chain-b'])
  })

  it('reports a chain whose earlier entries are not in the input without calling it broken', () => {
    // What a drained generation leaves behind: the chain continues correctly,
    // it just does not start at its genesis entry.
    const report = verify(chainLines(5).slice(2))
    expect(report.findings).toEqual([])
    expect(report.chains[0]).toMatchObject({ firstIndex: 2, lastIndex: 4, complete: false })
    expect(formatReport(report).join('\n')).toContain('entries 0-1 are not in this input')
  })
})

describe('a tampered spool', () => {
  it('names the record whose content was edited, and the line it is on', () => {
    const lines = chainLines(5)
    const edited = JSON.parse(lines[2] as string) as Record<string, unknown>
    edited['severity_id'] = 1
    edited['message'] = 'nothing to see here'
    lines[2] = JSON.stringify(edited)

    const report = verify(lines)
    expect(report.intact).toBe(false)
    expect(report.findings).toHaveLength(1)
    expect(report.findings[0]).toMatchObject({ kind: 'altered', file: 'spool.jsonl', line: 3, uid: 'S1:2' })
    expect(formatReport(report).join('\n')).toContain('BROKEN: 1 finding(s)')
  })

  it('catches an editor who recomputed the fingerprint, through the record after it', () => {
    const lines = chainLines(5)
    const edited = JSON.parse(lines[2] as string) as Record<string, unknown>
    edited['message'] = 'nothing to see here'
    const attestation = (edited['attestation_list'] as Record<string, unknown>[])[0] as Record<string, unknown>
    const { fingerprint, ...bare } = attestation
    void fingerprint
    attestation['fingerprint'] = fingerprintOf(canonicalJson({ ...edited, attestation_list: [bare] }))
    lines[2] = JSON.stringify(edited)

    const report = verify(lines)
    // The edited record now hashes to what it claims; its successor still
    // carries the fingerprint the original had.
    expect(kinds(report)).toEqual(['broken-link'])
    expect(report.findings[0]).toMatchObject({ line: 4, uid: 'S1:3' })
  })

  it('catches a deleted record through the chain positions either side of it', () => {
    const lines = chainLines(5)
    lines.splice(2, 1)
    const report = verify(lines)
    expect(kinds(report)).toEqual(['missing-records'])
    expect(report.findings[0]).toMatchObject({ line: 3, uid: 'S1:3' })
  })

  it('catches a record replayed into the file a second time', () => {
    const lines = chainLines(4)
    lines.splice(3, 0, lines[1] as string)
    expect(kinds(verify(lines))).toEqual(['out-of-order', 'missing-records'])
  })

  it('catches two records swapped in place', () => {
    const lines = chainLines(5)
    const held = lines[1] as string
    lines[1] = lines[2] as string
    lines[2] = held
    // A swap moves the chain position backwards and then forwards again, so
    // the record after the pair is reported too rather than silently accepted.
    expect(kinds(verify(lines))).toEqual(['missing-records', 'out-of-order', 'missing-records'])
  })

  it('catches a chain head that claims both to be the genesis entry and to have a predecessor', () => {
    const spliced = attestRecord(record('S1:0'), 'chain-2', 0, {
      uid: 'S1:x', type_uid: 600301, fingerprint: fingerprintOf('anything'),
    })
    expect(kinds(verify([JSON.stringify(spliced.record)]))).toEqual(['broken-link'])
  })

  it('catches a chain head that is past the genesis entry and claims no predecessor', () => {
    // Distinct from a drained generation, which leaves a head that does claim
    // one: this record says it began a chain three entries in.
    const orphan = attestRecord(record('S1:3'), 'chain-2', 3, undefined)
    expect(kinds(verify([JSON.stringify(orphan.record)]))).toEqual(['broken-link'])
  })

  it('names a record that carries no attestation at all', () => {
    const lines = [...chainLines(2), JSON.stringify(record('S1:9'))]
    const report = verify(lines)
    expect(kinds(report)).toEqual(['unattested'])
    expect(report.attested).toBe(2)
    expect(report.records).toBe(3)
    expect(report.intact).toBe(false)
  })

  it('names a line that is not JSON', () => {
    const report = verify([...chainLines(1), '{"truncated":'])
    expect(kinds(report)).toEqual(['unparsable'])
    expect(report.findings[0]).toMatchObject({ line: 2, uid: undefined })
    // There is no uid to print for a line that never parsed, and the report
    // says so rather than printing an empty column.
    expect(formatReport(report).join('\n')).toContain('spool.jsonl:2 <no uid>')
  })

  it('refuses to guess at an attestation it cannot read', () => {
    const genuine = JSON.parse(chainLines(1)[0] as string) as Record<string, unknown>
    const attestation = (genuine['attestation_list'] as Record<string, unknown>[])[0] as Record<string, unknown>
    const withAttestation = (value: unknown): string => JSON.stringify({ ...genuine, attestation_list: value })
    const withField = (changes: Record<string, unknown>): string =>
      withAttestation([{ ...attestation, ...changes }])

    const unreadable = [
      withAttestation('not-a-list'),
      withAttestation([]),
      withAttestation([attestation, attestation]),
      withField({ chain_uid: 7 }),
      withField({ uid: 7 }),
      withField({ fingerprint: { value: 7 } }),
      withField({ uid: 'other-chain:0' }),
      withField({ uid: `${String(attestation['chain_uid'])}:not-a-number` }),
    ]
    for (const line of unreadable) expect(kinds(verify([line]))).toEqual(['malformed'])
  })

  it('reports a record with no uid rather than treating it as the record before it', () => {
    const anonymous = record('')
    const stripped = { ...anonymous, metadata: { ...anonymous.metadata, uid: undefined } } as unknown as OcsfRecord
    const first = attestRecord(stripped, 'chain-1', 0, undefined)
    const second = attestRecord(record('S1:1'), 'chain-1', 1, first.link)
    const report = verify([JSON.stringify(first.record), JSON.stringify(second.record)])
    expect(report.findings[0]).toMatchObject({ kind: 'broken-link', line: 2, uid: 'S1:1' })
  })

  it('prints the first findings in full and counts the rest', () => {
    const lines = chainLines(30).map(line => line.replace(/"severity_id":\d/, '"severity_id":9'))
    const report = verify(lines)
    const printed = formatReport(report)
    expect(report.findings).toHaveLength(30)
    expect(printed.filter(line => line.includes('altered'))).toHaveLength(20)
    expect(printed.at(-2)).toContain('and 10 more finding(s)')
  })
})

describe('the verifier as a command', () => {
  it('verifies a spool on disk and exits zero', () => {
    const spool = join(dir, 'ocsf.jsonl')
    writeFileSync(spool, `${chainLines(3).join('\n')}\n`)
    const output: string[] = []
    expect(main([spool], line => output.push(line))).toBe(0)
    expect(output.join('\n')).toContain('3 record(s) in 1 file(s), 3 attested, 1 chain(s)')
  })

  it('exits one and names the finding when the spool was tampered with', () => {
    const spool = join(dir, 'ocsf.jsonl')
    const lines = chainLines(3)
    lines[1] = (lines[1] as string).replace('event 1', 'event x')
    writeFileSync(spool, `${lines.join('\n')}\n`)
    const output: string[] = []
    expect(main([spool], line => output.push(line))).toBe(1)
    expect(output.join('\n')).toContain(`altered ${spool}:2`)
  })

  it('emits the whole report as JSON when asked', () => {
    const spool = join(dir, 'ocsf.jsonl')
    writeFileSync(spool, `${chainLines(2).join('\n')}\n`)
    const output: string[] = []
    expect(main(['--json', spool], line => output.push(line))).toBe(0)
    expect(JSON.parse(output[0] as string)).toMatchObject({ records: 2, attested: 2, intact: true })
  })

  it('prints its usage: asked for, that is the whole job; unasked for, it is a usage error', () => {
    const asked: string[] = []
    expect(main(['--help', join(dir, 'ocsf.jsonl')], line => asked.push(line))).toBe(0)
    const unasked: string[] = []
    expect(main([], line => unasked.push(line))).toBe(2)
    expect(asked[0]).toContain('usage: dsh-ocsf-verify')
    expect(unasked).toEqual(asked)
  })

  it('exits two when a named spool cannot be read, rather than reporting it intact', () => {
    const output: string[] = []
    expect(main([join(dir, 'absent.jsonl')], line => output.push(line))).toBe(2)
    expect(output[0]).toContain('ENOENT')
  })

  it('does not call an empty spool intact: there is nothing there to have verified', () => {
    const spool = join(dir, 'ocsf.jsonl')
    writeFileSync(spool, '')
    const output: string[] = []
    expect(main([spool], line => output.push(line))).toBe(1)
    expect(output.join('\n')).toContain('NOT VERIFIED: there were no records to check.')
  })
})
