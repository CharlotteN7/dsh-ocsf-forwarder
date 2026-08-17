/**
 * The independent side of the hash chain: recompute every fingerprint, follow
 * every link, and say where the chain breaks.
 *
 * Nothing here reads the plugin's configuration or its state. The input is
 * spool files and the algorithm is the one written down in `docs/integrity.md`,
 * so this program is a reference implementation of a check a third party can
 * write themselves rather than a privileged verifier.
 * @module integrity/verify
 */

import { readFileSync } from 'node:fs'
import { canonicalJson, fingerprintOf } from './attest.ts'
import { rotatedGenerations } from '../sink/spool.ts'

/** What can be wrong with one record. */
export type FindingKind =
  /** The line is not JSON. */
  | 'unparsable'
  /** The record carries no attestation at all. */
  | 'unattested'
  /** The record carries something in `attestation_list` this verifier cannot read. */
  | 'malformed'
  /** The fingerprint does not match the record it covers: the record was changed. */
  | 'altered'
  /** The link to the previous record does not match the record before it. */
  | 'broken-link'
  /** Entries between the previous record and this one are not present. */
  | 'missing-records'
  /** This record's chain position is at or before the record before it. */
  | 'out-of-order'

/** One thing wrong with one record, located precisely enough to act on. */
export interface ChainFinding {
  readonly kind: FindingKind
  readonly file: string
  /** 1-based line number within the file. */
  readonly line: number
  /** The record's `metadata.uid`, when the line parsed far enough to have one. */
  readonly uid: string | undefined
  readonly detail: string
}

/** What one chain looked like across the whole input. */
export interface ChainSummary {
  readonly chainUid: string
  readonly records: number
  readonly firstIndex: number
  readonly lastIndex: number
  /**
   * True when the chain's genesis entry is in the input. False means entries
   * before `firstIndex` are elsewhere — drained and unlinked by the shipper, or
   * deleted. The spool alone cannot tell those apart; the shipper cursor can.
   */
  readonly complete: boolean
}

/** The result of verifying one set of spool files. */
export interface VerifyReport {
  readonly files: readonly string[]
  readonly records: number
  readonly attested: number
  readonly chains: readonly ChainSummary[]
  readonly findings: readonly ChainFinding[]
  /** True when every record was attested and nothing was found wrong. */
  readonly intact: boolean
}

/** One spool file's lines, in the order they were written. */
export interface SpoolSource {
  readonly path: string
  readonly lines: readonly string[]
}

/** The attestation of one record, once it has been read out of untrusted JSON. */
interface ChainEntry {
  readonly chainUid: string
  readonly index: number
  readonly prevUid: string | undefined
  readonly prevFingerprint: string | undefined
  /** The fingerprint the record claims for itself. */
  readonly claimed: string
  /** The fingerprint this input actually hashes to. */
  readonly recomputed: string
}

/** The chain state carried from one record to the next. */
interface ChainState {
  records: number
  readonly firstIndex: number
  lastIndex: number
  lastUid: string
  lastFingerprint: string
}

/** One field of an untrusted object, when it is a string. */
function stringField(value: unknown, key: string): string | undefined {
  if (typeof value !== 'object' || value === null) return undefined
  const field = (value as Record<string, unknown>)[key]
  return typeof field === 'string' ? field : undefined
}

/** One field of an untrusted object, when it is an object. */
function objectField(value: unknown, key: string): unknown {
  if (typeof value !== 'object' || value === null) return undefined
  return (value as Record<string, unknown>)[key]
}

/**
 * Read one record's attestation and recompute what it covers.
 *
 * `undefined` means the attestation is not one this verifier can read: a shape
 * it does not recognise, or more than one attester. Multi-attester records are
 * legal OCSF — a downstream processor may add its own — but the canonical
 * serialization each of those attesters covered is not derivable from this
 * record alone, so they are reported rather than guessed at.
 * @param record - the parsed record.
 * @returns the entry, or `undefined` when the attestation cannot be read.
 */
function inspect(record: Record<string, unknown>): ChainEntry | undefined {
  const list = record['attestation_list']
  if (!Array.isArray(list) || list.length !== 1) return undefined
  const attestation = list[0] as unknown
  const chainUid = stringField(attestation, 'chain_uid')
  const uid = stringField(attestation, 'uid')
  const claimed = stringField(objectField(attestation, 'fingerprint'), 'value')
  if (chainUid === undefined || uid === undefined || claimed === undefined) return undefined
  const position = uid.startsWith(`${chainUid}:`) ? uid.slice(chainUid.length + 1) : ''
  if (!/^\d+$/.test(position)) return undefined
  const prevEvent = objectField(attestation, 'prev_event')
  const bare = { ...attestation as Record<string, unknown> }
  delete bare['fingerprint']
  delete bare['signatures']
  return {
    chainUid,
    index: Number(position),
    prevUid: stringField(prevEvent, 'uid'),
    prevFingerprint: stringField(objectField(prevEvent, 'fingerprint'), 'value'),
    claimed,
    recomputed: fingerprintOf(canonicalJson({ ...record, attestation_list: [bare] })).value,
  }
}

/**
 * Check one record against the chain state its predecessor left, and update
 * that state.
 * @param entry - the record's attestation.
 * @param uid - the record's `metadata.uid`, the locator its successor references.
 * @param chains - the state of every chain seen so far, updated in place.
 * @returns the findings this record produced.
 */
function link(entry: ChainEntry, uid: string, chains: Map<string, ChainState>): FindingKind[] {
  const state = chains.get(entry.chainUid)
  const kinds: FindingKind[] = []
  if (state === undefined) {
    // The head of a chain in this input. A genesis entry has no predecessor and
    // a later entry must have one; either without the other is a spliced head.
    if ((entry.index === 0) !== (entry.prevUid === undefined)) kinds.push('broken-link')
    chains.set(entry.chainUid, {
      records: 1,
      firstIndex: entry.index,
      lastIndex: entry.index,
      lastUid: uid,
      lastFingerprint: entry.claimed,
    })
    return kinds
  }
  if (entry.index > state.lastIndex + 1) kinds.push('missing-records')
  else if (entry.index <= state.lastIndex) kinds.push('out-of-order')
  else if (entry.prevUid !== state.lastUid || entry.prevFingerprint !== state.lastFingerprint) {
    kinds.push('broken-link')
  }
  state.records += 1
  state.lastIndex = entry.index
  state.lastUid = uid
  state.lastFingerprint = entry.claimed
  return kinds
}

/** How a finding of each kind reads in the report. */
const DETAIL: Readonly<Record<FindingKind, string>> = Object.freeze({
  'unparsable': 'not JSON',
  'unattested': 'no attestation_list; this record was not covered by a chain',
  'malformed': 'attestation_list is not a single attestation this verifier can read',
  'altered': 'the record does not hash to the fingerprint it carries',
  'broken-link': 'prev_event does not match the record before it in this input',
  'missing-records': 'chain entries between the previous record and this one are not present',
  'out-of-order': 'chain entry is at or before the previous record of the same chain',
})

/**
 * Verify the chains across one ordered set of spool files.
 *
 * The files are treated as one append-only stream in the order given, which is
 * how a spool and its rotated generations relate: rotation renames a file, it
 * does not end a chain.
 * @param sources - the files and their lines, oldest first.
 * @returns what was checked and everything found wrong.
 */
export function verifyRecords(sources: readonly SpoolSource[]): VerifyReport {
  const findings: ChainFinding[] = []
  const chains = new Map<string, ChainState>()
  let records = 0
  let attested = 0
  for (const source of sources) {
    for (const [offset, text] of source.lines.entries()) {
      records += 1
      const at = { file: source.path, line: offset + 1 }
      let record: Record<string, unknown>
      try {
        record = JSON.parse(text) as Record<string, unknown>
      } catch {
        // A JSON parse failure only: a truncated last line after a kill, or an
        // edit that did not survive its own re-serialization.
        findings.push({ ...at, kind: 'unparsable', uid: undefined, detail: DETAIL['unparsable'] })
        continue
      }
      const uid = stringField(record['metadata'], 'uid')
      const entry = inspect(record)
      if (entry === undefined) {
        const kind: FindingKind = record['attestation_list'] === undefined ? 'unattested' : 'malformed'
        findings.push({ ...at, kind, uid, detail: DETAIL[kind] })
        continue
      }
      attested += 1
      const kinds = entry.recomputed === entry.claimed ? [] : ['altered' as const]
      for (const kind of [...kinds, ...link(entry, uid ?? '', chains)]) {
        findings.push({ ...at, kind, uid, detail: DETAIL[kind] })
      }
    }
  }
  const chainSummaries = [...chains].map(([chainUid, state]): ChainSummary => ({
    chainUid,
    records: state.records,
    firstIndex: state.firstIndex,
    lastIndex: state.lastIndex,
    complete: state.firstIndex === 0,
  }))
  return {
    files: sources.map(source => source.path),
    records,
    attested,
    chains: chainSummaries,
    findings,
    intact: findings.length === 0 && records > 0,
  }
}

/** Findings printed in full before the rest are counted. */
const MAX_PRINTED_FINDINGS = 20

/**
 * Render a report for a terminal.
 * @param report - the verification result.
 * @returns the lines to print, in order.
 */
export function formatReport(report: VerifyReport): string[] {
  const lines = [
    `${String(report.records)} record(s) in ${String(report.files.length)} file(s), `
    + `${String(report.attested)} attested, ${String(report.chains.length)} chain(s)`,
  ]
  for (const chain of report.chains) {
    lines.push(
      `  chain ${chain.chainUid}: ${String(chain.records)} record(s), entries `
      + `${String(chain.firstIndex)}-${String(chain.lastIndex)}`
      + (chain.complete
        ? ', from its genesis entry'
        : `, genesis absent — entries 0-${String(chain.firstIndex - 1)} are not in this input`),
    )
  }
  for (const finding of report.findings.slice(0, MAX_PRINTED_FINDINGS)) {
    lines.push(`  ${finding.kind} ${finding.file}:${String(finding.line)} ${finding.uid ?? '<no uid>'}: ${finding.detail}`)
  }
  if (report.findings.length > MAX_PRINTED_FINDINGS) {
    lines.push(`  … and ${String(report.findings.length - MAX_PRINTED_FINDINGS)} more finding(s)`)
  }
  if (report.intact) lines.push('INTACT: every record hashes to its own fingerprint and every link matches.')
  else if (report.findings.length > 0) lines.push(`BROKEN: ${String(report.findings.length)} finding(s).`)
  // An input with nothing in it is not a verified input. An audit tool that
  // exits zero on an empty file reports the absence of evidence as evidence.
  else lines.push('NOT VERIFIED: there were no records to check.')
  return lines
}

/**
 * Every file one named spool covers, oldest first.
 *
 * A live spool path is verified together with its rotated generations, because
 * the chain runs through the rename: naming only the live file would report a
 * chain whose genesis is missing on every rotated spool.
 * @param path - the spool path as an operator names it.
 * @returns the generations, oldest first, then the live file.
 */
export function spoolFiles(path: string): readonly string[] {
  return [...rotatedGenerations(path), path]
}

/** Read one file into the non-empty lines the spool wrote. */
function readLines(path: string): SpoolSource {
  return {
    path,
    lines: readFileSync(path, 'utf8').split('\n').filter(line => line.length > 0),
  }
}

/** How the command is used, printed on a usage error and on `--help`. */
const USAGE = [
  'usage: dsh-ocsf-verify [--json] <spool path>...',
  '',
  'Verifies the OCSF record_integrity hash chain of one or more spool files.',
  'Each path is verified together with its rotated generations, oldest first.',
  'Exit status: 0 intact, 1 findings, 2 the input could not be read.',
]

/**
 * Run the verifier as a command.
 * @param argv - arguments after the program name.
 * @param write - receives one output line at a time.
 * @returns the process exit status.
 */
export function main(argv: readonly string[], write: (line: string) => void): number {
  const paths = argv.filter(argument => !argument.startsWith('--'))
  const json = argv.includes('--json')
  if (argv.includes('--help')) {
    for (const line of USAGE) write(line)
    return 0
  }
  if (paths.length === 0) {
    for (const line of USAGE) write(line)
    return 2
  }
  let sources: SpoolSource[]
  try {
    sources = paths.flatMap(path => spoolFiles(path)).map(file => readLines(file))
  } catch (error: unknown) {
    // Rendered whole rather than reduced to `message`: for a `node:fs` failure
    // that is the errno code, the syscall, and the path, which is what tells an
    // operator which file the verifier could not read.
    write(`dsh-ocsf-verify: ${String(error)}`)
    return 2
  }
  const report = verifyRecords(sources)
  if (json) write(JSON.stringify(report))
  else for (const line of formatReport(report)) write(line)
  return report.intact ? 0 : 1
}
