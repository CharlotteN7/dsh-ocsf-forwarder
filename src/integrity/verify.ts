/**
 * The independent side of the hash chain: recompute every fingerprint, follow
 * every link, and say where the chain breaks.
 *
 * Nothing here reads the plugin's configuration or its state. The input is
 * spool files and the algorithm is the one written down in `docs/integrity.md`,
 * so this program is a reference implementation of a check a third party can
 * write themselves rather than a privileged verifier.
 *
 * **A spool cannot show that its own end was cut off.** Removing entries from
 * the end of a chain leaves a shorter chain whose every remaining link still
 * matches, so it verifies clean; only an interior deletion breaks anything.
 * Detecting a suffix truncation needs a reference from outside the file, which
 * is what a {@link ChainAnchor} is: the chain position and fingerprint of a
 * record that already left the host. Anchors are optional and a verification
 * without them is honest about what it did not check.
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
  /** The chain stops before an entry an anchor already accounts for. */
  | 'truncated'
  /** The record at an anchor's chain position is not the record the anchor came from. */
  | 'anchor-mismatch'
  /**
   * An anchor names a chain with no records in this input.
   *
   * The spool cannot distinguish a chain the shipper drained and unlinked from
   * one deleted wholesale, so this is reported only when the caller asks for it
   * — but it is the only signal a whole-spool replacement leaves, because a
   * chain written under a fresh `chain_uid` never disagrees with an anchor, it
   * fails to overlap one.
   */
  | 'uncorroborated-chain'

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

/**
 * One chain position a reader already holds a copy of, taken from a record that
 * left the host before the spool could be rewritten.
 *
 * This is the external reference a suffix truncation is detected against. The
 * index says how far the chain had got, which the surviving records cannot; the
 * fingerprint says which record was there, so a tail rewritten to the right
 * length is caught as well as one simply cut short.
 */
export interface ChainAnchor {
  readonly chainUid: string
  /** The entry index the shipped record occupied. */
  readonly index: number
  /** The fingerprint that record carried. */
  readonly fingerprint: string
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
  /**
   * The highest entry index an anchor accounts for. Absent when no anchor named
   * this chain, which is the state in which a suffix truncation of it is
   * undetectable from this input.
   */
  readonly anchoredThrough?: number
}

/** How strictly to read anchors that no record in the input corroborates. */
export interface VerifyOptions {
  /**
   * Treat an anchor naming a chain absent from the input as a finding.
   *
   * On by default. A spool replaced wholesale by a chain under a fresh
   * `chain_uid` leaves every prior anchor unmatched and nothing else, so
   * without this the one move that erases history verifies clean. The cost is
   * that a host whose shipper legitimately drained and unlinked a chain's every
   * generation reports the same way, which is why it can be turned off — but
   * off is a decision about that host's retention, not a default.
   *
   * It does not close the other direction: records appended past the last
   * anchored entry, or a second chain added beside an intact one, disturb no
   * anchor and are not reported here.
   */
  readonly strictAnchors?: boolean
}

/** The result of verifying one set of spool files. */
export interface VerifyReport {
  readonly files: readonly string[]
  readonly records: number
  readonly attested: number
  readonly chains: readonly ChainSummary[]
  readonly findings: readonly ChainFinding[]
  /**
   * Anchors naming a chain with no records in this input. Not a finding: a
   * chain whose every generation the shipper drained and unlinked looks exactly
   * like one deleted wholesale, and the spool cannot tell them apart.
   */
  readonly unmatchedAnchors: number
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

/** Where one record sits in the input. */
interface Location {
  readonly file: string
  /** 1-based line number within the file. */
  readonly line: number
}

/** The chain state carried from one record to the next. */
interface ChainState {
  records: number
  readonly firstIndex: number
  lastIndex: number
  lastUid: string
  lastFingerprint: string
  /** Where the chain's last entry so far is, which is where a truncation shows. */
  lastAt: Location
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
 * Take the anchors out of records a reader already holds — a SIEM export of
 * what this installation shipped, one JSON record per line.
 *
 * Only the attestation is read, so an export that reordered or dropped other
 * attributes still yields a usable anchor. A line that is not JSON, or a record
 * carrying no attestation this verifier can read, yields nothing; the caller
 * decides what an anchor input that yielded nothing means.
 * @param lines - the exported records, one per line.
 * @returns the anchors found, in the order the lines gave them.
 */
export function anchorsOf(lines: readonly string[]): readonly ChainAnchor[] {
  const anchors: ChainAnchor[] = []
  for (const text of lines) {
    let record: Record<string, unknown>
    try {
      record = JSON.parse(text) as Record<string, unknown>
    } catch {
      // A JSON parse failure only: an export that wrote something other than
      // one record per line contributes no anchor rather than failing the run.
      continue
    }
    const entry = inspect(record)
    if (entry === undefined) continue
    anchors.push({ chainUid: entry.chainUid, index: entry.index, fingerprint: entry.claimed })
  }
  return anchors
}

/**
 * Check one record against the chain state its predecessor left, and update
 * that state.
 * @param entry - the record's attestation.
 * @param uid - the record's `metadata.uid`, the locator its successor references.
 * @param at - where the record is in the input.
 * @param chains - the state of every chain seen so far, updated in place.
 * @returns the findings this record produced.
 */
function link(entry: ChainEntry, uid: string, at: Location, chains: Map<string, ChainState>): FindingKind[] {
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
      lastAt: at,
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
  state.lastAt = at
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
  'truncated': 'the chain ends here, before an entry an anchor taken off this host accounts for',
  'anchor-mismatch': 'this chain entry is not the record the anchor for the same position came from',
  // Every raise of this kind supplies its own detail, naming the chain and how
  // many anchors account for it; this is the generic form the table requires.
  'uncorroborated-chain': 'an anchor names a chain with no records in this input',
})

/** The anchors of one input, grouped by the chain each names. */
function byChain(anchors: readonly ChainAnchor[]): Map<string, ChainAnchor[]> {
  const grouped = new Map<string, ChainAnchor[]>()
  for (const anchor of anchors) {
    const existing = grouped.get(anchor.chainUid)
    if (existing === undefined) grouped.set(anchor.chainUid, [anchor])
    else existing.push(anchor)
  }
  return grouped
}

/**
 * Verify the chains across one ordered set of spool files.
 *
 * The files are treated as one append-only stream in the order given, which is
 * how a spool and its rotated generations relate: rotation renames a file, it
 * does not end a chain.
 * @param sources - the files and their lines, oldest first.
 * @param anchors - chain positions held outside this input, against which a
 *   truncated or rewritten tail is detected. Without them the chain's end is
 *   whatever the file says it is.
 * @returns what was checked and everything found wrong.
 */
export function verifyRecords(
  sources: readonly SpoolSource[],
  anchors: readonly ChainAnchor[] = [],
  options: VerifyOptions = {},
): VerifyReport {
  const findings: ChainFinding[] = []
  const chains = new Map<string, ChainState>()
  const anchored = byChain(anchors)
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
      const contradicted = (anchored.get(entry.chainUid) ?? [])
        .some(anchor => anchor.index === entry.index && anchor.fingerprint !== entry.claimed)
      const mismatch: FindingKind[] = contradicted ? ['anchor-mismatch'] : []
      for (const kind of [...kinds, ...mismatch, ...link(entry, uid ?? '', at, chains)]) {
        findings.push({ ...at, kind, uid, detail: DETAIL[kind] })
      }
    }
  }
  const chainSummaries: ChainSummary[] = []
  for (const [chainUid, state] of chains) {
    const through = (anchored.get(chainUid) ?? []).reduce((highest, anchor) => Math.max(highest, anchor.index), -1)
    // The one check the records themselves cannot make: an anchor accounts for
    // an entry past the end of the chain in this input, so the end was cut off.
    if (through > state.lastIndex) {
      findings.push({ ...state.lastAt, kind: 'truncated', uid: state.lastUid, detail: DETAIL['truncated'] })
    }
    chainSummaries.push({
      chainUid,
      records: state.records,
      firstIndex: state.firstIndex,
      lastIndex: state.lastIndex,
      complete: state.firstIndex === 0,
      ...through < 0 ? {} : { anchoredThrough: through },
    })
  }
  // Grouped by chain rather than counted per anchor: twenty anchors on one
  // absent chain is one thing wrong, and naming the chain is what an operator
  // acts on. Only raised when anchors were supplied — with none there is
  // nothing to corroborate against and nothing to be strict about.
  const uncorroborated = [...new Set(anchors.filter(anchor => !chains.has(anchor.chainUid)).map(anchor => anchor.chainUid))]
  if (options.strictAnchors !== false) {
    for (const chainUid of uncorroborated) {
      const covered = anchors.filter(anchor => anchor.chainUid === chainUid)
      const through = Math.max(...covered.map(anchor => anchor.index))
      findings.push({
        kind: 'uncorroborated-chain',
        file: sources[0]?.path ?? '',
        line: 0,
        uid: `${chainUid}:0`,
        detail: `no record of chain ${chainUid} is present, though ${String(covered.length)} anchor(s) account for entries through ${String(through)}`
          + '; a shipper that drained every generation of this chain looks the same, so confirm against this host\'s retention before treating it as deletion',
      })
    }
  }
  return {
    files: sources.map(source => source.path),
    records,
    attested,
    chains: chainSummaries,
    findings,
    unmatchedAnchors: anchors.filter(anchor => !chains.has(anchor.chainUid)).length,
    intact: findings.length === 0 && records > 0,
  }
}

/** Findings printed in full before the rest are counted. */
const MAX_PRINTED_FINDINGS = 20

/** What one chain's line says about the anchors that did or did not cover it. */
function anchorNote(chain: ChainSummary): string {
  if (chain.anchoredThrough === undefined) {
    return `, no anchor — nothing here can show whether entries after ${String(chain.lastIndex)} were removed`
  }
  return `, anchored through entry ${String(chain.anchoredThrough)}`
}

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
        : `, genesis absent — entries 0-${String(chain.firstIndex - 1)} are not in this input`)
      + anchorNote(chain),
    )
  }
  if (report.unmatchedAnchors > 0) {
    lines.push(
      `  ${String(report.unmatchedAnchors)} anchor(s) name a chain with no records here; `
      + 'a chain whose generations the shipper drained looks the same as one deleted',
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
  'usage: dsh-ocsf-verify [--json] [--no-strict-anchors]',
  '                       [--anchor <exported records>]... <spool path>...',
  '',
  'Verifies the OCSF record_integrity hash chain of one or more spool files.',
  'Each path is verified together with its rotated generations, oldest first.',
  '',
  'A chain cannot show that its own end was cut off: removing entries from the',
  'end leaves a shorter chain whose every link still matches. --anchor takes',
  'records this installation already shipped, as the SIEM holds them, one JSON',
  'record per line, and reports a chain that stops short of what they account',
  'for. Without it a suffix truncation is not detected and the report says so.',
  '',
  'An anchor naming a chain with no records here is a finding by default: a',
  'spool replaced wholesale by a chain under a fresh chain_uid leaves every',
  'prior anchor unmatched and no other trace. --no-strict-anchors makes it a',
  'count again, for a host whose shipper legitimately drained that chain.',
  'Neither setting reports records appended past the last anchored entry, or a',
  'second chain added beside an intact one: anchors bound a chain from below.',
  '',
  'Exit status: 0 intact, 1 findings, 2 the input could not be read.',
]

/** One parse of the command line. */
interface Invocation {
  readonly paths: readonly string[]
  readonly anchorPaths: readonly string[]
  readonly json: boolean
  /** The usage was asked for, which is the whole job. */
  readonly help: boolean
  /** An option this command does not take, or `--anchor` with nothing after it. */
  readonly malformed: boolean
  /** False when `--no-strict-anchors` asked for the pre-0.8 counting behaviour. */
  readonly strictAnchors: boolean
}

/**
 * Read the command line.
 *
 * An unknown option is a usage error rather than something to ignore: a
 * mistyped `--anchor` that is silently dropped turns a truncation check into a
 * report that says INTACT and checked nothing.
 * @param argv - arguments after the program name.
 * @returns what the invocation asked for.
 */
function parse(argv: readonly string[]): Invocation {
  const paths: string[] = []
  const anchorPaths: string[] = []
  let json = false
  let help = false
  let malformed = false
  let strictAnchors = true
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index] as string
    if (argument === '--json') json = true
    else if (argument === '--no-strict-anchors') strictAnchors = false
    else if (argument === '--help') help = true
    else if (argument === '--anchor') {
      const next = argv[index + 1]
      if (next === undefined || next.startsWith('--')) malformed = true
      else {
        anchorPaths.push(next)
        index += 1
      }
    }
    else if (argument.startsWith('--')) malformed = true
    else paths.push(argument)
  }
  return { paths, anchorPaths, json, help, malformed, strictAnchors }
}

/**
 * Run the verifier as a command.
 * @param argv - arguments after the program name.
 * @param write - receives one output line at a time.
 * @returns the process exit status.
 */
export function main(argv: readonly string[], write: (line: string) => void): number {
  const invocation = parse(argv)
  if (invocation.help) {
    for (const line of USAGE) write(line)
    return 0
  }
  if (invocation.malformed || invocation.paths.length === 0) {
    for (const line of USAGE) write(line)
    return 2
  }
  let sources: SpoolSource[]
  let anchors: readonly ChainAnchor[]
  try {
    sources = invocation.paths.flatMap(path => spoolFiles(path)).map(file => readLines(file))
    // Anchor inputs are exports, not spools: they have no rotated generations
    // and their line order carries no meaning.
    anchors = anchorsOf(invocation.anchorPaths.flatMap(path => readLines(path).lines))
  } catch (error: unknown) {
    // Rendered whole rather than reduced to `message`: for a `node:fs` failure
    // that is the errno code, the syscall, and the path, which is what tells an
    // operator which file the verifier could not read.
    write(`dsh-ocsf-verify: ${String(error)}`)
    return 2
  }
  if (invocation.anchorPaths.length > 0 && anchors.length === 0) {
    // Asking for the anchored check and getting none of it must not read as a
    // clean verification of a chain whose end was never checked.
    write('dsh-ocsf-verify: no attestation this verifier can read in the anchor input; nothing was anchored')
    return 2
  }
  const report = verifyRecords(sources, anchors, { strictAnchors: invocation.strictAnchors })
  if (invocation.json) write(JSON.stringify(report))
  else for (const line of formatReport(report)) write(line)
  return report.intact ? 0 : 1
}
