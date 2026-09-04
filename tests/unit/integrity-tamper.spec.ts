/**
 * What a tamperer who knows the scheme can do that the chain does not catch.
 *
 * `docs/integrity.md` already states the big one — the plugin runs at the
 * agent's uid and the algorithm is published, so the agent can rewrite the
 * spool — and states that anchors taken off the host close the suffix-deletion
 * gap. These cases pin the shape of what anchors do *not* close, because the
 * page's wording claims more than the verifier does:
 *
 * > Any later rewrite of the spool must either leave those records exactly as
 * > they were or produce a chain that disagrees with what the SIEM already has.
 *
 * A rewrite under a fresh `chain_uid` does neither. It does not disagree with
 * the anchors; it fails to overlap them, and the comparison never runs. The
 * same freedom lets records that never happened be added, in a new chain or on
 * the end of an anchored one.
 *
 * These are limitation pins, not defect reproductions: every case here passes
 * against the shipped verifier, and each fails the day the verifier is made to
 * treat an uncorroborated chain as a finding. Changing one is how that decision
 * gets recorded.
 */
import { describe, expect, it } from 'vitest'
import { AttestingSink, attestRecord } from '../../src/integrity/attest.ts'
import { anchorsOf, verifyRecords } from '../../src/integrity/verify.ts'
import type { OcsfPrevEvent, OcsfRecord } from '../../src/ocsf/types.ts'
import type { Sink } from '../../src/sink/spool.ts'

/** A record shaped like the ones the forwarder spools. */
function record(uid: string, message: string): OcsfRecord {
  return {
    class_uid: 6003,
    category_uid: 6,
    type_uid: 600301,
    activity_id: 1,
    severity_id: 1,
    time: 1_000,
    message,
    cloud: { provider: 'Other' },
    osint: [],
    metadata: {
      product: { name: 'p', vendor_name: 'v', version: '0' },
      version: '1.9.0',
      profiles: ['ai_operation', 'cloud', 'osint'],
      uid,
    },
  }
}

/** One self-consistent chain, as the lines a spool would hold. */
function chainLines(chainUid: string, count: number, message: (index: number) => string): string[] {
  const lines: string[] = []
  const sink: Sink = { write: item => { lines.push(JSON.stringify(item)) }, close: () => {} }
  const chained = new AttestingSink(sink, chainUid)
  for (let index = 0; index < count; index += 1) chained.write(record(`S1:${String(index)}`, message(index)))
  return lines
}

/** The honest spool, and the anchors a SIEM holding all of it would supply. */
function honest(): { lines: string[]; anchors: ReturnType<typeof anchorsOf> } {
  const lines = chainLines('chain-real', 10, index => `step ${String(index)} ended`)
  return { lines, anchors: anchorsOf(lines) }
}

/** Verify one spool's lines against anchors. */
function verify(
  lines: readonly string[],
  anchors: ReturnType<typeof anchorsOf>,
  options?: { strictAnchors?: boolean },
): ReturnType<typeof verifyRecords> {
  return verifyRecords([{ path: '/spool.jsonl', lines }], anchors, options)
}

describe('a tamperer who knows the scheme', () => {
  it('is caught cutting the tail off the chain the anchors name', () => {
    const { lines, anchors } = honest()
    const report = verify(lines.slice(0, 7), anchors)
    expect(report.intact).toBe(false)
    expect(report.findings.map(finding => finding.kind)).toEqual(['truncated'])
  })

  it('is caught rewriting a record the anchors cover', () => {
    const { lines, anchors } = honest()
    const rewritten = chainLines('chain-real', 10, index => index === 4 ? 'nothing happened' : `step ${String(index)} ended`)
    const report = verify(rewritten, anchors)
    expect(report.intact).toBe(false)
    expect(report.findings.map(finding => finding.kind)).toContain('anchor-mismatch')
  })

  it('is caught replacing the whole spool with a fresh chain, because every anchor falls through', () => {
    // The move the two cases above teach: do not touch the chain the anchors
    // name — replace it. Records 7 to 9 are gone and record 4 says something
    // else, every fingerprint recomputes and every link matches. Nothing in the
    // file is wrong; what is wrong is that the chain the SIEM saw is absent, and
    // since 0.8.0 that is a finding rather than a count.
    const { anchors } = honest()
    const rechained = chainLines('chain-forged', 7, index => index === 4 ? 'nothing happened' : `step ${String(index)} ended`)
    const report = verify(rechained, anchors)

    expect(report.intact).toBe(false)
    expect(report.findings.map(finding => finding.kind)).toEqual(['uncorroborated-chain'])
    // One finding for the chain, not one per anchor: twenty anchors on one
    // absent chain is one thing wrong, and the chain is what an operator acts on.
    expect(report.findings[0]?.detail).toContain('chain-real')
    expect(report.findings[0]?.detail).toContain('10 anchor(s)')
    expect(report.unmatchedAnchors).toBe(10)
  })

  it('is not reported for the same replacement when the operator turns strict anchors off', () => {
    // The escape hatch, and the reason it exists: a host whose shipper drained
    // and unlinked every generation of a chain reports exactly like this one.
    // Turning it off is a claim about that host's retention.
    const { anchors } = honest()
    const rechained = chainLines('chain-forged', 7, index => index === 4 ? 'nothing happened' : `step ${String(index)} ended`)
    const report = verify(rechained, anchors, { strictAnchors: false })

    expect(report.findings).toEqual([])
    expect(report.intact).toBe(true)
    expect(report.unmatchedAnchors).toBe(10)
  })

  it('is NOT caught adding a second chain of records that never happened', () => {
    const { lines, anchors } = honest()
    const fabricated = chainLines('chain-forged', 3, index => `approval rejected ${String(index)}`)
    const report = verify([...lines, ...fabricated], anchors)
    expect(report.findings).toEqual([])
    expect(report.intact).toBe(true)
    // Not even a count: a chain the SIEM has never seen is indistinguishable
    // from one written after the last delivery.
    expect(report.unmatchedAnchors).toBe(0)
    expect(report.chains).toHaveLength(2)
  })

  it('is NOT caught continuing the anchored chain with records that never happened', () => {
    // Nothing the SIEM holds is disturbed, so every anchor matches. The
    // fabrication is entirely past the anchored entries, which is the region
    // an anchor set says nothing about in either direction.
    const { lines, anchors } = honest()
    const last = JSON.parse(lines[lines.length - 1] as string) as OcsfRecord
    const attestation = last.attestation_list?.[0]
    if (attestation === undefined) throw new Error('the fixture chain wrote no attestation')
    let previous: OcsfPrevEvent = { uid: last.metadata.uid ?? '', type_uid: last.type_uid, fingerprint: attestation.fingerprint }
    const extended = [...lines]
    for (let index = 10; index < 12; index += 1) {
      const attested = attestRecord(record(`S1:${String(index)}`, 'approval rejected'), attestation.chain_uid, index, previous)
      extended.push(JSON.stringify(attested.record))
      previous = { uid: attested.record.metadata.uid ?? '', type_uid: attested.record.type_uid, fingerprint: attested.link.fingerprint }
    }
    const report = verify(extended, anchors)
    expect(report.findings).toEqual([])
    expect(report.intact).toBe(true)
    expect(report.chains[0]?.anchoredThrough).toBe(9)
    expect(report.chains[0]?.lastIndex).toBe(11)
  })
})
