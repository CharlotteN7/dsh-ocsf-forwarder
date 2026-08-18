/**
 * The producing half of the hash chain: canonicalisation, the attestation one
 * record carries, and the sink that links them.
 */
import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import {
  AttestingSink,
  FINGERPRINT_ALGORITHM_ID,
  FINGERPRINT_ENCODING_ID,
  RECORD_INTEGRITY_PROFILE,
  attestRecord,
  canonicalJson,
  fingerprintOf,
} from '../../src/integrity/attest.ts'
import type { OcsfRecord } from '../../src/ocsf/types.ts'
import type { Sink } from '../../src/sink/spool.ts'

/** A record shaped like the ones `buildRecord` produces, with a caller-chosen uid. */
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

/** Everything one sink received. */
function collect(): { sink: Sink; written: OcsfRecord[] } {
  const written: OcsfRecord[] = []
  return { sink: { write: item => { written.push(item) }, close: () => {} }, written }
}

describe('the canonical serialization', () => {
  it('orders object keys by code unit at every depth', () => {
    expect(canonicalJson({ b: 1, a: { d: 2, c: 3 }, A: 4 })).toBe('{"A":4,"a":{"c":3,"d":2},"b":1}')
  })

  it('renders primitives exactly as JSON.stringify does, so a reader can reproduce it', () => {
    for (const value of ['a"b\\c', 'é\u{1f600}', 1, -0, 1e21, 0.1, true, null, Number.NaN]) {
      expect(canonicalJson(value)).toBe(JSON.stringify(value) ?? 'null')
    }
  })

  it('drops undefined members and nulls undefined array elements, as the spooled JSON does', () => {
    const value = { kept: 1, dropped: undefined, list: [1, undefined, 2] }
    expect(canonicalJson(value)).toBe('{"kept":1,"list":[1,null,2]}')
    expect(JSON.parse(canonicalJson(value))).toEqual(JSON.parse(JSON.stringify(value)))
  })

  it('hashes with SHA-256 and reports the algorithm and encoding OCSF names', () => {
    expect(fingerprintOf('abc')).toEqual({
      value: createHash('sha256').update('abc', 'utf8').digest('hex'),
      algorithm_id: FINGERPRINT_ALGORITHM_ID,
      encoding_id: FINGERPRINT_ENCODING_ID,
    })
  })

  it('pins the algorithm and encoding ids to the OCSF enum values third parties verify against', () => {
    // Written as literals rather than through the constants: `docs/integrity.md`
    // publishes SHA-256 and hex as facts a reader recomputes a chain from, and
    // an assertion that names the constant agrees with whatever it is changed
    // to.
    expect(FINGERPRINT_ALGORITHM_ID).toBe(3)
    expect(FINGERPRINT_ENCODING_ID).toBe(1)
    expect(fingerprintOf('abc').value).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
  })
})

describe('one attestation', () => {
  it('covers the record including its own chain position, and excludes only the fingerprint', () => {
    const attested = attestRecord(record('S1:0'), 'chain-1', 0, undefined)
    const carried = attested.record.attestation_list?.[0]
    expect(carried).toMatchObject({ uid: 'chain-1:0', chain_uid: 'chain-1' })
    expect(carried?.prev_event).toBeUndefined()

    // The documented recomputation: everything but `fingerprint`.
    const { fingerprint, ...bare } = carried as unknown as Record<string, unknown>
    const recomputed = fingerprintOf(canonicalJson({ ...attested.record, attestation_list: [bare] }))
    expect(recomputed).toEqual(fingerprint)
  })

  it('declares the profile that owns the attribute, keeping the ones already declared', () => {
    const attested = attestRecord(record('S1:0'), 'chain-1', 0, undefined)
    expect(attested.record.metadata.profiles).toEqual(['ai_operation', 'cloud', 'osint', RECORD_INTEGRITY_PROFILE])
  })

  it('declares the profile on a record that declared none', () => {
    const bare = record('S1:0')
    const stripped = { ...bare, metadata: { ...bare.metadata, profiles: undefined } } as unknown as OcsfRecord
    const attested = attestRecord(stripped, 'chain-1', 0, undefined)
    expect(attested.record.metadata.profiles).toEqual([RECORD_INTEGRITY_PROFILE])
  })

  it('binds the predecessor by uid, class, and fingerprint', () => {
    const first = attestRecord(record('S1:0'), 'chain-1', 0, undefined)
    const second = attestRecord(record('S1:1'), 'chain-1', 1, first.link)
    expect(second.record.attestation_list?.[0]?.prev_event).toEqual({
      uid: 'S1:0',
      type_uid: 600301,
      fingerprint: first.record.attestation_list?.[0]?.fingerprint,
    })
  })

  it('changes the fingerprint when the predecessor changes, so the link is inside the hash', () => {
    const first = attestRecord(record('S1:0'), 'chain-1', 0, undefined)
    const other = attestRecord(record('S1:0', { message: 'different' }), 'chain-1', 0, undefined)
    const second = attestRecord(record('S1:1'), 'chain-1', 1, first.link)
    const spliced = attestRecord(record('S1:1'), 'chain-1', 1, other.link)
    expect(spliced.record.attestation_list?.[0]?.fingerprint?.value)
      .not.toBe(second.record.attestation_list?.[0]?.fingerprint?.value)
  })

  it('leaves the record it was given alone', () => {
    const original = record('S1:0')
    attestRecord(original, 'chain-1', 0, undefined)
    expect(original.attestation_list).toBeUndefined()
    expect(original.metadata.profiles).toEqual(['ai_operation', 'cloud', 'osint'])
  })
})

describe('the attesting sink', () => {
  it('numbers a chain from zero and links every record to the one before it', () => {
    const { sink, written } = collect()
    const chained = new AttestingSink(sink, 'chain-1')
    for (const index of [0, 1, 2]) chained.write(record(`S1:${String(index)}`))

    expect(written.map(item => item.attestation_list?.[0]?.uid)).toEqual(['chain-1:0', 'chain-1:1', 'chain-1:2'])
    for (const [index, item] of written.entries()) {
      const previous = written[index - 1]
      expect(item.attestation_list?.[0]?.prev_event?.fingerprint?.value)
        .toBe(previous?.attestation_list?.[0]?.fingerprint?.value)
    }
  })

  it('does not advance the chain over a record the sink refused', () => {
    const written: OcsfRecord[] = []
    let refuse = true
    const chained = new AttestingSink({
      write: (item) => {
        if (refuse) throw new Error('ENOSPC')
        written.push(item)
      },
      close: () => {},
    }, 'chain-1')

    expect(() => { chained.write(record('S1:0')) }).toThrow('ENOSPC')
    refuse = false
    // The forwarder leaves its cursor on an unwritten event and retries it, so
    // the retry must still be the genesis entry rather than a hole at index 0.
    chained.write(record('S1:0'))
    expect(written[0]?.attestation_list?.[0]?.uid).toBe('chain-1:0')
    expect(written[0]?.attestation_list?.[0]?.prev_event).toBeUndefined()
  })

  it('gives each lane its own chain over one shared record object', () => {
    const soc = collect()
    const restricted = collect()
    const socChain = new AttestingSink(soc.sink, 'chain-soc')
    const restrictedChain = new AttestingSink(restricted.sink, 'chain-restricted')
    const shared = record('S1:0')
    socChain.write(shared)
    restrictedChain.write(shared)

    expect(soc.written[0]?.attestation_list?.[0]?.chain_uid).toBe('chain-soc')
    expect(restricted.written[0]?.attestation_list?.[0]?.chain_uid).toBe('chain-restricted')
    expect(soc.written[0]?.attestation_list?.[0]?.fingerprint?.value)
      .not.toBe(restricted.written[0]?.attestation_list?.[0]?.fingerprint?.value)
  })

  it('closes the sink it wraps', () => {
    let closed = false
    new AttestingSink({ write: () => {}, close: () => { closed = true } }, 'chain-1').close()
    expect(closed).toBe(true)
  })
})
