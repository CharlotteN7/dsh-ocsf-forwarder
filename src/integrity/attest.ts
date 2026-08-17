/**
 * The `record_integrity` profile: a hash chain over the records one process
 * writes to one spool file.
 *
 * Each record carries one `attestation` holding the SHA-256 fingerprint of its
 * own canonical serialization, and — from the second record on — the previous
 * record's uid and fingerprint. Because the reference to the predecessor is
 * inside the hashed content, editing or removing any record breaks the record
 * after it as well as itself.
 *
 * **What this detects and what it does not.** The fingerprints are unkeyed and
 * the algorithm is published, so anyone can recompute the whole chain — that is
 * the point, and it is why no HMAC is used. It also means the chain does not
 * resist the agent it observes: this plugin runs in the agent's process at the
 * agent's uid, and an agent that can run `bash` can rewrite the spool and
 * recompute a consistent chain over the result. What the chain gives a reader is
 * evidence about records that were *shipped* or otherwise copied off the host
 * before they were touched, and detection of any later edit, deletion, or
 * reordering by anything that does not recompute the chain. The threat model is
 * in `docs/integrity.md`, and it is not optimistic.
 * @module integrity/attest
 */

import { createHash } from 'node:crypto'
import type { OcsfAttestation, OcsfFingerprint, OcsfPrevEvent, OcsfRecord } from '../ocsf/types.ts'
import type { Sink } from '../sink/spool.ts'

/** The OCSF profile these attestations belong to, as declared in `metadata.profiles`. */
export const RECORD_INTEGRITY_PROFILE = 'record_integrity'

/** `fingerprint.algorithm_id` for SHA-256. */
export const FINGERPRINT_ALGORITHM_ID = 3

/** `fingerprint.encoding_id` for hex. */
export const FINGERPRINT_ENCODING_ID = 1

/**
 * RFC 8785 (JSON Canonicalization Scheme) serialization of one JSON value.
 *
 * Object keys are sorted by UTF-16 code unit, there is no insignificant
 * whitespace, and strings and numbers are rendered by `JSON.stringify`, whose
 * output RFC 8785 is defined in terms of. Keys whose value is `undefined` are
 * dropped and `undefined` array elements become `null`, which is what
 * `JSON.stringify` does when the record reaches the spool, so the canonical form
 * covers exactly the JSON document a reader gets back.
 * @param value - the value to canonicalize.
 * @returns the canonical JSON text.
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null'
  if (Array.isArray(value)) return `[${value.map(item => canonicalJson(item)).join(',')}]`
  const fields = value as Record<string, unknown>
  const members = Object.keys(fields)
    .filter(key => fields[key] !== undefined)
    .sort()
    .map(key => `${JSON.stringify(key)}:${canonicalJson(fields[key])}`)
  return `{${members.join(',')}}`
}

/**
 * The fingerprint of one canonical serialization.
 * @param canonical - the canonical JSON text.
 * @returns the OCSF `fingerprint` object a record or a link carries.
 */
export function fingerprintOf(canonical: string): OcsfFingerprint {
  return {
    value: createHash('sha256').update(canonical, 'utf8').digest('hex'),
    algorithm_id: FINGERPRINT_ALGORITHM_ID,
    encoding_id: FINGERPRINT_ENCODING_ID,
  }
}

/** One attested record and the link its successor must carry. */
export interface AttestedRecord {
  readonly record: OcsfRecord
  readonly link: OcsfPrevEvent
}

/**
 * Attach one attestation to a record and declare the profile that owns it.
 *
 * The fingerprint covers the record with the attestation already on it, less
 * the `fingerprint` field itself — the serialization OCSF specifies, which is
 * why `chain_uid` and `prev_event` cannot be changed without invalidating it.
 * @param record - the finished record, with no attestation yet.
 * @param chainUid - the chain this record joins.
 * @param index - this record's position in the chain, counting from zero.
 * @param previous - the link to the preceding record; absent on the genesis record.
 * @returns the attested record and the link the next record must carry.
 */
export function attestRecord(
  record: OcsfRecord,
  chainUid: string,
  index: number,
  previous: OcsfPrevEvent | undefined,
): AttestedRecord {
  const unsigned = {
    uid: `${chainUid}:${String(index)}`,
    chain_uid: chainUid,
    ...previous === undefined ? {} : { prev_event: previous },
  }
  const covered = {
    ...record,
    metadata: { ...record.metadata, profiles: [...record.metadata.profiles ?? [], RECORD_INTEGRITY_PROFILE] },
    attestation_list: [unsigned],
  }
  const fingerprint = fingerprintOf(canonicalJson(covered))
  const attestation: OcsfAttestation = { ...unsigned, fingerprint }
  return {
    record: { ...covered, attestation_list: [attestation] },
    link: { uid: record.metadata.uid, type_uid: record.type_uid, fingerprint },
  }
}

/**
 * A sink that chains every record it passes on.
 *
 * One instance owns one chain, so each lane gets its own: the SOC and
 * restricted lanes are separate files carrying different records, and a chain
 * whose links point into another file cannot be verified from the file it is
 * in.
 *
 * The chain advances only after the inner sink accepted the record. A sink that
 * throws leaves the forwarder's cursor on the unwritten event, which is retried;
 * advancing first would give the retry a different index and a fingerprint the
 * previous link does not match.
 */
export class AttestingSink implements Sink {
  private index = 0
  private previous: OcsfPrevEvent | undefined

  /**
   * @param inner - the sink that receives the attested records.
   * @param chainUid - this chain's identifier, unique per process and lane.
   */
  constructor(private readonly inner: Sink, private readonly chainUid: string) {}

  /**
   * Attest one record and pass it on.
   * @param record - the finished OCSF record.
   */
  write(record: OcsfRecord): void {
    const attested = attestRecord(record, this.chainUid, this.index, this.previous)
    this.inner.write(attested.record)
    this.index += 1
    this.previous = attested.link
  }

  /** Close the inner sink; a chain holds no resources of its own. */
  close(): void {
    this.inner.close()
  }
}
