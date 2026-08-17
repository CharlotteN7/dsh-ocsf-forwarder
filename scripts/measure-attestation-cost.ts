/**
 * What attesting a record costs on the agent's event loop.
 *
 * The chain runs synchronously inside `session/event`, so its cost is charged
 * to the agent, not to a background drain. This measures the added work per
 * record — one canonical serialization plus one SHA-256 — against the
 * `JSON.stringify` the spool already did, over records a real forwarder run
 * produced rather than a synthetic object.
 *
 *   pnpm exec tsx scripts/measure-attestation-cost.ts [iterations]
 */

import { resolveConfig } from '../src/config.ts'
import { Forwarder, type ForwardableSession } from '../src/forwarder.ts'
import { attestRecord } from '../src/integrity/attest.ts'
import type { MappableEvent } from '../src/map/index.ts'
import { createEnvironment } from '../src/ocsf/record.ts'
import type { OcsfRecord } from '../src/ocsf/types.ts'
import type { Sink } from '../src/sink/spool.ts'

/** One turn's worth of the events a real session produces, repeated to fill the sample. */
function events(count: number): MappableEvent[] {
  const log: MappableEvent[] = [
    { type: 'turn/start', seq: 0, time: 1_000, data: { turn: 1 } },
    { type: 'request/context', seq: 1, time: 1_001, data: { provider: 'deepseek', model: 'deepseek-chat' } },
  ]
  for (let index = 0; log.length < count; index += 1) {
    const seq = log.length
    log.push({
      type: 'tool/call',
      seq,
      time: 1_000 + seq,
      data: {
        turn: 1,
        step: 0,
        callId: `c${String(index)}`,
        name: 'bash',
        arguments: JSON.stringify({ command: `rg --files-with-matches "TODO" packages/app/src/${String(index)}` }),
      },
    })
    log.push({
      type: 'tool/result',
      seq: seq + 1,
      time: 1_002 + seq,
      data: { message: { source: { callId: `c${String(index)}` } } },
    })
  }
  return log.slice(0, count)
}

/** Records one forwarder run produces, which is what the chain is asked to cover. */
function sample(count: number): readonly OcsfRecord[] {
  const config = resolveConfig({ spoolPath: '/dev/null', fleet: { installUid: 'measure' } })
  const records: OcsfRecord[] = []
  const sink: Sink = { write: record => { records.push(record) }, close: () => {} }
  const log = events(count)
  const session: ForwardableSession = { id: 'S1', firstLiveSeq: 0, seq: log.length, events: log, header: { cwd: '/srv' } }
  const forwarder = new Forwarder(createEnvironment(config, '0.0.0-measure'), config, sink, undefined, (error) => { throw error })
  forwarder.adopt(session)
  for (const event of log) forwarder.observe(session, event)
  return records
}

/** Microseconds per call of one unit of work, over the whole sample. */
function perRecordMicros(records: readonly OcsfRecord[], work: (record: OcsfRecord, index: number) => void): number {
  const started = process.hrtime.bigint()
  for (const [index, record] of records.entries()) work(record, index)
  const elapsed = Number(process.hrtime.bigint() - started)
  return elapsed / records.length / 1_000
}

const iterations = Number(process.argv[2] ?? '20000')
const records = sample(iterations)
// One untimed pass so the measurement is of steady-state code, not of the
// optimiser still deciding what to do with it.
perRecordMicros(records, record => JSON.stringify(attestRecord(record, 'warmup', 0, undefined).record))

const baseline = perRecordMicros(records, record => { JSON.stringify(record) })
const attested = perRecordMicros(records, (record, index) => {
  JSON.stringify(attestRecord(record, 'measure-chain', index, undefined).record)
})

const plain = records.map(record => JSON.stringify(record).length)
const chained = records.map((record, index) => JSON.stringify(attestRecord(record, 'measure-chain', index, {
  uid: 'S1:0', type_uid: 600301, fingerprint: { value: 'f'.repeat(64), algorithm_id: 3, encoding_id: 1 },
}).record).length)
const mean = (values: readonly number[]): number => values.reduce((sum, value) => sum + value, 0) / values.length

process.stdout.write([
  `records            ${String(records.length)}`,
  `serialize only     ${baseline.toFixed(2)} µs/record`,
  `attest + serialize ${attested.toFixed(2)} µs/record`,
  `added by attesting ${(attested - baseline).toFixed(2)} µs/record`,
  `record bytes       ${mean(plain).toFixed(0)} -> ${mean(chained).toFixed(0)} `
  + `(+${(mean(chained) - mean(plain)).toFixed(0)}, +${((mean(chained) / mean(plain) - 1) * 100).toFixed(1)}%)`,
  '',
].join('\n'))
