/**
 * The Splunk HEC wire format, against the contract Splunk documents:
 * `POST {base}/services/collector/event`, `Authorization: Splunk <token>`,
 * event objects stacked one after the other, and `time` in epoch seconds
 * "in the format <sec>.<ms>".
 */
import { describe, expect, it } from 'vitest'
import { classifySplunkStatus, createSplunkTransport, splunkPayload } from '../../src/sink/splunk.ts'
import type { OcsfRecord } from '../../src/ocsf/types.ts'

/** One record whose class this build names, so the sourcetype is derived rather than defaulted. */
function record(uid: string, classUid = 1007): OcsfRecord {
  return {
    class_uid: classUid,
    category_uid: Math.floor(classUid / 1000),
    type_uid: classUid * 100 + 1,
    activity_id: 1,
    severity_id: 1,
    time: 1_700_000_000_500,
    metadata: { product: { name: 'p', vendor_name: 'v', version: '1' }, version: '1.9.0', uid },
    cloud: { provider: 'Other' },
    osint: [],
  }
}

const metadata = { host: 'app-01', source: 'dsh:session', sourcetypePrefix: 'ocsf' }

describe('the HEC event envelope', () => {
  it('renders the record time as epoch seconds with millisecond precision', () => {
    const [event] = splunkPayload([record('a')], metadata).trim().split('\n')
      .map(line => JSON.parse(line) as { time: number })
    expect(event?.time).toBe(1_700_000_000.5)
  })

  it('names the OCSF class in the sourcetype, using the schema name rather than the caption', () => {
    const events = splunkPayload([record('a', 1007), record('b', 1001), record('c', 6002)], metadata)
      .trim().split('\n').map(line => JSON.parse(line) as { sourcetype: string })
    expect(events.map(event => event.sourcetype))
      .toEqual(['ocsf:process_activity', 'ocsf:file_activity', 'ocsf:application_lifecycle'])
  })

  it('falls back to the base event for a class this build does not name', () => {
    const [event] = splunkPayload([record('a', 4001)], metadata).trim().split('\n')
      .map(line => JSON.parse(line) as { sourcetype: string })
    expect(event?.sourcetype).toBe('ocsf:base_event')
  })

  it('carries the record whole under the event key, alongside the metadata keys', () => {
    const [event] = splunkPayload([record('a')], metadata).trim().split('\n')
      .map(line => JSON.parse(line) as { host: string; source: string; event: OcsfRecord; index?: string })
    expect(event?.host).toBe('app-01')
    expect(event?.source).toBe('dsh:session')
    expect(event?.event.metadata.uid).toBe('a')
    expect(event?.index).toBeUndefined()
  })

  it('names an index only when one is configured, so the token default applies otherwise', () => {
    const [event] = splunkPayload([record('a')], { ...metadata, index: 'sec' }).trim().split('\n')
      .map(line => JSON.parse(line) as { index?: string })
    expect(event?.index).toBe('sec')
  })

  it('stacks the objects rather than wrapping them in an array', () => {
    const body = splunkPayload([record('a'), record('b')], metadata)
    expect(body.startsWith('{')).toBe(true)
    expect(body.trimEnd().endsWith('}')).toBe(true)
    const lines = body.split('\n').filter(line => line.length > 0)
    expect(lines).toHaveLength(2)
    for (const line of lines) expect(() => JSON.parse(line)).not.toThrow()
  })
})

describe('the HEC transport', () => {
  const transport = createSplunkTransport('https://splunk.test:8088/services/collector/event', 'tok', { 'x-a': 'b' }, metadata)

  it('places the token in the authorization header under the Splunk scheme', () => {
    expect(transport.headers['authorization']).toBe('Splunk tok')
    expect(transport.headers['x-a']).toBe('b')
  })

  it('names itself so a quarantine report says which destination refused the batch', () => {
    expect(transport.kind).toBe('splunk-hec')
  })
})

describe('reading a HEC status', () => {
  it('accepts every 2xx, which is what HEC returns on success', () => {
    expect(classifySplunkStatus(200)).toBe('accepted')
    expect(classifySplunkStatus(201)).toBe('accepted')
  })

  it('refuses a 400, the content error, so one bad batch cannot block the rest', () => {
    expect(classifySplunkStatus(400)).toBe('reject')
  })

  it('retries a token failure rather than quarantining a spool over a rotated credential', () => {
    expect(classifySplunkStatus(401)).toBe('retry')
    expect(classifySplunkStatus(403)).toBe('retry')
  })

  it('retries HEC backpressure, which it reports as 429 as well as 503', () => {
    expect(classifySplunkStatus(429)).toBe('retry')
    expect(classifySplunkStatus(503)).toBe('retry')
    expect(classifySplunkStatus(500)).toBe('retry')
  })
})
