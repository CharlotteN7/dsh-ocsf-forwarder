/**
 * The OTLP/HTTP logs transport: each OCSF record becomes one OTLP `logRecord`
 * whose body is the record's JSON, so a collector routes and enriches on the
 * two indexed attributes without parsing the payload.
 * @module sink/otlp
 */

import type { OcsfRecord } from '../ocsf/types.ts'
import { classifyHttpStatus, type Transport } from './transport.ts'

/** OTLP severity numbers for the OCSF severities we emit. */
const OTLP_SEVERITY: Readonly<Record<number, number>> = Object.freeze({
  0: 0, 1: 9, 2: 13, 3: 17, 4: 21, 5: 21, 6: 24,
})

/** Convert one OCSF record into an OTLP `logRecord`. */
function toLogRecord(record: OcsfRecord): unknown {
  const time = typeof record.time === 'number' ? record.time : Date.now()
  const severity = typeof record.severity_id === 'number' ? record.severity_id : 0
  return {
    timeUnixNano: String(time * 1_000_000),
    observedTimeUnixNano: String(Date.now() * 1_000_000),
    severityNumber: OTLP_SEVERITY[severity] ?? 0,
    body: { stringValue: JSON.stringify(record) },
    attributes: [
      { key: 'ocsf.class_uid', value: { intValue: String(record.class_uid) } },
      { key: 'ocsf.type_uid', value: { intValue: String(record.type_uid) } },
    ],
  }
}

/**
 * Wrap records in the OTLP logs request envelope.
 * @param records - the records to ship.
 * @param productName - reported as `service.name` on the resource.
 * @returns the JSON body of one OTLP/HTTP logs request.
 */
export function otlpPayload(records: readonly OcsfRecord[], productName: string): unknown {
  return {
    resourceLogs: [{
      resource: { attributes: [{ key: 'service.name', value: { stringValue: productName } }] },
      scopeLogs: [{
        scope: { name: 'dsh-ocsf-forwarder' },
        logRecords: records.map(toLogRecord),
      }],
    }],
  }
}

/**
 * Build the OTLP/HTTP logs transport.
 * @param endpoint - the exact logs endpoint to post to.
 * @param headers - configured request headers.
 * @param productName - reported as `service.name` on every resource.
 * @returns the transport.
 */
export function createOtlpTransport(
  endpoint: string,
  headers: Readonly<Record<string, string>>,
  productName: string,
): Transport {
  return {
    kind: 'otlp',
    endpoint,
    headers,
    contentType: 'application/json',
    encode: records => JSON.stringify(otlpPayload(records, productName)),
    classify: classifyHttpStatus,
  }
}
