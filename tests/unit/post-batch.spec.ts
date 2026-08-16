/** The shipper's HTTP call against a real local collector, through a transport. */
import { createServer, type Server } from 'node:http'
import { afterEach, describe, expect, it } from 'vitest'
import { createOtlpTransport } from '../../src/sink/otlp.ts'
import { postBatch, type Transport } from '../../src/sink/transport.ts'

let server: Server | undefined

afterEach(async () => {
  await new Promise<void>(resolve => { server === undefined ? resolve() : server.close(() => resolve()) })
  server = undefined
})

/** Start a collector that answers every request with `status`, after `delayMs`. */
async function collector(status: number, delayMs = 0): Promise<{
  url: string
  bodies: string[]
  headers: Record<string, string | undefined>[]
}> {
  const bodies: string[] = []
  const headers: Record<string, string | undefined>[] = []
  server = createServer((request, response) => {
    let body = ''
    request.on('data', (chunk: Buffer) => { body += chunk.toString() })
    request.on('end', () => {
      bodies.push(body)
      headers.push({ ...request.headers } as Record<string, string | undefined>)
      setTimeout(() => { response.writeHead(status).end('{}') }, delayMs)
    })
  })
  await new Promise<void>(resolve => { server?.listen(0, '127.0.0.1', resolve) })
  const address = server.address()
  const port = typeof address === 'object' && address !== null ? address.port : 0
  return { url: `http://127.0.0.1:${port}/v1/logs`, bodies, headers }
}

/** An OTLP transport pointed at a local collector, with a body the caller supplies. */
function transport(url: string, extra: Readonly<Record<string, string>> = {}): Transport {
  return createOtlpTransport(url, extra, 'test')
}

describe('postBatch', () => {
  it('reports acceptance and sends the transport headers and content type', async () => {
    const { url, bodies, headers } = await collector(200)
    expect(await postBatch(transport(url, { authorization: 'Bearer t' }), '{"resourceLogs":[]}', 5_000))
      .toBe('accepted')
    expect(bodies).toEqual(['{"resourceLogs":[]}'])
    expect(headers[0]?.['authorization']).toBe('Bearer t')
    expect(headers[0]?.['content-type']).toBe('application/json')
  })

  it('asks for a retry when the collector is unwell, so the cursor stays put', async () => {
    const { url } = await collector(503)
    expect(await postBatch(transport(url), '{}', 5_000)).toBe('retry')
  })

  it('asks for a retry on the client errors that mean "not now"', async () => {
    for (const status of [408, 425, 429]) {
      const { url } = await collector(status)
      expect(await postBatch(transport(url), '{}', 5_000)).toBe('retry')
      await new Promise<void>(resolve => { server?.close(() => resolve()) })
      server = undefined
    }
  })

  it('reports a refusal on the client errors that will never succeed', async () => {
    const { url } = await collector(400)
    expect(await postBatch(transport(url), '{}', 5_000)).toBe('reject')
  })

  it('reports a timeout as a retry rather than throwing', async () => {
    const { url } = await collector(200, 500)
    expect(await postBatch(transport(url), '{}', 50)).toBe('retry')
  })

  it('reports an unreachable collector as a retry', async () => {
    expect(await postBatch(transport('http://127.0.0.1:1/v1/logs'), '{}', 1_000)).toBe('retry')
  })

  it('lets the transport read the status, rather than reading it here', async () => {
    // 200 is the one status no shared reading could call anything but accepted,
    // so a transport that refuses it proves the classifier is the transport's.
    const { url } = await collector(200)
    const opinionated: Transport = { ...transport(url), classify: () => 'reject' }
    expect(await postBatch(opinionated, '{}', 5_000)).toBe('reject')
  })
})
