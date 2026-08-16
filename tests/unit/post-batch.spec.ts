/** The shipper's HTTP call against a real local collector. */
import { createServer, type Server } from 'node:http'
import { afterEach, describe, expect, it } from 'vitest'
import { postBatch } from '../../src/sink/otlp.ts'

let server: Server | undefined

afterEach(async () => {
  await new Promise<void>(resolve => { server === undefined ? resolve() : server.close(() => resolve()) })
  server = undefined
})

/** Start a collector that answers every request with `status`, after `delayMs`. */
async function collector(status: number, delayMs = 0): Promise<{ url: string; bodies: string[] }> {
  const bodies: string[] = []
  server = createServer((request, response) => {
    let body = ''
    request.on('data', (chunk: Buffer) => { body += chunk.toString() })
    request.on('end', () => {
      bodies.push(body)
      setTimeout(() => { response.writeHead(status).end('{}') }, delayMs)
    })
  })
  await new Promise<void>(resolve => { server?.listen(0, '127.0.0.1', resolve) })
  const address = server.address()
  const port = typeof address === 'object' && address !== null ? address.port : 0
  return { url: `http://127.0.0.1:${port}/v1/logs`, bodies }
}

describe('postBatch', () => {
  it('reports acceptance and sends the configured headers', async () => {
    const { url, bodies } = await collector(200)
    expect(await postBatch(url, { authorization: 'Bearer t' }, '{"resourceLogs":[]}', 5_000)).toBe('accepted')
    expect(bodies).toEqual(['{"resourceLogs":[]}'])
  })

  it('asks for a retry when the collector is unwell, so the cursor stays put', async () => {
    const { url } = await collector(503)
    expect(await postBatch(url, {}, '{}', 5_000)).toBe('retry')
  })

  it('asks for a retry on the client errors that mean "not now"', async () => {
    for (const status of [408, 425, 429]) {
      const { url } = await collector(status)
      expect(await postBatch(url, {}, '{}', 5_000)).toBe('retry')
      await new Promise<void>(resolve => { server?.close(() => resolve()) })
      server = undefined
    }
  })

  it('reports a refusal on the client errors that will never succeed', async () => {
    const { url } = await collector(400)
    expect(await postBatch(url, {}, '{}', 5_000)).toBe('reject')
  })

  it('reports a timeout as a retry rather than throwing', async () => {
    const { url } = await collector(200, 500)
    expect(await postBatch(url, {}, '{}', 50)).toBe('retry')
  })

  it('reports an unreachable collector as a retry', async () => {
    expect(await postBatch('http://127.0.0.1:1/v1/logs', {}, '{}', 1_000)).toBe('retry')
  })
})
