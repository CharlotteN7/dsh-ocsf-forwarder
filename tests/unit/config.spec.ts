/** Configuration validation and the load-time failures it is responsible for. */
import { describe, expect, it } from 'vitest'
import { Config, DEFAULT_DROPPED_EVENT_TYPES, resolveConfig } from '../../src/config.ts'

const minimal = { spoolPath: '/var/log/dsh/ocsf.jsonl' }

describe('Config validation', () => {
  it('rejects configuration without a spool path', () => {
    expect(() => Config({} as never)).toThrow()
  })

  it('accepts a spool path alone and fills the rest in', () => {
    const validated = Config(minimal)
    expect(validated.spoolPath).toBe('/var/log/dsh/ocsf.jsonl')
    expect(validated.seedReplay).toBe('full')
  })

  it('rejects an unknown seed-replay mode', () => {
    expect(() => Config({ ...minimal, seedReplay: 'sometimes' } as never)).toThrow()
  })

  it('rejects a tool class outside the configurable vocabulary', () => {
    expect(() => Config({ ...minimal, toolClasses: { my_tool: 'kernel' } } as never)).toThrow()
  })
})

describe('resolution', () => {
  it('drops the high-volume and content-bearing types by default', () => {
    const resolved = resolveConfig(minimal)
    for (const type of DEFAULT_DROPPED_EVENT_TYPES) {
      expect(resolved.forwarded(type)).toBe(false)
    }
    expect(resolved.forwarded('tool/call')).toBe(true)
  })

  it('lets a deployment re-enable a default drop', () => {
    const resolved = resolveConfig({ ...minimal, includeEventTypes: ['todo/write'] })
    expect(resolved.forwarded('todo/write')).toBe(true)
  })

  it('lets a deployment drop a type that is forwarded by default', () => {
    const resolved = resolveConfig({ ...minimal, dropEventTypes: ['user/message'] })
    expect(resolved.forwarded('user/message')).toBe(false)
  })

  it('refuses the restricted lane without an acknowledgement', () => {
    expect(() => resolveConfig({ ...minimal, restricted: { path: '/tmp/full.jsonl' } }))
      .toThrow(/acknowledged/)
  })

  it('opens the restricted lane once acknowledged', () => {
    const resolved = resolveConfig({ ...minimal, restricted: { path: '/tmp/full.jsonl', acknowledged: true } })
    expect(resolved.restrictedPath).toBe('/tmp/full.jsonl')
  })

  it('fails loud when an env-sourced key names no variable', () => {
    expect(() => resolveConfig({ ...minimal, privacy: { hmacKey: { source: 'env' } } }))
      .toThrow(/hmacKey.variable is required/)
  })

  it('fails loud when the named variable is missing or too short', () => {
    expect(() => resolveConfig({ ...minimal, privacy: { hmacKey: { source: 'env', variable: 'OCSF_KEY' } } }, {}))
      .toThrow(/OCSF_KEY/)
    expect(() => resolveConfig(
      { ...minimal, privacy: { hmacKey: { source: 'env', variable: 'OCSF_KEY' } } },
      { OCSF_KEY: 'short' },
    )).toThrow(/at least 32 bytes/)
  })

  it('accepts a long enough env-sourced key', () => {
    const resolved = resolveConfig(
      { ...minimal, privacy: { hmacKey: { source: 'env', variable: 'OCSF_KEY' } } },
      { OCSF_KEY: 'x'.repeat(48) },
    )
    expect(resolved.hmacKey.length).toBe(48)
  })

  it('rejects a literal key that is too short', () => {
    expect(() => resolveConfig({ ...minimal, privacy: { hmacKey: { source: 'literal', value: 'nope' } } }))
      .toThrow(/at least 32 bytes/)
  })

  it('generates an ephemeral key when none is configured', () => {
    const first = resolveConfig(minimal).hmacKey
    const second = resolveConfig(minimal).hmacKey
    expect(first.length).toBe(32)
    expect(first.equals(second)).toBe(false)
  })

  it('appends the logs path to a bare OTLP endpoint and derives the cursor path', () => {
    const resolved = resolveConfig({ ...minimal, otlp: { endpoint: 'http://collector:4318' } })
    expect(resolved.otlp?.url).toBe('http://collector:4318/v1/logs')
    expect(resolved.otlp?.cursorPath).toBe('/var/log/dsh/ocsf.jsonl.cursor')
  })

  it('keeps an endpoint that already names a path', () => {
    const resolved = resolveConfig({ ...minimal, otlp: { endpoint: 'http://collector:4318/ingest/logs' } })
    expect(resolved.otlp?.url).toBe('http://collector:4318/ingest/logs')
  })

  it('rejects an endpoint that is not a URL', () => {
    expect(() => resolveConfig({ ...minimal, otlp: { endpoint: 'http://[' } })).toThrow(/not a valid URL/)
  })

  it('rejects an endpoint that is not http', () => {
    expect(() => resolveConfig({ ...minimal, otlp: { endpoint: 'collector:4318' } }))
      .toThrow(/must be an http or https URL/)
  })

  it('leaves the shipper off when no endpoint is configured', () => {
    expect(resolveConfig(minimal).otlp).toBeUndefined()
  })
})
