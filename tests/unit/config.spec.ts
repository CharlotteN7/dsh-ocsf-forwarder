/** Configuration validation and the load-time failures it is responsible for. */
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { Config, DEFAULT_DROPPED_EVENT_TYPES, resolveConfig } from '../../src/config.ts'

/**
 * An explicit install uid keeps resolution off the filesystem for every test
 * that is not about the install uid itself.
 */
const minimal = { spoolPath: '/var/log/dsh/ocsf.jsonl', fleet: { installUid: 'install-test' } }

let home: string

beforeEach(() => { home = mkdtempSync(join(tmpdir(), 'dsh-ocsf-config-')) })
afterEach(() => { rmSync(home, { recursive: true, force: true }) })

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
    expect(resolved.shipper?.transport.endpoint).toBe('http://collector:4318/v1/logs')
    expect(resolved.shipper?.cursorPath).toBe('/var/log/dsh/ocsf.jsonl.cursor')
  })

  it('keeps an endpoint that already names a path', () => {
    const resolved = resolveConfig({ ...minimal, otlp: { endpoint: 'http://collector:4318/ingest/logs' } })
    expect(resolved.shipper?.transport.endpoint).toBe('http://collector:4318/ingest/logs')
  })

  it('rejects an endpoint that is not a URL', () => {
    expect(() => resolveConfig({ ...minimal, otlp: { endpoint: 'http://[' } })).toThrow(/not a valid URL/)
  })

  it('rejects an endpoint that is not http', () => {
    expect(() => resolveConfig({ ...minimal, otlp: { endpoint: 'collector:4318' } }))
      .toThrow(/must be an http or https URL/)
  })

  it('leaves the shipper off when no endpoint is configured', () => {
    expect(resolveConfig(minimal).shipper).toBeUndefined()
  })

  it('derives the quarantine path and bounds the read window and the backoff', () => {
    const resolved = resolveConfig({ ...minimal, otlp: { endpoint: 'http://collector:4318' } })
    expect(resolved.shipper?.quarantinePath).toBe('/var/log/dsh/ocsf.jsonl.quarantine')
    expect(resolved.shipper?.maxReadBytes).toBeGreaterThan(0)
    expect(resolved.shipper?.maxBackoffMs).toBeGreaterThan(resolved.shipper?.flushIntervalMs ?? 0)
  })

  it('withholds a URL path by default, because a token rides there as readily as in a query', () => {
    expect(resolveConfig(minimal).url).toBe('host')
  })

  it('keeps the extension attributes out of the class namespace by default', () => {
    expect(resolveConfig(minimal).extensionPlacement).toBe('unmapped')
  })

  it('claims no OCSF extension uid until a deployment supplies a registered one', () => {
    expect(resolveConfig(minimal).extensionUid).toBeUndefined()
    expect(resolveConfig({ ...minimal, extension: { uid: 4242 } }).extensionUid).toBe(4242)
  })

  it('names a vendor rather than whatever directory the plugin was built in', () => {
    expect(resolveConfig(minimal).vendorName).toBe('dsh-security-plugins')
  })

  it('bounds the rotated generations that may await the shipper', () => {
    expect(resolveConfig(minimal).spoolMaxGenerations).toBeGreaterThan(1)
    expect(resolveConfig({ ...minimal, spoolMaxGenerations: 3 }).spoolMaxGenerations).toBe(3)
  })

  it('bounds the disk the spool may occupy, not only the file count', () => {
    expect(resolveConfig(minimal).spoolMaxTotalBytes).toBeGreaterThan(0)
    const resolved = resolveConfig({ ...minimal, spoolMaxTotalBytes: 4096, spoolHighWaterBytes: 2048 })
    expect(resolved.spoolMaxTotalBytes).toBe(4096)
    expect(resolved.spoolHighWaterBytes).toBe(2048)
  })

  it('keeps the high-water mark below the point rotation stops', () => {
    expect(resolveConfig(minimal).spoolHighWaterBytes).toBeLessThan(resolveConfig(minimal).spoolMaxTotalBytes)
    expect(() => resolveConfig({ ...minimal, spoolMaxTotalBytes: 1024, spoolHighWaterBytes: 4096 }))
      .toThrow(/never fire before rotation stopped/)
  })
})

describe('the Splunk destination', () => {
  const splunkBase = { ...minimal, splunk: { endpoint: 'https://splunk.internal:8088' } }

  it('posts to the HEC event endpoint and carries the Splunk authorization scheme', () => {
    const resolved = resolveConfig(
      { ...splunkBase, splunk: { ...splunkBase.splunk, token: { source: 'env' as const, variable: 'HEC' } } },
      { HEC: 'abc-123' },
    )
    expect(resolved.shipper?.transport.endpoint).toBe('https://splunk.internal:8088/services/collector/event')
    expect(resolved.shipper?.transport.headers['authorization']).toBe('Splunk abc-123')
    expect(resolved.shipper?.transport.kind).toBe('splunk-hec')
  })

  it('fails loud when the token variable is unset, rather than shipping unauthenticated', () => {
    expect(() => resolveConfig(
      { ...splunkBase, splunk: { ...splunkBase.splunk, token: { source: 'env' as const, variable: 'HEC' } } },
      {},
    )).toThrow(/HEC/)
    expect(() => resolveConfig(splunkBase, {})).toThrow(/token.variable is required/)
    expect(() => resolveConfig(
      { ...splunkBase, splunk: { ...splunkBase.splunk, token: { source: 'literal' as const } } },
      {},
    )).toThrow(/token.value is required/)
  })

  it('refuses two destinations on one cursor', () => {
    expect(() => resolveConfig({
      ...minimal,
      otlp: { endpoint: 'http://collector:4318' },
      splunk: { endpoint: 'https://splunk.internal:8088', token: { source: 'literal', value: 't' } },
    })).toThrow(/configure exactly one destination/)
  })
})

describe('fleet identity', () => {
  it('carries the tenant, labels and tags a multi-team SOC filters on', () => {
    const resolved = resolveConfig({
      ...minimal,
      fleet: { installUid: 'i', tenantUid: 'acme', labels: ['prod'], tags: { owner: 'soc' } },
    })
    expect(resolved.fleet.tenantUid).toBe('acme')
    expect(resolved.fleet.labels).toEqual(['prod'])
    expect(resolved.fleet.tags).toEqual([{ name: 'owner', value: 'soc' }])
  })

  it('omits every fleet field that was not configured, rather than inventing one', () => {
    const resolved = resolveConfig(minimal)
    expect(resolved.fleet.tenantUid).toBeUndefined()
    expect(resolved.fleet.labels).toBeUndefined()
    expect(resolved.fleet.tags).toBeUndefined()
  })

  it('mints an install uid once and reuses it, so a renamed host is still the same device', () => {
    const spoolPath = join(home, 'ocsf.jsonl')
    const first = resolveConfig({ spoolPath }).fleet.installUid
    const second = resolveConfig({ spoolPath }).fleet.installUid
    expect(first).toMatch(/^[0-9a-f-]{36}$/)
    expect(second).toBe(first)
    expect(readFileSync(`${spoolPath}.install-uid`, 'utf8').trim()).toBe(first)
  })

  it('reads an install uid a deployment placed at the configured path', () => {
    const installUidPath = join(home, 'fleet.uid')
    writeFileSync(installUidPath, 'laptop-17\n')
    expect(resolveConfig({ spoolPath: join(home, 'ocsf.jsonl'), fleet: { installUidPath } }).fleet.installUid)
      .toBe('laptop-17')
  })
})

describe('delegation tools', () => {
  it('carries the configured delegation names into the resolved configuration', () => {
    const resolved = resolveConfig({ ...minimal, delegationTools: { handoff: 'codex' } })
    expect(resolved.delegationTools).toEqual({ handoff: 'codex' })
  })
})
