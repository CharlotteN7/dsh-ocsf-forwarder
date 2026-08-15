/** Shared fixtures for the unit tests: a resolved config and a record environment. */
import { resolveConfig, type Config, type ResolvedConfig } from '../../src/config.ts'
import { createEnvironment, type RecordEnvironment } from '../../src/ocsf/record.ts'

/** A resolved configuration with a fixed key, so digests are reproducible. */
export function testConfig(overrides: Partial<Config> = {}): ResolvedConfig {
  return resolveConfig({
    spoolPath: '/tmp/does-not-exist/ocsf.jsonl',
    privacy: { hmacKey: { source: 'literal', value: 'k'.repeat(32) } },
    ...overrides,
  })
}

/** A record environment with a frozen clock. */
export function testEnvironment(config: ResolvedConfig = testConfig()): RecordEnvironment {
  return createEnvironment(config, '0.1.0-test', () => 1_700_000_000_000)
}
