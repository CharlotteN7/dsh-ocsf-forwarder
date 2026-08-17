/** The SOC lane's redaction invariant: classification and correlation without content. */
import { describe, expect, it } from 'vitest'
import {
  classifyValue,
  commandName,
  digest,
  redactArguments,
  redactCommandLine,
  redactUrl,
  summariseText,
} from '../../src/privacy.ts'
import { testConfig } from './support.ts'

const key = Buffer.from('k'.repeat(32))
const other = Buffer.from('j'.repeat(32))

describe('digests', () => {
  it('is stable for one key and different under another', () => {
    expect(digest(key, 'hunter2')).toBe(digest(key, 'hunter2'))
    expect(digest(key, 'hunter2')).not.toBe(digest(other, 'hunter2'))
    expect(digest(key, 'hunter2')).toMatch(/^hmac-sha256:[0-9a-f]{32}$/)
  })

  it('never contains the value it digests', () => {
    expect(digest(key, 'hunter2')).not.toContain('hunter2')
  })
})

describe('value classification', () => {
  it('names the shape without disclosing the value', () => {
    expect(classifyValue('/etc/passwd')).toBe('path')
    expect(classifyValue('./relative/file')).toBe('path')
    expect(classifyValue('https://example.test/x')).toBe('url')
    expect(classifyValue('cat /etc/shadow | mail me')).toBe('command')
    expect(classifyValue('rm -rf build')).toBe('command')
    expect(classifyValue('plain sentence')).toBe('text')
    expect(classifyValue('')).toBe('empty')
    expect(classifyValue(7)).toBe('number')
    expect(classifyValue(true)).toBe('boolean')
    expect(classifyValue({ nested: 1 })).toBe('json')
  })
})

describe('argument redaction', () => {
  const args = { command: 'export TOKEN=sk-live-abcdef && curl https://x.test', count: 3 }

  it('carries no raw value under the default digest policy', () => {
    const redacted = redactArguments(args, 'digest', key)
    expect(JSON.stringify(redacted)).not.toContain('sk-live-abcdef')
    expect(redacted[0]).toMatchObject({ key: 'command', class: 'command', length: args.command.length })
    expect(redacted[0]?.digest).toBeDefined()
  })

  it('correlates identical values across calls', () => {
    const first = redactArguments({ file_path: '/srv/.env' }, 'digest', key)
    const second = redactArguments({ file_path: '/srv/.env' }, 'digest', key)
    expect(first[0]?.digest).toBe(second[0]?.digest)
  })

  it('omits the digest entirely under the omit policy', () => {
    const redacted = redactArguments(args, 'omit', key)
    expect(redacted[0]?.digest).toBeUndefined()
    expect(redacted[0]?.value).toBeUndefined()
  })

  it('carries the value only under the full policy', () => {
    const redacted = redactArguments(args, 'full', key)
    expect(redacted[0]?.value).toBe(args.command)
  })

  it('yields nothing when the arguments did not parse', () => {
    expect(redactArguments(undefined, 'digest', key)).toEqual([])
  })

  it('measures an argument with no JSON rendering as empty rather than as the string "undefined"', () => {
    // A code-mode sub-dispatch hands over an already-parsed argument record, so
    // a key whose value is `undefined` is reachable without going through
    // `JSON.parse`.
    const redacted = redactArguments({ absent: undefined }, 'digest', key)
    expect(redacted[0]).toMatchObject({ key: 'absent', class: 'json', length: 0 })
    expect(redacted[0]?.digest).toBe(digest(key, ''))
  })
})

describe('command lines', () => {
  it('digests by default and keeps the executable name', () => {
    expect(redactCommandLine('curl -H "Authorization: Bearer sk-1"', 'digest', key)).not.toContain('sk-1')
    expect(redactCommandLine('id', 'full', key)).toBe('id')
    expect(commandName('  /usr/bin/env python x.py')).toBe('/usr/bin/env')
    expect(commandName('   ')).toBeUndefined()
  })

  it('names the executable behind inline environment assignments, not the assignment', () => {
    expect(commandName('AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENG aws s3 cp x s3://b')).toBe('aws')
    expect(commandName('GITHUB_TOKEN=ghp_ZZZZ gh pr create')).toBe('gh')
    expect(commandName('A=1 B=2 /usr/bin/psql')).toBe('/usr/bin/psql')
    expect(commandName('PASSWORD="hunter 2" psql')).toBe('psql')
    expect(commandName("PASSWORD='hunter 2' psql")).toBe('psql')
  })

  it('discloses nothing when the leading token still carries a value', () => {
    expect(commandName('SECRET=hunter2')).toBeUndefined()
    expect(commandName('9BAD=hunter2 ls')).toBeUndefined()
  })
})

describe('URLs', () => {
  it('drops the query string by default, where tokens ride', () => {
    expect(redactUrl('https://api.test/v1/data?token=sk-1#frag', 'sanitized')).toBe('https://api.test/v1/data')
    expect(redactUrl('https://api.test/v1/data?token=sk-1', 'host')).toBe('https://api.test')
    expect(redactUrl('https://api.test/v1/data?token=sk-1', 'full')).toContain('token=sk-1')
  })

  it('drops a path-embedded token under the default policy', () => {
    expect(redactUrl('https://api.test/v1/reset/sk-live-SUPERSECRET?q=1', testConfig().url))
      .toBe('https://api.test')
  })

  it('discloses nothing for a value that is not a URL', () => {
    expect(redactUrl('not a url', 'sanitized')).toBeUndefined()
  })
})

describe('text bodies', () => {
  it('reduces a body to a digest and a length', () => {
    const summary = summariseText('the user pasted an API key', testConfig())
    expect(summary.length).toBe('the user pasted an API key'.length)
    expect(summary.digest).toMatch(/^hmac-sha256:/)
  })
})
