/** Defensive payload readers: what they return for the shapes a durable log can hold. */
import { describe, expect, it } from 'vitest'
import { readArrayLength, readBoolean, readNested, readNumber, readRecord, readString, readStringArray } from '../../src/read.ts'

const payload = { name: 'bash', turn: 2, ok: true, items: [1, 2, 3], scopes: ['src/**', 7, 'lib/*'], nested: { a: 1 }, nil: null }

describe('readers', () => {
  it('returns the value when the field has the expected type', () => {
    expect(readString(payload, 'name')).toBe('bash')
    expect(readNumber(payload, 'turn')).toBe(2)
    expect(readBoolean(payload, 'ok')).toBe(true)
    expect(readArrayLength(payload, 'items')).toBe(3)
    expect(readNested(payload, 'nested')).toEqual({ a: 1 })
    expect(readStringArray(payload, 'scopes')).toEqual(['src/**', 'lib/*'])
    expect(readRecord(payload)).toBe(payload)
  })

  it('returns undefined for a field of the wrong type', () => {
    expect(readString(payload, 'turn')).toBeUndefined()
    expect(readNumber(payload, 'name')).toBeUndefined()
    expect(readBoolean(payload, 'name')).toBeUndefined()
    expect(readArrayLength(payload, 'name')).toBeUndefined()
    expect(readNested(payload, 'items')).toBeUndefined()
    expect(readStringArray(payload, 'name')).toBeUndefined()
    // A non-string member is left out rather than rendered, so the result
    // never carries a value the log did not spell.
    expect(readStringArray(payload, 'items')).toEqual([])
    expect(readNumber({ turn: Number.NaN }, 'turn')).toBeUndefined()
  })

  it('returns undefined for anything that is not a record', () => {
    for (const value of [null, undefined, 'text', 7, [1, 2]]) {
      expect(readRecord(value)).toBeUndefined()
      expect(readString(value, 'name')).toBeUndefined()
      expect(readNumber(value, 'turn')).toBeUndefined()
      expect(readBoolean(value, 'ok')).toBeUndefined()
      expect(readArrayLength(value, 'items')).toBeUndefined()
      expect(readNested(value, 'nested')).toBeUndefined()
      expect(readStringArray(value, 'scopes')).toBeUndefined()
    }
  })
})
