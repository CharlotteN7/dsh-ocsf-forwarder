/** Defensive payload readers: what they return for the shapes a durable log can hold. */
import { describe, expect, it } from 'vitest'
import { readArrayLength, readBoolean, readNested, readNumber, readRecord, readString } from '../../src/read.ts'

const payload = { name: 'bash', turn: 2, ok: true, items: [1, 2, 3], nested: { a: 1 }, nil: null }

describe('readers', () => {
  it('returns the value when the field has the expected type', () => {
    expect(readString(payload, 'name')).toBe('bash')
    expect(readNumber(payload, 'turn')).toBe(2)
    expect(readBoolean(payload, 'ok')).toBe(true)
    expect(readArrayLength(payload, 'items')).toBe(3)
    expect(readNested(payload, 'nested')).toEqual({ a: 1 })
    expect(readRecord(payload)).toBe(payload)
  })

  it('returns undefined for a field of the wrong type', () => {
    expect(readString(payload, 'turn')).toBeUndefined()
    expect(readNumber(payload, 'name')).toBeUndefined()
    expect(readBoolean(payload, 'name')).toBeUndefined()
    expect(readArrayLength(payload, 'name')).toBeUndefined()
    expect(readNested(payload, 'items')).toBeUndefined()
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
    }
  })
})
