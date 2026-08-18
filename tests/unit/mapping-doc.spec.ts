/**
 * `docs/mapping.md`'s event table, checked against the harness's own event
 * vocabulary and against what the mappers actually produce.
 *
 * Thirteen of the forty-four rows named a class and an activity for an event
 * type that had no `case` in the dispatcher and took the generic fallback —
 * API Activity 6003 / activity `99 Other` with metadata only. The table read
 * as a specification and was a wish list, and nothing in the suite could tell
 * the difference, because nothing read the table.
 */
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { KNOWN_SESSION_EVENT_TYPES } from '@deepseek-ai/dsh-session'
import { describe, expect, it } from 'vitest'
import { DEFAULT_DROPPED_EVENT_TYPES } from '../../src/config.ts'
import { SessionState } from '../../src/correlate.ts'
import { mapEvent } from '../../src/map/index.ts'
import { testConfig } from './support.ts'

/** One row of the event table. */
interface Row {
  readonly number: number
  readonly eventType: string
  /** The `class_uid` the row names, absent when the row names no class. */
  readonly classUid?: number
  /**
   * The `activity_id` the row names, absent when the row names none or names
   * several — a tool event's class and activity both follow the tool name, and
   * `schedule/change` lists one per durable operation.
   */
  readonly activityId?: number
}

/** The table, read from the published page rather than from a copy of it. */
function rows(): readonly Row[] {
  const page = readFileSync(fileURLToPath(new URL('../../docs/mapping.md', import.meta.url)), 'utf8')
  return page
    .split('\n')
    .map(line => /^\| (\d+) \| `([^`]+)` \| ([^|]+) \| ([^|]+) \|/.exec(line))
    .filter(match => match !== null)
    .map((match) => {
      const classUid = /\((\d{4})\)/.exec(match[3] as string)
      // A column listing several activities — `schedule/change` names one per
      // durable operation — pins the class but not one activity.
      const column = (match[4] as string).trim()
      const activityId = column.includes('/') ? null : /^(\d+) /.exec(column)
      return {
        number: Number(match[1]),
        eventType: match[2] as string,
        ...classUid === null ? {} : { classUid: Number(classUid[1]) },
        ...activityId === null ? {} : { activityId: Number(activityId[1]) },
      }
    })
}

describe('the published event table', () => {
  const table = rows()

  it('covers the harness event vocabulary exactly, once each and in order', () => {
    expect(table.map(row => row.number)).toEqual(table.map((_, index) => index + 1))
    expect(table.map(row => row.eventType).sort()).toEqual([...KNOWN_SESSION_EVENT_TYPES].sort())
  })

  it('names the class and activity each mapper actually produces', () => {
    const config = testConfig()
    const wrong = table
      .filter(row => row.classUid !== undefined)
      .map((row) => {
        // The payload carries nothing but the pairing id the two approval
        // mappers refuse to build a record without. Everything else is left
        // out on purpose: a row's class and activity must not depend on which
        // optional fields the payload happened to carry.
        const event = { type: row.eventType, seq: 1, time: 1_000, data: { id: 'a1' } }
        const mapping = mapEvent('S1', event, new SessionState(), config)
        if (mapping === undefined) return `${row.eventType}: no mapping`
        const claimed = `${String(row.classUid)}/${String(row.activityId ?? mapping.activityId)}`
        const emitted = `${String(mapping.classUid)}/${String(mapping.activityId)}`
        return claimed === emitted ? undefined : `${row.eventType}: table says ${claimed}, mapper emits ${emitted}`
      })
      .filter(entry => entry !== undefined)
    expect(wrong).toEqual([])
  })

  it('names no class for an event that produces no record, and that is every dropped type', () => {
    const classless = table.filter(row => row.classUid === undefined).map(row => row.eventType)
    // The tool events name their class by tool name rather than in the column.
    const byToolName = ['tool/call', 'tool/result', 'tool/code-dispatch-start', 'tool/code-dispatch']
    expect(classless.filter(type => !byToolName.includes(type)).sort())
      .toEqual([...DEFAULT_DROPPED_EVENT_TYPES].sort())
  })
})
