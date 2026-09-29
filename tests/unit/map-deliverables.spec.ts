/**
 * `deliverables/presented`: the files a turn declared as its deliverables.
 *
 * Before this mapper the event took the generic fallback, which reads no field
 * of a payload — so the one durable record of which files the agent handed to
 * the user named none of them. Each assertion below is on a field the fallback
 * cannot produce.
 */
import { describe, expect, it } from 'vitest'
import { SessionState } from '../../src/correlate.ts'
import { mapEvent } from '../../src/map/index.ts'
import { ACTIVITY, CLASS, OBSERVABLE, SEVERITY } from '../../src/ocsf/constants.ts'
import { testConfig } from './support.ts'

const SESSION = 'session-1'
const config = testConfig()

function map(data: unknown): ReturnType<typeof mapEvent> {
  return mapEvent(SESSION, { type: 'deliverables/presented', seq: 5, time: 1_000, data }, new SessionState(), config)
}

const data = {
  turn: 4,
  callId: 'call_7',
  files: [
    { path: '/srv/app/quarterly.pdf', description: 'the numbers' },
    { path: 'notes/draft.md' },
  ],
}

describe('deliverables/presented', () => {
  it('records a file activity rather than the generic API fallback', () => {
    const mapping = map(data)
    expect(mapping?.classUid).toBe(CLASS.fileSystemActivity)
    expect(mapping?.activityId).toBe(ACTIVITY.fileSystem.read)
    expect(mapping?.severityId).toBe(SEVERITY.low)
  })

  it('fills the class-required file from the first declared path', () => {
    expect(map(data)?.file).toEqual({ name: 'quarterly.pdf', type_id: 1, path: '/srv/app/quarterly.pdf' })
  })

  it('lists every path and gives each one its own observable', () => {
    const mapping = map(data)
    expect(mapping?.attributes?.['presented_paths']).toEqual(['/srv/app/quarterly.pdf', 'notes/draft.md'])
    expect(mapping?.attributes?.['presented_count']).toBe(2)
    expect(mapping?.observables).toEqual([
      { name: 'file.path', type_id: OBSERVABLE.filePath, value: '/srv/app/quarterly.pdf' },
      { name: 'file.path', type_id: OBSERVABLE.filePath, value: 'notes/draft.md' },
    ])
  })

  it('joins the declaration to the present call that produced it', () => {
    expect(map(data)?.correlationUid).toBe(`${SESSION}:call_7`)
    expect(map(data)?.attributes?.['call_id']).toBe('call_7')
  })

  it('carries the paths it declared and never the model-written description', () => {
    const serialized = JSON.stringify(map(data))
    expect(serialized).toContain('/srv/app/quarterly.pdf')
    expect(serialized).not.toContain('the numbers')
  })

  it('produces no record without a readable path, because the class requires a file', () => {
    expect(map({ turn: 1, callId: 'c', files: [] })).toBeUndefined()
    expect(map({ turn: 1, callId: 'c', files: [{ description: 'no path here' }] })).toBeUndefined()
    expect(map({ turn: 1 })).toBeUndefined()
  })

  it('still records the files when the payload names no call', () => {
    const mapping = map({ files: [{ path: '/a/b.txt' }] })
    expect(mapping?.correlationUid).toBeUndefined()
    expect(mapping?.attributes).not.toHaveProperty('call_id')
    expect(mapping?.attributes?.['turn']).toBe(0)
    expect(mapping?.file).toEqual({ name: 'b.txt', type_id: 1, path: '/a/b.txt' })
  })

  it('takes the whole value as the name when a path has no separator', () => {
    expect(map({ files: [{ path: 'report.txt' }] })?.file).toEqual({ name: 'report.txt', type_id: 1, path: 'report.txt' })
  })
})
