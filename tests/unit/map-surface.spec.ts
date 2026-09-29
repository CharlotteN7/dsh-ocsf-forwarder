/**
 * The four model-surface event types the `0.1.5` and `0.1.7` lines added, each
 * of which reached `mapGeneric` before it had a mapper — API Activity 6003 /
 * `99 Other` with no field of the payload read.
 *
 * Every assertion here is written against what the mapper produces *instead of*
 * that fallback, so a regression that deletes a `case` from the dispatcher
 * fails on the class, the activity, or a named attribute rather than passing
 * because a record was produced at all.
 */
import { describe, expect, it } from 'vitest'
import { SessionState } from '../../src/correlate.ts'
import { mapEvent } from '../../src/map/index.ts'
import { ACTIVITY, AI_ROLE, CLASS, SEVERITY, STATUS } from '../../src/ocsf/constants.ts'
import { digest } from '../../src/privacy.ts'
import { testConfig } from './support.ts'

const SESSION = 'session-1'
const config = testConfig()

function map(type: string, data: unknown, time = 1_000): ReturnType<typeof mapEvent> {
  return mapEvent(SESSION, { type, seq: 7, time, data }, new SessionState(), config)
}

/** The class and activity the generic fallback produces, which none of these may take. */
const FALLBACK = { classUid: CLASS.apiActivity, activityId: ACTIVITY.api.other }

describe('system/message', () => {
  const data = { turn: 2, step: 1, message: { id: 'sys-0', content: [{ type: 'text', text: 'obey the operator' }] } }

  it('records the rendered prompt as a capability change, not an API call', () => {
    const mapping = map('system/message', data)
    expect(mapping).not.toMatchObject(FALLBACK)
    expect(mapping?.classUid).toBe(CLASS.applicationLifecycle)
    expect(mapping?.activityId).toBe(ACTIVITY.applicationLifecycle.update)
    expect(mapping?.statusId).toBe(STATUS.success)
  })

  it('carries a keyed digest and a length, and never the prompt text', () => {
    const attributes = map('system/message', data)?.attributes
    expect(attributes?.['system_prompt_digest']).toBe(digest(config.hmacKey, 'obey the operator'))
    expect(attributes?.['system_prompt_length']).toBe('obey the operator'.length)
    expect(attributes?.['message_id']).toBe('sys-0')
    expect(attributes?.['turn']).toBe(2)
    expect(attributes?.['step']).toBe(1)
    expect(JSON.stringify(attributes)).not.toContain('obey the operator')
  })

  it('separates a cleared prompt from a changed one', () => {
    expect(map('system/message', { turn: 1, step: 0, message: { content: [] } })?.attributes?.['system_prompt_empty'])
      .toBe(true)
    expect(map('system/message', data)?.attributes?.['system_prompt_empty']).toBe(false)
  })
})

describe('developer/message', () => {
  const data = { turn: 3, step: 0, headerSeq: 41, message: { id: 'dev-0', content: [{ type: 'text', text: '+ write, - bash' }] } }

  it('grades a mid-session capability change above routine bookkeeping', () => {
    const mapping = map('developer/message', data)
    expect(mapping).not.toMatchObject(FALLBACK)
    expect(mapping?.classUid).toBe(CLASS.applicationLifecycle)
    expect(mapping?.activityId).toBe(ACTIVITY.applicationLifecycle.update)
    expect(mapping?.severityId).toBe(SEVERITY.low)
  })

  it('names the role OCSF has no member for through the enum sibling', () => {
    expect(map('developer/message', data)?.messageContext)
      .toEqual({ ai_role_id: AI_ROLE.other, ai_role: 'developer' })
  })

  it('points at the request header that defines the added tools, and digests the text', () => {
    const attributes = map('developer/message', data)?.attributes
    expect(attributes?.['header_seq']).toBe(41)
    expect(attributes?.['text_digest']).toBe(digest(config.hmacKey, '+ write, - bash'))
    expect(attributes?.['text_length']).toBe('+ write, - bash'.length)
    expect(JSON.stringify(attributes)).not.toContain('+ write, - bash')
  })

  it('omits the header seq when the change added no tool', () => {
    const mapping = map('developer/message', { turn: 1, step: 0, message: { content: [] } })
    expect(mapping).not.toMatchObject(FALLBACK)
    expect(mapping?.attributes?.['text_length']).toBe(0)
    expect(mapping?.attributes).not.toHaveProperty('header_seq')
    expect(mapping?.attributes).not.toHaveProperty('message_id')
  })
})

describe('assistant/attempt', () => {
  it('records an attempt that committed nothing as a failed model read', () => {
    const mapping = map('assistant/attempt', { turn: 1, step: 2, stream: [{ kind: 'a' }, { kind: 'b' }] })
    expect(mapping).not.toMatchObject(FALLBACK)
    expect(mapping?.classUid).toBe(CLASS.apiActivity)
    expect(mapping?.activityId).toBe(ACTIVITY.api.read)
    expect(mapping?.statusId).toBe(STATUS.failure)
    expect(mapping?.statusDetail).toBe('no-surface-message')
    expect(mapping?.correlationUid).toBe(`${SESSION}:1:2`)
  })

  it('counts the stream without reading it', () => {
    expect(map('assistant/attempt', { turn: 1, step: 2, stream: [{}, {}, {}] })?.attributes?.['stream_records']).toBe(3)
    expect(map('assistant/attempt', { turn: 1, step: 2 })?.attributes?.['stream_records']).toBe(0)
  })
})

describe('image/offload', () => {
  const data = { targets: [{ seq: 12, imageIndexes: [0, 2] }, { seq: 19, imageIndexes: [1] }] }

  it('records a permanent removal of model-visible content as a delete', () => {
    const mapping = map('image/offload', data)
    expect(mapping).not.toMatchObject(FALLBACK)
    expect(mapping?.classUid).toBe(CLASS.apiActivity)
    expect(mapping?.activityId).toBe(ACTIVITY.api.delete)
    expect(mapping?.severityId).toBe(SEVERITY.low)
  })

  it('names the surface nodes it edited and how many images went', () => {
    const attributes = map('image/offload', data)?.attributes
    expect(attributes?.['offload_seqs']).toEqual([12, 19])
    expect(attributes?.['offload_target_count']).toBe(2)
    expect(attributes?.['offload_image_count']).toBe(3)
  })

  it('reports an empty or unreadable target list as zero rather than guessing', () => {
    expect(map('image/offload', { targets: [] })?.attributes?.['offload_target_count']).toBe(0)
    expect(map('image/offload', {})?.attributes?.['offload_seqs']).toEqual([])
    expect(map('image/offload', { targets: [{ imageIndexes: [0] }] })?.attributes)
      .toMatchObject({ offload_seqs: [], offload_target_count: 1, offload_image_count: 1 })
    expect(map('image/offload', { targets: [{ seq: 4 }] })?.attributes)
      .toMatchObject({ offload_seqs: [4], offload_target_count: 1, offload_image_count: 0 })
  })
})

describe('subagent/catalog', () => {
  const data = { version: 1, childId: 'child-9', childCreatedAt: 1_700, mode: 'continuable', label: 'review the diff' }

  it('links the parent to the child it catalogued', () => {
    const mapping = map('subagent/catalog', data)
    expect(mapping).not.toMatchObject(FALLBACK)
    expect(mapping?.classUid).toBe(CLASS.applicationLifecycle)
    expect(mapping?.activityId).toBe(ACTIVITY.applicationLifecycle.start)
    expect(mapping?.delegation).toEqual({ uid: 'child-9', parent_uid: SESSION, created_time: 1_700 })
    expect(mapping?.correlationUid).toBe(`${SESSION}:subagent:child-9`)
  })

  it('digests the label, which is the delegating call’s own description', () => {
    const attributes = map('subagent/catalog', data)?.attributes
    expect(attributes?.['label_digest']).toBe(digest(config.hmacKey, 'review the diff'))
    expect(attributes?.['label_length']).toBe('review the diff'.length)
    expect(attributes?.['subagent_mode']).toBe('continuable')
    expect(attributes?.['catalog_version']).toBe(1)
    expect(JSON.stringify(attributes)).not.toContain('review the diff')
  })

  it('produces no record when the payload names no child', () => {
    expect(map('subagent/catalog', { version: 1, mode: 'one-shot' })).toBeUndefined()
  })

  it('omits the creation time and the label when the entry carries neither', () => {
    const attributes = map('subagent/catalog', { childId: 'child-9' })?.attributes
    expect(attributes).not.toHaveProperty('child_created_at')
    expect(attributes).not.toHaveProperty('label_digest')
    expect(map('subagent/catalog', { childId: 'child-9' })?.delegation)
      .toEqual({ uid: 'child-9', parent_uid: SESSION })
  })
})
