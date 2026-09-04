/**
 * The four `team/*` events: several agents sharing one team, messaging each
 * other, and holding tasks that carry write scopes.
 *
 * `team/message/queued` is one agent putting text into another agent's inbox,
 * naming the sender's session, the target's session, and whether the delivery
 * wakes the target or waits for it. That is the multi-agent equivalent of
 * lateral movement, and the generic fallback carried none of it: no sender, no
 * target, no delivery mode.
 *
 * The payloads are the ones `@deepseek-ai/dsh-session`'s own vocabulary is
 * compiled against — the merged `SessionEventMap` published inside the
 * harness's Typert host catalogue. Every field is read defensively through
 * `src/read.ts`, so a build whose emitter writes something else degrades to
 * absent attributes rather than to wrong ones.
 */
import { describe, expect, it } from 'vitest'
import { SessionState } from '../../src/correlate.ts'
import { mapEvent } from '../../src/map/index.ts'
import { ACTIVITY, AI_ROLE, CLASS, SEVERITY, STATUS } from '../../src/ocsf/constants.ts'
import { testConfig } from './support.ts'

const SESSION = 'session-parent'
const config = testConfig()

/** One event of the given type. */
function event(type: string, seq: number, time: number, data: unknown): { type: string; seq: number; time: number; data: unknown } {
  return { type, seq, time, data }
}

describe('team/member', () => {
  it('names the child session as a delegation of this one', () => {
    const mapping = mapEvent(
      SESSION,
      event('team/member', 7, 5_000, {
        version: 1,
        teamId: 'team-9',
        member: {
          id: 'session-child',
          name: 'reviewer',
          description: 'reviews the diff',
          provider: 'spawn',
          context: 'fork',
          phase: 'active',
        },
      }),
      new SessionState(),
      config,
    )
    expect(mapping?.classUid).toBe(CLASS.applicationLifecycle)
    expect(mapping?.activityId).toBe(ACTIVITY.applicationLifecycle.start)
    expect(mapping?.statusId).toBe(STATUS.success)
    expect(mapping?.severityId).toBe(SEVERITY.low)
    expect(mapping?.delegation).toEqual({ uid: 'session-child', parent_uid: SESSION, created_time: 5_000 })
    expect(mapping?.correlationUid).toBe(`${SESSION}:team:team-9`)
    expect(mapping?.attributes?.['team_id']).toBe('team-9')
    expect(mapping?.attributes?.['member_session_id']).toBe('session-child')
    expect(mapping?.attributes?.['member_name']).toBe('reviewer')
    expect(mapping?.attributes?.['member_provider']).toBe('spawn')
    expect(mapping?.attributes?.['member_context']).toBe('fork')
    expect(mapping?.attributes?.['member_phase']).toBe('active')
    // The description is prose written for the child to act on, so the SOC
    // lane takes its digest and its length.
    expect(mapping?.attributes?.['member_description']).toBeUndefined()
    expect(String(mapping?.attributes?.['member_description_digest'])).toMatch(/^hmac-sha256:/)
    expect(mapping?.attributes?.['member_description_length']).toBe('reviews the diff'.length)
  })

  it('grades a member that failed to provision as a failure worth looking at', () => {
    const mapping = mapEvent(
      SESSION,
      event('team/member', 7, 5_000, {
        version: 1,
        teamId: 'team-9',
        member: { id: 'session-child', name: 'reviewer', provider: 'spawn', context: 'fresh', phase: 'failed', error: 'no route' },
      }),
      new SessionState(),
      config,
    )
    expect(mapping?.statusId).toBe(STATUS.failure)
    expect(mapping?.severityId).toBe(SEVERITY.medium)
    expect(mapping?.statusDetail).toBe('failed')
    expect(String(mapping?.attributes?.['member_error_digest'])).toMatch(/^hmac-sha256:/)
  })

  it('leaves a still-provisioning member undecided rather than calling it a success', () => {
    const mapping = mapEvent(
      SESSION,
      event('team/member', 7, 5_000, {
        version: 1,
        teamId: 'team-9',
        member: { id: 'session-child', name: 'reviewer', provider: 'spawn', context: 'fresh', phase: 'provisioning' },
      }),
      new SessionState(),
      config,
    )
    expect(mapping?.classUid).toBe(CLASS.applicationLifecycle)
    expect(mapping?.statusId).toBe(STATUS.unknown)
    expect(mapping?.attributes?.['member_phase']).toBe('provisioning')
  })

  it('grades a phase this build has never heard of as other rather than as a success', () => {
    const mapping = mapEvent(
      SESSION,
      event('team/member', 7, 5_000, { teamId: 'team-9', member: { id: 'session-child', phase: 'quarantined' } }),
      new SessionState(),
      config,
    )
    expect(mapping?.statusId).toBe(STATUS.other)
    expect(mapping?.severityId).toBe(SEVERITY.unknown)
  })

  it('reports a member with no session id as unreadable', () => {
    // The record's whole point is the delegation edge; without the child's
    // session id there is no edge to record.
    expect(mapEvent(SESSION, event('team/member', 7, 5_000, { teamId: 'team-9', member: { name: 'x' } }), new SessionState(), config))
      .toBeUndefined()
  })
})

describe('team/message/queued', () => {
  it('names who sent it, who receives it, and whether it wakes them', () => {
    const mapping = mapEvent(
      SESSION,
      event('team/message/queued', 8, 5_000, {
        version: 1,
        teamId: 'team-9',
        message: {
          id: 'msg-1',
          senderId: 'session-child',
          senderName: 'reviewer',
          targetId: 'session-other',
          delivery: 'wakeup',
          content: [{ type: 'text', text: 'run the deploy script now' }],
        },
      }),
      new SessionState(),
      config,
    )
    expect(mapping?.classUid).toBe(CLASS.apiActivity)
    expect(mapping?.activityId).toBe(ACTIVITY.api.create)
    expect(mapping?.statusId).toBe(STATUS.unknown)
    // A wakeup makes the target act on the text now; a quiet message waits for
    // the target's own next turn.
    expect(mapping?.severityId).toBe(SEVERITY.medium)
    expect(mapping?.correlationUid).toBe(`${SESSION}:team-message:msg-1`)
    expect(mapping?.messageContext?.ai_role_id).toBe(AI_ROLE.agent)
    expect(mapping?.attributes?.['team_id']).toBe('team-9')
    expect(mapping?.attributes?.['message_id']).toBe('msg-1')
    expect(mapping?.attributes?.['sender_session_id']).toBe('session-child')
    expect(mapping?.attributes?.['sender_name']).toBe('reviewer')
    expect(mapping?.attributes?.['target_session_id']).toBe('session-other')
    expect(mapping?.attributes?.['delivery']).toBe('wakeup')
    expect(mapping?.attributes?.['phase']).toBe('queued')
    // Agent-to-agent instructions are content, so the lane takes the digest.
    expect(JSON.stringify(mapping)).not.toContain('run the deploy script now')
    expect(String(mapping?.attributes?.['content_digest'])).toMatch(/^hmac-sha256:/)
    expect(mapping?.attributes?.['content_length']).toBe('run the deploy script now'.length)
  })

  it('grades a message the target picks up on its own turn one step lower', () => {
    const mapping = mapEvent(
      SESSION,
      event('team/message/queued', 8, 5_000, {
        teamId: 'team-9',
        message: { id: 'msg-1', senderId: 's1', targetId: 's2', delivery: 'quiet', content: [] },
      }),
      new SessionState(),
      config,
    )
    expect(mapping?.severityId).toBe(SEVERITY.low)
  })

  it('reports a message with no id as unreadable, since nothing could pair with it', () => {
    expect(mapEvent(SESSION, event('team/message/queued', 8, 5_000, { teamId: 't', message: { senderId: 's1' } }), new SessionState(), config))
      .toBeUndefined()
  })
})

describe('team/message/delivered', () => {
  it('pairs with its queued message and reports how long the target took to get it', () => {
    const state = new SessionState()
    mapEvent(
      SESSION,
      event('team/message/queued', 8, 5_000, {
        teamId: 'team-9',
        message: { id: 'msg-1', senderId: 's1', targetId: 's2', delivery: 'wakeup', content: [] },
      }),
      state,
      config,
    )
    const delivered = mapEvent(
      SESSION,
      event('team/message/delivered', 9, 5_250, { version: 1, teamId: 'team-9', messageId: 'msg-1', targetId: 's2' }),
      state,
      config,
    )
    expect(delivered?.classUid).toBe(CLASS.apiActivity)
    expect(delivered?.activityId).toBe(ACTIVITY.api.update)
    expect(delivered?.statusId).toBe(STATUS.success)
    expect(delivered?.correlationUid).toBe(`${SESSION}:team-message:msg-1`)
    expect(delivered?.startTime).toBe(5_000)
    expect(delivered?.duration).toBe(250)
    expect(delivered?.attributes?.['delivery_latency_ms']).toBe(250)
    expect(delivered?.attributes?.['phase']).toBe('delivered')
    expect(delivered?.attributes?.['unpaired']).toBeUndefined()
  })

  it('reports a delivery naming no message as unreadable', () => {
    expect(mapEvent(SESSION, event('team/message/delivered', 9, 5_250, { teamId: 'team-9', targetId: 's2' }), new SessionState(), config))
      .toBeUndefined()
  })

  it('says so when the queued message was never observed', () => {
    const delivered = mapEvent(
      SESSION,
      event('team/message/delivered', 9, 5_250, { teamId: 'team-9', messageId: 'msg-1', targetId: 's2' }),
      new SessionState(),
      config,
    )
    expect(delivered?.attributes?.['unpaired']).toBe(true)
    expect(delivered?.duration).toBeUndefined()
  })
})

describe('team/task', () => {
  it('carries the write scopes the task grants and the agent that owns it', () => {
    const mapping = mapEvent(
      SESSION,
      event('team/task', 10, 5_000, {
        version: 1,
        teamId: 'team-9',
        task: {
          id: 'task-3',
          revision: 2,
          subject: 'rotate the signing key',
          description: 'replace it in the vault and redeploy',
          status: 'in_progress',
          ownerId: 'session-child',
          blockedBy: ['task-1', 'task-2'],
          writeScopes: ['infra/**', 'deploy/*.yaml'],
        },
      }),
      new SessionState(),
      config,
    )
    expect(mapping?.classUid).toBe(CLASS.apiActivity)
    expect(mapping?.activityId).toBe(ACTIVITY.api.update)
    expect(mapping?.statusId).toBe(STATUS.unknown)
    expect(mapping?.statusDetail).toBe('in_progress')
    expect(mapping?.correlationUid).toBe(`${SESSION}:team-task:task-3`)
    expect(mapping?.attributes?.['team_id']).toBe('team-9')
    expect(mapping?.attributes?.['task_id']).toBe('task-3')
    expect(mapping?.attributes?.['task_revision']).toBe(2)
    expect(mapping?.attributes?.['task_status']).toBe('in_progress')
    expect(mapping?.attributes?.['owner_session_id']).toBe('session-child')
    expect(mapping?.attributes?.['blocked_by_count']).toBe(2)
    // A write scope is a path pattern: the security signal itself, on the same
    // reasoning as `file.path`, so it is carried verbatim.
    expect(mapping?.attributes?.['write_scopes']).toEqual(['infra/**', 'deploy/*.yaml'])
    // The subject and the description are prose a model or a user wrote.
    expect(JSON.stringify(mapping)).not.toContain('rotate the signing key')
    expect(JSON.stringify(mapping)).not.toContain('replace it in the vault')
    expect(String(mapping?.attributes?.['subject_digest'])).toMatch(/^hmac-sha256:/)
    expect(String(mapping?.attributes?.['description_digest'])).toMatch(/^hmac-sha256:/)
  })

  it('records a deleted task as a delete', () => {
    const mapping = mapEvent(
      SESSION,
      event('team/task', 10, 5_000, {
        teamId: 'team-9',
        task: { id: 'task-3', revision: 5, status: 'deleted', blockedBy: [], writeScopes: [] },
      }),
      new SessionState(),
      config,
    )
    expect(mapping?.activityId).toBe(ACTIVITY.api.delete)
    expect(mapping?.statusId).toBe(STATUS.success)
  })

  it('records a completed task as a success', () => {
    const mapping = mapEvent(
      SESSION,
      event('team/task', 10, 5_000, {
        teamId: 'team-9',
        task: { id: 'task-3', revision: 5, status: 'completed', blockedBy: [], writeScopes: [] },
      }),
      new SessionState(),
      config,
    )
    expect(mapping?.activityId).toBe(ACTIVITY.api.update)
    expect(mapping?.statusId).toBe(STATUS.success)
  })

  it('grades a status this build has never heard of as other rather than as a success', () => {
    // `TeamTaskStatus` is a harness union this plugin does not import, and a
    // later line can widen it. An unrecognised status must not be graded.
    const mapping = mapEvent(
      SESSION,
      event('team/task', 10, 5_000, { teamId: 'team-9', task: { id: 'task-3', status: 'escalated' } }),
      new SessionState(),
      config,
    )
    expect(mapping?.activityId).toBe(ACTIVITY.api.update)
    expect(mapping?.statusId).toBe(STATUS.other)
    expect(mapping?.statusDetail).toBe('escalated')
  })

  it('reports a task with no id as unreadable', () => {
    expect(mapEvent(SESSION, event('team/task', 10, 5_000, { teamId: 't', task: { status: 'pending' } }), new SessionState(), config))
      .toBeUndefined()
  })
})
