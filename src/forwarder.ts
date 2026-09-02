/**
 * The read path: session adoption, seed replay, per-event mapping, and the
 * unresolved-pair flush.
 *
 * One mechanism covers three problems at once. Every observation catches the
 * spool up from a per-session cursor to the observed event's `seq` by walking
 * the session's whole log, which handles the constructor seed (never
 * published), the `session/end-seed` marker (appended before the store
 * attaches, so also never published), and any event appended while this plugin
 * was not yet mounted.
 * @module forwarder
 */

import type { ResolvedConfig } from './config.ts'
import { SessionState } from './correlate.ts'
import { mapHeartbeat, type HeartbeatState } from './map/heartbeat.ts'
import { mapEvent, type MappableEvent } from './map/index.ts'
import { mapSeedBoundary } from './map/lifecycle.ts'
import { mapUnresolvedApproval } from './map/authorization.ts'
import { mapUnresolvedCall } from './map/tool-events.ts'
import { buildRecord, type EventMapping, type RecordEnvironment, type RecordSubject } from './ocsf/record.ts'
import type { Sink } from './sink/spool.ts'

/**
 * The parts of a harness `Session` this forwarder reads.
 *
 * Two of them are spelled differently on either side of
 * `@deepseek-ai/dsh-session@0.1.2-alpha.4`, and the peer range admits versions
 * from both sides, so both spellings are declared and
 * {@link logOf} / {@link seedLengthOf} pick the one the resolved version has.
 */
export interface ForwardableSession {
  readonly id: string
  readonly firstLiveSeq: number
  readonly seq: number
  /** The whole log, up to `0.1.1`. Replaced by {@link ForwardableSession.snapshotEvents}. */
  readonly events?: readonly MappableEvent[]
  /**
   * The whole log, from `0.1.2-alpha.4`. Called with no arguments it defaults
   * to the log's first entry through its current end, which is what the
   * accessor it replaced returned.
   */
  readonly snapshotEvents?: () => readonly MappableEvent[]
  /** The fork-inherited prefix length, from `0.1.2-alpha.4`. */
  readonly inheritedEventCount?: number
  readonly header: {
    readonly parentSession?: string
    /** The fork-inherited prefix length, up to `0.1.1`. */
    readonly seedLength?: number
    readonly agentPreset?: string
    readonly cwd?: string
  }
}

/**
 * One session's whole event log.
 *
 * `Session.events` became `Session.snapshotEvents()` in
 * `@deepseek-ai/dsh-session@0.1.2-alpha.4`. Called with no arguments the method
 * returns the same cached frozen array of the log from index zero that the
 * accessor did, so this is a choice between two published spellings of one
 * capability rather than a reconstruction of a capability that went away.
 * @param session - the session whose log is being read.
 * @returns every event the session holds, in log order.
 */
function logOf(session: ForwardableSession): readonly MappableEvent[] {
  if (session.snapshotEvents !== undefined) return session.snapshotEvents()
  if (session.events !== undefined) return session.events
  throw new Error(
    'session exposes neither events nor snapshotEvents(); the resolved '
    + '@deepseek-ai/dsh-session is outside the range this plugin declares',
  )
}

/**
 * The fork-inherited prefix length a record reports as `seed_length`.
 *
 * `header.seedLength` moved to `Session.inheritedEventCount` in
 * `@deepseek-ai/dsh-session@0.1.2-alpha.4`, where the header field is not
 * merely absent but rejected on write.
 * @param session - the session being described.
 * @returns the prefix length, or `undefined` when the session inherited none.
 */
function seedLengthOf(session: ForwardableSession): number | undefined {
  return session.header.seedLength ?? session.inheritedEventCount
}

/** Counters an operator can read to tell a quiet forwarder from a broken one. */
export interface ForwarderStats {
  /** Records handed to the sink. */
  readonly forwarded: number
  /** Events deliberately not forwarded, by drop policy. */
  readonly dropped: number
  /** Events whose payload lacked the identity a record needs. */
  readonly unreadable: number
  /** Failures contained inside the listener. */
  readonly failed: number
}

/** Normalises session events into OCSF records and hands them to a sink. */
export class Forwarder {
  private readonly states = new WeakMap<object, SessionState>()
  private forwarded = 0
  private dropped = 0
  private unreadable = 0
  private failed = 0
  /** Heartbeats emitted by this process; the sequence a consumer detects gaps in. */
  private heartbeats = 0

  /**
   * @param env - the per-process record identity.
   * @param config - the resolved configuration.
   * @param sink - the SOC-lane destination.
   * @param restricted - the restricted-lane destination, when that lane is open.
   * @param onError - reports a contained failure; must not throw.
   */
  constructor(
    private readonly env: RecordEnvironment,
    private readonly config: ResolvedConfig,
    private readonly sink: Sink,
    private readonly restricted: Sink | undefined,
    private readonly onError: (error: unknown) => void,
  ) {}

  /** Current counters. */
  stats(): ForwarderStats {
    return { forwarded: this.forwarded, dropped: this.dropped, unreadable: this.unreadable, failed: this.failed }
  }

  /**
   * Write one heartbeat, so a host that goes quiet is distinguishable from one
   * that is idle.
   *
   * It belongs to no session: `metadata.uid` is keyed on the install uid and a
   * per-process counter, and no `ai_agent.instance_uid` is set. It is
   * deliberately absent from the counters it reports — a self-report that
   * counted itself would make two consecutive heartbeats differ by one with no
   * session activity behind the difference.
   * @param state - what this heartbeat reports.
   */
  heartbeat(state: HeartbeatState): void {
    this.contain(() => {
      const sequence = this.heartbeats
      this.heartbeats += 1
      const time = Date.now()
      const subject: RecordSubject = {
        seq: sequence,
        time,
        eventType: 'forwarder/heartbeat',
        replayed: false,
        uid: `${this.env.config.fleet.installUid}:heartbeat:${String(sequence)}`,
      }
      const record = buildRecord(this.env, subject, mapHeartbeat(state))
      this.sink.write(record)
      this.restricted?.write(record)
    })
  }

  /**
   * Adopt a session, applying the configured treatment of its constructor
   * seed. Adopting twice is a no-op, so the mount-time sweep and the
   * `session/created` listener can both call it.
   * @param session - the session to adopt.
   */
  adopt(session: ForwardableSession): void {
    this.contain(() => {
      if (this.states.has(session)) return
      const state = new SessionState()
      this.states.set(session, state)
      const seedLength = session.firstLiveSeq
      if (seedLength === 0 || this.config.seedReplay === 'full') return
      // The seed is not replayed: skip past it so the live path starts at the
      // first event this process actually produced.
      state.cursor = seedLength
      if (this.config.seedReplay === 'boundary') {
        this.deliver(session, state, {
          seq: seedLength,
          time: Date.now(),
          eventType: 'session/adopted',
          uid: `${session.id}:adopted:${seedLength}`,
          replayed: false,
        }, mapSeedBoundary(session.id, seedLength, session.header.parentSession), undefined)
      }
    })
  }

  /**
   * Forward everything up to and including one observed event.
   * @param session - the session whose log grew.
   * @param event - the appended event, exactly as recorded.
   */
  observe(session: ForwardableSession, event: MappableEvent): void {
    this.contain(() => {
      this.catchUp(session, this.stateOf(session), event.seq)
    })
  }

  /**
   * Close a session: forward anything still uncaught, then emit one record per
   * tool call or approval that never settled, so an abandoned action is
   * visible rather than absent.
   * @param session - the session leaving the store.
   */
  dispose(session: ForwardableSession): void {
    this.contain(() => {
      const state = this.stateOf(session)
      this.catchUp(session, state, Number.POSITIVE_INFINITY)
      // Log time, not wall time: a resumed session's events carry the times
      // they were originally appended.
      const time = state.lastEventTime ?? Date.now()
      const { calls, approvals } = state.drain()
      for (const call of calls) {
        this.deliver(session, state, {
          seq: session.seq,
          time,
          eventType: 'tool/call',
          uid: `${session.id}:unresolved:${call.callId}`,
          replayed: false,
        }, mapUnresolvedCall(session.id, call, time), undefined)
      }
      for (const approval of approvals) {
        this.deliver(session, state, {
          seq: session.seq,
          time,
          eventType: 'approval/asked',
          uid: `${session.id}:unresolved:approval:${approval.id}`,
          replayed: false,
        }, mapUnresolvedApproval(session.id, approval, time), undefined)
      }
    })
  }

  /**
   * Forward every event from the session cursor up to `throughSeq`.
   *
   * The cursor advances only after an event's record reaches the sink, so a
   * sink that throws — a full disk, a revoked permission — leaves the event
   * pending instead of consuming it. The walk stops at the first failure and
   * the next observation retries from exactly there, which keeps the spool in
   * log order and turns an outage into a delay rather than a hole.
   * @param session - the session whose log is being drained.
   * @param state - that session's forwarding state.
   * @param throughSeq - the last `seq` to forward in this pass.
   */
  private catchUp(session: ForwardableSession, state: SessionState, throughSeq: number): void {
    // Read once: materialising the log is a frozen copy of the whole of it.
    const events = logOf(session)
    while (state.index < events.length) {
      const pending = events[state.index]
      if (pending === undefined || pending.seq > throughSeq) return
      if (pending.seq < state.cursor) {
        state.index += 1
        continue
      }
      try {
        this.forward(session, state, pending)
      } catch (error: unknown) {
        this.failed += 1
        this.onError(error)
        return
      }
      state.cursor = pending.seq + 1
      state.lastEventTime = pending.time
      state.index += 1
    }
  }

  /** Map and deliver one event, honouring the drop policy. */
  private forward(session: ForwardableSession, state: SessionState, event: MappableEvent): void {
    if (!this.config.forwarded(event.type)) {
      this.dropped += 1
      return
    }
    const mapping = mapEvent(session.id, event, state, this.config)
    if (mapping === undefined) {
      this.unreadable += 1
      return
    }
    this.deliver(session, state, {
      seq: event.seq,
      time: event.time,
      eventType: event.type,
      replayed: event.seq < session.firstLiveSeq,
      // The session log's native rendering of the append time, passed through
      // rather than reformatted; the normalised value is `time`.
      originalTime: String(event.time),
    }, mapping, event.data)
  }

  /** Build the SOC record, and the restricted record when that lane is open. */
  private deliver(
    session: ForwardableSession,
    state: SessionState,
    subject: Pick<RecordSubject, 'seq' | 'time' | 'eventType' | 'replayed' | 'originalTime' | 'uid'>,
    mapping: EventMapping,
    payload: unknown,
  ): void {
    const seedLength = seedLengthOf(session)
    const base: RecordSubject = {
      sessionId: session.id,
      ...subject,
      ...session.header.parentSession === undefined ? {} : { parentSessionId: session.header.parentSession },
      ...seedLength === undefined ? {} : { seedLength },
      ...session.header.agentPreset === undefined ? {} : { agentPreset: session.header.agentPreset },
      ...session.header.cwd === undefined ? {} : { cwd: session.header.cwd },
      ...state.aiModel === undefined ? {} : { aiModel: state.aiModel },
    }
    this.sink.write(buildRecord(this.env, base, mapping))
    this.forwarded += 1
    if (this.restricted === undefined) return
    // The restricted lane is the same record plus the verbatim payload, so a
    // reader joins the two lanes on `metadata.uid`.
    this.restricted.write(buildRecord(this.env, {
      ...base,
      ...payload === undefined ? {} : { rawData: JSON.stringify(payload) },
    }, mapping))
  }

  /** The session's state, created on demand for a session never adopted. */
  private stateOf(session: ForwardableSession): SessionState {
    const existing = this.states.get(session)
    if (existing !== undefined) return existing
    const state = new SessionState()
    this.states.set(session, state)
    return state
  }

  /**
   * Run one unit of work with total containment: the `session/event` listener
   * is fire-and-forget, so a throw here would be silent record loss rather
   * than a visible failure.
   */
  private contain(work: () => void): void {
    try {
      work()
    } catch (error: unknown) {
      this.failed += 1
      this.onError(error)
    }
  }
}
