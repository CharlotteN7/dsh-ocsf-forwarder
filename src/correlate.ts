/**
 * Per-session pairing state: tool call ↔ tool result, approval ask ↔ decision,
 * and the open turn/step brackets that give a record its duration.
 *
 * The `SessionEvent` envelope carries no session id, turn, step, or call id, so
 * every pairing key comes from the payload and the state is keyed by the
 * `Session` object the listener was handed.
 * @module correlate
 */

import type { OcsfAiModel, OcsfFile, OcsfHttpRequest, OcsfProcess } from './ocsf/types.ts'
import type { ToolClass } from './map/tools.ts'

/**
 * One tool call awaiting its result.
 *
 * The class-specific object built from the call's arguments is kept here
 * because the result event has none: OCSF requires `process` on every Process
 * Activity record and `file` on every File System Activity record, including
 * the one that reports the call settling.
 */
export interface PendingCall {
  readonly callId: string
  readonly name: string
  readonly toolClass: ToolClass
  readonly time: number
  readonly seq: number
  readonly turn: number
  readonly step: number
  readonly process?: OcsfProcess
  readonly file?: OcsfFile
  readonly httpRequest?: OcsfHttpRequest
  /**
   * The harness a `delegation-external` call hands the task to. Kept on the
   * call because the flush that reports an abandoned delegation runs without
   * the configuration that named the provider.
   */
  readonly delegationProvider?: string
}

/** One approval question awaiting its decision. */
export interface PendingApproval {
  readonly id: string
  readonly toolName: string
  readonly callId?: string
  readonly time: number
  readonly seq: number
}

/**
 * Everything the forwarder remembers about one live session. Held in a
 * `WeakMap` keyed by the `Session` object, so a disposed session's state is
 * collectable even if disposal is never observed.
 */
export class SessionState {
  /** Next log seq this forwarder has not yet emitted. */
  cursor = 0
  /**
   * Position in `session.events` the catch-up walk resumes from. Scanning the
   * log from index 0 on every append is quadratic in the session's length, and
   * that walk runs synchronously on the agent-loop hot path.
   */
  index = 0
  /**
   * Append time of the last event forwarded for this session, used instead of
   * the wall clock when an unresolved pair is flushed: a resumed session
   * replays log times from hours ago, and `Date.now()` against them reports
   * durations in days.
   */
  lastEventTime: number | undefined
  /** The session's current model route, folded from `request/context`. */
  aiModel: OcsfAiModel | undefined
  /** Set once the session's seed has been handled. */
  adopted = false

  private readonly calls = new Map<string, PendingCall>()
  private readonly approvals = new Map<string, PendingApproval>()
  private readonly turns = new Map<number, number>()
  private readonly steps = new Map<string, number>()

  /**
   * Record one tool call so its result can be paired.
   * @param call - the call's identity and start time.
   */
  openCall(call: PendingCall): void {
    this.calls.set(call.callId, call)
  }

  /**
   * Take the call one result closes.
   * @param callId - the result's call id.
   * @returns the pending call, or `undefined` when the call was never seen.
   */
  closeCall(callId: string): PendingCall | undefined {
    const call = this.calls.get(callId)
    this.calls.delete(callId)
    return call
  }

  /**
   * Record one approval question so its decision can be paired.
   * @param approval - the question's identity and ask time.
   */
  openApproval(approval: PendingApproval): void {
    this.approvals.set(approval.id, approval)
  }

  /**
   * Take the question one decision closes.
   * @param id - the decision's approval-request id.
   * @returns the pending question, or `undefined` when the ask was never seen.
   */
  closeApproval(id: string): PendingApproval | undefined {
    const approval = this.approvals.get(id)
    this.approvals.delete(id)
    return approval
  }

  /**
   * Open a turn bracket.
   * @param turn - the turn number.
   * @param time - the `turn/start` append time.
   */
  openTurn(turn: number, time: number): void {
    this.turns.set(turn, time)
  }

  /**
   * Close a turn bracket.
   * @param turn - the turn number.
   * @returns the turn's start time, or `undefined` when the start was not seen.
   */
  closeTurn(turn: number): number | undefined {
    const time = this.turns.get(turn)
    this.turns.delete(turn)
    return time
  }

  /**
   * Open a step bracket.
   * @param turn - the enclosing turn.
   * @param step - the step number.
   * @param time - the `step/start` append time.
   */
  openStep(turn: number, step: number, time: number): void {
    this.steps.set(`${turn}:${step}`, time)
  }

  /**
   * Close a step bracket.
   * @param turn - the enclosing turn.
   * @param step - the step number.
   * @returns the step's start time, or `undefined` when the start was not seen.
   */
  closeStep(turn: number, step: number): number | undefined {
    const key = `${turn}:${step}`
    const time = this.steps.get(key)
    this.steps.delete(key)
    return time
  }

  /**
   * Everything still open, for the unresolved flush at session disposal.
   * @returns the pending calls and approvals, and clears them.
   */
  drain(): { calls: readonly PendingCall[]; approvals: readonly PendingApproval[] } {
    const calls = [...this.calls.values()]
    const approvals = [...this.approvals.values()]
    this.calls.clear()
    this.approvals.clear()
    return { calls, approvals }
  }
}
