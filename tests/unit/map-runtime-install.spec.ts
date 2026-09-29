/**
 * `load_workspace_dependencies`, the tool that copies Desktop's bundled
 * Python/Node/pnpm payload onto the host.
 *
 * The tool declares `parameters: {}` and appends no session event of its own,
 * so classified as an ordinary API read its two records said nothing about the
 * interpreter that landed on the machine. Every assertion below is on a field
 * the API classification could not produce, and the last one pins that the
 * install report comes from the result rather than being assumed.
 */
import { describe, expect, it } from 'vitest'
import { SessionState, type PendingCall } from '../../src/correlate.ts'
import { mapEvent, type MappableEvent } from '../../src/map/index.ts'
import { mapUnresolvedCall } from '../../src/map/tool-events.ts'
import { ACTIVITY, CLASS, OBSERVABLE, STATUS } from '../../src/ocsf/constants.ts'
import { testConfig } from './support.ts'

const SESSION = 'session-1'
const config = testConfig()
const ROOT = '/home/a/.dsh/dsh-runtimes/dsh-primary-runtime'

const REPORT = {
  python: `${ROOT}/dependencies/python/bin/python3`,
  node: `${ROOT}/dependencies/node/bin/node`,
  pnpm: `${ROOT}/dependencies/pnpm/bin/pnpm.mjs`,
  pythonPackages: `${ROOT}/dependencies/python/lib/python3.13/site-packages`,
  nodePackages: `${ROOT}/dependencies/node/node_modules`,
  pythonDistributions: { numpy: '2.1.3', pandas: '2.2.3', Pillow: '11.0.0' },
}

/** The call and the result of one install, mapped through one correlation state. */
function install(resultContent: unknown): {
  call: ReturnType<typeof mapEvent>
  result: ReturnType<typeof mapEvent>
} {
  const state = new SessionState()
  const callEvent: MappableEvent = {
    type: 'tool/call',
    seq: 1,
    time: 1_000,
    data: { turn: 1, step: 0, callId: 'c1', name: 'load_workspace_dependencies', arguments: '{}' },
  }
  const resultEvent: MappableEvent = {
    type: 'tool/result',
    seq: 2,
    time: 4_000,
    data: { message: { source: { callId: 'c1' }, content: resultContent } },
  }
  return {
    call: mapEvent(SESSION, callEvent, state, config),
    result: mapEvent(SESSION, resultEvent, state, config),
  }
}

const jsonBlock = [{ type: 'text', text: JSON.stringify(REPORT) }]

describe('a runtime install', () => {
  it('is an application install, not an API read', () => {
    const { call, result } = install(jsonBlock)
    for (const mapping of [call, result]) {
      expect(mapping?.classUid).toBe(CLASS.applicationLifecycle)
      expect(mapping?.activityId).toBe(ACTIVITY.applicationLifecycle.install)
    }
    expect(call?.attributes?.['tool_class']).toBe('runtime-install')
    expect(result?.statusId).toBe(STATUS.success)
  })

  it('names the installed runtime as the application, on both records', () => {
    const { call, result } = install(jsonBlock)
    expect(call?.application).toEqual({ name: 'dsh-primary-runtime' })
    expect(result?.application).toEqual({ name: 'dsh-primary-runtime' })
  })

  it('carries no api object, because Application Lifecycle does not define one', () => {
    const { call, result } = install(jsonBlock)
    expect(call?.api).toBeUndefined()
    expect(result?.api).toBeUndefined()
  })

  it('reads the interpreter and library paths out of the result', () => {
    expect(install(jsonBlock).result?.attributes).toMatchObject({
      runtime_python_path: REPORT.python,
      runtime_node_path: REPORT.node,
      runtime_pnpm_path: REPORT.pnpm,
      runtime_python_packages_path: REPORT.pythonPackages,
      runtime_node_packages_path: REPORT.nodePackages,
    })
  })

  it('carries the bundled distribution inventory and its count', () => {
    const attributes = install(jsonBlock).result?.attributes
    expect(attributes?.['runtime_python_distributions'])
      .toEqual({ numpy: '2.1.3', pandas: '2.2.3', Pillow: '11.0.0' })
    expect(attributes?.['runtime_python_distribution_count']).toBe(3)
  })

  it('gives every installed executable its own file.path observable', () => {
    expect(install(jsonBlock).result?.observables).toEqual([
      { name: 'file.path', type_id: OBSERVABLE.filePath, value: REPORT.python },
      { name: 'file.path', type_id: OBSERVABLE.filePath, value: REPORT.node },
      { name: 'file.path', type_id: OBSERVABLE.filePath, value: REPORT.pnpm },
    ])
  })

  it('reports only what the payload actually shipped', () => {
    const minimal = [{ type: 'text', text: JSON.stringify({ python: REPORT.python, pythonPackages: REPORT.pythonPackages }) }]
    const attributes = install(minimal).result?.attributes
    expect(attributes).not.toHaveProperty('runtime_node_path')
    expect(attributes).not.toHaveProperty('runtime_pnpm_path')
    expect(attributes).not.toHaveProperty('runtime_node_packages_path')
    expect(attributes).not.toHaveProperty('runtime_python_distributions')
    expect(install(minimal).result?.observables).toHaveLength(1)
  })

  it('drops a distribution whose version is not a string rather than rendering it', () => {
    const odd = [{ type: 'text', text: JSON.stringify({ python: REPORT.python, pythonDistributions: { numpy: '2.1.3', broken: 7 } }) }]
    expect(install(odd).result?.attributes?.['runtime_python_distributions']).toEqual({ numpy: '2.1.3' })
    expect(install(odd).result?.attributes?.['runtime_python_distribution_count']).toBe(1)
  })

  it('reads nothing from a failed call, whose result text is a diagnostic', () => {
    const failed = install(
      [{ type: 'text', text: `refusing: ${ROOT} is busy`, isError: true }],
    )
    expect(failed.result?.statusId).toBe(STATUS.failure)
    expect(failed.result?.application).toEqual({ name: 'dsh-primary-runtime' })
    expect(failed.result?.attributes).not.toHaveProperty('runtime_python_path')
    expect(failed.result?.observables).toEqual([])
  })

  it('reads nothing when the result is not the declared JSON report, and still names the install', () => {
    for (const content of [[{ type: 'text', text: 'not json' }], [{ type: 'text', text: '["a"]' }], [{ type: 'image' }], 'nope']) {
      const result = install(content).result
      expect(result?.classUid).toBe(CLASS.applicationLifecycle)
      expect(result?.application).toEqual({ name: 'dsh-primary-runtime' })
      expect(result?.attributes).not.toHaveProperty('runtime_python_path')
      expect(result?.attributes).not.toHaveProperty('runtime_python_distributions')
    }
  })

  it('is still an install when the model dispatched it from inside run_code', () => {
    const state = new SessionState()
    const start = mapEvent(SESSION, {
      type: 'tool/ptc-dispatch-start',
      seq: 3,
      time: 1_000,
      data: { rootCallId: 'r', parentCallId: 'r', subCallId: 'r:ptc:1', name: 'load_workspace_dependencies', arguments: {} },
    }, state, config)
    expect(start?.classUid).toBe(CLASS.applicationLifecycle)
    expect(start?.activityId).toBe(ACTIVITY.applicationLifecycle.install)
    expect(start?.application).toEqual({ name: 'dsh-primary-runtime' })

    const settle = mapEvent(SESSION, {
      type: 'tool/ptc-dispatch',
      seq: 4,
      time: 1_500,
      data: { subCallId: 'r:ptc:1', name: 'load_workspace_dependencies', isError: false, content: [{ type: 'text', text: JSON.stringify({ python: REPORT.python }) }] },
    }, state, config)
    expect(settle?.attributes?.['runtime_python_path']).toBeUndefined()
    expect(settle?.application).toEqual({ name: 'dsh-primary-runtime' })
  })

  it('keeps the application on a call the session never saw settle', () => {
    const state = new SessionState()
    mapEvent(
      SESSION,
      { type: 'tool/call', seq: 1, time: 1_000, data: { turn: 1, step: 0, callId: 'c1', name: 'load_workspace_dependencies', arguments: '{}' } },
      state,
      config,
    )
    const [pending] = state.drain().calls
    expect(pending).toBeDefined()
    const flushed = mapUnresolvedCall(SESSION, pending as PendingCall, 9_000)
    expect(flushed.classUid).toBe(CLASS.applicationLifecycle)
    expect(flushed.application).toEqual({ name: 'dsh-primary-runtime' })
  })
})
