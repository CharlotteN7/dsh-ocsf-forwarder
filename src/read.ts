/**
 * Safe readers for session-event payloads whose types this build does not
 * import.
 *
 * `SessionEventMap` is merge-extensible: the types of events contributed by
 * harness packages we do not depend on are not in our type graph, and an
 * out-of-repo plugin can merge more at any time. Those payloads arrive from a
 * durable log, which is a validation boundary, so they are read defensively
 * instead of asserted.
 * @module read
 */

/**
 * Read a string field.
 * @param data - the event payload.
 * @param key - the field name.
 * @returns the value, or `undefined` when absent or not a string.
 */
export function readString(data: unknown, key: string): string | undefined {
  const value = readRecord(data)?.[key]
  return typeof value === 'string' ? value : undefined
}

/**
 * Read a finite number field.
 * @param data - the event payload.
 * @param key - the field name.
 * @returns the value, or `undefined` when absent or not a finite number.
 */
export function readNumber(data: unknown, key: string): number | undefined {
  const value = readRecord(data)?.[key]
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined
}

/**
 * Read a boolean field.
 * @param data - the event payload.
 * @param key - the field name.
 * @returns the value, or `undefined` when absent or not a boolean.
 */
export function readBoolean(data: unknown, key: string): boolean | undefined {
  const value = readRecord(data)?.[key]
  return typeof value === 'boolean' ? value : undefined
}

/**
 * Read an array field's length without reading its contents.
 * @param data - the event payload.
 * @param key - the field name.
 * @returns the length, or `undefined` when absent or not an array.
 */
export function readArrayLength(data: unknown, key: string): number | undefined {
  const value = readRecord(data)?.[key]
  return Array.isArray(value) ? value.length : undefined
}

/**
 * Read an array field's string members.
 * @param data - the event payload.
 * @param key - the field name.
 * @returns the members that are strings, or `undefined` when the field is
 *   absent or not an array. A member of any other type is left out rather than
 *   rendered, so the result never carries a value the log did not spell.
 */
export function readStringArray(data: unknown, key: string): readonly string[] | undefined {
  const value = readRecord(data)?.[key]
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : undefined
}

/**
 * Narrow a value to a plain record.
 * @param data - the candidate value.
 * @returns the record, or `undefined` for anything else (arrays included).
 */
export function readRecord(data: unknown): Readonly<Record<string, unknown>> | undefined {
  return data !== null && typeof data === 'object' && !Array.isArray(data)
    ? data as Record<string, unknown>
    : undefined
}

/**
 * Read a nested record field.
 * @param data - the event payload.
 * @param key - the field name.
 * @returns the nested record, or `undefined` when absent or not a record.
 */
export function readNested(data: unknown, key: string): Readonly<Record<string, unknown>> | undefined {
  return readRecord(readRecord(data)?.[key])
}
