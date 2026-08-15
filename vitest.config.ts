/**
 * Unit tests: no subprocess, no network beyond a loopback collector, no
 * harness checkout required.
 *
 * The thresholds sit at the level the suite actually reaches, so a regression
 * fails the gate. The residual gap is almost entirely the absent half of
 * `field === undefined ? {} : { field }` spreads in the mappers — the optional
 * OCSF attributes — plus the two `apply()` lines that only run when a sink
 * reports a failure through `ctx.logger`.
 */
import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['tests/unit/**/*.spec.ts'],
    coverage: {
      include: ['src/**/*.ts'],
      thresholds: { lines: 99, functions: 97, branches: 79, statements: 97 },
    },
  },
})
