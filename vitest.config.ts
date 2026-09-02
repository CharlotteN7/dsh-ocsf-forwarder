/**
 * Unit tests: no subprocess, no network beyond a loopback collector, no
 * harness checkout required.
 *
 * The gate is **per file**. An aggregate threshold is met by whichever files
 * are easy to cover: `src/map/lifecycle.ts` sat at 75.93% branch behind a
 * passing 88% aggregate, and `src/sink/spool.ts` at 90.9% while holding a
 * defect that silently killed the audit sink for the life of the process.
 *
 * Every file is therefore pinned at the level it actually reaches. Vitest
 * applies the top-level numbers to every file *in addition to* any glob entry,
 * so the top level is the floor a file added without its own entry must clear,
 * and the entries below ratchet each existing file above it. Raising one means
 * writing the test; the entry is what records that the test exists.
 *
 * Sixteen of the twenty-four source files are at 100 on all four metrics. The
 * eight that are not are held exactly where they are rather than exempted, and
 * no `v8 ignore` is used anywhere: the residual gap is the absent half of a few
 * `field === undefined ? {} : { field }` spreads and of two `error instanceof
 * Error` renderings, reachable only from inputs no boundary produces today.
 */
import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['tests/unit/**/*.spec.ts'],
    coverage: {
      include: ['src/**/*.ts'],
      thresholds: {
        perFile: true,
        // The floor every file clears, which is the weakest file's number on
        // each metric. A new source file meets this until it is listed below.
        lines: 100,
        functions: 95.45,
        branches: 94.54,
        statements: 98.43,

        'src/config.ts': { lines: 100, functions: 100, branches: 97.95, statements: 100 },
        'src/correlate.ts': { lines: 100, functions: 100, branches: 100, statements: 100 },
        'src/delegation.ts': { lines: 100, functions: 100, branches: 100, statements: 100 },
        'src/forwarder.ts': { lines: 100, functions: 100, branches: 100, statements: 100 },
        'src/index.ts': { lines: 100, functions: 100, branches: 95.45, statements: 100 },
        'src/integrity/attest.ts': { lines: 100, functions: 100, branches: 100, statements: 100 },
        'src/integrity/verify.ts': { lines: 100, functions: 100, branches: 100, statements: 100 },
        'src/map/authorization.ts': { lines: 100, functions: 100, branches: 97.61, statements: 100 },
        'src/map/heartbeat.ts': { lines: 100, functions: 100, branches: 100, statements: 100 },
        'src/map/index.ts': { lines: 100, functions: 100, branches: 100, statements: 100 },
        'src/map/interaction.ts': { lines: 100, functions: 100, branches: 100, statements: 100 },
        'src/map/lifecycle.ts': { lines: 100, functions: 100, branches: 99.03, statements: 100 },
        'src/map/tool-events.ts': { lines: 100, functions: 100, branches: 98.38, statements: 100 },
        'src/map/tools.ts': { lines: 100, functions: 100, branches: 95.65, statements: 100 },
        'src/ocsf/constants.ts': { lines: 100, functions: 100, branches: 100, statements: 100 },
        'src/ocsf/record.ts': { lines: 100, functions: 100, branches: 100, statements: 100 },
        'src/ocsf/types.ts': { lines: 100, functions: 100, branches: 100, statements: 100 },
        'src/privacy.ts': { lines: 100, functions: 100, branches: 100, statements: 100 },
        'src/read.ts': { lines: 100, functions: 100, branches: 100, statements: 100 },
        'src/sink/otlp.ts': { lines: 100, functions: 100, branches: 100, statements: 100 },
        'src/sink/shipper.ts': { lines: 100, functions: 95.45, branches: 95.45, statements: 98.43 },
        'src/sink/splunk.ts': { lines: 100, functions: 100, branches: 100, statements: 100 },
        'src/sink/spool.ts': { lines: 100, functions: 100, branches: 94.54, statements: 99.37 },
        'src/sink/transport.ts': { lines: 100, functions: 100, branches: 100, statements: 100 },
      },
    },
  },
})
