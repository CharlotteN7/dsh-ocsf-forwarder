/**
 * Keyless assembled-application E2E. Each test boots a real `dsh` subprocess,
 * so the timeouts are generous and files run serially to keep mock ports and
 * temporary homes from competing.
 */
import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['tests/e2e/**/*.e2e.ts'],
    testTimeout: 180_000,
    hookTimeout: 60_000,
    fileParallelism: false,
  },
})
