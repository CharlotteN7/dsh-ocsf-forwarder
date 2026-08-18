#!/usr/bin/env node
// The `record_integrity` verifier as a command. All of it is in
// `lib/integrity/verify.js`; this file exists only because a published bin has
// to be a linkable file with a shebang, and the module the tests import must
// not run anything when it is imported.
import { main } from '../lib/integrity/verify.js'

// A reader that stops early — `| head`, `| grep -q` — closes the pipe under us.
// Node raises that as an unhandled `error` event on stdout and the process dies
// with a stack trace, which for a verifier reads like the spool failed to
// verify. A closed reader is not a verification failure, so exit quietly.
process.stdout.on('error', (error) => {
  if (error.code === 'EPIPE') process.exit(0)
  throw error
})

process.exitCode = main(process.argv.slice(2), (line) => { process.stdout.write(`${line}\n`) })
