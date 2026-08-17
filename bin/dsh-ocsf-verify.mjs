#!/usr/bin/env node
// The `record_integrity` verifier as a command. All of it is in
// `lib/integrity/verify.js`; this file exists only because a published bin has
// to be a linkable file with a shebang, and the module the tests import must
// not run anything when it is imported.
import { main } from '../lib/integrity/verify.js'

process.exitCode = main(process.argv.slice(2), (line) => { process.stdout.write(`${line}\n`) })
