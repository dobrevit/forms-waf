#!/usr/bin/env node
// R-18/R-23: fail CI on high or critical advisories, except those explicitly
// accepted in .audit-allowlist.json. An allowlist entry expires, so an accepted
// risk resurfaces rather than becoming permanent.
import { execSync } from 'node:child_process'
import { readFileSync } from 'node:fs'

const FAIL_AT = new Set(['high', 'critical'])

let report
try {
  report = JSON.parse(execSync('npm audit --json', { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }))
} catch (err) {
  // npm audit exits non-zero when it finds anything; the JSON is still on stdout.
  if (!err.stdout) {
    console.error('audit-gate: could not run npm audit')
    process.exit(2)
  }
  report = JSON.parse(err.stdout)
}

const allowlist = JSON.parse(readFileSync(new URL('../.audit-allowlist.json', import.meta.url)))
const today = new Date().toISOString().slice(0, 10)

const allowed = new Map()
let expired = false
for (const entry of allowlist.allow ?? []) {
  if (entry.reviewBy && entry.reviewBy < today) {
    console.error(`EXPIRED  ${entry.id} (${entry.package}) - reviewBy ${entry.reviewBy} has passed`)
    expired = true
    continue
  }
  allowed.set(entry.id, entry)
}

const blocking = []
for (const [name, vuln] of Object.entries(report.vulnerabilities ?? {})) {
  if (!FAIL_AT.has(vuln.severity)) continue
  for (const via of vuln.via) {
    if (typeof via !== 'object' || !via.url) continue
    const id = via.url.split('/').pop()
    if (allowed.has(id)) {
      console.log(`allowed  ${id}  ${name}  (review by ${allowed.get(id).reviewBy})`)
    } else {
      blocking.push({ id, name, severity: vuln.severity, title: via.title })
    }
  }
}

if (blocking.length > 0) {
  console.error(`\n${blocking.length} advisory/advisories are not allowlisted:`)
  for (const b of blocking) console.error(`  ${b.severity.padEnd(8)} ${b.name.padEnd(22)} ${b.id}  ${b.title ?? ''}`)
  console.error('\nFix them, or add a justified, time-boxed entry to admin-ui/.audit-allowlist.json')
  process.exit(1)
}
if (expired) {
  console.error('\nAn allowlist entry has expired and must be re-reviewed.')
  process.exit(1)
}
console.log('\naudit-gate: no unaccepted high/critical advisories')
