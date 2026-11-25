// Exercise the installed browser package against the measured HTTP test backend.
import assert from 'node:assert/strict'
import { readFile, realpath } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { http2Fetch } from '../../package/test/browser/helpers/http2-fetch.js'

const [consumer, image, endpoint = 'http://172.30.0.2:2222'] = process.argv.slice(2)
if (!consumer || !image || process.argv.length > 5) {
  throw new Error('Usage: node nitro/scripts/test-fetch.mjs CONSUMER_DIR IMAGE_DIR [ENDPOINT]')
}
const installed = createRequire(await realpath(join(consumer, 'node_modules/attest-link/package.json')))
const { attestLink } = await import(pathToFileURL(installed.resolve('attest-link')))
const { measurements } = JSON.parse(await readFile(join(image, 'measurements.json'), 'utf8'))
let hellos = 0
const fetch = attestLink(endpoint, {
  pcr0: measurements.PCR0,
  fetch(url, init) {
    if (new URL(url).pathname.endsWith('/hello')) hellos++
    return http2Fetch(url, init)
  },
})

const paths = ['/one', '/two', '/three']
const responses = await Promise.all(paths.map(path => fetch(path)))
assert.equal(hellos, 1)
let lastCount
for (const [i, response] of responses.entries()) {
  assert.equal(response.status, 200)
  const { path, count } = await response.json()
  assert.equal(path, paths[i])
  assert.ok(Number.isSafeInteger(count))
  if (i > 0) assert.equal(count, lastCount + 1)
  lastCount = count
  assert.equal(response.evidence.pcrs[0], measurements.PCR0)
  assert.deepEqual(response.evidence, responses[0].evidence)
}
console.log(JSON.stringify({ ok: true, hellos, paths, pcr0: measurements.PCR0 }))
