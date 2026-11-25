// Save a fresh, verified AWS document for the npm tarball qualification.
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { client } from '../../package/src/attest-duplex.js'
import { verifyDoc } from '../../package/src/attest.js'
import { validPCR } from '../../package/src/util.js'

const [image, endpoint = 'http://172.30.0.2:2222'] = process.argv.slice(2)
if (!image || process.argv.length > 4) {
  throw new Error('Usage: node nitro/scripts/capture-evidence.mjs IMAGE_DIR [ENDPOINT]')
}
const { measurements } = JSON.parse(await readFile(join(image, 'measurements.json'), 'utf8'))
const pcr0 = measurements.PCR0
validPCR(pcr0)

let hello
const [encrypt, decrypt, evidence] = await client(endpoint, {
  pcr0, signal: AbortSignal.timeout(10_000),
  verify(document, nonce, publicKey) {
    hello = { document, nonce, publicKey }
    return verifyDoc(document, nonce, publicKey, pcr0)
  },
})
encrypt.destroy()
decrypt.destroy()

for (const n of [1, 2, 6]) {
  const expected = measurements[`PCR${n}`]
  assert.match(expected, /^[a-f0-9]{96}$/)
  assert.equal(evidence.pcrs[n], expected, `Hardware PCR${n} differs from the built image`)
}
console.log(JSON.stringify({ ...hello, pcr0, evidence }))
