import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import * as attest from '../../src/browser/attest-wasm.js'

const fixture = JSON.parse(await readFile(new URL('./fixtures/wasm.json', import.meta.url), 'utf8'))
const { nonce, publicKey, pcr0, rootPem } = fixture
const document = fixture.documents[0].document

test('the WASM Rust verifier returns the same evidence as the native Rust verifier', async t => {
  t.mock.method(Date, 'now', () => fixture.time)
  for (const { name, document, evidence } of fixture.documents) {
    await t.test(name, async () => {
      assert.deepEqual(await attest.verifyDoc(document, nonce, publicKey, pcr0, rootPem), evidence)
      assert.deepEqual(await attest.verifyDoc(document, nonce, publicKey, undefined, rootPem), evidence)
    })
  }
})

test('WASM verification rejects bad signatures, roots and nonce/key/PCR substitutions', async t => {
  t.mock.method(Date, 'now', () => fixture.time)
  const corrupt = Buffer.from(document, 'base64')
  corrupt[corrupt.length - 1] ^= 1
  for (const [name, args] of [
    ['signature', [corrupt.toString('base64'), nonce, publicKey, pcr0, rootPem]],
    ['wrong root', [document, nonce, publicKey, pcr0, fixture.otherRootPem]],
    ['default AWS root rejects fixture CA', [document, nonce, publicKey, pcr0]],
    ['nonce', [document, '06'.repeat(32), publicKey, pcr0, rootPem]],
    ['public key', [document, nonce, Buffer.alloc(32, 6).toString('base64'), pcr0, rootPem]],
    ['PCR0', [document, nonce, publicKey, '06'.repeat(48), rootPem]],
    ['debug PCR0', [fixture.debugDocument, nonce, publicKey, undefined, rootPem]],
    ['malformed document', ['not base64!', nonce, publicKey, pcr0, rootPem]],
    ['oversize document', ['A'.repeat(24 * 1024 + 1), nonce, publicKey, pcr0, rootPem]],
    ['oversize input', ['A'.repeat(40 * 1024), nonce, publicKey, pcr0, rootPem]],
  ]) {
    await t.test(name, async () => assert.equal(await attest.verifyDoc(...args), false))
  }
})

test('WASM certificate validation uses the current runtime clock', async t => {
  let now = fixture.time
  t.mock.method(Date, 'now', () => now)
  assert.ok(await attest.verifyDoc(document, nonce, publicKey, pcr0, rootPem))
  now += 2 * 24 * 60 * 60 * 1000
  assert.equal(await attest.verifyDoc(document, nonce, publicKey, pcr0, rootPem), false)
  now = fixture.time - 2 * 24 * 60 * 60 * 1000
  assert.equal(await attest.verifyDoc(document, nonce, publicKey, pcr0, rootPem), false)
})

test('WASM invocation errors throw instead of looking like rejected evidence', async t => {
  t.mock.method(Date, 'now', () => fixture.time)
  await assert.rejects(attest.verifyDoc(document, nonce, publicKey, '00'.repeat(48), rootPem), /PCR0/)
  await assert.rejects(attest.verifyDoc(document, 'bad nonce', publicKey, pcr0, rootPem), /Attestation helper failed/)
  await assert.rejects(attest.verifyDoc(document, nonce, publicKey, pcr0, 'not a PEM'), /Attestation helper failed/)
})
