import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { Readable } from 'node:stream'
import { pipeline } from 'node:stream/promises'
import test from 'node:test'
import sodium from 'libsodium-wrappers'
import { EncryptStream, DecryptStream, MAX_CIPHERTEXT } from '../src/streams.js'

await sodium.ready

async function collect(source) {
  const chunks = []
  for await (const chunk of source) chunks.push(chunk)
  return Buffer.concat(chunks)
}

function encrypt(source, key) {
  return pipeline(source, new EncryptStream(key), collect)
}

function decrypt(source, key) {
  return pipeline(source, new DecryptStream(key), collect)
}

function pieces(bytes) {
  const result = []
  let offset = 0
  for (let i = 0; offset < bytes.length; i++) {
    const size = [1, 3, 7, 1024, 16384][i % 5]
    result.push(bytes.subarray(offset, offset + size))
    offset += size
  }
  return Readable.from(result)
}

test('secretstream preserves bulk bytes across arbitrary TCP chunk boundaries', async () => {
  const plaintext = randomBytes(2 * 1024 * 1024 + 11)
  const key = randomBytes(32)
  const encrypted = await encrypt(Readable.from([plaintext]), key)
  const decoded = await decrypt(pieces(encrypted), key)
  assert.deepEqual(decoded, plaintext)
  assert.ok(encrypted.length > plaintext.length)
})

test('encrypted frames reject tampering and wrong keys', async () => {
  const key = randomBytes(32)
  const ciphertext = await encrypt(Readable.from([Buffer.from('private SSH bytes')]), key)
  const changed = Buffer.from(ciphertext)
  changed[30] ^= 1
  for (const [bytes, decryptKey] of [[changed, key], [ciphertext, randomBytes(32)]]) {
    await assert.rejects(decrypt(pieces(bytes), decryptKey), /authentication failed/)
  }
})

test('missing FINAL, incomplete frames and bytes after FINAL are errors', async () => {
  const key = randomBytes(32)
  const encrypted = await encrypt(Readable.from([Buffer.from('hello')]), key)
  for (const truncated of [encrypted.subarray(0, 12), encrypted.subarray(0, -1), encrypted.subarray(0, -21)]) {
    await assert.rejects(decrypt(pieces(truncated), key), /Truncated/)
  }
  await assert.rejects(decrypt(pieces(Buffer.concat([encrypted, Buffer.from([0])])), key), /Bytes after final/)
})

test('oversized frame is rejected after four length bytes, without waiting for its body', async () => {
  const key = randomBytes(32)
  const encrypted = await encrypt(Readable.from([]), key)
  for (const length of [0, 16, MAX_CIPHERTEXT + 1, 0xffffffff]) {
    const invalid = Buffer.alloc(28)
    encrypted.copy(invalid, 0, 0, 24)
    invalid.writeUInt32BE(length, 24)
    await assert.rejects(decrypt(Readable.from([invalid]), key), /frame length/)
  }
})

test('empty byte stream still requires and verifies its authenticated final frame', async () => {
  const key = randomBytes(32)
  const encrypted = await encrypt(Readable.from([]), key)
  assert.equal(encrypted.length, 24 + 4 + 17)
  assert.equal((await decrypt(pieces(encrypted), key)).length, 0)
})
