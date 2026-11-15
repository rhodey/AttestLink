import sodium from 'libsodium-wrappers'

export const FETCH_MAX_BYTES = 8 * 1024 * 1024

const encoder = new TextEncoder()
const decoder = new TextDecoder('utf-8', { fatal: true })

export function encodeBase64(bytes) {
  return sodium.to_base64(bytes, sodium.base64_variants.ORIGINAL)
}

export function decodeBase64(value) {
  if (typeof value !== 'string') throw new Error('Expected base64 data')
  const bytes = sodium.from_base64(value, sodium.base64_variants.ORIGINAL)
  if (encodeBase64(bytes) !== value) throw new Error('Invalid base64 data')
  return bytes
}

export function encryptJson(value, key) {
  const plain = encoder.encode(JSON.stringify(value))
  try {
    if (plain.length > FETCH_MAX_BYTES) throw new Error('Fetch payload is too large')
    const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)
    const encrypted = sodium.crypto_secretbox_easy(plain, nonce, key)
    const box = { nonce: encodeBase64(nonce), encrypted: encodeBase64(encrypted) }
    if (JSON.stringify(box).length > FETCH_MAX_BYTES) throw new Error('Fetch payload is too large')
    return box
  } finally {
    plain.fill(0)
  }
}

export function decryptJson(box, key) {
  const nonce = decodeBase64(box?.nonce)
  const encrypted = decodeBase64(box?.encrypted)
  if (nonce.length !== sodium.crypto_secretbox_NONCEBYTES || encrypted.length > FETCH_MAX_BYTES) {
    throw new Error('Invalid encrypted fetch payload')
  }
  const plain = sodium.crypto_secretbox_open_easy(encrypted, nonce, key)
  try { return JSON.parse(decoder.decode(plain)) }
  finally { plain.fill(0) }
}

export async function readBytes(response, limit = FETCH_MAX_BYTES, signal) {
  signal?.throwIfAborted()
  if (!response.body) return new Uint8Array()
  const reader = response.body.getReader()
  const cancel = () => { reader.cancel(signal?.reason).catch(() => {}) }
  signal?.addEventListener('abort', cancel, { once: true })
  const chunks = []
  let length = 0
  try {
    while (true) {
      const { value, done } = await reader.read()
      signal?.throwIfAborted()
      if (done) break
      length += value.byteLength
      if (length > limit) throw new Error('Fetch body is too large')
      chunks.push(value)
    }
    const bytes = new Uint8Array(length)
    let offset = 0
    for (const chunk of chunks) {
      bytes.set(chunk, offset)
      offset += chunk.byteLength
    }
    return bytes
  } catch (error) {
    cancel()
    throw error
  } finally {
    signal?.removeEventListener('abort', cancel)
    reader.releaseLock()
  }
}

export async function readJson(response, limit = FETCH_MAX_BYTES, signal) {
  return JSON.parse(decoder.decode(await readBytes(response, limit, signal)))
}
