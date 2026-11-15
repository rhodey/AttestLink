import { Transform } from 'node:stream'
import sodium from 'libsodium-wrappers'

export const MAX_PLAINTEXT = 64 * 1024
export const MAX_CIPHERTEXT = MAX_PLAINTEXT + 17

export function erase(bytes) {
  if (bytes) sodium.memzero(bytes)
}

function freeState(state) {
  if (state === null) return
  // The libsodium wrapper returns a WASM allocation, without a
  // public free() method. Erase and release it when the Transform is destroyed.
  const module = sodium.libsodium
  module.HEAPU8.fill(0, state, state + module._crypto_secretstream_xchacha20poly1305_statebytes())
  module._free(state)
}

function frame(bytes) {
  const length = Buffer.alloc(4)
  length.writeUInt32BE(bytes.length)
  return Buffer.concat([length, bytes])
}

// Await sodium.ready before constructing either stream, as in lock.host.
export class EncryptStream extends Transform {
  constructor(key) {
    super()
    const res = sodium.crypto_secretstream_xchacha20poly1305_init_push(key)
    this.state = res.state
    this.push(Buffer.from(res.header))
  }

  _transform(chunk, encoding, callback) {
    try {
      for (let offset = 0; offset < chunk.length; offset += MAX_PLAINTEXT) {
        const message = chunk.subarray(offset, offset + MAX_PLAINTEXT)
        const bytes = sodium.crypto_secretstream_xchacha20poly1305_push(
          this.state, message, null, sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
        )
        this.push(frame(bytes))
      }
      callback()
    } catch (err) {
      callback(err)
    }
  }

  _flush(callback) {
    try {
      const bytes = sodium.crypto_secretstream_xchacha20poly1305_push(
        this.state, Buffer.alloc(0), null, sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL,
      )
      this.push(frame(bytes))
      callback()
    } catch (err) {
      callback(err)
    }
  }

  _destroy(err, callback) {
    freeState(this.state)
    this.state = null
    callback(err)
  }
}

export class DecryptStream extends Transform {
  constructor(key) {
    super()
    this.key = Buffer.from(key)
    this.state = null
    this.buf = Buffer.alloc(0)
    this.len = null
    this.final = false
  }

  _next() {
    if (this.len === null) {
      if (this.buf.length < 4) return null
      this.len = this.buf.readUInt32BE(0)
      if (this.len < 17 || this.len > MAX_CIPHERTEXT) {
        throw new Error('Invalid encrypted frame length')
      }
      this.buf = this.buf.subarray(4)
    }
    if (this.buf.length < this.len) return null
    const next = this.buf.subarray(0, this.len)
    this.buf = this.buf.subarray(this.len)
    this.len = null
    return next
  }

  _transform(chunk, encoding, callback) {
    try {
      this.buf = Buffer.concat([this.buf, chunk])
      if (this.final && this.buf.length) throw new Error('Bytes after final frame')

      if (this.state === null) {
        const size = sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES
        if (this.buf.length < size) return callback()
        const header = this.buf.subarray(0, size)
        this.state = sodium.crypto_secretstream_xchacha20poly1305_init_pull(header, this.key)
        erase(this.key)
        this.key = null
        this.buf = this.buf.subarray(size)
      }

      let next = this._next()
      while (next !== null) {
        const res = sodium.crypto_secretstream_xchacha20poly1305_pull(this.state, next, null)
        if (!res) throw new Error('Encrypted frame authentication failed')
        if (res.tag === sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
          if (res.message.length) throw new Error('Invalid final frame')
          this.final = true
          if (this.buf.length) throw new Error('Bytes after final frame')
          break
        }
        if (res.tag !== sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE) {
          throw new Error('Unexpected encrypted frame tag')
        }
        this.push(Buffer.from(res.message))
        next = this._next()
      }
      callback()
    } catch (err) {
      callback(err)
    }
  }

  _flush(callback) {
    callback(this.final ? null : new Error('Truncated encrypted stream'))
  }

  _destroy(err, callback) {
    erase(this.key)
    this.key = null
    freeState(this.state)
    this.state = null
    this.buf = Buffer.alloc(0)
    callback(err)
  }
}
