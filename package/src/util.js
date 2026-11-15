import { randomBytes } from 'node:crypto'
import { lstatSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { stripVTControlCharacters } from 'node:util'

export function cleanMessage(text) {
  return stripVTControlCharacters(String(text)).replace(/[\u0000-\u001f\u007f-\u009f]/g, '')
}

export function executable() {
  if (process.env.ATTEST_LINK_RUST !== undefined) return process.env.ATTEST_LINK_RUST
  const platform = `${process.platform}-${process.arch}`
  if (['darwin-arm64', 'linux-arm64', 'linux-x64'].includes(platform)) {
    const bundled = fileURLToPath(new URL(`../bin/${platform}/attest-link-rust`, import.meta.url))
    try {
      lstatSync(bundled)
      return bundled
    } catch (error) {
      if (error.code !== 'ENOENT') throw error
    }
  }
  return 'attest-link-rust'
}

export function randomHex() {
  return randomBytes(32).toString('hex')
}

export function parseAddress(address, defaultHost) {
  const parts = String(address).match(/^(?:\[([^\]]+)\]:|([^:]+):)?(\d+)$/)
  if (!parts || Number(parts[3]) > 65535) throw new Error('Expected PORT or HOST:PORT with a port from 0 to 65535')
  return { host: parts[1] ?? parts[2] ?? defaultHost, port: Number(parts[3]) }
}

export function validPCR(pcr0) {
  if (!/^[a-f0-9]{96}$/.test(pcr0 ?? '') || /^0+$/.test(pcr0)) {
    throw new Error('PCR0 must be a nonzero SHA-384 measurement (96 lowercase hex digits)')
  }
}

export function decodeKey(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(value)) {
    throw new Error('Expected a base64-encoded 32-byte public key')
  }
  const bytes = Buffer.from(value, 'base64')
  if (bytes.length !== 32 || bytes.toString('base64') !== value) throw new Error('Invalid public key')
  return bytes
}

export async function readJson(stream, limit) {
  let length = 0
  const chunks = []
  for await (const chunk of stream.iterator({ destroyOnReturn: false })) {
    length += chunk.length
    if (length > limit) throw new Error('Attestation JSON is too large')
    chunks.push(chunk)
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'))
}
