import http from 'node:http'
import { Writable } from 'node:stream'
import { pipeline } from 'node:stream/promises'
import { createGunzip, createInflate, createBrotliDecompress } from 'node:zlib'
import * as envelope from './fetch-util.js'

// These describe the outer transport, not the HTTP request inside the tunnel.
const TRANSPORT_HEADERS = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade', 'content-length',
  'attest-link-session',
])

function copyHeaders(entries) {
  const headers = new Headers()
  const connection = new Headers(entries).get('connection')
  const nominated = new Set((connection ?? '').toLowerCase().split(',').map(value => value.trim()))
  for (const [name, value] of entries) {
    if (TRANSPORT_HEADERS.has(name.toLowerCase()) || nominated.has(name.toLowerCase())) continue
    headers.append(name, value)
  }
  return headers
}

async function readBody(response, method, signal) {
  const empty = method === 'HEAD' || [204, 205, 304].includes(response.statusCode)
  const encodings = empty ? [] : (response.headers['content-encoding'] ?? '').split(',').filter(Boolean)
  const decoders = encodings.reverse().map(encoding => {
    switch (encoding.trim().toLowerCase()) {
      case 'identity': return null
      case 'gzip': return createGunzip()
      case 'deflate': return createInflate()
      case 'br': return createBrotliDecompress()
      default: throw new Error('Unsupported backend content encoding')
    }
  }).filter(Boolean)
  const chunks = []
  let length = 0
  const output = new Writable({
    write(chunk, encoding, done) {
      length += chunk.length
      if (length > envelope.FETCH_MAX_BYTES) return done(new Error('HTTP response is too large'))
      chunks.push(chunk)
      done()
    },
  })
  await pipeline(response, ...decoders, output, { signal })
  return empty ? null : envelope.encodeBase64(Buffer.concat(chunks))
}

export async function fetchBackend(request, outerHeaders, target, signal) {
  const { path, method, body } = request
  if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//') ||
      /[\\\r\n#]/.test(path)) throw new Error('Expected an HTTP backend path')
  if (typeof method !== 'string' || !/^[A-Z]+$/.test(method)) throw new Error('Invalid HTTP method')
  const host = target.host.includes(':') ? `[${target.host}]` : target.host
  const backend = new URL(`http://${host}:${target.port}`)
  const url = new URL(path, backend)
  if (url.origin !== backend.origin) throw new Error('Request must stay on the configured backend')

  const headers = copyHeaders(request.headers)
  // Only cookies and the public Host come from the unencrypted outer request.
  headers.delete('cookie')
  if (outerHeaders.cookie !== undefined) headers.set('cookie', outerHeaders.cookie)
  headers.set('host', outerHeaders[':authority'] ?? outerHeaders.host ?? url.host)
  headers.set('accept-encoding', 'identity')
  const bytes = body === null ? undefined : envelope.decodeBase64(body)
  if (bytes !== undefined) headers.set('content-length', String(bytes.length))
  // Native fetch replaces Host with the backend address. HTTP request preserves
  // the public Host while the connection still targets only our configured URL.
  const response = await new Promise((resolve, reject) => {
    const request = http.request(url, { method, headers: Object.fromEntries(headers), signal }, resolve)
    request.on('error', reject)
    request.end(bytes)
  })
  try {
    const body = await readBody(response, method, signal)
    const entries = []
    for (let i = 0; i < response.rawHeaders.length; i += 2) entries.push(response.rawHeaders.slice(i, i + 2))
    const returned = copyHeaders(entries)
    returned.delete('content-encoding') // The encrypted envelope is not gzip/br data.
    returned.delete('set-cookie')
    const responseHeaders = {}
    if (response.headers['set-cookie']) responseHeaders['set-cookie'] = response.headers['set-cookie']
    return {
      headers: responseHeaders,
      body: { status: response.statusCode, statusText: response.statusMessage, headers: [...returned], body },
    }
  } finally {
    response.destroy()
  }
}
