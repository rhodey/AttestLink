import net from 'node:net'
import { STATUS_CODES } from 'node:http'
import http2 from 'node:http2'
import { spawn } from 'node:child_process'
import { once } from 'node:events'
import { finished } from 'node:stream/promises'
import sodium from 'libsodium-wrappers'
import * as attest from './attest.js'
import { EncryptStream, DecryptStream, erase } from './streams.js'
import * as util from './util.js'
import * as envelope from './browser/fetch-util.js'
import { fetchBackend } from './browser/fetch-backend.js'

const SESSION_TTL = 5_000
const RESPONSE_TTL = 5_000
const HOOK_TIMEOUT = 5_000
const HELLO_MAX_BYTES = 32 * 1024
const HOOK_MAX_BYTES = 64 * 1024
const MAX_DOC_PENDING = Number(process.env.MAX_DOC_PENDING ?? 8)
const CORS_ORIGIN = process.env.CORS_ORIGIN ?? '*'

function writeHead(stream, status, contentType = 'application/json') {
  stream.respond({
    ':status': status, 'content-type': contentType, 'cache-control': 'no-store',
    'access-control-allow-origin': CORS_ORIGIN,
  })
  if (status >= 400) {
    // Bound cleanup if a rejected request leaves its upload open.
    const timer = setTimeout(() => stream.close(http2.constants.NGHTTP2_CANCEL), 250)
    timer.unref()
    stream.once('close', () => clearTimeout(timer))
  }
}

function on400(stream, status = 400) {
  if (stream.destroyed || stream.headersSent) return
  writeHead(stream, status)
  stream.end(JSON.stringify({ status, error: STATUS_CODES[status] }))
}

function on500(stream, status = 500) {
  if (stream.destroyed || stream.headersSent) return
  writeHead(stream, status)
  stream.end(JSON.stringify({ status, error: STATUS_CODES[status] }))
}

function eraseKeys(keys) {
  erase(keys.sharedRx)
  erase(keys.sharedTx)
}

function takeKeys(sessions, sessionId, mode) {
  const session = sessions.get(sessionId)
  if (!session || session.mode !== mode) return
  sessions.delete(sessionId)
  clearTimeout(session.expiryTimer)
  return session.keys
}

function runHook(hook, input, signal) {
  return new Promise((resolve, reject) => {
    const child = spawn('bash', ['-o', 'pipefail', '-c', hook], {
      detached: true, signal, timeout: HOOK_TIMEOUT, killSignal: 'SIGKILL',
    })
    const stdout = [], stderr = []
    const kill = () => {
      if (!child.pid) return
      try { process.kill(-child.pid, 'SIGKILL') }
      catch (err) { if (err.code !== 'ESRCH') reject(err) }
    }
    const fail = err => { kill(); reject(err) }
    child.on('error', fail)
    // Also stop pipeline/background children when Bash exits or is killed.
    child.once('exit', kill)
    for (const [stream, chunks] of [[child.stdout, stdout], [child.stderr, stderr]]) {
      let length = 0
      stream.on('error', fail)
      stream.on('data', chunk => {
        length += chunk.length
        if (length > HOOK_MAX_BYTES) return fail(new Error('Attestation hook output is too large'))
        chunks.push(chunk)
      })
    }
    child.once('close', (code, signal) => {
      if (code !== 0 && code !== 2) {
        const detail = Buffer.concat(stderr).toString().trim() || `exit ${code ?? signal}`
        return reject(new Error(`Attestation hook failed: ${detail}`))
      }
      try {
        const output = JSON.parse(Buffer.concat(stdout).toString())
        if (!output || typeof output !== 'object' || Array.isArray(output)) {
          throw new Error('Attestation hook must output a JSON object')
        }
        resolve([code, output])
      } catch (err) { reject(err) }
    })
    child.stdin.on('error', () => {})
    child.stdin.end(`${JSON.stringify(input)}\n`)
  })
}

async function onHello(stream, headers, runtime) {
  const { nonce, publicKey, extra, mode = 'duplex' } = await util.readJson(stream, HELLO_MAX_BYTES, SESSION_TTL)
  if (mode !== 'duplex' && mode !== 'fetch') return on400(stream)
  const cookies = headers.cookie ?? ''
  if (!/^[a-f0-9]{64}$/.test(nonce ?? '')) return on400(stream)
  const clientKey = util.decodeKey(publicKey)

  const server = sodium.crypto_kx_keypair()
  const controller = new AbortController()
  const cancel = () => controller.abort()
  stream.once('close', cancel)
  try {
    let userData
    if (runtime.hook !== undefined) {
      const [code, output] = await runHook(runtime.hook, { nonce, publicKey, extra, cookies }, controller.signal)
      if (code === 2) {
        if (!Number.isInteger(output.code) || output.code < 400 || output.code > 599 || typeof output.message !== 'string') {
          throw new Error('Attestation hook rejection requires an HTTP error code and a message')
        }
        writeHead(stream, output.code)
        stream.end(JSON.stringify({ code: output.code, message: output.message }))
        return
      }
      userData = output
    }
    if (controller.signal.aborted || stream.destroyed) return
    if (runtime.pendingAttestations >= MAX_DOC_PENDING) return on500(stream, 503)
    runtime.pendingAttestations++
    let document
    try {
      document = await runtime.getDoc(
        nonce, Buffer.from(server.publicKey).toString('base64'), userData,
      )
    } finally {
      runtime.pendingAttestations--
    }
    if (controller.signal.aborted || stream.destroyed) return
    const keys = sodium.crypto_kx_server_session_keys(
      server.publicKey, server.privateKey, clientKey,
    )
    const sessionId = util.randomHex()
    const expiryTimer = setTimeout(() => {
      runtime.sessions.delete(sessionId)
      eraseKeys(keys)
    }, SESSION_TTL)
    expiryTimer.unref()
    runtime.sessions.set(sessionId, { mode, keys, expiryTimer })
    writeHead(stream, 200)
    stream.end(JSON.stringify({
      version: '1.0.0', platform: 'nitro',
      document, sessionId, publicKey: Buffer.from(server.publicKey).toString('base64'),
    }))
  } catch (error) {
    on500(stream)
    throw error
  } finally {
    stream.off('close', cancel)
    erase(server.privateKey)
  }
}

async function onFetch(stream, headers, sessions, target) {
  const keys = takeKeys(sessions, headers['attest-link-session'], 'fetch')
  if (!keys) return on400(stream, 403)
  const controller = new AbortController()
  const cancel = () => controller.abort()
  stream.once('close', cancel)
  let timer
  try {
    let request
    try {
      const body = await util.readJson(stream, envelope.FETCH_MAX_BYTES, SESSION_TTL)
      request = envelope.decryptJson(body, keys.sharedRx)
    } catch (err) {
      on400(stream)
      return
    }
    timer = setTimeout(() => {
      const error = new Error('Fetch response timeout')
      controller.abort(error)
      stream.destroy(error)
    }, RESPONSE_TTL)
    timer.unref()
    const response = await fetchBackend(request, headers, target, controller.signal)
    const body = JSON.stringify(envelope.encryptJson(response.body, keys.sharedTx))
    if (Buffer.byteLength(body) > envelope.FETCH_MAX_BYTES) throw new Error('HTTP response is too large')
    stream.respond({
      ...response.headers, ':status': 200, 'content-type': 'application/json', 'cache-control': 'no-store',
      'access-control-allow-origin': CORS_ORIGIN,
    })
    stream.end(body)
    await finished(stream, { readable: false, cleanup: true })
  } catch (err) {
    on500(stream)
    console.error('attest-link (warn)', util.cleanMessage(err.message))
  } finally {
    clearTimeout(timer)
    stream.off('close', cancel)
    eraseKeys(keys)
  }
}

async function connectToTcp(target, signal) {
  const conn = net.createConnection({ ...target, allowHalfOpen: true })
  conn.on('error', () => {})
  try {
    await once(conn, 'connect', { signal: AbortSignal.any([signal, AbortSignal.timeout(5000)]) })
    return conn
  } catch (err) {
    conn.destroy()
    throw err
  }
}

async function onDuplex(client, headers, sessions, target) {
  const keys = takeKeys(sessions, headers['attest-link-session'], 'duplex')
  if (!keys) return on400(client, 403)
  try {
    const controller = new AbortController()
    const cancelled = () => controller.abort()
    client.once('close', cancelled)
    let server
    try {
      server = await connectToTcp(target, controller.signal)
    } finally {
      client.removeListener('close', cancelled)
    }
    const encrypt = new EncryptStream(keys.sharedTx)
    const decrypt = new DecryptStream(keys.sharedRx)
    const cleanup = () => {
      server.destroy()
      client.destroy()
      encrypt.destroy()
      decrypt.destroy()
    }
    const streams = [server, client, encrypt, decrypt]
    for (const stream of streams) stream.on('error', cleanup)
    try {
      writeHead(client, 200, 'application/octet-stream')
      // Observe all four streams before piping so errors and EOF are accounted for.
      const done = Promise.all(streams.map(stream => finished(stream, { cleanup: true })))
      server.pipe(encrypt).pipe(client)
      client.pipe(decrypt).pipe(server)
      await done
    } finally {
      cleanup()
    }
  } finally {
    eraseKeys(keys)
  }
}

export async function attestServer(backend, hook, getDoc = attest.getDoc) {
  const target = util.parseAddress(backend, '127.0.0.1')
  await sodium.ready
  const connections = new Set()
  const runtime = { hook, getDoc, pendingAttestations: 0, sessions: new Map() }
  const server = http2.createServer({
    maxSessionMemory: 4, maxHeaderListPairs: 64,
    settings: { maxConcurrentStreams: 2, maxHeaderListSize: 16 * 1024 },
  })

  // Connections are tracked only for shutdown. Keys belong to session IDs.
  server.on('session', conn => {
    connections.add(conn)
    conn.on('error', err => console.error('attest-link (warn)', util.cleanMessage(err.message)))
    conn.once('close', () => connections.delete(conn))
  })

  server.on('stream', async (stream, headers) => {
    stream.on('error', () => {})
    try {
      const path = headers[':path']
      const method = headers[':method']
      if (typeof path !== 'string') return on400(stream)
      const url = new URL(path, 'http://attest-link.invalid')
      if (url.pathname.endsWith('/health')) {
        writeHead(stream, 200, 'text/plain')
        stream.end('OK')
      } else if (method === 'OPTIONS' && /\/(hello|fetch)$/.test(url.pathname)) {
        stream.respond({
          ':status': 204, 'cache-control': 'no-store',
          'access-control-allow-origin': CORS_ORIGIN, 'access-control-allow-methods': 'POST',
          'access-control-allow-headers': 'content-type, attest-link-session',
          'access-control-max-age': '600',
        })
        stream.end()
      } else if (method === 'POST' && url.pathname.endsWith('/hello')) {
        await onHello(stream, headers, runtime)
      } else if (method === 'POST' && url.pathname.endsWith('/fetch')) {
        await onFetch(stream, headers, runtime.sessions, target)
      } else if (method === 'POST' && url.pathname.endsWith('/duplex')) {
        await onDuplex(stream, headers, runtime.sessions, target)
      } else {
        on400(stream, 404)
      }
    } catch (err) {
      console.error('attest-link (warn)', util.cleanMessage(err.message))
      on400(stream)
    }
  })
  server.closeConnections = () => {
    for (const conn of connections) conn.destroy()
    for (const session of runtime.sessions.values()) {
      clearTimeout(session.expiryTimer)
      eraseKeys(session.keys)
    }
    runtime.sessions.clear()
  }
  return server
}

