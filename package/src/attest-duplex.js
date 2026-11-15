import http2 from 'node:http2'
import net from 'node:net'
import tls from 'node:tls'
import { once } from 'node:events'
import sodium from 'libsodium-wrappers'
import semver from 'semver'
import * as attest from './attest.js'
import { EncryptStream, DecryptStream, erase } from './streams.js'
import * as util from './util.js'

const HELLO_MAX_BYTES = 32 * 1024
const HANDSHAKE_TIMEOUT = 5_000

export function endpointUrl(url) {
  const parsed = new URL(url)
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password || parsed.hash) {
    throw new Error('Endpoint must be an http:// or https:// URL without credentials or a fragment')
  }
  parsed.pathname = `${parsed.pathname.replace(/\/+$/, '')}/`
  return parsed.href
}

function openHttp2(url, timeout, cancelled) {
  const controller = new AbortController()
  const signal = AbortSignal.any([cancelled, controller.signal])
  const target = new URL(endpointUrl(url))
  const secure = target.protocol === 'https:'
  const host = target.hostname.replace(/^\[|\]$/g, '')
  const address = { host, port: Number(target.port || (secure ? 443 : 80)) }
  // Own the socket so a timeout also cancels a TCP connect that hasn't finished.
  const socket = secure ? tls.connect({
    ...address, servername: net.isIP(host) ? undefined : host,
    ALPNProtocols: ['h2'], rejectUnauthorized: true,
  }) : net.createConnection(address)
  const conn = http2.connect(target.origin, {
    createConnection: () => socket,
    maxSessionMemory: 4, maxHeaderListPairs: 16,
    settings: { enablePush: false, maxConcurrentStreams: 2, maxHeaderListSize: 4096 },
  })
  socket.on('error', () => {})
  conn.on('error', err => controller.abort(err))
  const timer = setTimeout(() => controller.abort(new Error('Attestation handshake timeout')), timeout)
  timer.unref()
  const close = err => { socket.destroy(err); conn.destroy(err) }
  const abort = () => close(signal.reason)
  signal.addEventListener('abort', abort, { once: true })
  conn.once('close', () => {
    clearTimeout(timer)
    signal.removeEventListener('abort', abort)
    controller.abort(new Error('HTTP/2 connection closed'))
    socket.destroy()
  })
  if (signal.aborted) abort()
  return { conn, signal, url: target, close, finishHandshake: () => clearTimeout(timer) }
}

async function waitForResponse(stream, signal) {
  // A clean close may never emit either response or error.
  const [headers] = await Promise.race([
    once(stream, 'response', { signal }),
    once(stream, 'close', { signal }).then(() => {
      throw new Error('HTTP/2 stream closed before response headers')
    }),
  ])
  if (headers[':status'] !== 200) {
    const body = await util.readJson(stream, HELLO_MAX_BYTES).catch(() => null)
    const detail = typeof body?.message === 'string' ? body.message : ''
    const message = detail ? `: ${detail}` : ''
    throw new Error(`Server returned HTTP ${headers[':status']}${message}`)
  }
}

async function sendHello(connection, nonce, keys, extra) {
  const { conn, signal, url } = connection
  if (signal.aborted) throw signal.reason
  await once(conn, 'connect', { signal })
  const publicKey = Buffer.from(keys.publicKey).toString('base64')
  const req = conn.request({
    ':method': 'POST', ':path': `${url.pathname}hello${url.search}`,
    'content-type': 'application/json',
  })
  req.on('error', () => {})
  req.end(JSON.stringify({ nonce, publicKey, extra }))
  await waitForResponse(req, signal)
  const body = await util.readJson(req, HELLO_MAX_BYTES)
  if (typeof body.version !== 'string' || !semver.satisfies(body.version, '^1.0.0')) {
    throw new Error('Incompatible protocol version')
  }
  if (body.platform !== 'nitro') throw new Error('Unsupported attestation platform')
  if (!/^[a-f0-9]{64}$/.test(body.sessionId ?? '')) {
    throw new Error('Invalid hello response')
  }
  util.decodeKey(body.publicKey)
  return body
}

async function startCrypto(verify, hello, nonce, pcr0, keys) {
  const evidence = await verify(hello.document, nonce, hello.publicKey, pcr0)
  if (!evidence) throw new Error('Attestation verification failed')
  const publicKey = util.decodeKey(hello.publicKey)
  const sessionKeys = sodium.crypto_kx_client_session_keys(
    keys.publicKey, keys.privateKey, publicKey,
  )
  return { sessionId: hello.sessionId, sessionKeys, evidence }
}

async function startDuplex(connection, state) {
  const { conn, signal, url } = connection
  const req = conn.request({
    ':method': 'POST', ':path': `${url.pathname}duplex${url.search}`, 'attest-link-session': state.sessionId,
    'content-type': 'application/octet-stream',
  }, { endStream: false })
  req.on('error', () => {})
  await waitForResponse(req, signal)

  const encrypt = new EncryptStream(state.sessionKeys.sharedTx)
  const decrypt = new DecryptStream(state.sessionKeys.sharedRx)
  const close = err => {
    encrypt.destroy(err)
    decrypt.destroy(err)
    connection.close(err)
  }
  encrypt.on('error', close)
  decrypt.on('error', close)
  req.on('error', close)
  conn.on('error', close)

  // Allow a completed sending direction to finish independently of receiving.
  const finish = () => {
    if (req.writableFinished && decrypt.readableEnded) conn.close()
  }
  req.once('finish', finish)
  decrypt.once('end', finish)
  encrypt.once('close', () => { if (!encrypt.readableEnded) close() })
  decrypt.once('close', () => { if (!decrypt.readableEnded) close() })
  const connectionClosed = () => {
    if (!req.readableEnded || !req.writableFinished) close(new Error('Session closed before stream EOF'))
  }
  req.once('close', connectionClosed)

  encrypt.pipe(req)
  req.pipe(decrypt)
  return [encrypt, decrypt]
}

// Client handshake: hello, verify/derive keys, start the encrypted duplex.
export async function client(url, {
  verify = attest.verifyDoc, pcr0, extra, timeout = HANDSHAKE_TIMEOUT, signal,
} = {}) {
  if (pcr0 !== undefined) util.validPCR(pcr0)
  await sodium.ready
  const connection = openHttp2(url, timeout, signal)
  const nonce = util.randomHex()
  const keys = sodium.crypto_kx_keypair()
  let state
  try {
    const hello = await sendHello(connection, nonce, keys, extra)
    state = await startCrypto(verify, hello, nonce, pcr0, keys)
    connection.signal.throwIfAborted()
    const [encrypt, decrypt] = await startDuplex(connection, state)
    connection.finishHandshake()
    return [encrypt, decrypt, state.evidence]
  } catch (err) {
    connection.close()
    throw connection.signal.aborted ? connection.signal.reason : err
  } finally {
    erase(keys.privateKey)
    if (state) {
      erase(state.sessionKeys.sharedTx)
      erase(state.sessionKeys.sharedRx)
    }
  }
}
