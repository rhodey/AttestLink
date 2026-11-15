import assert from 'node:assert/strict'
import { once } from 'node:events'
import http from 'node:http'
import http2 from 'node:http2'
import test from 'node:test'
import sodium from 'libsodium-wrappers'
import { attestServer } from '../src/attest-server.js'
import { EncryptStream, DecryptStream } from '../src/streams.js'
import { attestLink } from '../src/browser/attest-fetch.js'
import * as util from '../src/browser/fetch-util.js'
import { http2Fetch } from './browser/helpers/http2-fetch.js'

const PCR0 = '12'.repeat(48)
const getDoc = async (nonce, publicKey) => Buffer.from(JSON.stringify({ nonce, publicKey, pcrs: { 0: PCR0 } })).toString('base64')
const verify = async (document, nonce, publicKey, pcr0) => {
  const evidence = JSON.parse(Buffer.from(document, 'base64'))
  return evidence.nonce === nonce && evidence.publicKey === publicKey && evidence.pcrs[0] === pcr0 && evidence
}

async function rig(t) {
  let release, started
  const pending = new Promise(resolve => { release = resolve })
  const ready = new Promise(resolve => { started = resolve })
  const paths = []
  const backend = http.createServer(async (req, res) => {
    req.resume()
    await once(req, 'end')
    paths.push(req.url)
    if (req.url === '/wait') { started(); await pending }
    res.setHeader('content-type', 'text/plain')
    res.end(req.url)
  })
  // Keep a pending HTTP response writable after the tunnel's sending side ends.
  backend.httpAllowHalfOpen = true
  backend.listen(0, '127.0.0.1')
  await once(backend, 'listening')
  const server = await attestServer(backend.address().port, undefined, getDoc)
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  t.after(async () => {
    release()
    server.closeConnections()
    backend.closeAllConnections()
    await Promise.all([server, backend].map(server => new Promise(resolve => server.close(resolve))))
  })
  return { endpoint: `http://127.0.0.1:${server.address().port}`, ready, release, paths }
}

function connection(t, endpoint) {
  const conn = http2.connect(endpoint)
  conn.on('error', () => {})
  t.after(() => conn.destroy())
  return conn
}

async function hello(t, endpoint, conn, mode) {
  const keys = sodium.crypto_kx_keypair()
  try {
    const response = await http2Fetch(`${endpoint}/hello`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        nonce: sodium.to_hex(sodium.randombytes_buf(32)),
        publicKey: util.encodeBase64(keys.publicKey), mode,
      }),
    }, conn)
    assert.equal(response.status, 200)
    const hello = await response.json()
    const sessionKeys = sodium.crypto_kx_client_session_keys(keys.publicKey, keys.privateKey, util.decodeBase64(hello.publicKey))
    t.after(() => { sodium.memzero(sessionKeys.sharedTx); sodium.memzero(sessionKeys.sharedRx) })
    return { sessionId: hello.sessionId, sessionKeys }
  } finally {
    sodium.memzero(keys.privateKey)
  }
}

async function duplex(conn, session) {
  const request = conn.request({
    ':method': 'POST', ':path': '/duplex', 'attest-link-session': session.sessionId,
  }, { endStream: false })
  request.on('error', () => {})
  const [headers] = await once(request, 'response')
  assert.equal(headers[':status'], 200)
  const encrypt = new EncryptStream(session.sessionKeys.sharedTx)
  const decrypt = new DecryptStream(session.sessionKeys.sharedRx)
  request.on('error', error => decrypt.destroy(error))
  encrypt.on('error', error => request.destroy(error))
  const closed = new Promise(resolve => request.once('close', resolve))
  encrypt.pipe(request)
  request.pipe(decrypt)
  const result = (async () => {
    const chunks = []
    for await (const chunk of decrypt) chunks.push(chunk)
    await closed
    return Buffer.concat(chunks).toString()
  })()
  result.catch(() => {})
  return { result, send: path => encrypt.end(`GET ${path} HTTP/1.1\r\nHost: backend\r\nConnection: close\r\n\r\n`) }
}

async function rejected(endpoint, conn, path, sessionId) {
  const response = await http2Fetch(`${endpoint}/${path}`, {
    method: 'POST', headers: { 'attest-link-session': sessionId }, body: '{}',
  }, conn)
  assert.equal(response.status, 403)
  await response.text()
}

test('fetch, duplex and failed requests share a connection without closing unrelated streams', { timeout: 5000 }, async t => {
  t.mock.method(console, 'error', () => {})
  const { endpoint, ready, release } = await rig(t)
  const conn = connection(t, endpoint)
  const session = await hello(t, endpoint, conn)
  const tunnel = await duplex(conn, session)
  tunnel.send('/wait')
  await ready

  const malformed = await http2Fetch(`${endpoint}/hello`, { method: 'POST', body: '{' }, conn)
  assert.equal(malformed.status, 400)
  await malformed.text()
  const fetch = (url, init) => http2Fetch(url, init, conn)
  const attestFetch = attestLink(endpoint, { pcr0: PCR0, fetch, verify })
  assert.equal(await (await attestFetch('/browser')).text(), '/browser')
  release()
  assert.match(await tunnel.result, /\r\n\r\n\/wait$/)
  assert.equal(conn.closed, false)
  assert.equal(await (await attestFetch('/after-duplex')).text(), '/after-duplex')
})

test('a duplex session survives its hello connection and can be consumed only once', { timeout: 5000 }, async t => {
  const { endpoint, paths } = await rig(t)
  const first = connection(t, endpoint)
  const session = await hello(t, endpoint, first)
  const closed = once(first, 'close')
  first.close()
  await closed
  const next = connection(t, endpoint)
  const tunnel = await duplex(next, session)
  tunnel.send('/different-connection')
  assert.ok((await tunnel.result).endsWith('/different-connection'))
  await rejected(endpoint, next, 'duplex', session.sessionId)
  assert.deepEqual(paths, ['/different-connection'])
})

test('session IDs cannot cross modes and rejection does not consume the matching session', { timeout: 5000 }, async t => {
  const { endpoint, paths } = await rig(t)
  const conn = connection(t, endpoint)
  const streaming = await hello(t, endpoint, conn)
  const fetching = await hello(t, endpoint, conn, 'fetch')
  await rejected(endpoint, conn, 'fetch', streaming.sessionId)
  await rejected(endpoint, conn, 'duplex', fetching.sessionId)
  const tunnel = await duplex(conn, streaming)
  tunnel.send('/streaming')
  assert.ok((await tunnel.result).endsWith('/streaming'))
  const response = await http2Fetch(`${endpoint}/fetch`, {
    method: 'POST', headers: { 'attest-link-session': fetching.sessionId },
    body: JSON.stringify(util.encryptJson({ path: '/fetching', method: 'GET', headers: [], body: null }, fetching.sessionKeys.sharedTx)),
  }, conn)
  assert.equal(response.status, 200)
  const plain = util.decryptJson(await response.json(), fetching.sessionKeys.sharedRx)
  assert.equal(Buffer.from(plain.body, 'base64').toString(), '/fetching')
  assert.deepEqual(paths, ['/streaming', '/fetching'])
})

test('unused duplex sessions expire without imposing an idle deadline on an established tunnel', { timeout: 5000 }, async t => {
  const { endpoint, ready, release, paths } = await rig(t)
  t.mock.timers.enable({ apis: ['setTimeout'] })
  const conn = connection(t, endpoint)
  const unused = await hello(t, endpoint, conn)
  t.mock.timers.tick(5001)
  await rejected(endpoint, conn, 'duplex', unused.sessionId)
  assert.deepEqual(paths, [])
  const active = await hello(t, endpoint, conn)
  const tunnel = await duplex(conn, active)
  tunnel.send('/wait')
  await ready
  t.mock.timers.tick(5001)
  assert.equal(conn.closed, false)
  release()
  assert.match(await tunnel.result, /\r\n\r\n\/wait$/)
})

test('a fetch can finish after five seconds without a server request deadline', { timeout: 5000 }, async t => {
  const { endpoint, ready, release } = await rig(t)
  t.mock.timers.enable({ apis: ['setTimeout'] })
  const conn = connection(t, endpoint)
  const session = await hello(t, endpoint, conn, 'fetch')
  const pending = http2Fetch(`${endpoint}/fetch`, {
    method: 'POST', headers: { 'attest-link-session': session.sessionId },
    body: JSON.stringify(util.encryptJson({ path: '/wait', method: 'GET', headers: [], body: null }, session.sessionKeys.sharedTx)),
  }, conn)
  pending.catch(() => {})
  await ready
  t.mock.timers.tick(5001)
  release()
  const response = await pending
  assert.equal(response.status, 200)
  const plain = util.decryptJson(await response.json(), session.sessionKeys.sharedRx)
  assert.equal(Buffer.from(plain.body, 'base64').toString(), '/wait')
})
