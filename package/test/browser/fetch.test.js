import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { once } from 'node:events'
import http from 'node:http'
import http2 from 'node:http2'
import { gzipSync, deflateSync, brotliCompressSync } from 'node:zlib'
import test from 'node:test'
import sodium from 'libsodium-wrappers'
import { attestLink } from '../../src/browser/attest-fetch.js'
import { attestServer } from '../../src/attest-server.js'
import * as util from '../../src/browser/fetch-util.js'
import { http2Fetch } from './helpers/http2-fetch.js'

const PCR0 = '12'.repeat(48)

// Transport fixtures only. The browser verifier has its own signed-document
// tests; production code uses the Rust verifier compiled to WebAssembly.
const getDoc = async (nonce, publicKey, userData = {}) => Buffer.from(JSON.stringify({
  nonce, publicKey, pcrs: { 0: PCR0 }, userData,
})).toString('base64')
const verify = async (document, nonce, publicKey, pcr0) => {
  const evidence = JSON.parse(Buffer.from(document, 'base64'))
  if (evidence.nonce !== nonce || evidence.publicKey !== publicKey) return false
  if (pcr0 !== undefined && evidence.pcrs[0] !== pcr0) return false
  return evidence
}

async function rig(t, hook) {
  const requests = [], wire = []
  const backend = http.createServer(async (req, res) => {
    const chunks = []
    for await (const chunk of req) chunks.push(chunk)
    const body = Buffer.concat(chunks)
    requests.push({ path: req.url, method: req.method, headers: req.headers, body })
    res.setHeader('x-backend', 'attested-app')
    res.setHeader('set-cookie', ['session=one; HttpOnly; Path=/; SameSite=Lax', 'theme=dark; Path=/'])
    if (req.url.startsWith('/compressed/')) {
      const encoding = req.url.slice('/compressed/'.length)
      const compress = { gzip: gzipSync, deflate: deflateSync, br: brotliCompressSync }[encoding]
      res.setHeader('content-type', 'application/octet-stream')
      res.setHeader('content-encoding', encoding)
      res.end(compress(body))
    } else if (req.url === '/binary') {
      res.setHeader('content-type', 'application/octet-stream')
      res.end(body)
    } else if (req.url === '/empty') {
      res.writeHead(204)
      res.end()
    } else {
      res.setHeader('content-type', 'application/json')
      res.writeHead(req.url === '/error' ? 418 : req.method === 'POST' ? 201 : 200)
      res.end(JSON.stringify({ path: req.url, method: req.method, body: body.toString('base64') }))
    }
  })
  backend.listen(0, '127.0.0.1')
  await once(backend, 'listening')
  const server = await attestServer(backend.address().port, hook, getDoc)
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  t.after(async () => {
    server.closeConnections()
    backend.closeAllConnections()
    await Promise.all([server, backend].map(server => new Promise(resolve => server.close(resolve))))
  })
  const endpoint = `http://127.0.0.1:${server.address().port}/attest?tenant=one`
  const fetch = (url, init) => { wire.push({ url, init }); return http2Fetch(url, init) }
  return { endpoint, fetch, requests, wire, server }
}

async function startFetch(endpoint) {
  await sodium.ready
  const keys = sodium.crypto_kx_keypair()
  try {
    const url = new URL(endpoint)
    url.pathname += '/hello'
    const response = await http2Fetch(url, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        nonce: sodium.to_hex(sodium.randombytes_buf(32)),
        publicKey: util.encodeBase64(keys.publicKey), mode: 'fetch',
      }),
    })
    assert.equal(response.status, 200)
    const hello = await response.json()
    return {
      sessionId: hello.sessionId,
      keys: sodium.crypto_kx_client_session_keys(keys.publicKey, keys.privateKey, util.decodeBase64(hello.publicKey)),
    }
  } finally {
    sodium.memzero(keys.privateKey)
  }
}

test('browser fetch requires an explicit PCR policy and a valid endpoint', () => {
  assert.throws(() => attestLink('https://example.com/attest'), /Supply pcr0/)
  assert.throws(() => attestLink('https://example.com/attest', { pcr0: PCR0, anyPCR: true }), /not both/)
  assert.throws(() => attestLink('https://example.com/attest', { pcr0: '00'.repeat(48) }), /nonzero/)
  assert.throws(() => attestLink('file:///attest', { anyPCR: true }), /Endpoint/)
  assert.throws(() => attestLink('https://user:pass@example.com/attest', { anyPCR: true }), /Endpoint/)
})

test('browser fetch crosses HTTP/2 connections and returns a normal HTTP response with evidence', async t => {
  const { endpoint, fetch, requests, wire } = await rig(t, "printf '%s' '{\"fortune\":\"hello browser\"}'")
  const attestFetch = attestLink(endpoint, { pcr0: PCR0, fetch, verify })
  const response = await attestFetch('/inside/enclave?hello=world', { method: 'POST', body: 'secret body' })
  assert.equal(response.status, 201)
  assert.equal(response.statusText, 'Created')
  assert.equal(response.headers.get('content-type'), 'application/json')
  assert.equal(response.headers.get('x-backend'), 'attested-app')
  assert.equal(response.headers.get('content-length'), null)
  assert.deepEqual(response.evidence.userData, { fortune: 'hello browser' })
  assert.deepEqual(await response.json(), {
    path: '/inside/enclave?hello=world', method: 'POST', body: Buffer.from('secret body').toString('base64'),
  })
  assert.equal(requests.length, 1)
  assert.equal(requests[0].headers.host, new URL(endpoint).host)
  assert.deepEqual(wire.map(({ url }) => new URL(url).pathname), ['/attest/hello', '/attest/fetch'])
  assert.ok(wire.every(({ url }) => new URL(url).search === '?tenant=one'))
  assert.equal(wire[1].init.body.includes('secret body'), false)
  assert.equal(wire[1].init.body.includes('/inside/enclave'), false)
})

test('browser and ALB headers fit alongside a normal cookie header', async t => {
  const { endpoint, fetch, requests } = await rig(t)
  const headers = Object.fromEntries(Array.from({ length: 24 }, (_, i) => [`x-browser-${i}`, 'value']))
  headers.cookie = `session=${'a'.repeat(5000)}`
  const response = await attestLink(endpoint, { pcr0: PCR0, fetch, verify })('/headers', { headers })
  assert.equal(response.status, 200)
  assert.equal(requests[0].headers.cookie, headers.cookie)
  assert.equal(requests[0].headers['x-browser-23'], 'value')
})

test('ALB Host headers and request body lengths reach the HTTP backend correctly', async t => {
  const { endpoint, fetch, requests, server } = await rig(t)
  server.prependListener('stream', (stream, headers) => {
    headers.host = 'example.com'
    delete headers[':authority']
  })
  const attestFetch = attestLink(endpoint, { pcr0: PCR0, fetch, verify })
  for (const method of ['POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']) {
    const body = `hello ${method} Ω`
    const response = await attestFetch('/methods', { method, body })
    const request = requests.at(-1)
    assert.equal(response.status, method === 'POST' ? 201 : 200)
    assert.equal(request.headers.host, 'example.com')
    assert.equal(request.headers['content-length'], String(Buffer.byteLength(body)))
    assert.equal(request.body.toString(), body)
  }
})

test('compressed backend bodies are decoded before entering the encrypted response', async t => {
  const { endpoint, fetch } = await rig(t)
  const attestFetch = attestLink(endpoint, { pcr0: PCR0, fetch, verify })
  const body = randomBytes(32 * 1024)
  for (const encoding of ['gzip', 'deflate', 'br']) {
    const response = await attestFetch(`/compressed/${encoding}`, { method: 'POST', body })
    assert.equal(response.headers.get('content-encoding'), null)
    assert.ok(body.equals(Buffer.from(await response.arrayBuffer())))
  }
})

test('preflight allows only transport headers and can be cached without calling the hook or backend', async t => {
  const { endpoint, requests } = await rig(t, 'exit 1')
  for (const action of ['hello', 'fetch']) {
    for (const requested of ['content-type,attest-link-session', 'authorization,x-application']) {
      const url = new URL(endpoint)
      url.pathname += `/${action}`
      const response = await http2Fetch(url, {
        method: 'OPTIONS', headers: {
          origin: 'https://example.com', 'access-control-request-method': 'POST',
          'access-control-request-headers': requested,
        },
      })
      assert.equal(response.status, 204)
      assert.equal(response.headers.get('access-control-allow-origin'), '*')
      assert.equal(response.headers.get('access-control-allow-methods'), 'POST')
      assert.equal(response.headers.get('access-control-allow-headers'), 'content-type, attest-link-session')
      assert.equal(response.headers.get('access-control-max-age'), '600')
      assert.equal(response.headers.get('access-control-allow-credentials'), null)
      assert.equal(response.headers.get('access-control-expose-headers'), null)
    }
  }
  assert.equal(requests.length, 0)
})

test('CORS permits reading transport errors without allowing browser credentials', async t => {
  const { endpoint, requests } = await rig(t, 'exit 1')
  t.mock.method(console, 'error', () => {})
  const hello = JSON.stringify({
    nonce: 'ab'.repeat(32), publicKey: Buffer.alloc(32, 1).toString('base64'), mode: 'fetch',
  })
  for (const [action, body, status] of [['hello', '{}', 400], ['fetch', '{}', 403], ['hello', hello, 500]]) {
    const url = new URL(endpoint)
    url.pathname += `/${action}`
    const response = await http2Fetch(url, {
      method: 'POST', headers: { origin: 'https://example.com', 'content-type': 'application/json' }, body,
    })
    assert.equal(response.status, status)
    assert.equal(response.headers.get('access-control-allow-origin'), '*')
    assert.equal(response.headers.get('access-control-allow-credentials'), null)
    assert.equal(response.headers.get('access-control-expose-headers'), null)
    assert.equal((await response.json()).status, status)
  }
  assert.equal(requests.length, 0)
})

test('application headers are encrypted while cookies use the outer requests and responses', async t => {
  const { endpoint, fetch, requests, wire } = await rig(t, 'cat')
  const responses = []
  const capture = async (url, init) => {
    const response = await fetch(url, init)
    responses.push(response)
    return response
  }
  const attestFetch = attestLink(endpoint, { anyPCR: true, fetch: capture, verify, extra: ['hello'], credentials: 'include' })
  const response = await attestFetch('/cookies', { headers: {
    cookie: 'session=existing; theme=light', authorization: 'Bearer app-token', 'x-app': 'present',
    'content-type': 'application/x-private',
  } })
  await response.text()
  assert.equal(response.evidence.userData.cookies, 'session=existing; theme=light')
  assert.deepEqual(response.evidence.userData.extra, ['hello'])
  assert.equal(requests[0].headers.cookie, 'session=existing; theme=light')
  assert.equal(requests[0].headers.authorization, 'Bearer app-token')
  assert.equal(requests[0].headers['x-app'], 'present')
  assert.equal(requests[0].headers['content-type'], 'application/x-private')
  assert.ok(wire.every(({ init }) => init.credentials === 'include'))
  for (const { init } of wire) {
    assert.equal(init.headers.get('authorization'), null)
    assert.equal(init.headers.get('x-app'), null)
    assert.equal(init.headers.get('cookie'), 'session=existing; theme=light')
    assert.equal(init.headers.get('content-type'), 'application/json')
    assert.equal(init.body.includes('Bearer app-token'), false)
    assert.equal(init.body.includes('x-app'), false)
    assert.equal(init.body.includes('application/x-private'), false)
  }
  for (const response of responses) {
    assert.equal(response.headers.get('access-control-allow-origin'), '*')
    assert.equal(response.headers.get('access-control-allow-credentials'), null)
    assert.equal(response.headers.get('access-control-expose-headers'), null)
    assert.equal(response.headers.get('access-control-allow-headers'), null)
    assert.equal(response.headers.get('access-control-allow-methods'), null)
  }
  // The Node adapter exposes the outer Set-Cookie headers. Browsers process
  // them themselves; the reconstructed Response never exposes their values.
  assert.deepEqual(responses[1].headers.getSetCookie(), [
    'session=one; HttpOnly; Path=/; SameSite=Lax', 'theme=dark; Path=/',
  ])
  assert.deepEqual(response.headers.getSetCookie(), [])
  await attestFetch('/cookies', { credentials: 'omit' })
  assert.ok(wire.slice(2).every(({ init }) => init.credentials === 'omit'))
})

test('outer request headers cannot add or replace application headers', async t => {
  const { endpoint, fetch, requests } = await rig(t)
  const inject = (url, init) => {
    const headers = new Headers(init.headers)
    headers.set('authorization', 'Bearer injected')
    headers.set('x-app', 'injected')
    headers.set('x-injected', 'proxy')
    headers.set('x-forwarded-for', '192.0.2.1')
    headers.set('cookie', 'session=browser')
    return fetch(url, { ...init, headers })
  }
  const attestFetch = attestLink(endpoint, { pcr0: PCR0, fetch: inject, verify })
  await attestFetch('/protected', { headers: { authorization: 'Bearer private', 'x-app': 'private' } })
  await attestFetch('/anonymous')
  assert.equal(requests[0].headers.authorization, 'Bearer private')
  assert.equal(requests[0].headers['x-app'], 'private')
  assert.equal(requests[1].headers.authorization, undefined)
  assert.equal(requests[1].headers['x-app'], undefined)
  for (const { headers } of requests) {
    assert.equal(headers['x-injected'], undefined)
    assert.equal(headers['x-forwarded-for'], undefined)
    assert.equal(headers.cookie, 'session=browser')
  }
})

test('outer response headers cannot add or replace application headers', async t => {
  const { endpoint, fetch } = await rig(t)
  const inject = async (url, init) => {
    const response = await fetch(url, init)
    response.headers.set('content-type', 'text/plain')
    response.headers.set('x-backend', 'injected')
    response.headers.set('x-injected', 'proxy')
    response.headers.set('cache-control', 'public, max-age=3600')
    return response
  }
  const attestFetch = attestLink(endpoint, { pcr0: PCR0, fetch: inject, verify })
  const response = await attestFetch('/binary', { method: 'POST', body: 'private body' })
  assert.equal(response.headers.get('content-type'), 'application/octet-stream')
  assert.equal(response.headers.get('x-backend'), 'attested-app')
  assert.equal(response.headers.get('x-injected'), null)
  assert.equal(response.headers.get('cache-control'), null)
  assert.equal(await response.text(), 'private body')
})

test('backend cookies and Host come only from the outer request', async t => {
  const { endpoint, requests } = await rig(t)
  for (const cookie of [undefined, 'session=outer']) {
    const session = await startFetch(endpoint)
    try {
      const url = new URL(endpoint)
      url.pathname += '/fetch'
      const headers = { 'attest-link-session': session.sessionId, 'content-type': 'application/json' }
      if (cookie) headers.cookie = cookie
      const response = await http2Fetch(url, {
        method: 'POST', headers,
        body: JSON.stringify(util.encryptJson({
          path: '/cookies', method: 'GET', body: null,
          headers: [['cookie', 'session=inner'], ['host', 'elsewhere.test']],
        }, session.keys.sharedTx)),
      })
      assert.equal(response.status, 200)
      await response.text()
      assert.equal(requests.at(-1).headers.cookie, cookie)
      assert.equal(requests.at(-1).headers.host, new URL(endpoint).host)
    } finally {
      sodium.memzero(session.keys.sharedTx)
      sodium.memzero(session.keys.sharedRx)
    }
  }
})

test('browser fetch preserves binary bodies, HEAD, empty responses and application errors', async t => {
  const { endpoint, fetch } = await rig(t)
  const attestFetch = attestLink(endpoint, { pcr0: PCR0, fetch, verify })
  const input = randomBytes(256 * 1024)
  const response = await attestFetch('/binary', {
    method: 'POST', body: input, headers: { 'content-type': 'application/octet-stream' },
  })
  const output = Buffer.from(await response.arrayBuffer())
  assert.equal(output.length, input.length)
  assert.ok(output.equals(input))
  const head = await attestFetch('/head', { method: 'HEAD' })
  assert.equal(head.status, 200)
  assert.equal(head.body, null)
  const empty = await attestFetch('/empty')
  assert.equal(empty.status, 204)
  assert.equal(empty.body, null)
  const error = await attestFetch('/error')
  assert.equal(error.status, 418)
  assert.equal(error.ok, false)
  assert.equal((await error.json()).path, '/error')
})

test('concurrent browser fetches use independent attestations and keys', async t => {
  const { endpoint, fetch, wire, requests } = await rig(t)
  const attestFetch = attestLink(endpoint, { pcr0: PCR0, fetch, verify })
  const responses = await Promise.all(Array.from({ length: 6 }, (_, i) => attestFetch(`/request/${i}`)))
  const bodies = await Promise.all(responses.map(response => response.json()))
  assert.deepEqual(bodies.map(body => body.path), Array.from({ length: 6 }, (_, i) => `/request/${i}`))
  assert.equal(new Set(responses.map(response => response.evidence.nonce)).size, 6)
  assert.equal(new Set(wire.filter(item => new URL(item.url).pathname.endsWith('/fetch'))
    .map(item => item.init.headers.get('attest-link-session'))).size, 6)
  assert.equal(requests.length, 6)
})

test('one pooled HTTP/2 connection serves independent hellos while fetches can switch connections', async t => {
  const { endpoint, requests, server } = await rig(t)
  let connections = 0
  server.on('session', () => connections++)
  const conn = http2.connect(endpoint)
  t.after(() => conn.destroy())
  const pooled = (url, init) => http2Fetch(url, init, new URL(url).pathname.endsWith('/hello') ? conn : undefined)
  const attestFetch = attestLink(endpoint, { pcr0: PCR0, fetch: pooled, verify })
  const first = await Promise.all([attestFetch('/one'), attestFetch('/two')])
  assert.deepEqual(await Promise.all(first.map(response => response.json())).then(bodies => bodies.map(body => body.path)), ['/one', '/two'])
  assert.equal((await (await attestFetch('/three')).json()).path, '/three')
  assert.equal(requests.length, 3)
  assert.equal(connections, 4, 'One shared hello connection plus three independent fetch connections')

  const sameConnection = attestLink(endpoint, {
    pcr0: PCR0, fetch: (url, init) => http2Fetch(url, init, conn), verify,
  })
  assert.equal((await (await sameConnection('/four')).json()).path, '/four')
  assert.equal(connections, 4)
})

test('an unused browser session expires and a new hello can authorize a later request', async t => {
  const { endpoint, fetch, requests } = await rig(t)
  t.mock.timers.enable({ apis: ['setTimeout'] })
  let delayed = false
  const delayFirst = async (url, init) => {
    if (!delayed && new URL(url).pathname.endsWith('/fetch')) {
      delayed = true
      t.mock.timers.tick(5001)
    }
    return fetch(url, init)
  }
  const attestFetch = attestLink(endpoint, { pcr0: PCR0, fetch: delayFirst, verify, timeout: 10000 })
  await assert.rejects(attestFetch('/expired'), /HTTP 403/)
  assert.equal(requests.length, 0)
  assert.equal((await (await attestFetch('/fresh')).json()).path, '/fresh')
  assert.equal(requests.length, 1)
})

test('validly encrypted backend escape paths cannot reach an application', async t => {
  const { endpoint, requests } = await rig(t)
  t.mock.method(console, 'error', () => {})
  for (const path of ['http://elsewhere.test/', '//elsewhere.test/', '/\\elsewhere.test/', '/private\r\nHost: elsewhere.test']) {
    const session = await startFetch(endpoint)
    try {
      const url = new URL(endpoint)
      url.pathname += '/fetch'
      const response = await http2Fetch(url, {
        method: 'POST', headers: { 'attest-link-session': session.sessionId, 'content-type': 'application/json' },
        body: JSON.stringify(util.encryptJson({ path, method: 'GET', headers: [], body: null }, session.keys.sharedTx)),
      })
      assert.ok(response.status >= 400)
      await response.text()
    } finally {
      sodium.memzero(session.keys.sharedTx)
      sodium.memzero(session.keys.sharedRx)
    }
  }
  assert.equal(requests.length, 0)
})

test('response application headers are encrypted and HttpOnly cookies remain outside the envelope', async t => {
  const { endpoint } = await rig(t)
  const session = await startFetch(endpoint)
  try {
    const url = new URL(endpoint)
    url.pathname += '/fetch'
    const response = await http2Fetch(url, {
      method: 'POST', headers: { 'attest-link-session': session.sessionId, 'content-type': 'application/json' },
      body: JSON.stringify(util.encryptJson({ path: '/binary', method: 'GET', headers: [], body: null }, session.keys.sharedTx)),
    })
    assert.equal(response.status, 200)
    assert.equal(response.headers.getSetCookie().length, 2)
    assert.equal(response.headers.get('content-type'), 'application/json')
    assert.equal(response.headers.get('x-backend'), null)
    const body = await response.text()
    assert.equal(body.includes('attested-app'), false)
    assert.equal(body.includes('application/octet-stream'), false)
    const payload = util.decryptJson(JSON.parse(body), session.keys.sharedRx)
    assert.deepEqual(Object.keys(payload).sort(), ['body', 'headers', 'status', 'statusText'])
    const headers = new Headers(payload.headers)
    assert.equal(headers.get('content-type'), 'application/octet-stream')
    assert.equal(headers.get('x-backend'), 'attested-app')
    assert.equal(headers.get('set-cookie'), null)
    assert.equal(JSON.stringify(payload).includes('session=one'), false)
  } finally {
    sodium.memzero(session.keys.sharedTx)
    sodium.memzero(session.keys.sharedRx)
  }
})

test('wrong PCR and rejected evidence never forward an application request', async t => {
  const { endpoint, fetch, requests } = await rig(t)
  await assert.rejects(attestLink(endpoint, { pcr0: '34'.repeat(48), fetch, verify })('/private'), /verification failed/)
  await assert.rejects(attestLink(endpoint, { anyPCR: true, fetch, verify: async () => false })('/private'), /verification failed/)
  assert.equal(requests.length, 0)
})

test('browser fetch rejects malformed hello and tampered encrypted responses', async t => {
  const { endpoint, fetch, requests } = await rig(t)
  for (const fields of [{ version: '2.0.0' }, { platform: 'tdx' }, { sessionId: 'bad' }, { publicKey: 'bad' }]) {
    const altered = async (url, init) => {
      const response = await fetch(url, init)
      return new Response(JSON.stringify({ ...await response.json(), ...fields }))
    }
    await assert.rejects(attestLink(endpoint, { pcr0: PCR0, fetch: altered, verify })('/private'))
  }
  assert.equal(requests.length, 0)
  const tampered = async (url, init) => {
    const response = await fetch(url, init)
    if (!new URL(url).pathname.endsWith('/fetch')) return response
    const box = await response.json()
    const encrypted = util.decodeBase64(box.encrypted)
    encrypted[0] ^= 1
    return new Response(JSON.stringify({ ...box, encrypted: util.encodeBase64(encrypted) }))
  }
  await assert.rejects(attestLink(endpoint, { pcr0: PCR0, fetch: tampered, verify })('/private'))
  assert.equal(requests.length, 1)
})

test('browser fetch does not retry a POST after a lost response and rejects session replay', async t => {
  const { endpoint, fetch, requests, wire } = await rig(t)
  const lost = async (url, init) => {
    const response = await fetch(url, init)
    if (!new URL(url).pathname.endsWith('/fetch')) return response
    await response.arrayBuffer()
    throw new Error('Response lost')
  }
  await assert.rejects(attestLink(endpoint, { pcr0: PCR0, fetch: lost, verify })('/write', { method: 'POST', body: 'once' }), /Response lost/)
  assert.equal(requests.length, 1)
  const first = wire.find(({ url }) => new URL(url).pathname.endsWith('/fetch'))
  const replay = await http2Fetch(first.url, { ...first.init, signal: undefined })
  assert.equal(replay.status, 403)
  await replay.text()
  assert.equal(requests.length, 1)
})

test('browser fetch handles cancellation and verification timeouts before forwarding', async t => {
  const { endpoint, fetch, requests } = await rig(t)
  const controller = new AbortController()
  controller.abort(new Error('User cancelled'))
  await assert.rejects(attestLink(endpoint, { pcr0: PCR0, fetch, verify })('/private', { signal: controller.signal }), /User cancelled/)
  await assert.rejects(attestLink(endpoint, {
    pcr0: PCR0, fetch, verify: () => new Promise(() => {}), timeout: 40,
  })('/private'), /timeout/)
  assert.equal(requests.length, 0)
})

test('browser fetch rejects backend escapes and bounds buffered data', async () => {
  const attestFetch = attestLink('https://example.com/attest', { anyPCR: true })
  for (const path of ['https://elsewhere.test/', '//elsewhere.test/', '/\\elsewhere.test/', '/private#fragment']) {
    await assert.rejects(attestFetch(path), /Fetch path/)
  }
  await sodium.ready
  await assert.rejects(util.readBytes(new Response('too long'), 3), /too large/)
  assert.throws(() => util.encryptJson({ body: 'a'.repeat(util.FETCH_MAX_BYTES) }, sodium.randombytes_buf(32)), /too large/)
})
