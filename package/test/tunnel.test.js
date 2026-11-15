import assert from 'node:assert/strict'
import { createHash, randomBytes } from 'node:crypto'
import { once } from 'node:events'
import http2 from 'node:http2'
import net from 'node:net'
import test from 'node:test'
import sodium from 'libsodium-wrappers'
import { attestServer } from '../src/attest-server.js'
import { attestTunnel } from '../src/attest-client.js'
import * as duplex from '../src/attest-duplex.js'
import * as util from '../src/util.js'
import { Readable } from 'node:stream'

const PCR0 = '12'.repeat(48)
const HELLO_MAX_BYTES = 32 * 1024

// These callbacks isolate transport tests from the hardware verifier. They are
// passed directly to library functions; production CLIs always invoke NSM and
// the real signed-document verifier and cannot enable these fixtures.
const attest = async (nonce, publicKey) => Buffer.from(JSON.stringify({ nonce, publicKey, pcr0: PCR0 })).toString('base64')
const verify = async (document, nonce, publicKey, pcr0) => {
  const fixture = JSON.parse(Buffer.from(document, 'base64'))
  if (fixture.nonce !== nonce || fixture.publicKey !== publicKey) return false
  if (pcr0 !== undefined && fixture.pcr0 !== pcr0) return false
  return { pcrs: { 0: fixture.pcr0 } }
}

async function listen(server, host = '127.0.0.1') {
  server.listen(0, host)
  await once(server, 'listening')
  return server.address().port
}

async function rig(t, {
  attestor = attest, verifier = verify, pcr0 = PCR0, timeout = 1000,
  backendUnavailable = false, backendHost, path = '', hello,
} = {}) {
  let backendConnections = 0
  const backends = new Set()
  const backend = net.createServer({ allowHalfOpen: true }, socket => {
    backendConnections++
    backends.add(socket)
    socket.on('error', () => {})
    socket.once('close', () => backends.delete(socket))
    // Return the digest only after EOF. This exercises half-close and prevents
    // a test from passing merely by echoing a prefix of a large transfer.
    const hash = createHash('sha256')
    socket.on('data', chunk => hash.update(chunk))
    socket.once('end', () => socket.end(hash.digest('hex')))
  })
  const backendPort = await listen(backend, backendHost)
  if (backendUnavailable) await new Promise(resolve => backend.close(resolve))
  const target = backendHost ? `${backendHost.includes(':') ? `[${backendHost}]` : backendHost}:${backendPort}` : backendPort
  const server = await attestServer(target, undefined, attestor)
  const requestPaths = []
  server.on('stream', (stream, headers) => requestPaths.push(headers[':path']))
  server.prependListener('stream', (stream, headers) => {
    if (!hello || !new URL(headers[':path'], 'http://test').pathname.endsWith('/hello')) return
    const end = stream.end
    t.mock.method(stream, 'end', function (body, ...args) {
      return end.call(this, JSON.stringify({ ...JSON.parse(body), ...hello }), ...args)
    })
  })
  const port = await listen(server)
  const endpoint = `http://127.0.0.1:${port}${path}`
  const proxy = attestTunnel(endpoint, pcr0, undefined, verifier, timeout)
  const localPort = await listen(proxy)
  t.after(async () => {
    proxy.closeConnections()
    server.closeConnections()
    for (const socket of backends) socket.destroy()
    await Promise.all([proxy, server, backend].map(s => new Promise(resolve => s.close(resolve))))
  })
  return { endpoint, localPort, backends, requestPaths, connections: () => backendConnections }
}

async function transfer(port, bytes) {
  const socket = net.createConnection({ host: '127.0.0.1', port, allowHalfOpen: true })
  socket.on('error', () => {})
  await once(socket, 'connect')
  socket.end(bytes)
  const chunks = []
  for await (const chunk of socket) chunks.push(chunk)
  return Buffer.concat(chunks).toString()
}

test('concurrent attested connections preserve bulk data and TCP half-close', { timeout: 10000 }, async t => {
  const errors = t.mock.method(console, 'error', () => {})
  const { localPort, connections } = await rig(t)
  const payloads = Array.from({ length: 6 }, (_, i) => randomBytes(512 * 1024 + i))
  const results = await Promise.all(payloads.map(payload => transfer(localPort, payload)))
  assert.deepEqual(results, payloads.map(payload => createHash('sha256').update(payload).digest('hex')))
  assert.equal(connections(), 6)
  assert.equal(errors.mock.callCount(), 0)
})

test('wrong measurement rejects before any backend connection or plaintext forwarding', async t => {
  const { localPort, connections } = await rig(t, { pcr0: '34'.repeat(48) })
  assert.equal(await transfer(localPort, Buffer.from('must never reach sshd')).catch(error => { assert.equal(error.code, 'ECONNRESET'); return '' }), '')
  assert.equal(connections(), 0)
})

test('compatible Nitro protocol versions complete an attested transfer', async t => {
  for (const version of ['1.0.0', '1.0.7', '1.2.0', '1.9.1+build.3']) {
    await t.test(version, async t => {
      const { localPort, connections } = await rig(t, { hello: { version } })
      const payload = randomBytes(1024)
      assert.equal(await transfer(localPort, payload), createHash('sha256').update(payload).digest('hex'))
      assert.equal(connections(), 1)
    })
  }
})

test('incompatible versions and platforms stop before verification or duplex setup', async t => {
  const cases = [
    ...[undefined, null, 1, {}, 'invalid', '1.0', '0.9.0', '2.0.0', '1.1.0-beta.1'].map(version => ({ version })),
    ...[undefined, null, 'Nitro', 'tdx', 'sev'].map(platform => ({ platform })),
  ]
  for (const hello of cases) {
    const [field] = Object.keys(hello)
    await t.test(`${field}: ${String(hello[field])}`, async t => {
      let verifications = 0
      const verifier = async (...args) => { verifications++; return verify(...args) }
      const { endpoint, requestPaths, connections } = await rig(t, { hello, verifier })
      await assert.rejects(duplex.client(endpoint, {
        verify: verifier, pcr0: PCR0, signal: new AbortController().signal,
      }), field === 'version' ? /Incompatible protocol version/ : /Unsupported attestation platform/)
      assert.equal(verifications, 0)
      assert.equal(connections(), 0)
      assert.equal(requestPaths.length, 1)
    })
  }
})

test('endpoint paths are appended literally and explicit backend addresses carry the tunnel', async t => {
  for (const [path, backendHost] of [
    ['', '127.0.0.2'],
    ['/idk', '127.0.0.2'],
    ['/idk/', '::1'],
    ['/nested/%20name?tenant=attest-link', '127.0.0.2'],
    [`/${'long'.repeat(80)}`, '127.0.0.2'],
  ]) {
    await t.test(path || '/', async t => {
      const { localPort, requestPaths, connections } = await rig(t, { path, backendHost })
      const payload = randomBytes(4096)
      assert.equal(await transfer(localPort, payload), createHash('sha256').update(payload).digest('hex'))
      assert.equal(connections(), 1)
      const requests = requestPaths.map(value => new URL(value, 'http://test'))
      const base = new URL(path || '/', 'http://test')
      const prefix = base.pathname.replace(/\/+$/, '')
      assert.deepEqual(requests.map(url => url.pathname), [`${prefix}/hello`, `${prefix}/duplex`])
      assert.deepEqual(requests.map(url => url.searchParams.get('tenant')), [base.searchParams.get('tenant'), base.searchParams.get('tenant')])
      assert.deepEqual(requests.map(url => url.search), [base.search, base.search])
    })
  }
})

test('proxy forwards verified connections without an expected PCR0', async t => {
  const { endpoint, connections } = await rig(t)
  const proxy = attestTunnel(endpoint, undefined, undefined, verify)
  t.after(async () => {
    proxy.closeConnections()
    await new Promise(resolve => proxy.close(resolve))
  })
  const port = await listen(proxy)
  const payload = randomBytes(1024)
  assert.equal(await transfer(port, payload), createHash('sha256').update(payload).digest('hex'))
  assert.equal(connections(), 1)
})

test('client returns evidence with optional PCR0 and closes the backend when streams are destroyed', { timeout: 2000 }, async t => {
  const { endpoint, connections, backends } = await rig(t)
  for (const pcr0 of [undefined, PCR0]) {
    const controller = new AbortController()
    const [encrypt, decrypt, evidence] = await duplex.client(endpoint, { pcr0, verify, signal: controller.signal })
    assert.equal(evidence.pcrs[0], PCR0)
    assert.equal(backends.size, 1)
    const closed = Promise.all([...backends].map(socket => once(socket, 'close')))
    encrypt.destroy()
    decrypt.destroy()
    await closed
    assert.equal(backends.size, 0)
  }
  assert.equal(connections(), 2)
})

test('client rejects false evidence even without a PCR0 policy', async t => {
  const { endpoint, connections } = await rig(t)
  const controller = new AbortController()
  await assert.rejects(duplex.client(endpoint, {
    verify: async () => false, signal: controller.signal,
  }), /Attestation verification failed/)
  assert.equal(connections(), 0)
})

test('duplex endpoint rejects an unknown session ID', async t => {
  const { endpoint, connections } = await rig(t)
  const session = http2.connect(endpoint)
  t.after(() => session.destroy())
  const request = session.request({ ':method': 'POST', ':path': '/.well-known/attest-link/duplex', 'attest-link-session': 'ab'.repeat(32) })
  const response = once(request, 'response')
  request.end()
  request.resume()
  assert.equal((await response)[0][':status'], 403)
  assert.equal(connections(), 0)
})

test('a cancelled connection does not cancel another connection', { timeout: 10000 }, async t => {
  const { localPort } = await rig(t)
  const cancelled = net.createConnection({ host: '127.0.0.1', port: localPort })
  cancelled.on('error', () => {})
  await once(cancelled, 'connect')
  cancelled.destroy()
  const payload = randomBytes(1024 * 1024)
  assert.equal(await transfer(localPort, payload), createHash('sha256').update(payload).digest('hex'))
})

test('attestation timeout closes the local connection without touching sshd', async t => {
  let finishAttestation
  const attestor = (nonce, publicKey) => new Promise(resolve => {
    finishAttestation = () => resolve(attest(nonce, publicKey))
  })
  t.after(() => finishAttestation?.())
  const { localPort, connections } = await rig(t, { attestor, timeout: 40 })
  assert.equal(await transfer(localPort, Buffer.from('withheld until verification')).catch(error => { assert.equal(error.code, 'ECONNRESET'); return '' }), '')
  assert.equal(connections(), 0)
})

test('proxy and client reject invalid supplied PCR0 policies', async () => {
  for (const pcr0 of [null, '', '12', '00'.repeat(48)]) {
    assert.throws(() => attestTunnel('http://127.0.0.1:2222', pcr0), /PCR0|pcr0/)
    const controller = new AbortController()
    await assert.rejects(duplex.client('http://127.0.0.1:2222', { pcr0, signal: controller.signal }), /PCR0|pcr0/)
  }
  assert.throws(() => attestTunnel('ftp://127.0.0.1:2222', PCR0), /http:\/\/ or https:\/\//)
})

test('nonce and attested key substitutions fail before opening the SSH backend', async t => {
  for (const field of ['nonce', 'publicKey']) {
    await t.test(field, async t => {
      const attestor = async (nonce, publicKey) => {
        const fixture = JSON.parse(Buffer.from(await attest(nonce, publicKey), 'base64'))
        fixture[field] = field === 'nonce' ? 'ab'.repeat(32) : randomBytes(32).toString('base64')
        return Buffer.from(JSON.stringify(fixture)).toString('base64')
      }
      const { localPort, connections } = await rig(t, { attestor })
      const received = await transfer(localPort, Buffer.from('private data')).catch(error => {
        assert.equal(error.code, 'ECONNRESET')
        return ''
      })
      assert.equal(received, '')
      assert.equal(connections(), 0)
    })
  }
})

test('attestation response reader enforces its size bound', async () => {
  await assert.rejects(util.readJson(Readable.from([Buffer.alloc(HELLO_MAX_BYTES + 1)]), HELLO_MAX_BYTES), /too large/)
})

test('JSON reader preserves native parser errors and their input context', async () => {
  for (const body of ['{"version":"1.0.0"', '\u001b[31mnot JSON\u0007\r\n']) {
    let expected
    try { JSON.parse(body) } catch (error) { expected = error }
    await assert.rejects(util.readJson(Readable.from([Buffer.from(body)]), HELLO_MAX_BYTES), error => {
      assert.ok(error instanceof SyntaxError)
      assert.equal(error.message, expected.message)
      return true
    })
  }
})

test('backend connection failure closes only the stream that leaves its POST body open', { timeout: 2000 }, async t => {
  const { endpoint } = await rig(t, { backendUnavailable: true })
  const session = http2.connect(endpoint)
  session.on('error', () => {})
  t.after(() => session.destroy())
  const keys = sodium.crypto_kx_keypair()
  const body = { nonce: randomBytes(32).toString('hex'), publicKey: Buffer.from(keys.publicKey).toString('base64') }
  sodium.memzero(keys.privateKey)
  const hello = session.request({ ':method': 'POST', ':path': '/.well-known/attest-link/hello', 'content-type': 'application/json' })
  hello.end(JSON.stringify(body))
  const reply = await util.readJson(hello, HELLO_MAX_BYTES)
  assert.equal(reply.version, '1.0.0')
  assert.equal(reply.platform, 'nitro')
  const request = session.request({
    ':method': 'POST', ':path': '/.well-known/attest-link/duplex', 'attest-link-session': reply.sessionId,
  }, { endStream: false })
  const closed = new Promise(resolve => request.once('close', resolve))
  request.on('error', () => {})
  const [headers] = await once(request, 'response')
  assert.equal(headers[':status'], 400)
  request.resume()
  await closed
  assert.equal(session.closed, false)
  const health = session.request({ ':method': 'GET', ':path': '/health' })
  health.end()
  const [response] = await once(health, 'response')
  assert.equal(response[':status'], 200)
  health.resume()
})

test('pending TCP connects are destroyed on handshake timeout and cancellation', { timeout: 2000 }, async t => {
  for (const mode of ['timeout', 'cancellation']) {
    await t.test(mode, async t => {
      // A deliberately unfinished lookup gives us a real Socket in connecting
      // state, without depending on an external address dropping SYN packets.
      const socket = new net.Socket()
      socket.on('error', () => {})
      socket.connect({ host: 'pending.invalid', port: 2222, lookup() {} })
      t.mock.method(net, 'createConnection', () => socket)
      const keepAlive = setInterval(() => {}, 1000)
      t.after(() => { clearInterval(keepAlive); socket.destroy() })
      const controller = new AbortController()
      const cancellation = mode === 'cancellation' ? setTimeout(() => controller.abort(), 20) : null
      t.after(() => clearTimeout(cancellation))
      const started = performance.now()
      await assert.rejects(duplex.client('http://pending.invalid:2222', {
        signal: controller.signal,
        timeout: mode === 'timeout' ? 20 : 1000,
      }), /abort|timeout/i)
      assert.equal(socket.destroyed, true, 'The underlying pending TCP socket must be destroyed')
      assert.ok(performance.now() - started < 500, 'Cleanup must not wait for the OS connection timeout')
    })
  }
})
