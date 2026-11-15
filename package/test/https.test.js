import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash, randomBytes } from 'node:crypto'
import { once } from 'node:events'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import net from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import tls from 'node:tls'
import { attestServer } from '../src/attest-server.js'
import { attestTunnel } from '../src/attest-client.js'
import * as duplex from '../src/attest-duplex.js'

const PCR0 = '12'.repeat(48)
// Generate a short-lived test identity; no TLS keys enter the app or image.
const directory = await mkdtemp(join(tmpdir(), 'attest-link-tls-'))
let key, cert
try {
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-noenc', '-days', '1',
    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
    '-keyout', join(directory, 'key.pem'), '-out', join(directory, 'cert.pem'),
  ], { stdio: 'pipe' })
  key = await readFile(join(directory, 'key.pem'))
  cert = await readFile(join(directory, 'cert.pem'), 'utf8')
} finally {
  await rm(directory, { recursive: true, force: true })
}

function trustCertificate(t) {
  const previous = tls.getCACertificates('default')
  tls.setDefaultCACertificates([...previous, cert])
  t.after(() => tls.setDefaultCACertificates(previous))
}

async function listen(server) {
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  return server.address().port
}

const verify = async (document, nonce, publicKey, pcr0) => {
  const evidence = JSON.parse(Buffer.from(document, 'base64'))
  if (evidence.nonce !== nonce || evidence.publicKey !== publicKey || evidence.pcr0 !== pcr0) return false
  return evidence
}

async function rig(t) {
  const sockets = new Set()
  const tlsInfo = []
  const paths = []
  let backendConnections = 0
  const track = socket => {
    sockets.add(socket)
    socket.on('error', () => {})
    socket.once('close', () => sockets.delete(socket))
    return socket
  }
  const backend = net.createServer({ allowHalfOpen: true }, socket => {
    track(socket)
    backendConnections++
    const hash = createHash('sha256')
    socket.on('data', chunk => hash.update(chunk))
    socket.once('end', () => socket.end(hash.digest('hex')))
  })
  const backendPort = await listen(backend)
  const server = await attestServer(backendPort, undefined, async (nonce, publicKey) => {
    return Buffer.from(JSON.stringify({ nonce, publicKey, pcr0: PCR0 })).toString('base64')
  })
  server.on('stream', (stream, headers) => paths.push(headers[':path']))
  const serverPort = await listen(server)

  // Terminate TLS, forwarding the HTTP/2 bytes to the ordinary attestation
  // server. Attestation and secretstream still run between the two apps.
  const frontend = tls.createServer({ key, cert, ALPNProtocols: ['h2'], allowHalfOpen: true }, client => {
    track(client)
    tlsInfo.push({ servername: client.servername, alpn: client.alpnProtocol })
    const upstream = track(net.createConnection({ host: '127.0.0.1', port: serverPort, allowHalfOpen: true }))
    client.once('close', () => upstream.destroy())
    upstream.once('close', () => client.destroy())
    client.pipe(upstream).pipe(client)
  })
  frontend.on('connection', track)
  frontend.on('tlsClientError', () => {})
  const port = await listen(frontend)
  t.after(async () => {
    for (const socket of sockets) socket.destroy()
    server.closeConnections()
    await Promise.all([frontend, server, backend].map(listener => new Promise(resolve => listener.close(resolve))))
  })
  return { endpoint: `https://localhost:${port}/idk?tenant=attest-link`, tlsInfo, paths, connections: () => backendConnections }
}

test('HTTPS validates its certificate and tunnels attested streams through TLS termination', { timeout: 5000 }, async t => {
  trustCertificate(t)
  const { endpoint, tlsInfo, paths, connections } = await rig(t)
  const proxy = attestTunnel(endpoint, PCR0, undefined, verify)
  t.after(async () => { proxy.closeConnections(); await new Promise(resolve => proxy.close(resolve)) })
  const port = await listen(proxy)
  const payloads = Array.from({ length: 3 }, () => randomBytes(256 * 1024 + 17))
  const results = await Promise.all(payloads.map(async payload => {
    const socket = net.createConnection({ host: '127.0.0.1', port, allowHalfOpen: true })
    await once(socket, 'connect')
    socket.end(payload)
    const chunks = []
    for await (const chunk of socket) chunks.push(chunk)
    return Buffer.concat(chunks).toString()
  }))
  assert.deepEqual(results, payloads.map(payload => createHash('sha256').update(payload).digest('hex')))
  assert.equal(connections(), 3)
  assert.deepEqual(tlsInfo, Array.from({ length: 3 }, () => ({ servername: 'localhost', alpn: 'h2' })))
  const requests = paths.map(path => new URL(path, 'https://localhost'))
  assert.equal(requests.filter(url => url.pathname === '/idk/hello').length, 3)
  assert.equal(requests.filter(url => url.pathname === '/idk/duplex').length, 3)
  assert.ok(requests.every(url => url.searchParams.get('tenant') === 'attest-link'))
})

test('HTTPS rejects untrusted certificates before attestation', { timeout: 3000 }, async t => {
  const { endpoint, connections } = await rig(t)
  let verifications = 0
  await assert.rejects(duplex.client(endpoint, {
    signal: new AbortController().signal,
    verify: async () => { verifications++; return {} },
  }), { code: 'DEPTH_ZERO_SELF_SIGNED_CERT' })
  assert.equal(verifications, 0)
  assert.equal(connections(), 0)
})

test('HTTPS rejects a trusted certificate for the wrong hostname', { timeout: 3000 }, async t => {
  trustCertificate(t)
  const { endpoint, connections } = await rig(t)
  let verifications = 0
  await assert.rejects(duplex.client(endpoint.replace('localhost', '127.0.0.1'), {
    signal: new AbortController().signal,
    verify: async () => { verifications++; return {} },
  }), { code: 'ERR_TLS_CERT_ALTNAME_INVALID' })
  assert.equal(verifications, 0)
  assert.equal(connections(), 0)
})

test('valid HTTPS cannot bypass a rejected attestation', { timeout: 3000 }, async t => {
  trustCertificate(t)
  const { endpoint, connections } = await rig(t)
  await assert.rejects(duplex.client(endpoint, {
    pcr0: '34'.repeat(48), verify, signal: new AbortController().signal,
  }), /Attestation verification failed/)
  assert.equal(connections(), 0)
})

test('a stalled TLS handshake is closed on timeout or cancellation', { timeout: 3000 }, async t => {
  for (const mode of ['timeout', 'cancellation']) {
    await t.test(mode, async t => {
      const accepted = Promise.withResolvers()
      let peer
      const server = net.createServer(socket => { peer = socket; socket.resume(); accepted.resolve(socket) })
      const port = await listen(server)
      t.after(async () => { peer?.destroy(); await new Promise(resolve => server.close(resolve)) })
      const controller = new AbortController()
      const request = duplex.client(`https://127.0.0.1:${port}`, {
        timeout: mode === 'timeout' ? 40 : 1000, signal: controller.signal,
      })
      const rejected = assert.rejects(request, mode === 'timeout' ? /Attestation handshake timeout/ : /cancelled/)
      const socket = await accepted.promise
      const closed = once(socket, 'close')
      if (mode === 'cancellation') controller.abort(new Error('cancelled'))
      await rejected
      await closed
    })
  }
})
