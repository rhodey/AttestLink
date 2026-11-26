import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { once } from 'node:events'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import net from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { attestServer } from '../src/attest-server.js'

const cli = fileURLToPath(new URL('../src/bin.js', import.meta.url))
const PCR0 = '12'.repeat(48)
const userData = { text: 'first\nsecond\r\n日本語 🦊', nested: { enabled: true } }
const banner = Buffer.from([10, 255, 0, 13, 10, 128])

async function listen(server) {
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  return server.address().port
}

async function rig(t, beforeDocument = async () => {}, hook) {
  const directory = await mkdtemp(join(tmpdir(), 'attest-link-stdio-'))
  const helper = join(directory, 'verify-fixture.cjs')
  // Replace only the external helper in this child process. The production
  // command has no fixture mode; the real Rust verifier remains tested separately.
  await writeFile(helper, `#!${process.execPath}
const args = process.argv.slice(2)
if (args.shift() !== '-v') process.exit(1)
const options = Object.fromEntries(Array.from({ length: args.length / 2 }, (_, i) => args.slice(i * 2, i * 2 + 2)))
const document = require('node:fs').readFileSync(0, 'utf8').trim()
const evidence = JSON.parse(Buffer.from(document, 'base64'))
if (evidence.nonce !== options['--nonce'] || evidence.publicKey !== options['--public-key'] ||
    (options['--pcr0'] !== undefined && evidence.pcrs['0'] !== options['--pcr0'])) process.exit(2)
process.stdout.write(JSON.stringify(evidence))
`, { mode: 0o700 })

  let connections = 0
  const sockets = new Set()
  const backend = net.createServer({ allowHalfOpen: true }, socket => {
    connections++
    sockets.add(socket)
    socket.on('error', () => {})
    socket.once('close', () => sockets.delete(socket))
    socket.write(banner)
    const input = []
    socket.on('data', chunk => input.push(chunk))
    // The response is deliberately withheld until stdin/TCP EOF reaches us.
    socket.once('end', () => {
      if (!socket.writableEnded) socket.end(Buffer.concat(input))
    })
  })
  const backendPort = await listen(backend)
  const server = await attestServer(backendPort, hook, async (nonce, publicKey, metadata) => {
    await beforeDocument()
    const data = hook === undefined ? userData : metadata
    return Buffer.from(JSON.stringify({ timestamp: 123, nonce, publicKey, pcrs: { 0: PCR0 }, userData: data })).toString('base64')
  })
  const port = await listen(server)
  t.after(async () => {
    server.closeConnections()
    for (const socket of sockets) socket.destroy()
    await Promise.all([backend, server].map(server => new Promise(resolve => server.close(resolve))))
    await rm(directory, { recursive: true, force: true })
  })
  return { endpoint: `http://127.0.0.1:${port}/stdio-test`, helper, backend, server, sockets, connections: () => connections }
}

function start(t, helper, args) {
  const child = spawn(process.execPath, [cli, ...args], {
    env: { ...process.env, ATTEST_LINK_RUST: helper }, timeout: 8000,
  })
  const closed = once(child, 'close')
  t.after(async () => { child.kill('SIGKILL'); await closed })
  const chunks = [], errors = []
  child.stdout.on('data', chunk => chunks.push(chunk))
  child.stderr.on('data', chunk => errors.push(chunk))
  child.stdin.on('error', () => {})
  const output = () => Buffer.concat(chunks)
  const stderr = () => Buffer.concat(errors).toString()
  const line = async number => {
    for (;;) {
      const bytes = output()
      let begin = 0
      for (let i = 0; i <= number; i++) {
        const end = bytes.indexOf(10, begin)
        if (end === -1) break
        if (i === number) return JSON.parse(bytes.subarray(begin, end).toString('utf8'))
        begin = end + 1
      }
      await Promise.race([
        once(child.stdout, 'data'),
        closed.then(() => { throw new Error(`CLI ended before line ${number}: ${stderr()}`) }),
      ])
    }
  }
  return { child, closed, output, stderr, line }
}

function decodeOutput(bytes) {
  const first = bytes.indexOf(10)
  const second = bytes.indexOf(10, first + 1)
  assert.ok(first >= 0 && second > first, 'Expected two complete JSON lines')
  return {
    listening: JSON.parse(bytes.subarray(0, first).toString('utf8')),
    evidence: JSON.parse(bytes.subarray(first + 1, second).toString('utf8')),
    data: bytes.subarray(second + 1),
  }
}

test('stdio emits two compact headers then binary data and waits for the response after stdin EOF', { timeout: 10000 }, async t => {
  const { endpoint, helper, connections } = await rig(t)
  const command = start(t, helper, ['stdio', endpoint, PCR0])
  const payload = randomBytes(2 * 1024 * 1024 + 17)
  command.child.stdin.end(payload)
  assert.deepEqual(await command.line(0), { event: 'listening', address: 'stdio' })
  // Stop reading temporarily so piping must honor stdout backpressure.
  command.child.stdout.pause()
  await new Promise(resolve => setTimeout(resolve, 100))
  command.child.stdout.resume()
  assert.deepEqual(await command.closed, [0, null], command.stderr())
  const { listening, evidence, data } = decodeOutput(command.output())
  assert.deepEqual(listening, { event: 'listening', address: 'stdio' })
  assert.equal(evidence.pcrs[0], PCR0)
  assert.deepEqual(evidence.serverClaims, userData)
  assert.equal(data.length, banner.length + payload.length)
  assert.ok(data.equals(Buffer.concat([banner, payload])), 'Tunnel payload differs')
  assert.equal(connections(), 1)
  assert.equal(command.stderr(), '')
})

test('stdio with --any-pcr withholds both headers and input until attestation succeeds', { timeout: 10000 }, async t => {
  let allowDocument, reachedHello
  const waiting = new Promise(resolve => { reachedHello = resolve })
  const gate = new Promise(resolve => { allowDocument = resolve })
  t.after(() => allowDocument())
  const { endpoint, helper, connections } = await rig(t, () => { reachedHello(); return gate })
  const command = start(t, helper, ['--any-pcr', 'stdio', endpoint])
  command.child.stdin.end('input buffered before verification')
  await waiting
  assert.equal(command.output().length, 0)
  assert.equal(connections(), 0)
  allowDocument()
  assert.deepEqual(await command.closed, [0, null], command.stderr())
  assert.deepEqual(decodeOutput(command.output()).data,
    Buffer.concat([banner, Buffer.from('input buffered before verification')]))
  assert.equal(connections(), 1)
})

test('stdio rejects failed attestation without stdout, headers, or a backend connection', async t => {
  const { endpoint, helper, connections } = await rig(t)
  const command = start(t, helper, ['stdio', endpoint, '34'.repeat(48)])
  command.child.stdin.end('must not reach backend')
  assert.deepEqual(await command.closed, [1, null])
  assert.equal(command.output().length, 0)
  assert.equal(connections(), 0)
  assert.match(command.stderr(), /attest-link \(error\) Attestation verification failed/)
})

test('stdio still delivers stdin and its EOF after the backend finishes sending first', { timeout: 10000 }, async t => {
  const { endpoint, helper, backend } = await rig(t)
  const received = new Promise(resolve => backend.once('connection', socket => {
    const chunks = []
    socket.on('data', chunk => chunks.push(chunk))
    socket.once('end', () => resolve(Buffer.concat(chunks)))
    socket.end()
    socket.pause()
    setTimeout(() => socket.resume(), 200)
  }))
  const command = start(t, helper, ['stdio', endpoint, PCR0])
  await command.line(1)
  const payload = randomBytes(2 * 1024 * 1024 + 17)
  command.child.stdin.end(payload)
  assert.deepEqual(await command.closed, [0, null], command.stderr())
  assert.deepEqual(decodeOutput(command.output()).data, banner)
  const data = await received
  assert.equal(data.length, payload.length)
  assert.ok(data.equals(payload), 'Uploaded payload differs')
})

test('stdio exits nonzero on a truncated tunnel or a closed stdout pipe even while stdin stays open', async t => {
  for (const failure of ['tunnel', 'stdout']) {
    await t.test(failure, async t => {
      const { endpoint, helper, server, sockets } = await rig(t)
      const command = start(t, helper, ['stdio', endpoint, PCR0])
      await command.line(1)
      if (failure === 'tunnel') server.closeConnections()
      else {
        command.child.stdout.destroy()
        for (const socket of sockets) socket.write(Buffer.alloc(64 * 1024))
      }
      assert.deepEqual(await command.closed, [1, null], command.stderr())
      assert.match(command.stderr(), /attest-link \(error\)/)
    })
  }
})

test('port zero keeps formatted evidence output with no listening event', async t => {
  const { endpoint, helper } = await rig(t)
  const command = start(t, helper, ['0', endpoint, PCR0])
  command.child.stdin.end()
  assert.deepEqual(await command.closed, [0, null], command.stderr())
  assert.ok(command.output().toString().startsWith('{\n  '))
  assert.equal(JSON.parse(command.output()).pcrs[0], PCR0)
  assert.equal(JSON.parse(command.output()).event, undefined)
})

test('TCP client logs one readiness line then compact evidence for each connection', async t => {
  const { endpoint, helper } = await rig(t)
  const reservation = net.createServer()
  const port = await listen(reservation)
  await new Promise(resolve => reservation.close(resolve))
  const command = start(t, helper, [String(port), endpoint, PCR0])
  command.child.stdin.end()
  assert.deepEqual(await command.line(0), { event: 'listening', address: '127.0.0.1', port })
  await Promise.all(Array.from({ length: 3 }, async (_, index) => {
    const socket = net.createConnection({ host: '127.0.0.1', port, allowHalfOpen: true })
    socket.end(String(index))
    const chunks = []
    for await (const chunk of socket) chunks.push(chunk)
    assert.deepEqual(Buffer.concat(chunks), Buffer.concat([banner, Buffer.from(String(index))]))
  }))
  const evidence = await Promise.all([1, 2, 3].map(command.line))
  for (const item of evidence) {
    assert.equal(item.pcrs[0], PCR0)
    assert.deepEqual(item.serverClaims, userData)
  }
  assert.equal(new Set(evidence.map(item => item.nonce)).size, 3)
  command.child.kill('SIGTERM')
  assert.deepEqual(await command.closed, [0, null], command.stderr())
  assert.equal(command.output().toString().split('\n').length, 5)
})

test('port-zero, stdio and TCP clients expose the verified server claims and both session keys', async t => {
  for (const [mode, extra] of [['0', 0], ['stdio', false], ['tcp', ['hello', { nested: null }]]]) {
    await t.test(mode, async t => {
      const { endpoint, helper } = await rig(t, undefined, 'cat')
      let address = mode
      if (mode === 'tcp') {
        const reservation = net.createServer()
        address = String(await listen(reservation))
        await new Promise(resolve => reservation.close(resolve))
      }
      const command = start(t, helper, ['-e', JSON.stringify(extra), address, endpoint, '--any-pcr'])
      command.child.stdin.end()
      let evidence
      if (mode === 'tcp') {
        await command.line(0)
        const socket = net.createConnection({ host: '127.0.0.1', port: Number(address), allowHalfOpen: true })
        socket.end('data')
        for await (const chunk of socket) assert.ok(chunk.length > 0)
        evidence = await command.line(1)
        command.child.kill('SIGTERM')
      }
      assert.deepEqual(await command.closed, [0, null], command.stderr())
      if (mode === '0') evidence = JSON.parse(command.output())
      if (mode === 'stdio') evidence = decodeOutput(command.output()).evidence
      const { nonce, clientPubKey, serverPubKey } = evidence
      assert.match(nonce, /^[a-f0-9]{64}$/)
      for (const key of [clientPubKey, serverPubKey]) assert.equal(Buffer.from(key, 'base64').length, 32)
      assert.notEqual(clientPubKey, serverPubKey)
      assert.deepEqual(evidence, {
        pcrs: { 0: PCR0 }, nonce, clientPubKey, serverPubKey, timestamp: 123,
        serverClaims: { nonce, clientPubKey, serverPubKey, extra, cookies: '' },
      })
    })
  }
})
