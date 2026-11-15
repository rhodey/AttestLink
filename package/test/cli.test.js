import assert from 'node:assert/strict'
import { execFile, spawn } from 'node:child_process'
import { once } from 'node:events'
import http2 from 'node:http2'
import net from 'node:net'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import * as duplex from '../src/attest-duplex.js'

const run = promisify(execFile)
const cli = fileURLToPath(new URL('../src/bin.js', import.meta.url))

async function readiness(t, args) {
  const child = spawn(process.execPath, [cli, ...args], { timeout: 3000 })
  const closed = once(child, 'close')
  let stderr = ''
  child.stderr.on('data', chunk => { stderr += chunk })
  t.after(async () => { child.kill('SIGTERM'); await closed })
  const [chunk] = await Promise.race([
    once(child.stdout, 'data'),
    closed.then(() => { throw new Error(`CLI exited before readiness: ${stderr}`) }),
  ])
  const event = JSON.parse(chunk.toString())
  assert.equal(event.event, 'listening')
  return event
}

test('client and server modes bind bare ports and explicit IPv4/IPv6 addresses', async t => {
  for (const host of [undefined, '127.0.0.2', '0.0.0.0', '::1']) {
    await t.test(host ?? 'bare port', async t => {
      const address = port => host ? `${host.includes(':') ? `[${host}]` : host}:${port}` : String(port)
      const server = await readiness(t, ['-s', address(0), '127.0.0.2:2223'])
      assert.equal(server.address, host ?? '0.0.0.0')
      assert.ok(server.port > 0)

      // Port zero means evidence-only in client mode, so reserve a port and release
      // it before starting its listener on the same address.
      const reservation = net.createServer()
      reservation.listen(0, host ?? '127.0.0.1')
      await once(reservation, 'listening')
      const port = reservation.address().port
      await new Promise(resolve => reservation.close(resolve))
      const client = await readiness(t, [address(port), 'http://127.0.0.1:2222/idk', '--any-pcr'])
      assert.equal(client.address, host ?? '127.0.0.1')
      assert.equal(client.port, port)
    })
  }
})

async function expectFailure(t, server, message) {
  const sockets = new Set()
  server.on('connection', socket => {
    sockets.add(socket)
    socket.on('error', () => {})
    socket.once('close', () => sockets.delete(socket))
  })
  server.on('session', session => session.on('error', () => {}))
  t.after(async () => {
    for (const socket of sockets) socket.destroy()
    await new Promise(resolve => server.close(resolve))
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const endpoint = `http://127.0.0.1:${server.address().port}`
  for (const listen of ['0', 'stdio']) {
    await assert.rejects(run(process.execPath, [cli, listen, endpoint, '--any-pcr'], { timeout: 3000 }), error => {
      assert.equal(error.code, 1, 'The CLI must reject the handshake itself, without being killed by the test')
      assert.equal(error.signal, null)
      assert.equal(error.stdout, '', 'Failed handshakes must not print readiness or evidence')
      assert.match(error.stderr, /attest-link \(error\) .+/)
      assert.doesNotMatch(error.stderr, /[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/)
      if (message) assert.match(error.stderr, message)
      return true
    })
  }
}

test('port zero and stdio exit with an error when TCP closes before attestation', async t => {
  for (const method of ['end', 'destroy', 'resetAndDestroy']) {
    await t.test(method, async t => {
      await expectFailure(t, net.createServer(socket => socket[method]()))
    })
  }
})

test('port zero and stdio exit with an error when HTTP/2 closes before response headers', async t => {
  for (const mode of ['connection', 'stream end', 'stream cancel']) {
    await t.test(mode, async t => {
      const server = http2.createServer()
      server.on('stream', stream => {
        stream.on('error', () => {})
        if (mode === 'connection') stream.session.destroy()
        else stream.close(mode === 'stream end' ? http2.constants.NGHTTP2_NO_ERROR : http2.constants.NGHTTP2_CANCEL)
      })
      await expectFailure(t, server)
    })
  }
})

test('port zero and stdio exit with an error when the response has no complete evidence', async t => {
  for (const body of ['', '{"version":"1.0.0"', '\u001b[31mnot JSON\u0007\r\n']) {
    await t.test(JSON.stringify(body), async t => {
      const server = http2.createServer()
      server.on('stream', stream => {
        stream.respond({ ':status': 200 })
        stream.end(body)
      })
      await expectFailure(t, server, body.startsWith('\u001b') ? /Unexpected token.*not JSON/ : undefined)
    })
  }
})

test('unverified endpoint errors cannot emit terminal controls or forge log lines', async t => {
  const server = http2.createServer()
  const message = '\u001b]0;untrusted title\u0007\u001b[31mAccess denied\u001b[0m\r\n\b\u0007\u009b2J 日本語'
  const connections = new Set()
  server.on('session', connection => {
    connections.add(connection)
    connection.on('error', () => {})
    connection.once('close', () => connections.delete(connection))
  })
  server.on('stream', stream => {
    stream.on('error', () => {})
    stream.respond({ ':status': 403, 'content-type': 'application/json' })
    stream.end(JSON.stringify({ message }))
  })
  t.after(async () => {
    for (const connection of connections) connection.destroy()
    await new Promise(resolve => server.close(resolve))
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const endpoint = `http://127.0.0.1:${server.address().port}`
  await assert.rejects(duplex.client(endpoint, {
    signal: new AbortController().signal,
  }), { message: `Server returned HTTP 403: ${message}` })
  for (const listen of ['0', 'stdio']) {
    await assert.rejects(run(process.execPath, [cli, listen, endpoint, '--any-pcr'], { timeout: 3000 }), error => {
      assert.equal(error.code, 1)
      assert.equal(error.stdout, '')
      assert.match(error.stderr, /^attest-link \(error\) Server returned HTTP 403: .*Access denied 日本語\n$/)
      assert.doesNotMatch(error.stderr.slice(0, -1), /[\u0000-\u001f\u007f-\u009f]/)
      return true
    })
  }
})

test('invalid extra JSON and hook options in the wrong mode fail before listening', async () => {
  for (const args of [
    ['-e', '{', '0', 'http://127.0.0.1:1'],
    ['-c', 'cat', '0', 'http://127.0.0.1:1'],
    ['-s', '-e', '{}', '0', '1'],
  ]) {
    await assert.rejects(run(process.execPath, [cli, ...args], { timeout: 3000 }), error => {
      assert.equal(error.code, 1)
      assert.equal(error.stdout, '')
      assert.match(error.stderr, /attest-link \(error\)/)
      return true
    })
  }
})

test('client requires PCR0 or --any-pcr, and rejects conflicting or server-only use', async () => {
  const endpoint = 'http://127.0.0.1:1'
  for (const [args, message] of [
    ...['0', 'stdio', '2222'].map(listen => [[listen, endpoint], 'Provide PCR0 or --any-pcr']),
    [['0', endpoint, '12'.repeat(48), '--any-pcr'], 'Cannot combine PCR0 with --any-pcr'],
    [['-s', '0', '1', '--any-pcr'], '--any-pcr is only valid in client mode'],
  ]) {
    await assert.rejects(run(process.execPath, [cli, ...args], { timeout: 3000 }), error => {
      assert.equal(error.code, 1)
      assert.equal(error.signal, null)
      assert.equal(error.stdout, '')
      assert.equal(error.stderr.trim(), `attest-link (error) ${message}`)
      return true
    })
  }
})
