import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { once } from 'node:events'
import { access, mkdtemp, rm } from 'node:fs/promises'
import http2 from 'node:http2'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { attestServer } from '../src/attest-server.js'
import * as duplex from '../src/attest-duplex.js'
import * as util from '../src/util.js'

const cli = fileURLToPath(new URL('../src/bin.js', import.meta.url))
const quote = value => `'${value.replaceAll("'", "'\\''")}'`
const input = extra => ({ nonce: randomBytes(32).toString('hex'), publicKey: randomBytes(32).toString('base64'), extra })

async function rig(t, hook) {
  const calls = []
  const server = await attestServer(1, hook, async (nonce, publicKey, userData) => {
    const evidence = { nonce, publicKey, userData }
    calls.push(evidence)
    return Buffer.from(JSON.stringify(evidence)).toString('base64')
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  t.after(async () => {
    server.closeConnections()
    await new Promise(resolve => server.close(resolve))
  })
  return { endpoint: `http://127.0.0.1:${server.address().port}/hello-test?tenant=one`, calls, server }
}

function session(t, endpoint) {
  const connection = http2.connect(endpoint)
  connection.on('error', () => {})
  t.after(() => connection.destroy())
  return connection
}

async function request(t, endpoint, body, method = 'POST', requestHeaders = {}) {
  const connection = session(t, endpoint)
  const url = new URL(endpoint)
  const stream = connection.request({
    ':method': method, ':path': `${url.pathname.replace(/\/+$/, '')}/hello${url.search}`,
    'content-type': 'application/json', ...requestHeaders,
  }, { endStream: false })
  stream.on('error', () => {})
  const response = once(stream, 'response')
  stream.end(body)
  const [headers] = await response
  const output = await util.readJson(stream, 64 * 1024)
  connection.close()
  return { status: headers[':status'], body: output }
}

test('POST hello sends every JSON extra type to the hook and attests its object output', async t => {
  const { endpoint, calls } = await rig(t, 'cat')
  for (const extra of [undefined, null, false, 0, '', 'hello\n日本語', [], [1, true, null], { nested: { value: 42 } }]) {
    const hello = input(extra)
    const response = await request(t, endpoint, JSON.stringify(hello))
    assert.equal(response.status, 200)
    const evidence = JSON.parse(Buffer.from(response.body.document, 'base64'))
    assert.deepEqual(evidence.userData, { ...JSON.parse(JSON.stringify(hello)), cookies: '' })
    assert.equal(evidence.nonce, hello.nonce)
    assert.equal(evidence.publicKey, response.body.publicKey)
    assert.notEqual(evidence.publicKey, hello.publicKey, 'The document binds the server key; hook input contains the client key')
  }
  assert.equal(calls.length, 9)
})

test('hook cookies come from HTTP headers, preserving values and duplicate order', async t => {
  const { endpoint } = await rig(t, 'cat')
  for (const [cookie, expected] of [
    [undefined, ''],
    ['session=a%3Bb%3Dc+e; repeat=first; repeat=second', 'session=a%3Bb%3Dc+e; repeat=first; repeat=second'],
    [['repeat=first', 'token=%2F%3D+value', 'repeat=second'], 'repeat=first; token=%2F%3D+value; repeat=second'],
  ]) {
    const hello = { ...input(), cookies: 'forged=from-json' }
    const headers = cookie === undefined ? {} : { cookie }
    const response = await request(t, endpoint, JSON.stringify(hello), 'POST', headers)
    assert.equal(response.status, 200)
    const evidence = JSON.parse(Buffer.from(response.body.document, 'base64'))
    assert.deepEqual(evidence.userData, {
      nonce: hello.nonce, publicKey: hello.publicKey, cookies: expected,
    })
  }
})

test('extra is stdin data, never part of the Bash hook', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'attest-link-hello-'))
  t.after(() => rm(directory, { recursive: true, force: true }))
  const marker = join(directory, 'injected')
  const extra = `$(touch ${quote(marker)}); \`touch ${quote(marker)}\`\n'\"\\`
  const { endpoint } = await rig(t, 'cat')
  const response = await request(t, endpoint, JSON.stringify(input(extra)))
  assert.equal(response.status, 200)
  assert.equal(JSON.parse(Buffer.from(response.body.document, 'base64')).userData.extra, extra)
  await assert.rejects(access(marker), { code: 'ENOENT' })
})

test('hello requires POST and a valid bounded JSON request before running the hook', async t => {
  t.mock.method(console, 'error', () => {})
  const { endpoint, calls } = await rig(t, 'exit 1')
  assert.equal((await request(t, endpoint, JSON.stringify(input()), 'GET')).status, 404)
  for (const body of ['', '{', 'null', '[]', '{}', JSON.stringify({ ...input(), nonce: 'wrong' }), JSON.stringify({ ...input(), publicKey: 'wrong' }), JSON.stringify(input('x'.repeat(33 * 1024)))]) {
    assert.equal((await request(t, endpoint, body)).status, 400)
  }
  assert.equal(calls.length, 0)
})

test('malformed hello requests retain parsing detail in safe server warnings', async t => {
  const errors = t.mock.method(console, 'error', () => {})
  const { endpoint, calls } = await rig(t)
  const response = await request(t, endpoint, '\u001b[31mnot JSON\u0007\r\n')
  assert.equal(response.status, 400)
  assert.equal(calls.length, 0)
  assert.equal(errors.mock.callCount(), 1)
  const [prefix, message] = errors.mock.calls[0].arguments
  assert.equal(prefix, 'attest-link (warn)')
  assert.match(message, /Unexpected token.*not JSON/)
  assert.doesNotMatch(message, /[\u0000-\u001f\u007f-\u009f]/)
})

test('hook exit two returns its HTTP error and message without obtaining a document', async t => {
  const rejection = { code: 429, message: 'Please try again later' }
  const { endpoint, calls } = await rig(t, `printf '%s' ${quote(JSON.stringify(rejection))}; exit 2`)
  assert.deepEqual(await request(t, endpoint, JSON.stringify(input())), { status: 429, body: rejection })
  await assert.rejects(duplex.client(endpoint, {
    signal: new AbortController().signal,
    verify: async () => { throw new Error('Verification must not run') },
  }), /Server returned HTTP 429.*Please try again later/)
  assert.equal(calls.length, 0)
})

test('hook failures and invalid output return HTTP 500 without obtaining a document', async t => {
  t.mock.method(console, 'error', () => {})
  for (const hook of [
    'exit 1', 'exit 3', 'kill -KILL $$',
    "printf 'not JSON'", "printf 'null'", "printf '[]'", "printf '\"text\"'",
    "printf '%s' '{\"code\":200,\"message\":\"wrong status\"}'; exit 2",
    "printf '%s' '{\"code\":403}'; exit 2",
    "printf '%*s' 70000 ''; printf '{}'",
    "printf '%*s' 70000 '' >&2; printf '{}'",
    "false | printf '{}'",
  ]) {
    await t.test(hook, async t => {
      const { endpoint, calls } = await rig(t, hook)
      const response = await request(t, endpoint, JSON.stringify(input()))
      assert.equal(response.status, 500)
      assert.deepEqual(response.body, { status: 500, error: 'Internal Server Error' })
      assert.equal(calls.length, 0)
    })
  }
})

test('hello can finish after five seconds without a server request deadline', async t => {
  const { endpoint, server } = await rig(t)
  t.mock.timers.enable({ apis: ['setTimeout'] })
  const connection = session(t, endpoint)
  const received = once(server, 'stream')
  const stream = connection.request({ ':method': 'POST', ':path': '/hello' })
  stream.on('error', () => {})
  const response = once(stream, 'response')
  const body = JSON.stringify(input())
  stream.write(body.slice(0, 1))
  const [incoming] = await received
  t.mock.timers.tick(5001)
  assert.equal(incoming.closed, false)
  stream.end(body.slice(1))
  assert.equal((await response)[0][':status'], 200)
  assert.equal(typeof (await util.readJson(stream, 64 * 1024)).document, 'string')
})

test('disconnect and stream cancellation stop hook descendants', { timeout: 6000 }, async t => {
  for (const mode of ['disconnect', 'stream cancellation']) {
    await t.test(mode, async t => {
      const directory = await mkdtemp(join(tmpdir(), 'attest-link-hook-'))
      t.after(() => rm(directory, { recursive: true, force: true }))
      const ready = join(directory, 'ready')
      const leaked = join(directory, 'leaked')
      const hook = `(printf ready > ${quote(ready)}; sleep 1; printf leaked > ${quote(leaked)}) & wait`
      const { endpoint, calls } = await rig(t, hook)
      const connection = session(t, endpoint)
      const closed = new Promise(resolve => connection.once('close', resolve))
      const stream = connection.request({ ':method': 'POST', ':path': '/hello', 'content-type': 'application/json' })
      stream.on('error', () => {})
      stream.end(JSON.stringify(input()))
      // Wait for the child to start so disconnect cannot pass by preventing spawn.
      for (let attempt = 0;; attempt++) {
        try { await access(ready); break } catch (err) {
          if (err.code !== 'ENOENT' || attempt === 40) throw err
          await new Promise(resolve => setTimeout(resolve, 10))
        }
      }
      if (mode === 'stream cancellation') {
        const cancelled = once(stream, 'close')
        stream.close(http2.constants.NGHTTP2_CANCEL)
        await cancelled
      } else {
        connection.destroy()
        await closed
      }
      await new Promise(resolve => setTimeout(resolve, 1100))
      await assert.rejects(access(leaked), { code: 'ENOENT' })
      assert.equal(calls.length, 0)
    })
  }
})

test('server CLI passes -c to Bash before requesting any attestation', async t => {
  const rejection = { code: 403, message: 'Not allowed by this hook' }
  const child = spawn(process.execPath, [cli, '-s', '-c', `printf '%s' ${quote(JSON.stringify(rejection))}; exit 2`, '127.0.0.1:0', '1'], { timeout: 3000 })
  const closed = once(child, 'close')
  t.after(async () => { child.kill('SIGTERM'); await closed })
  let stderr = ''
  child.stderr.on('data', chunk => { stderr += chunk })
  const [line] = await Promise.race([
    once(child.stdout, 'data'),
    closed.then(() => { throw new Error(`Server exited before readiness: ${stderr}`) }),
  ])
  const { port } = JSON.parse(line.toString())
  assert.deepEqual(await request(t, `http://127.0.0.1:${port}`, JSON.stringify(input())), { status: 403, body: rejection })
})
