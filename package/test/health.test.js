import assert from 'node:assert/strict'
import { once } from 'node:events'
import http2 from 'node:http2'
import net from 'node:net'
import test from 'node:test'
import { attestServer } from '../src/attest-server.js'

test('health paths answer without attestation, hooks or backend connections', async t => {
  let backendConnections = 0
  const backend = net.createServer(socket => {
    backendConnections++
    socket.destroy()
  })
  backend.listen(0, '127.0.0.1')
  await once(backend, 'listening')
  const getDoc = t.mock.fn(() => { throw new Error('Health must not request attestation') })
  const server = await attestServer(backend.address().port, 'exit 1', getDoc)
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const conn = http2.connect(`http://127.0.0.1:${server.address().port}`)
  t.after(async () => {
    conn.destroy()
    server.closeConnections()
    await Promise.all([server, backend].map(server => new Promise(resolve => server.close(resolve))))
  })

  async function request(method, path) {
    const stream = conn.request({ ':method': method, ':path': path })
    const response = once(stream, 'response')
    stream.end()
    const [headers] = await response
    const chunks = []
    for await (const chunk of stream) chunks.push(chunk)
    return { status: headers[':status'], body: Buffer.concat(chunks).toString() }
  }

  for (const method of ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']) {
    for (const path of ['/health', '/attest/health', '/any/nested/path/health?check=1']) {
      assert.deepEqual(await request(method, path), {
        status: 200, body: method === 'HEAD' ? '' : 'OK',
      })
    }
  }
  for (const path of ['/health/', '/healthcheck', '/not-health', '/other?path=/health']) {
    assert.equal((await request('GET', path)).status, 404)
  }
  assert.equal(getDoc.mock.callCount(), 0)
  assert.equal(backendConnections, 0)
})
