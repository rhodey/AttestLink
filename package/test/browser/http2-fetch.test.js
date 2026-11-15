import assert from 'node:assert/strict'
import { once } from 'node:events'
import http2 from 'node:http2'
import test from 'node:test'
import { http2Fetch } from './helpers/http2-fetch.js'

test('HTTP/2 test adapter rejects connection refusal without an uncaught session error', async () => {
  const server = http2.createServer()
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const endpoint = `http://127.0.0.1:${server.address().port}`
  await new Promise(resolve => server.close(resolve))

  await assert.rejects(http2Fetch(endpoint), error => (error.cause ?? error).code === 'ECONNREFUSED')
})
