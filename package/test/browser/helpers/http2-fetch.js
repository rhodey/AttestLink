import http2 from 'node:http2'
import { Readable } from 'node:stream'

// Native browser fetch chooses HTTP/2 behind HTTPS. This adapter lets the same
// browser client exercise the server's cleartext HTTP/2 listener in Node tests.
export function http2Fetch(url, init = {}, connection) {
  return new Promise((resolve, reject) => {
    const target = new URL(url)
    const conn = connection ?? http2.connect(target.origin)
    let stream
    const fail = error => {
      reject(error)
      stream?.destroy(error)
      if (!connection) conn.destroy()
    }
    const abort = () => fail(init.signal.reason)
    conn.on('error', fail)
    init.signal?.addEventListener('abort', abort, { once: true })
    if (init.signal?.aborted) return abort()
    const headers = Object.fromEntries(new Headers(init.headers))
    stream = conn.request({
      ...headers, ':method': init.method ?? 'GET', ':path': target.pathname + target.search,
    })
    stream.on('error', fail)
    stream.once('close', () => {
      init.signal?.removeEventListener('abort', abort)
      // An owned session can emit its connection error after the stream closes.
      if (connection) conn.removeListener('error', fail)
      else conn.close()
    })
    stream.once('response', headers => {
      const responseHeaders = new Headers()
      for (const [name, value] of Object.entries(headers)) {
        if (name.startsWith(':')) continue
        for (const entry of Array.isArray(value) ? value : [value]) responseHeaders.append(name, entry)
      }
      const status = headers[':status']
      const empty = init.method === 'HEAD' || [204, 205, 304].includes(status)
      if (empty) stream.resume()
      resolve(new Response(empty ? null : Readable.toWeb(stream), { status, headers: responseHeaders }))
    })
    stream.end(init.body)
  })
}
