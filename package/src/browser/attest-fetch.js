import sodium from 'libsodium-wrappers'
import semver from 'semver'
import * as attest from './attest-wasm.js'
import * as util from './fetch-util.js'

const HELLO_MAX_BYTES = 32 * 1024
const FETCH_TIMEOUT = 5_000

async function wait(promise, signal) {
  let abort
  const cancelled = new Promise((resolve, reject) => {
    abort = () => reject(signal.reason)
    if (signal.aborted) abort()
    else signal.addEventListener('abort', abort, { once: true })
  })
  try { return await Promise.race([promise, cancelled]) }
  finally { signal.removeEventListener('abort', abort) }
}

export function attestLink(endpoint, {
  pcr0, anyPCR, extra, credentials = 'same-origin', fetch = globalThis.fetch,
  verify = attest.verifyDoc, timeout = FETCH_TIMEOUT,
} = {}) {
  if (pcr0 === undefined) {
    if (anyPCR !== true) throw new Error('Supply pcr0 or anyPCR: true')
  } else {
    if (anyPCR) throw new Error('Supply pcr0 or anyPCR, not both')
    if (!/^[a-f0-9]{96}$/.test(pcr0) || /^0+$/.test(pcr0)) {
      throw new Error('PCR0 must be a nonzero SHA-384 measurement (96 lowercase hex digits)')
    }
  }
  const target = new URL(endpoint)
  if (!['http:', 'https:'].includes(target.protocol) || target.username || target.password || target.hash) {
    throw new Error('Endpoint must be an http:// or https:// URL without credentials or a fragment')
  }
  const actionUrl = action => {
    const url = new URL(target)
    url.pathname = `${url.pathname.replace(/\/+$/, '')}/${action}`
    return url.href
  }

  return async function attestFetch(path, init = {}) {
    if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//') || /[\\#\r\n]/.test(path)) {
      throw new Error('Fetch path must start with / and stay within the backend')
    }
    const controller = new AbortController()
    const signal = init.signal ? AbortSignal.any([init.signal, controller.signal]) : controller.signal
    const timer = setTimeout(() => controller.abort(new Error('Attested fetch timeout')), timeout)
    let keys, sessionKeys
    try {
      await wait(sodium.ready, signal)
      const request = new Request(new URL(path, target.origin), { ...init, signal })
      const headers = new Headers(request.headers)
      for (const name of ['host', 'content-length', 'connection', 'transfer-encoding', 'attest-link-session']) headers.delete(name)
      const wireHeaders = new Headers({ 'content-type': 'application/json' })
      // Browsers supply cookies through credentials; Node callers can set them explicitly.
      if (headers.has('cookie')) wireHeaders.set('cookie', headers.get('cookie'))
      headers.delete('cookie')
      const selectedCredentials = init.credentials ?? credentials
      const send = async (action, body, sessionId) => {
        const headers = new Headers(wireHeaders)
        if (sessionId) headers.set('attest-link-session', sessionId)
        const response = await wait(fetch(actionUrl(action), {
          method: 'POST', headers, body: JSON.stringify(body), signal,
          credentials: selectedCredentials, redirect: 'error', cache: 'no-store',
        }), signal)
        if (response.status !== 200) {
          const error = await util.readJson(response, HELLO_MAX_BYTES, signal).catch(() => null)
          const message = typeof error?.message === 'string' ? `: ${error.message}` : ''
          throw new Error(`Server returned HTTP ${response.status}${message}`)
        }
        return response
      }

      const body = request.body ? util.encodeBase64(await util.readBytes(request, util.FETCH_MAX_BYTES, signal)) : null
      keys = sodium.crypto_kx_keypair()
      const nonce = sodium.to_hex(sodium.randombytes_buf(32))
      const hello = await util.readJson(await send('hello', {
        nonce, publicKey: util.encodeBase64(keys.publicKey), extra, mode: 'fetch',
      }), HELLO_MAX_BYTES, signal)
      if (typeof hello.version !== 'string' || !semver.satisfies(hello.version, '^1.0.0')) {
        throw new Error('Incompatible protocol version')
      }
      if (hello.platform !== 'nitro') throw new Error('Unsupported attestation platform')
      if (!/^[a-f0-9]{64}$/.test(hello.sessionId ?? '')) throw new Error('Invalid hello response')
      const publicKey = util.decodeBase64(hello.publicKey)
      if (publicKey.length !== 32) throw new Error('Invalid server public key')
      const evidence = await wait(verify(hello.document, nonce, hello.publicKey, pcr0), signal)
      if (!evidence) throw new Error('Attestation verification failed')
      sessionKeys = sodium.crypto_kx_client_session_keys(keys.publicKey, keys.privateKey, publicKey)

      const response = await send('fetch', util.encryptJson({
        path, method: request.method, headers: [...headers], body,
      }, sessionKeys.sharedTx), hello.sessionId)
      const result = util.decryptJson(await util.readJson(response, util.FETCH_MAX_BYTES, signal), sessionKeys.sharedRx)
      if (!Number.isInteger(result.status) || result.status < 200 || result.status > 599 ||
          typeof result.statusText !== 'string' || !Array.isArray(result.headers)) {
        throw new Error('Invalid HTTP response')
      }
      const responseHeaders = new Headers(result.headers)
      for (const name of ['set-cookie', 'content-length', 'content-encoding', 'transfer-encoding']) responseHeaders.delete(name)
      const bytes = result.body === null ? null : util.decodeBase64(result.body)
      const output = new Response(bytes, { status: result.status, statusText: result.statusText, headers: responseHeaders })
      output.evidence = evidence
      return output
    } catch (error) {
      throw signal.aborted ? signal.reason : error
    } finally {
      clearTimeout(timer)
      controller.abort()
      if (keys) sodium.memzero(keys.privateKey)
      if (sessionKeys) {
        sodium.memzero(sessionKeys.sharedTx)
        sodium.memzero(sessionKeys.sharedRx)
      }
    }
  }
}
