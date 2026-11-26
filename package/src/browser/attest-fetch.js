import sodium from 'libsodium-wrappers'
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

function httpResponse(result, evidence) {
  if (!Number.isInteger(result?.status) || result.status < 200 || result.status > 599 ||
      typeof result.statusText !== 'string' || !Array.isArray(result.headers)) {
    throw new Error('Invalid HTTP response')
  }
  const headers = new Headers(result.headers)
  for (const name of ['set-cookie', 'content-length', 'content-encoding', 'transfer-encoding']) headers.delete(name)
  const bytes = result.body === null ? null : util.decodeBase64(result.body)
  const response = new Response(bytes, { status: result.status, statusText: result.statusText, headers })
  response.evidence = structuredClone(evidence)
  return response
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

  let queue = Promise.resolve()
  let session, idleTimer

  function forgetSession() {
    clearTimeout(idleTimer)
    sodium.memzero(session.keys.sharedTx)
    sodium.memzero(session.keys.sharedRx)
    session = undefined
  }

  async function openSession(send, signal) {
    const keys = sodium.crypto_kx_keypair()
    try {
      const nonce = sodium.to_hex(sodium.randombytes_buf(32))
      const clientPubKey = util.encodeBase64(keys.publicKey)
      const hello = await send('hello', {
        mode: 'fetch', version: util.PROTOCOL_VERSION, nonce, publicKey: clientPubKey, extra,
      }, HELLO_MAX_BYTES)
      if (!util.compatibleVersion(hello.version)) throw new Error('Incompatible protocol version')
      if (hello.platform !== 'nitro') throw new Error('Unsupported attestation platform')
      if (!/^[a-f0-9]{64}$/.test(hello.sessionId ?? '')) throw new Error('Invalid hello response')
      const publicKey = util.decodeBase64(hello.publicKey)
      if (publicKey.length !== 32) throw new Error('Invalid server public key')
      const verified = await wait(verify(hello.document, nonce, hello.publicKey, pcr0), signal)
      if (!verified) throw new Error('Attestation verification failed')
      return {
        id: hello.sessionId, seq: 0, expires: Date.now() + util.FETCH_SESSION_IDLE_MS,
        evidence: util.connectionEvidence(verified, nonce, clientPubKey),
        keys: sodium.crypto_kx_client_session_keys(keys.publicKey, keys.privateKey, publicKey),
      }
    } finally {
      sodium.memzero(keys.privateKey)
    }
  }

  async function dispatch(path, request, selectedCredentials, signal) {
    signal.throwIfAborted()
    await wait(sodium.ready, signal)
    const headers = new Headers(request.headers)
    for (const name of ['host', 'content-length', 'connection', 'transfer-encoding', 'attest-link-session']) headers.delete(name)
    const wireHeaders = new Headers({ 'content-type': 'application/json' })
    // Browsers supply cookies through credentials; Node callers can set them explicitly.
    if (headers.has('cookie')) wireHeaders.set('cookie', headers.get('cookie'))
    headers.delete('cookie')

    async function send(action, payload, limit, sessionId) {
      signal.throwIfAborted()
      const headers = new Headers(wireHeaders)
      if (sessionId) headers.set('attest-link-session', sessionId)
      const response = await wait(fetch(actionUrl(action), {
        method: 'POST', headers, body: JSON.stringify(payload), signal,
        credentials: selectedCredentials, redirect: 'error', cache: 'no-store',
      }), signal)
      if (response.status !== 200) {
        if (sessionId && response.status === 403) forgetSession()
        const error = await util.readJson(response, HELLO_MAX_BYTES, signal).catch(() => null)
        const message = typeof error?.message === 'string' ? `: ${error.message}` : ''
        throw new Error(`Server returned HTTP ${response.status}${message}`)
      }
      return util.readJson(response, limit, signal)
    }

    const body = request.body ? util.encodeBase64(await util.readBytes(request, util.FETCH_MAX_BYTES, signal)) : null
    if (session && (Date.now() >= session.expires || session.seq === Number.MAX_SAFE_INTEGER)) forgetSession()
    if (!session) session = await openSession(send, signal)
    // Hold the keys until this call finishes, even if the idle deadline passes.
    clearTimeout(idleTimer)
    const seq = ++session.seq
    const sent = Date.now()
    try {
      const box = util.encryptJson({ seq, request: { path, method: request.method, headers: [...headers], body } }, session.keys.sharedTx)
      const reply = await send('fetch', box, util.FETCH_MAX_BYTES, session.id)
      const result = util.decryptJson(reply, session.keys.sharedRx)
      if (result?.seq !== seq) throw new Error('Fetch response sequence mismatch')
      session.expires = sent + util.FETCH_SESSION_IDLE_MS
      return httpResponse(result.response, session.evidence)
    } finally {
      if (session) {
        const remaining = session.expires - Date.now()
        if (remaining <= 0) forgetSession()
        else {
          idleTimer = setTimeout(forgetSession, remaining)
          idleTimer.unref?.()
        }
      }
    }
  }

  return async function attestFetch(path, init = {}) {
    if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//') || /[\\#\r\n]/.test(path)) {
      throw new Error('Fetch path must start with / and stay within the backend')
    }
    const controller = new AbortController()
    const signal = init.signal ? AbortSignal.any([init.signal, controller.signal]) : controller.signal
    const timer = setTimeout(() => controller.abort(new Error('Attested fetch timeout')), timeout)
    try {
      signal.throwIfAborted()
      const request = new Request(new URL(path, target.origin), { ...init, signal })
      const selectedCredentials = init.credentials ?? credentials
      const work = queue.then(() => dispatch(path, request, selectedCredentials, signal))
      queue = work.then(() => {}, () => {})
      return await wait(work, signal)
    } catch (error) {
      throw signal.aborted ? signal.reason : error
    } finally {
      clearTimeout(timer)
      controller.abort()
    }
  }
}
