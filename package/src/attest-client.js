import net from 'node:net'
import * as duplex from './attest-duplex.js'
import * as util from './util.js'

// A local TCP listener.
export function attestTunnel(endpoint, pcr0, extra, verify, timeout) {
  if (pcr0 !== undefined) util.validPCR(pcr0)
  endpoint = duplex.endpointUrl(endpoint)
  const connections = new Set()

  const tcpServer = net.createServer({ pauseOnConnect: true, allowHalfOpen: true }, async client => {
    const controller = new AbortController()
    let encrypt, decrypt, evidence
    const close = () => {
      controller.abort()
      client.destroy()
      encrypt?.destroy()
      decrypt?.destroy()
      connections.delete(close)
    }
    connections.add(close)
    client.on('error', close)
    client.once('close', () => {
      // Normal EOF still needs to flush EncryptStream's final frame.
      if (!client.readableEnded || !client.writableFinished) close()
    })

    try {
      [encrypt, decrypt, evidence] = await duplex.client(endpoint, { pcr0, extra, verify, timeout, signal: controller.signal })
      if (client.destroyed) return close()
      const onStreamError = err => { console.error('attest-link (warn)', util.cleanMessage(err.message)); close() }
      encrypt.on('error', onStreamError)
      decrypt.on('error', onStreamError)
      const finished = () => {
        if (encrypt.readableEnded && decrypt.readableEnded) connections.delete(close)
      }
      encrypt.once('end', finished)
      decrypt.once('end', finished)

      tcpServer.emit('evidence', evidence)
      client.pipe(encrypt)
      decrypt.pipe(client)
    } catch (err) {
      if (!controller.signal.aborted) console.error('attest-link (warn)', util.cleanMessage(err.message))
      close()
    }
  })

  tcpServer.closeConnections = () => { for (const close of connections) close() }
  return tcpServer
}

