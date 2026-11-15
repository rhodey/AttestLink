#!/usr/bin/env node
import minimist from 'minimist'
import { spawn } from 'node:child_process'
import { once } from 'node:events'
import * as util from './util.js'

async function runRust(args) {
  const child = spawn(util.executable(), args, { stdio: 'inherit' })
  const signals = ['SIGTERM', 'SIGINT', 'SIGHUP'].map(signal => {
    const forward = () => child.kill(signal)
    process.on(signal, forward)
    return [signal, forward]
  })
  const [code, signal] = await once(child, 'exit').finally(() => {
    for (const [signal, forward] of signals) process.off(signal, forward)
  })
  if (signal) process.kill(process.pid, signal)
  else process.exitCode = code
}

async function runStdio(endpoint, pcr0, extra) {
  const duplex = await import('./attest-duplex.js')
  const { pipeline } = await import('node:stream/promises')
  const controller = new AbortController()
  const abort = err => controller.abort(err)
  process.stdin.on('error', abort)
  process.stdout.on('error', abort)
  let encrypt, decrypt, evidence
  try {
    [encrypt, decrypt, evidence] = await duplex.client(endpoint, { pcr0, extra, signal: controller.signal })
    process.stdout.write(`${JSON.stringify({ event: 'listening', address: 'stdio' })}\n${JSON.stringify(evidence)}\n`)
    await Promise.all([
      pipeline(process.stdin, encrypt),
      pipeline(decrypt, process.stdout),
    ])
  } catch (err) {
    controller.abort(err)
    encrypt?.destroy()
    decrypt?.destroy()
    throw err
  } finally {
    // On success, the duplex flushes its final frame and closes HTTP/2 itself.
    process.stdin.destroy()
    process.stdin.off('error', abort)
    process.stdout.off('error', abort)
  }
}

async function main() {
  const argv = process.argv.slice(2)
  const args = minimist(argv, {
    boolean: ['s', 'g', 'v', 'x', 'any-pcr'],
    string: ['_', 'c', 'e'],
  })
  if (args.g || args.v || args.x) {
    if (args.s) throw new Error('Cannot combine -s with -g, -v, or -x')
    return runRust(argv)
  }
  if (args._.length < 2 || args._.length > (args.s ? 2 : 3)) {
    console.error('attest-link (error)', 'Usage: attest-link [-e JSON] LISTEN ENDPOINT (PCR0 | --any-pcr)\n       attest-link [-e JSON] stdio ENDPOINT (PCR0 | --any-pcr)\n       attest-link -s [-c HOOK] LISTEN BACKEND\n       attest-link -g [-x] --nonce HEX --public-key BASE64 [--user-data BASE64_JSON] [--root-cert PATH]\n       attest-link -v --nonce HEX --public-key BASE64 [--pcr0 HEX] [--root-cert PATH] < document.base64')
    process.exitCode = 1
    return
  }
  if (args.c !== undefined && !args.s) throw new Error('-c requires server mode (-s)')
  if (args.e !== undefined && args.s) throw new Error('-e is only valid in client mode')
  if (args['any-pcr'] && args.s) throw new Error('--any-pcr is only valid in client mode')
  const extra = args.e === undefined ? undefined : JSON.parse(args.e)
  const [listen, target, pcr0] = args._
  if (!args.s) {
    if (pcr0 === undefined && !args['any-pcr']) throw new Error('Provide PCR0 or --any-pcr')
    if (pcr0 !== undefined && args['any-pcr']) throw new Error('Cannot combine PCR0 with --any-pcr')
  }
  if (!args.s && listen === 'stdio') return runStdio(target, pcr0, extra)

  const { attestTunnel } = await import('./attest-client.js')
  const { attestServer } = await import('./attest-server.js')
  const duplex = await import('./attest-duplex.js')
  const address = util.parseAddress(listen, args.s ? '0.0.0.0' : '127.0.0.1')
  if (!args.s && address.port === 0) {
    const controller = new AbortController()
    const [encrypt, decrypt, evidence] = await duplex.client(target, {
      pcr0, extra, signal: controller.signal,
    })
    encrypt.destroy()
    decrypt.destroy()
    console.log(JSON.stringify(evidence, null, 2))
    return
  }

  const server = args.s ? await attestServer(target, args.c) : attestTunnel(target, pcr0, extra)
  if (!args.s) server.on('evidence', evidence => console.log(JSON.stringify(evidence)))
  server.on('error', err => { console.error('attest-link (error)', util.cleanMessage(err.message)); process.exitCode = 1 })
  server.listen(address, () => {
    const { address, port } = server.address()
    console.log(JSON.stringify({ event: 'listening', address, port }))
  })
  const stop = () => { server.closeConnections(); server.close() }
  process.once('SIGTERM', stop)
  process.once('SIGINT', stop)
}

main().catch(err => { console.error('attest-link (error)', util.cleanMessage(err.message)); process.exitCode = 1 })
