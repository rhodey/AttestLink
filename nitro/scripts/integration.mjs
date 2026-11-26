#!/usr/bin/env node
// Run on the Linux development host after starting a real confidential Sandbox.
// This script only stops its own client/SSH children; it leaves the Sandbox up.
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { once } from 'node:events'
import { createHash, randomBytes } from 'node:crypto'
import { readFile, realpath, stat } from 'node:fs/promises'
import net from 'node:net'
import path from 'node:path'
import { parseArgs } from 'node:util'

const children = new Set()
const passed = []
const log = message => process.stderr.write(`integration: ${message}\n`)

function childProcess(command, args) {
  const child = spawn(command, args, { stdio: ['pipe', 'pipe', 'pipe'] })
  children.add(child)
  child.once('close', () => children.delete(child))
  return child
}

async function stop(child) {
  if (child.exitCode !== null || child.signalCode !== null) return
  await new Promise(resolve => {
    const timer = setTimeout(() => child.kill('SIGKILL'), 2000)
    child.once('close', () => { clearTimeout(timer); resolve() })
    child.kill('SIGTERM')
  })
}

async function cleanup() { await Promise.all([...children].map(stop)) }

function run(command, args, { input = Buffer.alloc(0), timeout = 20_000, allowFailure = false, maxOutput = 4 * 1024 * 1024 } = {}) {
  return new Promise((resolve, reject) => {
    const child = childProcess(command, args)
    const output = []
    let outputLength = 0
    let stderr = ''
    let failure
    const fail = error => {
      failure ??= error
      child.kill('SIGKILL')
    }
    const timer = setTimeout(() => fail(new Error(`${command} timed out after ${timeout} ms`)), timeout)
    child.once('error', error => { failure = error })
    child.stdout.on('data', chunk => {
      outputLength += chunk.length
      if (outputLength > maxOutput) return fail(new Error(`${command} exceeded its output limit`))
      output.push(chunk)
    })
    child.stderr.on('data', chunk => { stderr = (stderr + chunk.toString()).slice(-16 * 1024) })
    child.stdin.on('error', () => {})
    child.stdin.end(input)
    child.once('close', (code, signal) => {
      clearTimeout(timer)
      if (failure) return reject(failure)
      if (code !== 0 && !allowFailure) {
        return reject(new Error(`${command} failed (${code ?? signal}): ${stderr.trim()}`))
      }
      resolve({ code, signal, stdout: Buffer.concat(output), stderr })
    })
  })
}

async function startClient(endpoint, pcr0) {
  const listener = net.createServer()
  listener.listen(0, '127.0.0.1')
  await once(listener, 'listening')
  const port = listener.address().port
  await new Promise(resolve => listener.close(resolve))
  return new Promise((resolve, reject) => {
    const child = childProcess('attest-link', [String(port), endpoint, pcr0])
    child.stdin.end()
    let buffer = ''
    let diagnostics = ''
    let ready = false
    const fail = error => {
      if (!ready) reject(error)
      child.kill('SIGTERM')
    }
    const timer = setTimeout(() => fail(new Error('Attesting client did not start in time')), 10_000)
    child.once('error', error => { clearTimeout(timer); fail(error) })
    child.once('close', code => {
      clearTimeout(timer)
      if (!ready) reject(new Error(`Attesting client exited before readiness (${code})`))
    })
    child.stderr.on('data', chunk => {
      diagnostics = (diagnostics + chunk.toString()).slice(-16 * 1024)
      process.stderr.write(chunk)
    })
    child.stdout.on('data', chunk => {
      if (ready) return // Later lines contain evidence for individual connections.
      buffer += chunk.toString()
      if (buffer.length > 64 * 1024) return fail(new Error('Client readiness output exceeded its limit'))
      for (;;) {
        const end = buffer.indexOf('\n')
        if (end === -1) break
        const line = buffer.slice(0, end)
        buffer = buffer.slice(end + 1)
        if (ready || !line.trim()) continue
        try {
          const event = JSON.parse(line)
          assert.equal(event.event, 'listening')
          assert.equal(event.address, '127.0.0.1')
          assert.ok(Number.isInteger(event.port) && event.port > 0 && event.port <= 65535)
          ready = true
          clearTimeout(timer)
          resolve({ child, port: event.port, diagnostics: () => diagnostics })
        } catch (error) { fail(new Error(`Invalid client readiness event: ${error.message}`)) }
      }
    })
  })
}

function sshArgs(identity, port, command) {
  return [
    '-F', '/dev/null', '-T', '-p', String(port), '-i', identity,
    '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none',
    '-o', 'PreferredAuthentications=publickey', '-o', 'PasswordAuthentication=no',
    '-o', 'KbdInteractiveAuthentication=no', '-o', 'ConnectionAttempts=1',
    '-o', 'ConnectTimeout=5', '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=2',
    // Every invocation must create a fresh TCP connection and attestation.
    '-o', 'ControlMaster=no', '-o', 'ControlPath=none',
    // Sandbox host keys are ephemeral. The approved NSM-bound encrypted channel
    // authenticates the server image before these SSH bytes can be forwarded.
    '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
    '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'LogLevel=ERROR',
    'sandbox@127.0.0.1', command,
  ]
}

function assertRawSshClosed(sandboxIP) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: sandboxIP, port: 2223 })
    const timer = setTimeout(() => { socket.destroy(); resolve() }, 2500)
    socket.once('connect', () => {
      clearTimeout(timer)
      socket.destroy()
      reject(new Error(`Raw SSH backend is externally reachable at ${sandboxIP}:2223`))
    })
    socket.once('error', error => {
      clearTimeout(timer)
      // A routing/permission error in the test harness must not count as proof
      // that the backend is closed. Refusal or packet-filter timeout does.
      if (error.code === 'ECONNREFUSED' || error.code === 'ETIMEDOUT') resolve()
      else reject(error)
    })
  })
}

async function waitForEndpoint(endpoint) {
  const url = new URL(endpoint)
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.hash) {
    throw new Error('--endpoint must be an http:// or https:// URL without credentials or a fragment')
  }
  const host = url.hostname.replace(/^\[|\]$/g, '')
  const port = Number(url.port || (url.protocol === 'https:' ? 443 : 80))
  const deadline = performance.now() + 60_000
  let lastError = 'no connection'
  while (performance.now() < deadline) {
    const reachable = await new Promise(resolve => {
      const socket = net.createConnection({ host, port })
      const finish = connected => {
        clearTimeout(timer)
        socket.destroy()
        resolve(connected)
      }
      const timer = setTimeout(() => {
        lastError = 'connection timed out'
        finish(false)
      }, Math.min(1000, Math.max(1, deadline - performance.now())))
      socket.once('connect', () => finish(true))
      socket.once('error', error => { lastError = error.code ?? error.message; finish(false) })
    })
    if (reachable) return
    const remaining = deadline - performance.now()
    if (remaining > 0) await new Promise(resolve => setTimeout(resolve, Math.min(250, remaining)))
  }
  throw new Error(`Sandbox endpoint did not become reachable within 60 seconds (${lastError})`)
}

async function main() {
  const { values } = parseArgs({ options: {
    image: { type: 'string' }, identity: { type: 'string' },
    endpoint: { type: 'string', default: 'http://172.30.0.2:2222' },
    'sandbox-ip': { type: 'string', default: '172.30.0.2' },
    help: { type: 'boolean', default: false },
  } })
  if (values.help) {
    process.stdout.write('Usage: node nitro/scripts/integration.mjs --image DIR --identity PRIVATE_KEY\n' +
      '       [--endpoint http://172.30.0.2:2222] [--sandbox-ip 172.30.0.2]\n')
    return
  }
  if (!values.image || !values.identity) throw new Error('--image and --identity are required')
  if (!net.isIP(values['sandbox-ip'])) throw new Error('--sandbox-ip must be an IP address')
  const identity = await realpath(values.identity)
  const identityStat = await stat(identity)
  if (!identityStat.isFile() || identityStat.mode & 0o077) {
    throw new Error('The private identity must be a regular file readable only by its owner')
  }
  if (identity.startsWith('/nix/store/')) throw new Error('Private SSH keys must not be stored in the Nix store')
  const manifest = JSON.parse(await readFile(path.join(values.image, 'measurements.json'), 'utf8'))
  const expected = {}
  for (const number of [0, 1, 2, 6]) {
    const name = `PCR${number}`
    const measurement = manifest.measurements?.[name]
    assert.match(measurement ?? '', /^[a-f0-9]{96}$/i, `Invalid local ${name}`)
    expected[name] = measurement.toLowerCase()
  }
  assert.notEqual(expected.PCR0, '0'.repeat(96), 'Debug/zero PCR0 cannot be approved')

  log('Waiting up to 60 seconds for the Sandbox attestation endpoint.')
  await waitForEndpoint(values.endpoint)
  // Only reachability is retried. Verification or image-policy failures below
  // fail the test immediately; waiting must never weaken image approval.
  log('Checking real signed NSM evidence against the local image manifest.')
  const attestation = await run('attest-link', ['0', values.endpoint, expected.PCR0])
  const evidence = JSON.parse(attestation.stdout.toString())
  assert.equal(typeof evidence.serverClaims?.fortune, 'string', 'Server claims must contain the signed fortune')
  assert.ok(evidence.serverClaims.fortune.trim(), 'The signed fortune must not be empty')
  for (const number of [0, 1, 2, 6]) {
    assert.equal(evidence.pcrs?.[String(number)]?.toLowerCase(), expected[`PCR${number}`],
      `Hardware PCR${number} differs from the locally built image`)
  }
  passed.push('signed-attestation-and-local-measurements')
  passed.push('signed-fortune-server-claims')

  const client = await startClient(values.endpoint, expected.PCR0)
  const ssh = (command, options) => run('ssh', sshArgs(identity, client.port, command), options)
  log('Checking the Sandbox identity, ARM64 execution, and unprivileged SSH account.')
  const platform = await ssh('printf "%s\\n" "$(uname -m)" "$(id -u)" "$(id -un)" "$(hostname)"')
  assert.deepEqual(platform.stdout.toString().trim().split('\n'), ['aarch64', '1000', 'sandbox', 'nitro-sandbox'])
  passed.push('arm64-unprivileged-ssh')

  log('Checking that the Sandbox has a working system clock.')
  const beforeClock = Date.now()
  const sandboxClock = Number((await ssh("node -p 'Date.now()'")).stdout.toString())
  assert.ok(sandboxClock >= beforeClock - 2000 && sandboxClock <= Date.now() + 2000,
    'Sandbox time must be within two seconds of the test host')
  passed.push('sandbox-system-clock')

  log('Checking system DNS through the local DoT proxy.')
  const resolverConfig = (await ssh('cat /etc/resolv.conf')).stdout.toString()
  const nameservers = [...resolverConfig.matchAll(/^nameserver\s+(\S+)/gm)].map(match => match[1])
  assert.deepEqual(nameservers, ['127.0.0.1'])
  for (const transport of ['-lun', '-ltn']) {
    const dnsListeners = (await ssh(`ss -H ${transport}`)).stdout.toString().trim().split('\n')
      .map(line => line.trim().split(/\s+/)[3]).filter(address => address?.endsWith(':53'))
    assert.deepEqual(dnsListeners, ['127.0.0.1:53'])
  }
  const resolved = await ssh(`node -e 'require("node:dns").lookup("example.com", { family: 4 }, (error, address) => { if (error) throw error; console.log(address) })'`)
  assert.ok(net.isIPv4(resolved.stdout.toString().trim()), 'System DNS must resolve an IPv4 address')
  passed.push('system-dns-through-loopback-proxy')

  log('Waiting for chrony to synchronize using authenticated NTS sources.')
  await ssh('chronyc -n waitsync 90 0.1 0 1', { timeout: 100_000 })
  const tracking = (await ssh('chronyc -n tracking')).stdout.toString()
  assert.match(tracking, /Leap status\s*:\s*Normal/)
  const authdata = (await ssh('chronyc -c authdata')).stdout.toString().trim()
    .split('\n').map(line => line.split(','))
  assert.ok(authdata.length >= 2, 'Expected at least two NTS sources')
  assert.ok(authdata.every(row => row[1] === 'NTS'), 'Every network source must require NTS')
  assert.ok(authdata.filter(row => Number(row[4]) > 0).length >= 2,
    'At least two NTS sources must have established keys')
  log(tracking.trim())
  passed.push('chrony-authenticated-network-sync')

  const clockControl = await ssh('chronyc makestep', { allowFailure: true })
  assert.notEqual(clockControl.code, 0, 'SSH users must not control chrony')
  assert.match(clockControl.stdout.toString(), /Not authorised/)
  const timeListeners = (await ssh('ss -H -lun')).stdout.toString().trim().split('\n')
    .map(line => line.trim().split(/\s+/)[3])
    .filter(address => /:(123|323)$/.test(address))
  assert.deepEqual(timeListeners, ['127.0.0.1:323'])
  passed.push('chrony-control-restricted-to-privileged-socket')

  log('Checking NSM and measured-store permissions.')
  const probe = `/nix/store/.nitro-sandbox-integration-${randomBytes(8).toString('hex')}`
  const permissions = await ssh([
    'test ! -r /dev/nsm && test ! -w /dev/nsm || exit 1',
    `if touch ${probe} 2>/dev/null; then rm -f ${probe}; exit 1; fi`,
    'printf "permissions-ok\\n"',
  ].join('; '))
  assert.equal(permissions.stdout.toString(), 'permissions-ok\n')
  passed.push('ssh-user-cannot-access-nsm-or-write-store')

  log('Running four concurrent SSH sessions, each with fresh attestation.')
  const parallel = await Promise.all(Array.from({ length: 4 }, (_, index) => ssh(`printf 'session-${index}\\n'`)))
  assert.deepEqual(parallel.map(result => result.stdout.toString()), Array.from({ length: 4 }, (_, i) => `session-${i}\n`))
  passed.push('four-concurrent-attested-ssh-sessions')

  log('Checking a binary round trip with SHA-256.')
  const payload = randomBytes(1024 * 1024 + 17)
  const echoed = await ssh('cat', { input: payload, timeout: 30_000, maxOutput: payload.length + 1024 })
  assert.equal(echoed.stdout.length, payload.length)
  const digest = bytes => createHash('sha256').update(bytes).digest('hex')
  assert.equal(digest(echoed.stdout), digest(payload))
  passed.push('binary-round-trip-sha256')

  log('Checking the SSH listener address inside the Sandbox.')
  const listeners = await ssh('ss -H -lnt')
  const sshListeners = listeners.stdout.toString().trim().split('\n')
    .map(line => line.trim().split(/\s+/)[3])
    .filter(address => address?.endsWith(':2223'))
  assert.deepEqual(sshListeners, ['127.0.0.1:2223'], 'Sandbox sshd must listen only on IPv4 loopback')
  passed.push('ssh-backend-binds-sandbox-loopback')

  log('Checking that raw SSH has no Sandbox network listener.')
  await assertRawSshClosed(values['sandbox-ip'])
  passed.push('raw-ssh-backend-unreachable')

  log('Checking rejection of an explicitly wrong image measurement.')
  const wrongPcr0 = expected.PCR0 === 'ab'.repeat(48) ? 'cd'.repeat(48) : 'ab'.repeat(48)
  const wrongClient = await startClient(values.endpoint, wrongPcr0)
  const rejected = await run('ssh', sshArgs(identity, wrongClient.port, 'printf forbidden'), {
    allowFailure: true, timeout: 20_000,
  })
  assert.equal(rejected.code, 255, 'SSH must reject the wrong-PCR0 connection normally')
  assert.equal(rejected.stdout.length, 0, 'SSH produced application output with a wrong PCR0')
  assert.match(wrongClient.diagnostics(), /Attestation verification failed/,
    'The client must report failed attestation')
  await stop(wrongClient.child)
  passed.push('wrong-measurement-rejected-before-ssh')

  await stop(client.child)
  process.stdout.write(`${JSON.stringify({ ok: true, passed, measurements: expected, fortune: evidence.serverClaims.fortune, transferBytes: payload.length })}\n`)
}

for (const [signal, code] of [['SIGINT', 130], ['SIGTERM', 143]]) {
  process.once(signal, () => { cleanup().finally(() => process.exit(code)) })
}

try {
  await main()
} catch (error) {
  log(error.message)
  process.stdout.write(`${JSON.stringify({ ok: false, passed, error: error.message })}\n`)
  process.exitCode = 1
} finally {
  await cleanup()
}
