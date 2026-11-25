import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import {
  accessSync, chmodSync, copyFileSync, mkdirSync, readFileSync, realpathSync,
  renameSync, rmSync, statSync, symlinkSync, writeFileSync,
} from 'node:fs'
import { createRequire } from 'node:module'
import { release } from 'node:os'
import { basename, dirname, join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

const args = process.argv.slice(2)
if (args.length !== 5) {
  throw new Error('Usage: node qualify-tarball.mjs PACKAGE.tgz SHA256 FIXTURE.json AWS_FIXTURE.json NEW_DIRECTORY')
}
const [archive, expectedHash, fixtureFile, awsFile, output] = args
const tarball = resolve(archive)
const directory = resolve(output)
const consumer = join(directory, 'consumer')
const tools = join(directory, 'tools')
const version = json(new URL('../package.json', import.meta.url)).version
const sha256 = file => createHash('sha256').update(readFileSync(file)).digest('hex')
const report = {
  version, tarball: basename(tarball), sha256: sha256(tarball),
  platform: process.platform, arch: process.arch, kernel: release(), node: process.version,
  startedAt: new Date().toISOString(), checks: [],
}

function json(file) {
  return JSON.parse(readFileSync(file, 'utf8'))
}

assert.equal(report.sha256, expectedHash, 'Tarball must match the SHA-256 recorded when packing')
const fixture = json(fixtureFile)
const aws = json(awsFile)
process.umask(0o022)
mkdirSync(directory)
for (const dir of [consumer, tools, join(directory, 'home')]) mkdirSync(dir)
symlinkSync(process.execPath, join(tools, 'node'))
symlinkSync('/bin/sh', join(tools, 'sh'))
const env = {
  HOME: join(directory, 'home'), PATH: tools,
  npm_config_registry: 'https://registry.npmjs.org/', npm_config_update_notifier: 'false',
}
const runtime = dirname(process.execPath)
const npm = join(runtime, 'npm')
const npx = join(runtime, 'npx')

function run(executable, args, { input, code = 0, extraEnv } = {}) {
  const result = spawnSync(executable, args, {
    cwd: consumer, env: { ...env, ...extraEnv }, input, encoding: 'utf8', timeout: 120_000,
  })
  if (result.error) throw result.error
  assert.equal(result.status, code, `${basename(executable)} ${args.join(' ')}\n${result.stderr}`)
  if (code !== 0) assert.equal(result.stdout, '')
  return result
}

function verifyArgs({ nonce, publicKey, pcr0 }, root) {
  const args = ['-v', '--nonce', nonce, '--public-key', publicKey]
  if (pcr0) args.push('--pcr0', pcr0)
  if (root) args.push('--root-cert', root)
  return args
}

async function qualify() {
  const pkg = join(consumer, 'node_modules/attest-link')
  const cli = join(consumer, 'node_modules/.bin/attest-link')
  const helper = join(pkg, 'bin', `${process.platform}-${process.arch}`, 'attest-link-rust')
  const root = join(directory, 'fixture-root.pem')
  const signed = verifyArgs(fixture, root)
  const input = fixture.document + '\n'
  const installed = createRequire(join(consumer, 'package.json'))

  report.npm = run(npm, ['--version']).stdout.trim()
  report.os = process.platform === 'darwin'
    ? run('/usr/bin/sw_vers', ['-productVersion']).stdout.trim()
    : readFileSync('/etc/os-release', 'utf8')
  writeFileSync(join(consumer, 'package.json'), '{"private":true,"type":"module"}\n')
  run(npm, ['install', '--ignore-scripts', '--no-audit', '--no-fund', tarball])
  const metadata = json(join(pkg, 'package.json'))
  assert.equal(metadata.name, 'attest-link')
  assert.equal(metadata.version, version)
  for (const hook of ['preinstall', 'install', 'postinstall']) assert.equal(metadata.scripts?.[hook], undefined)
  assert.equal(realpathSync(cli), realpathSync(join(pkg, metadata.bin['attest-link'])))
  accessSync(join(pkg, metadata.exports.types))
  assert.equal(statSync(helper).mode & 0o777, 0o755)
  report.helperSha256 = sha256(helper)
  report.wasmSha256 = sha256(join(pkg, 'wasm/attest-link.js'))
  report.checks.push('installed package, native executable and type declarations')

  writeFileSync(root, fixture.rootPem)
  for (const [command, prefix] of [
    [helper, []], [cli, []], [npm, ['exec', '--offline', '--', 'attest-link']],
    [npx, ['--offline', 'attest-link']],
  ]) {
    const result = run(command, [...prefix, ...signed], { input })
    assert.deepEqual(JSON.parse(result.stdout), fixture.evidence)
  }
  const unpinned = run(cli, verifyArgs({ ...fixture, pcr0: undefined }, root), { input })
  assert.deepEqual(JSON.parse(unpinned.stdout), fixture.evidence)
  run(cli, ['-v'], { code: 1 })
  report.checks.push('direct helper, CLI, npm exec and npx')

  const corrupt = Buffer.from(fixture.document, 'base64')
  corrupt[corrupt.length - 1] ^= 1
  const invalid = [
    { ...fixture, document: corrupt.toString('base64') }, { ...fixture, nonce: '0a'.repeat(32) },
    { ...fixture, publicKey: Buffer.alloc(32, 10).toString('base64') }, { ...fixture, pcr0: '0a'.repeat(48) },
  ]
  for (const bad of invalid) run(cli, verifyArgs(bad, root), { input: bad.document + '\n', code: 2 })
  run(cli, verifyArgs(fixture), { input, code: 2 })
  const awsResult = run(cli, verifyArgs(aws), { input: aws.document + '\n' })
  assert.deepEqual(JSON.parse(awsResult.stdout), aws.evidence)
  report.checks.push('native signatures, nonce, keys, measurements, roots and exit codes')

  // Exercise the installed JS entry points and the actual WASM with the system clock.
  delete process.env.ATTEST_LINK_RUST
  const { attestLink } = await import(pathToFileURL(installed.resolve('attest-link')))
  assert.equal(typeof attestLink('https://example.test', { pcr0: aws.pcr0 }), 'function')
  const native = await import(pathToFileURL(join(pkg, 'src/attest.js')))
  const wasm = await import(pathToFileURL(join(pkg, 'src/browser/attest-wasm.js')))
  for (const verifier of [native, wasm]) {
    assert.deepEqual(await verifier.verifyDoc(aws.document, aws.nonce, aws.publicKey, aws.pcr0), aws.evidence)
    assert.equal(await verifier.verifyDoc(fixture.document, fixture.nonce, fixture.publicKey, fixture.pcr0), false)
  }
  assert.deepEqual(await wasm.verifyDoc(fixture.document, fixture.nonce, fixture.publicKey, fixture.pcr0, fixture.rootPem), fixture.evidence)
  for (const bad of invalid) assert.equal(await wasm.verifyDoc(bad.document, bad.nonce, bad.publicKey, bad.pcr0, fixture.rootPem), false)
  report.checks.push('installed browser export, native bridge and WASM verification of real AWS and synthetic evidence')

  // Only the disposable consumer is changed. Leave it usable for the Sandbox tests.
  const manual = join(tools, 'attest-link-rust')
  const missing = join(tools, 'missing-helper')
  const saved = join(directory, 'saved-helper')
  copyFileSync(helper, manual)
  try {
    const override = run(cli, signed, { input, extraEnv: { ATTEST_LINK_RUST: manual } })
    assert.deepEqual(JSON.parse(override.stdout), fixture.evidence)
    assert.match(run(cli, signed, { input, code: 1, extraEnv: { ATTEST_LINK_RUST: missing } }).stderr, /ENOENT/)
    chmodSync(helper, 0o644)
    assert.match(run(cli, signed, { input, code: 1 }).stderr, /EACCES/)
    renameSync(helper, saved)
    try {
      const fallback = run(cli, signed, { input })
      assert.deepEqual(JSON.parse(fallback.stdout), fixture.evidence)
      rmSync(manual)
      assert.match(run(cli, signed, { input, code: 1 }).stderr, /ENOENT/)
    } finally {
      renameSync(saved, helper)
    }
  } finally {
    chmodSync(helper, 0o755)
    rmSync(manual, { force: true })
  }
  report.checks.push('explicit override, unusable bundle and manual PATH fallback')
}

try {
  await qualify()
  report.passed = true
} catch (error) {
  report.passed = false
  report.error = error.stack
  throw error
} finally {
  writeFileSync(join(directory, 'result.json'), JSON.stringify(report, null, 2) + '\n')
  console.log(join(directory, 'result.json'))
}
