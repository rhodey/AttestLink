import assert from 'node:assert/strict'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import * as attest from '../src/attest.js'

test('attestation returns evidence or false and throws on helper failures', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'attest-link-rust-'))
  const executable = join(dir, 'helper')
  const original = process.env.ATTEST_LINK_RUST
  t.after(async () => {
    if (original === undefined) delete process.env.ATTEST_LINK_RUST
    else process.env.ATTEST_LINK_RUST = original
    await rm(dir, { recursive: true, force: true })
  })
  process.env.ATTEST_LINK_RUST = executable

  // Exercise the subprocess boundary without substituting any production trust root.
  const helper = source => writeFile(executable, `#!${process.execPath}
process.stdin.resume()
process.stdin.on('end', () => { ${source} })
`, { mode: 0o700 })
  const document = Buffer.from('fixture').toString('base64')
  const nonce = '07'.repeat(32)
  const publicKey = Buffer.alloc(32, 8).toString('base64')
  const pcr0 = '09'.repeat(48)
  const userData = { role: 'ssh', enabled: true, version: 2, labels: ['a', null], nested: { name: '日本語' } }
  const evidence = { timestamp: 1_800_000_000_000, pcrs: { 0: pcr0 }, nonce, publicKey, userData }
  const readers = [
    document => attest.verifyDoc(document, nonce, publicKey, pcr0),
    document => attest.verifyDoc(document, nonce, publicKey),
  ]

  for (const [index, read] of readers.entries()) {
    const args = ['-v', '--nonce', nonce, '--public-key', publicKey]
    if (index === 0) args.push('--pcr0', pcr0)
    await helper(`
      if (JSON.stringify(process.argv.slice(2)) !== ${JSON.stringify(JSON.stringify(args))}) {
        throw new Error('Incorrect verification arguments')
      }
      process.stdout.write(${JSON.stringify(JSON.stringify(evidence))})
    `)
    assert.deepEqual(await read(document), evidence)

    for (const userData of [0, 1, {}, null, ['ssh']]) {
      const output = { ...evidence, userData }
      await helper(`process.stdout.write(${JSON.stringify(JSON.stringify(output))})`)
      assert.deepEqual(await read(document), output)
    }

    await helper('process.exitCode = 2')
    assert.equal(await read(document), false)

    for (const code of [1, 3]) {
      await helper(`process.stderr.write('helper failure'); process.exitCode = ${code}`)
      await assert.rejects(read(document), {
        code, message: 'Attestation helper failed: helper failure',
      })
    }

    await helper("process.kill(process.pid, 'SIGTERM')")
    await assert.rejects(read(document), { signal: 'SIGTERM' })

    await helper("process.stdout.write('not JSON')")
    await assert.rejects(read(document), SyntaxError)
  }

  process.env.ATTEST_LINK_RUST = join(dir, 'missing')
  for (const pcr0 of [null, '', '12', '00'.repeat(48)]) {
    await assert.rejects(attest.verifyDoc(document, nonce, publicKey, pcr0), /PCR0|pcr0/)
  }
  for (const read of readers) {
    await assert.rejects(read(document), { code: 'ENOENT' })
    for (const invalid of [undefined, '', 'invalid base64!']) {
      assert.equal(await read(invalid), false)
    }
  }

  process.env.ATTEST_LINK_RUST = executable
  for (const value of [undefined, userData]) {
    await helper(`
      if (process.argv[2] !== '-g') throw new Error('Expected -g flag')
      const data = process.argv[process.argv.indexOf('--user-data') + 1]
      if (Buffer.from(data, 'base64').toString('utf8') !== ${JSON.stringify(JSON.stringify(value ?? {}))}) {
        throw new Error('Incorrect JSON')
      }
      process.stdout.write(${JSON.stringify(document)})
    `)
    assert.equal(await attest.getDoc(nonce, publicKey, value), document)
  }
  for (const userData of [null, [], 'text', 1]) {
    await assert.rejects(attest.getDoc(nonce, publicKey, userData), /userData must be an object/)
  }
  for (const code of [1, 2]) {
    await helper(`process.exitCode = ${code}`)
    await assert.rejects(attest.getDoc(nonce, publicKey), { code })
  }
  await helper("process.stdout.write('invalid base64!')")
  await assert.rejects(attest.getDoc(nonce, publicKey), /Invalid attestation document encoding/)
})
