import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { once } from 'node:events'
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const cli = fileURLToPath(new URL('../src/bin.js', import.meta.url))

async function fixture(t, source) {
  const directory = await mkdtemp(join(tmpdir(), 'attest-link-passthrough-'))
  t.after(() => rm(directory, { recursive: true, force: true }))
  const helper = join(directory, 'helper')
  await writeFile(helper, `#!${process.execPath}\n${source}\n`, { mode: 0o700 })
  return { directory, helper }
}

async function run(t, helper, args, input = '', entry = cli) {
  const child = spawn(process.execPath, [entry, ...args], {
    env: { ...process.env, ATTEST_LINK_RUST: helper }, timeout: 3000,
  })
  t.after(() => child.kill('SIGKILL'))
  const stdout = [], stderr = []
  child.stdout.on('data', chunk => stdout.push(chunk))
  child.stderr.on('data', chunk => stderr.push(chunk))
  child.stdin.on('error', () => {})
  child.stdin.end(input)
  const [code, signal] = await once(child, 'close')
  return { code, signal, stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr) }
}

test('helper modes preserve arguments, stdin, stdout, stderr, and exit codes', async t => {
  for (const [mode, code] of [[['-g'], 0], [['-g', '-x'], 0], [['-v'], 0], [['-v'], 1], [['-v'], 2], [['-v'], 3]]) {
    await t.test(`${mode.join(' ')} exit ${code}`, async t => {
      const args = [...mode, '--nonce', '00'.repeat(32), '--public-key', 'key==', '--root-cert', '/a path/root.pem']
      const { helper } = await fixture(t, `
        if (JSON.stringify(process.argv.slice(2)) !== ${JSON.stringify(JSON.stringify(args))}) process.exit(99)
        process.stdin.pipe(process.stdout)
        process.stdin.on('end', () => {
          process.stderr.write('helper diagnostic\\n')
          process.exitCode = ${code}
        })
      `)
      const input = Buffer.from([0, 255, 13, 10, 65, 32])
      const result = await run(t, helper, args, input)
      assert.equal(result.code, code)
      assert.equal(result.signal, null)
      assert.deepEqual(result.stdout, input)
      assert.equal(result.stderr.toString(), 'helper diagnostic\n')
    })
  }
})

test('helper modes run without loading tunnel or libsodium modules', async t => {
  const { directory, helper } = await fixture(t, "process.stdout.write('evidence\\n')")
  await writeFile(join(directory, 'package.json'), '{"type":"module"}')
  await mkdir(join(directory, 'node_modules'))
  const require = createRequire(import.meta.url)
  await symlink(dirname(require.resolve('minimist/package.json')), join(directory, 'node_modules/minimist'), 'dir')
  const entry = join(directory, 'bin.js')
  await writeFile(entry, await readFile(cli))
  await writeFile(join(directory, 'util.js'), await readFile(new URL('../src/util.js', import.meta.url)))
  const result = await run(t, helper, ['-g', '-x'], '', entry)
  assert.equal(result.code, 0)
  assert.equal(result.stdout.toString(), 'evidence\n')
})

test('helper launch errors and conflicting server mode exit one', async t => {
  const { directory, helper } = await fixture(t, 'process.exit(99)')
  const missing = await run(t, join(directory, 'missing'), ['-v'])
  assert.equal(missing.code, 1)
  assert.equal(missing.stdout.length, 0)
  assert.match(missing.stderr.toString(), /attest-link \(error\).*ENOENT/)
  for (const mode of ['-g', '-v', '-x']) {
    const result = await run(t, helper, ['-s', mode])
    assert.equal(result.code, 1)
    assert.equal(result.stdout.length, 0)
    assert.match(result.stderr.toString(), /Cannot combine -s/)
  }
})

test('termination signals reach the helper and retain their exit meaning', async t => {
  for (const signal of ['SIGTERM', 'SIGINT', 'SIGHUP']) {
    await t.test(signal, async t => {
      const { helper } = await fixture(t, `
        process.stdout.write(String(process.pid) + '\\n')
        setInterval(() => {}, 1000)
      `)
      const child = spawn(process.execPath, [cli, '-v'], {
        env: { ...process.env, ATTEST_LINK_RUST: helper }, timeout: 3000,
      })
      t.after(() => child.kill('SIGKILL'))
      const closed = once(child, 'close')
      const [ready] = await Promise.race([
        once(child.stdout, 'data'),
        closed.then(() => { throw new Error('Helper exited before readiness') }),
      ])
      const helperPid = Number(ready.toString())
      t.after(() => { try { process.kill(helperPid, 'SIGKILL') } catch {} })
      child.kill(signal)
      assert.deepEqual(await closed, [null, signal])
      assert.throws(() => process.kill(helperPid, 0), { code: 'ESRCH' })
    })
  }
})
