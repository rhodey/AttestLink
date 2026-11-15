import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { chmod, cp, mkdir, mkdtemp, realpath, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

const run = promisify(execFile)
const platform = `${process.platform}-${process.arch}`

async function fixture(t) {
  const directory = await realpath(await mkdtemp(join(tmpdir(), 'attest-link-rust-resolution-')))
  t.after(() => rm(directory, { recursive: true, force: true }))
  await mkdir(join(directory, 'src'))
  await writeFile(join(directory, 'package.json'), '{"type":"module"}')
  for (const file of ['bin.js', 'attest.js', 'util.js']) {
    await cp(new URL(`../src/${file}`, import.meta.url), join(directory, 'src', file))
  }
  await symlink(fileURLToPath(new URL('../node_modules', import.meta.url)), join(directory, 'node_modules'), 'dir')
  await writeFile(join(directory, 'verify.js'), `
    import * as attest from './src/attest.js'
    console.log(JSON.stringify(await attest.verifyDoc('Zml4dHVyZQ==', '00'.repeat(32), 'key')))
  `)
  const bundled = join(directory, 'bin', platform, 'attest-link-rust')
  const fallback = join(directory, 'path', 'attest-link-rust')
  const override = join(directory, 'override')
  const env = { ...process.env, PATH: join(directory, 'path') }
  delete env.ATTEST_LINK_RUST
  const helper = async (path, selected) => {
    await mkdir(join(path, '..'), { recursive: true })
    await writeFile(path, `#!${process.execPath}\nconsole.log(${JSON.stringify(JSON.stringify({ selected }))})\n`, { mode: 0o755 })
  }
  const invoke = (mode, variables = env) => run(process.execPath,
    mode === 'cli' ? [join(directory, 'src/bin.js'), '-v'] : [join(directory, 'verify.js')],
    { env: variables, timeout: 3000 },
  )
  return { directory, bundled, fallback, override, env, helper, invoke }
}

test('CLI and verification use the bundled helper, with an explicit override taking precedence', async t => {
  const { bundled, fallback, override, env, helper, invoke } = await fixture(t)
  await helper(bundled, 'bundled')
  await helper(fallback, 'PATH')
  await helper(override, 'override')
  for (const mode of ['cli', 'verify']) {
    assert.equal(JSON.parse((await invoke(mode)).stdout).selected, 'bundled')
    assert.equal(JSON.parse((await invoke(mode, { ...env, ATTEST_LINK_RUST: override })).stdout).selected, 'override')
  }
})

test('a checkout without bundled helpers can use a Cargo-installed helper on PATH', async t => {
  const { fallback, helper, invoke } = await fixture(t)
  await helper(fallback, 'PATH')
  for (const mode of ['cli', 'verify']) {
    assert.equal(JSON.parse((await invoke(mode)).stdout).selected, 'PATH')
  }
})

test('present but unusable bundled helpers and invalid overrides never fall back', async t => {
  const { directory, bundled, fallback, override, env, helper, invoke } = await fixture(t)
  await helper(fallback, 'must not run')
  await helper(bundled, 'bundled')
  await chmod(bundled, 0o644)
  for (const mode of ['cli', 'verify']) {
    await assert.rejects(invoke(mode), error => {
      assert.match(error.stderr, /EACCES/)
      assert.equal(error.stdout, '')
      return true
    })
  }
  await rm(bundled)
  await symlink(join(directory, 'missing'), bundled)
  for (const mode of ['cli', 'verify']) {
    for (const variables of [env, { ...env, ATTEST_LINK_RUST: override }]) {
      await assert.rejects(invoke(mode, variables), error => {
        assert.match(error.stderr, /ENOENT/)
        assert.equal(error.stdout, '')
        return true
      })
    }
  }
})

test('missing helpers report their launch error', async t => {
  const { invoke } = await fixture(t)
  for (const mode of ['cli', 'verify']) {
    await assert.rejects(invoke(mode), error => {
      assert.match(error.stderr, /ENOENT/)
      assert.equal(error.stdout, '')
      return true
    })
  }
})

test('all bundled platforms resolve by architecture; other platforms use PATH', async t => {
  const { directory, helper } = await fixture(t)
  for (const platform of ['darwin-arm64', 'linux-arm64', 'linux-x64']) {
    await helper(join(directory, 'bin', platform, 'attest-link-rust'), platform)
  }
  for (const platform of ['darwin-arm64', 'linux-arm64', 'linux-x64', 'darwin-x64', 'freebsd-arm64']) {
    const [os, arch] = platform.split('-')
    const source = `
      import * as util from './src/util.js'
      delete process.env.ATTEST_LINK_RUST
      Object.defineProperty(process, 'platform', { value: ${JSON.stringify(os)} })
      Object.defineProperty(process, 'arch', { value: ${JSON.stringify(arch)} })
      console.log(util.executable())
    `
    const { stdout } = await run(process.execPath, ['--input-type=module', '-e', source], { cwd: directory })
    const expected = ['darwin-arm64', 'linux-arm64', 'linux-x64'].includes(platform)
      ? join(directory, 'bin', platform, 'attest-link-rust') : 'attest-link-rust'
    assert.equal(stdout.trim(), expected)
  }
})
