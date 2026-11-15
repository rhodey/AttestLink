import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { cp, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { promisify } from 'node:util'

const run = promisify(execFile)

test('npm includes all three executable helpers and licenses, excluding build and private files', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'attest-link-pack-'))
  t.after(() => rm(directory, { recursive: true, force: true }))
  for (const file of ['package.json', '.npmignore']) {
    await cp(new URL(`../${file}`, import.meta.url), join(directory, file))
  }
  const binaries = ['darwin-arm64', 'linux-arm64', 'linux-x64'].map(platform => `bin/${platform}/attest-link-rust`)
  const included = [
    'src/bin.js', 'src/util.js', 'src/browser/attest-fetch.js', 'src/browser/attest-fetch.d.ts',
    'wasm/attest-link.js', 'licenses/OpenSSL.txt',
  ]
  const excluded = [
    '.env', 'AGENTS.md', 'linux_ssh', 'old.tgz', 'build.log',
    'test/fixture.js', 'scripts/build.sh',
    'bin/linux-x64/build.log', 'bin/linux-arm64/unused-helper',
    'src/.env.local', 'src/draft.swp', 'wasm/.DS_Store',
  ]
  for (const file of [...binaries, ...included, ...excluded]) {
    const path = join(directory, file)
    await mkdir(dirname(path), { recursive: true })
    await writeFile(path, 'package fixture\n', { mode: binaries.includes(file) ? 0o755 : 0o644 })
  }
  const { stdout } = await run('npm', [
    'pack', '--dry-run', '--ignore-scripts', '--json', '--cache', join(directory, 'cache'),
  ], { cwd: directory, timeout: 15000 })
  const [packed] = JSON.parse(stdout)
  const paths = packed.files.map(file => file.path)
  assert.deepEqual(paths.sort(), ['package.json', ...binaries, ...included].sort())
  for (const path of binaries) assert.equal(packed.files.find(file => file.path === path).mode, 0o755)
})
