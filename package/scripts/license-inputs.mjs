#!/usr/bin/env node
// Assemble the inputs for licenses.mjs on the Mac that built the native helper.
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises'
import { dirname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const [linux, reportFile, output] = process.argv.slice(2)
if (process.argv.length !== 5) {
  throw new Error('Usage: node package/scripts/license-inputs.mjs LINUX_NOTICES MAC_BUILD_REPORT OUTPUT_DIRECTORY')
}
const crate = fileURLToPath(new URL('../../rust/', import.meta.url))
const report = JSON.parse(await readFile(reportFile, 'utf8'))
const lockHash = createHash('sha256').update(await readFile(join(crate, 'Cargo.lock'))).digest('hex')
if (report.platform !== 'darwin-arm64' || report.cargoLockSha256 !== lockHash) {
  throw new Error('Expected a macOS build report for this Cargo.lock')
}
const rust = report.rust.match(/^release: (\S+)$/m)[1]
function rustup(...args) {
  return execFileSync('rustup', ['run', rust, ...args], { encoding: 'utf8' }).trim()
}
if (rustup('rustc', '-Vv') !== report.rust) throw new Error('Rust toolchain differs from the macOS build')

function filesUnder(directory, names) {
  return Object.fromEntries(names.map(name => [name, resolve(directory, name)]))
}
const components = JSON.parse(await readFile(join(linux, 'components.json'), 'utf8'))
for (const component of components) {
  const dir = resolve(linux, component.id)
  const entries = await readdir(dir, { recursive: true, withFileTypes: true })
  component.files = filesUnder(dir, entries.filter(entry => entry.isFile())
    .map(entry => relative(dir, join(entry.parentPath, entry.name))))
}

const rustDocs = join(rustup('rustc', '--print', 'sysroot'), 'share/doc/rust')
const licenses = await readdir(join(rustDocs, 'licenses'))
components.push({
  id: 'rust-macos', name: 'Rust standard library (macOS ARM64)', version: rust,
  source: `https://github.com/rust-lang/rust/tree/${rust}`,
  files: filesUnder(rustDocs, ['COPYRIGHT-library.html', ...licenses.map(name => 'licenses/' + name)]),
})

const cargo = rustup('cargo', 'metadata', '--locked', '--offline', '--manifest-path', join(crate, 'Cargo.toml'), '--format-version', '1')
const openssl = JSON.parse(cargo).packages.find(pkg => pkg.name === 'openssl-src')
if (openssl?.version !== report.openssl.crateVersion) throw new Error('Vendored OpenSSL differs from the macOS build')
components.push({
  id: 'openssl-vendored', name: 'OpenSSL (Cargo-vendored macOS and WebAssembly)',
  version: openssl.version.split('+')[1], source: `https://crates.io/crates/openssl-src/${openssl.version}`,
  files: filesUnder(join(dirname(openssl.manifest_path), 'openssl'), ['LICENSE.txt']),
})

await mkdir(output, { recursive: true })
await writeFile(join(output, 'cargo-metadata.json'), cargo + '\n')
await writeFile(join(output, 'inputs.json'), JSON.stringify({ cargoMetadata: 'cargo-metadata.json', components }, null, 2) + '\n')
