#!/usr/bin/env node
// Assemble notices from the source files and toolchains used for a release.
// Usage: node package/scripts/licenses.mjs INPUTS.json [OUTPUT_DIRECTORY]
// INPUTS contains cargoMetadata and components: [{ id, name, version, source,
// files: { "LICENSE.txt": "path/to/LICENSE.txt" } }]. Paths are relative to INPUTS.
import { createHash } from 'node:crypto'
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const [input, destination] = process.argv.slice(2)
if (!input || process.argv.length > 4) {
  throw new Error('Usage: node package/scripts/licenses.mjs INPUTS.json [OUTPUT_DIRECTORY]')
}
const directory = dirname(resolve(input))
const output = destination ?? fileURLToPath(new URL('../licenses/', import.meta.url))
const inputs = JSON.parse(await readFile(input, 'utf8'))
const metadata = JSON.parse(await readFile(resolve(directory, inputs.cargoMetadata), 'utf8'))
const inventory = []

function plainText(text, name) {
  if (!name.endsWith('.html')) return text.trimEnd()
  // Rust ships its standard-library copyright inventory as HTML. Keep its text,
  // including the escaped copyright notices and license bodies, without markup.
  return text.replace(/<head\b[^>]*>[\s\S]*?<\/head>/gi, '')
    .replace(/<\/?(?:p|h[1-6]|li|pre|div|details|summary|ul)\b[^>]*>/gi, '\n')
    .replace(/<[^>]*>/g, '')
    .replace(/&(#x[\da-f]+|#\d+|amp|lt|gt|quot|apos|nbsp);/gi, (_, entity) => {
      if (entity[0] === '#') return String.fromCodePoint(Number(entity[1].toLowerCase() === 'x' ? `0${entity.slice(1)}` : entity.slice(1)))
      return { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' }[entity.toLowerCase()]
    }).replace(/\n[ \t]*\n(?:[ \t]*\n)+/g, '\n\n').trim()
}

async function notice(label, filename) {
  const bytes = await readFile(filename)
  if (!bytes.length) throw new Error(`Empty notice: ${filename}`)
  inventory.push(`${label}: SHA-256 ${createHash('sha256').update(bytes).digest('hex')}`)
  return { label, text: plainText(bytes.toString('utf8'), filename) }
}

async function writeNotices(filename, heading, notices) {
  const groups = new Map()
  for (const { label, text } of notices) {
    if (!groups.has(text)) groups.set(text, [])
    groups.get(text).push(label)
  }
  const sections = [...groups].map(([text, labels]) => `${labels.join('\n')}\n\n${text}`)
  await writeFile(resolve(output, filename), `${heading}\n\n${sections.join('\n\n' + '='.repeat(78) + '\n\n')}\n`)
}

await mkdir(output, { recursive: true })
const cargo = []
for (const crate of metadata.packages.filter(crate => crate.source).sort((a, b) => a.id.localeCompare(b.id))) {
  const root = dirname(crate.manifest_path)
  const names = (await readdir(root, { withFileTypes: true }))
    .filter(entry => entry.isFile() && /^(?:licen[cs]es?|copying|copyright|notices?|authors)(?:[._-]|$)/i.test(entry.name))
    .map(entry => entry.name)
  if (crate.license_file && !names.includes(crate.license_file)) names.push(crate.license_file)
  if (!names.length) throw new Error(`No notice files found for ${crate.name} ${crate.version}`)
  for (const name of names.sort()) {
    const label = `${crate.name} ${crate.version} — ${crate.license ?? 'see license file'} — ${name}\n${crate.repository ?? crate.source}`
    cargo.push(await notice(label, resolve(root, name)))
  }
}
await writeNotices('cargo.txt', 'Notices for the locked Rust dependency graph, including build dependencies.', cargo)

for (const component of inputs.components.toSorted((a, b) => a.id.localeCompare(b.id))) {
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(component.id) || ['cargo', 'sources'].includes(component.id)) {
    throw new Error(`Invalid component ID: ${component.id}`)
  }
  const notices = []
  for (const [name, path] of Object.entries(component.files).sort(([a], [b]) => a.localeCompare(b))) {
    notices.push(await notice(`${component.name} ${component.version} — ${name}`, resolve(directory, path)))
  }
  if (!notices.length) throw new Error(`No notice files provided for ${component.id}`)
  await writeNotices(`${component.id}.txt`, `${component.name} ${component.version}\n${component.source}`, notices)
}

await writeFile(resolve(output, 'sources.txt'), [
  'Third-party notices for the bundled native helpers and browser verifier.',
  'Generated from the release dependency sources and toolchains; npm dependencies',
  'also carry their own notices. Some entries apply only to particular targets.',
  'Identical license texts are grouped while retaining their source labels.',
  '',
  ...inventory,
  '',
].join('\n'))
console.log(`Wrote notices for ${metadata.packages.filter(crate => crate.source).length} Rust dependencies and ${inputs.components.length} runtime components to ${output}`)
