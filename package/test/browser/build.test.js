import test from 'node:test'
import assert from 'node:assert/strict'
import { build } from 'esbuild'

test('the npm browser entry bundles without Node APIs or a service worker', async () => {
  const result = await build({
    stdin: {
      contents: "import { attestLink } from 'attest-link'\nglobalThis.attestLink = attestLink",
      resolveDir: new URL('../..', import.meta.url).pathname,
    },
    bundle: true, platform: 'browser', format: 'esm', write: false, metafile: true,
  })
  assert.equal(result.errors.length, 0)
  const inputs = Object.keys(result.metafile.inputs)
  assert.ok(inputs.some(file => file.endsWith('wasm/attest-link.js')))
  assert.ok(inputs.some(file => file.endsWith('src/browser/attest-wasm.js')))
  assert.ok(!inputs.some(file => file.includes('node:') || file.endsWith('src/attest.js')))
})
