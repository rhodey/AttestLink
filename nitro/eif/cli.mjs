#!/usr/bin/env node
import { readFile, writeFile } from 'node:fs/promises'
import { spawnSync } from 'node:child_process'
import { parseArgs } from 'node:util'
import { measureImage } from './measure.mjs'

try {
  const { values } = parseArgs({
    options: {
      kernel: { type: 'string' },
      initramfs: { type: 'string' },
      cmdline: { type: 'string' },
      output: { type: 'string' },
      manifest: { type: 'string' },
      inspect: { type: 'string' },
    },
  })
  if (values.inspect) {
    const bytes = await readFile(values.inspect)
    console.log(JSON.stringify(measureImage(bytes), null, 2))
  } else {
    for (const name of ['kernel', 'initramfs', 'cmdline', 'output', 'manifest']) {
      if (values[name] === undefined) throw new Error(`missing --${name}`)
    }
    if (values.output === values.manifest) throw new Error('output and manifest paths must differ')
    const writer = process.env.NITRO_EIF_WRITER ?? 'nitro-eif-write'
    const child = spawnSync(writer, [values.kernel, values.initramfs, values.cmdline, values.output], {
      stdio: ['ignore', 'inherit', 'inherit'],
    })
    if (child.error) throw child.error
    if (child.status !== 0) throw new Error(`EIF writer failed with status ${child.status}`)
    const manifest = measureImage(await readFile(values.output))
    await writeFile(values.manifest, `${JSON.stringify(manifest, null, 2)}\n`, { flag: 'wx' })
    console.log(JSON.stringify(manifest.measurements, null, 2))
  }
} catch (error) {
  console.error('nitro-eif (error)', error.message)
  process.exitCode = 1
}
