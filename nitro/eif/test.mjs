import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, utimes, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { test } from 'node:test'
import { crc32 } from 'node:zlib'
import { decodeImage, measureImage } from './measure.mjs'

const writer = process.env.NITRO_EIF_WRITER
  ?? fileURLToPath(new URL('./target/debug/nitro-eif-write', import.meta.url))

async function withImage(callback) {
  const directory = await mkdtemp(join(tmpdir(), 'nitro-eif-test-'))
  try {
    const kernel = join(directory, 'Image')
    const initramfs = join(directory, 'initramfs')
    const output = join(directory, 'image.eif')
    await writeFile(kernel, 'a small synthetic kernel')
    await writeFile(initramfs, 'a small synthetic initramfs')
    const build = (path) => {
      const result = spawnSync(writer, [kernel, initramfs, 'console=ttyS0', path], { encoding: 'utf8' })
      assert.ifError(result.error)
      assert.equal(result.status, 0, result.stderr)
    }
    build(output)
    await callback({ directory, kernel, initramfs, output, build, image: await readFile(output) })
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
}

function repairCrc(bytes) {
  bytes.writeUInt32BE(crc32(bytes.subarray(548), crc32(bytes.subarray(0, 544))), 544)
}

test('upstream writer produces the same bytes after input timestamps change', async () => {
  await withImage(async ({ directory, kernel, initramfs, build, image }) => {
    await utimes(kernel, 123456, 123456)
    await utimes(initramfs, 987654, 987654)
    const second = join(directory, 'another-name.eif')
    build(second)
    assert.deepEqual(await readFile(second), image)
    const manifest = measureImage(image)
    assert.equal(manifest.launch.memoryMiB, 2048)
    assert.equal(manifest.launch.vcpus, 1)
    assert.equal(manifest.launch.flags, '0x0241')
    // Published AWS empty-input PCR2 vector, independent of this implementation.
    assert.equal(manifest.measurements.PCR2,
      '21b9efbc184807662e966d34f390821309eeac6802309798826296bf3e8bec7c10edb30948c90ba67310f7b964fc500a')
  })
})

test('tampering and malformed section tables cannot produce approval measurements', async () => {
  await withImage(async ({ image }) => {
    const corrupted = Buffer.from(image)
    corrupted[600] ^= 1
    assert.throws(() => measureImage(corrupted), /CRC32 mismatch/)

    const badOffset = Buffer.from(image)
    badOffset.writeBigUInt64BE(0xffffffffffffffffn, 28 + 16)
    repairCrc(badOffset)
    assert.throws(() => measureImage(badOffset), /section offsets/)

    const trailing = Buffer.concat([image, Buffer.from('extra')])
    repairCrc(trailing)
    assert.throws(() => measureImage(trailing), /trailing data/)
  })
})

test('images with a different memory or CPU profile cannot produce approval measurements', async () => {
  await withImage(async ({ image }) => {
    const moreMemory = Buffer.from(image)
    moreMemory.writeBigUInt64BE(4096n * 1024n * 1024n, 8)
    repairCrc(moreMemory)
    assert.throws(() => measureImage(moreMemory), /memory size/)

    const moreCpus = Buffer.from(image)
    moreCpus.writeBigUInt64BE(2n, 16)
    repairCrc(moreCpus)
    assert.throws(() => measureImage(moreCpus), /CPU count/)
  })
})

test('the first initramfs is measured by PCR1, even with no later application ramdisk', async () => {
  await withImage(async ({ image, initramfs, directory, build }) => {
    const original = measureImage(image)
    await writeFile(initramfs, 'changed application')
    const second = join(directory, 'changed.eif')
    build(second)
    const changed = measureImage(await readFile(second))
    assert.notEqual(changed.measurements.PCR0, original.measurements.PCR0)
    assert.notEqual(changed.measurements.PCR1, original.measurements.PCR1)
    assert.equal(changed.measurements.PCR2, original.measurements.PCR2)
    assert.notEqual(changed.measurements.PCR6, original.measurements.PCR6)
  })
})

test('PCR0 uses the matched feature flags in BE16 and excludes the EIF architecture bit', async () => {
  await withImage(async ({ image }) => {
    const manifest = measureImage(image)
    // Fixed vectors independently computed with Python hashlib from the literal
    // fixture bytes. The PCR0 suffix is 02 40, although the EIF header says 02 41.
    // The encoding was confirmed against real, signed Sandbox NSM measurements.
    assert.equal(manifest.measurements.PCR0,
      '38e2e230adae311c5b3edbaac55e3728c0dd6de2ae5882442f304dd0dda19cca5e5ff584cded49902b2876784a233ea7')
    assert.equal(manifest.measurements.PCR1,
      'f5e34a3261e17fe83a9d4df623d969458be5c5171d77c7779bebdf27b305b31383adcbedb96d45c49cab072ab916bf27')
  })
})

test('metadata changes the complete image measurement but not Sandbox-content measurements', async () => {
  await withImage(async ({ image }) => {
    const original = measureImage(image)
    const changedImage = Buffer.from(image)
    const sections = decodeImage(changedImage)
    const index = sections.metadata.indexOf('firecracker-enclave')
    assert.ok(index >= 0)
    sections.metadata[index] = 'F'.charCodeAt(0)
    repairCrc(changedImage)
    const changed = measureImage(changedImage)
    for (const pcr of ['PCR0', 'PCR1', 'PCR2']) {
      assert.equal(changed.measurements[pcr], original.measurements[pcr])
    }
    assert.notEqual(changed.measurements.PCR6, original.measurements.PCR6)
    assert.notEqual(changed.sha256.eif, original.sha256.eif)
  })
})
