import { createHash } from 'node:crypto'
import { crc32 } from 'node:zlib'

const HEADER_BYTES = 548
const SECTION_HEADER_BYTES = 12
const ZERO_PCR = Buffer.alloc(48)
// Matched launch features occupy bits 6..15. Bit 0 describes ARM64 in the EIF
// header but is not a matched launch feature and does not enter the PCR0 suffix.
const MATCHED_FEATURE_MASK = 0xffc0

function hash(algorithm, ...parts) {
  const digest = createHash(algorithm)
  for (const part of parts) digest.update(part)
  return digest.digest()
}

const sha384 = (...parts) => hash('sha384', ...parts)
const measurement = (...parts) => sha384(ZERO_PCR, sha384(...parts)).toString('hex')

function fail(message) {
  throw new Error(`Invalid EIF: ${message}`)
}

// Verify the image layout before deriving approval values from its contents.
// This accepts exactly our unsigned, single-initramfs ARM64 Sandbox profile.
export function decodeImage(image) {
  if (!Buffer.isBuffer(image) || image.length < HEADER_BYTES) fail('truncated header')
  if (!image.subarray(0, 4).equals(Buffer.from('.eif'))) fail('magic')
  if (image.readUInt16BE(4) !== 4) fail('version')
  if (image.readUInt16BE(6) !== 0x241) fail('launch feature flags')
  if (image.readBigUInt64BE(8) !== 2048n * 1024n * 1024n) fail('memory size')
  if (image.readBigUInt64BE(16) !== 1n) fail('CPU count')
  if (image.readUInt16BE(24) !== 0 || image.readUInt32BE(540) !== 0) fail('reserved fields')
  if (image.readUInt16BE(26) !== 4) fail('expected kernel, command line, initramfs and metadata')
  const actualCrc = crc32(image.subarray(548), crc32(image.subarray(0, 544)))
  if (actualCrc !== image.readUInt32BE(544)) fail('CRC32 mismatch')

  let offset = HEADER_BYTES
  const sections = []
  const expectedTypes = [1, 2, 3, 5]
  for (let index = 0; index < 32; index++) {
    const recordedOffset = image.readBigUInt64BE(28 + index * 8)
    const recordedSize = image.readBigUInt64BE(284 + index * 8)
    if (index >= 4) {
      if (recordedOffset !== 0n || recordedSize !== 0n) fail('unused section table entry')
      continue
    }
    if (recordedOffset !== BigInt(offset)) fail('non-contiguous section offsets')
    if (offset + SECTION_HEADER_BYTES > image.length) fail('truncated section header')
    if (image.readUInt16BE(offset) !== expectedTypes[index]) fail('section ordering')
    if (image.readUInt16BE(offset + 2) !== 0) fail('section flags')
    const size = image.readBigUInt64BE(offset + 4)
    if (size !== recordedSize) fail('section size mismatch')
    if (size > BigInt(image.length - offset - SECTION_HEADER_BYTES)) fail('truncated section')
    offset += SECTION_HEADER_BYTES
    sections.push(image.subarray(offset, offset + Number(size)))
    offset += Number(size)
  }
  if (offset !== image.length) fail('trailing data')
  if (sections[0].length === 0 || sections[2].length === 0) fail('empty kernel or initramfs')
  return {
    kernel: sections[0],
    commandLine: sections[1],
    initramfs: sections[2],
    metadata: sections[3],
    flags: image.subarray(6, 8),
  }
}

export function measureImage(image) {
  const { kernel, commandLine, initramfs, flags } = decodeImage(image)
  const measuredFlags = Buffer.alloc(2)
  measuredFlags.writeUInt16BE(flags.readUInt16BE() & MATCHED_FEATURE_MASK)
  return {
    schemaVersion: 1,
    architecture: 'aarch64',
    launch: {
      memoryMiB: 2048,
      vcpus: 1,
      flags: '0x0241',
      confidential: true,
      cpuOvercommit: false,
      hotplug: false,
      commandLine: commandLine.toString('utf8'),
    },
    sha256: {
      kernel: hash('sha256', kernel).toString('hex'),
      initramfs: hash('sha256', initramfs).toString('hex'),
      eif: hash('sha256', image).toString('hex'),
    },
    measurements: {
      HashAlgorithm: 'SHA384',
      // Confirmed against signed NSM evidence on 2026-11-11: append the matched
      // feature bits as BE16 before hashing the Sandbox's content, then extend PCR0.
      PCR0: measurement(kernel, commandLine, initramfs, measuredFlags),
      PCR1: measurement(kernel, commandLine, initramfs),
      PCR2: measurement(Buffer.alloc(0)),
      PCR6: measurement(image),
    },
    measurementProfile: 'sandbox-arm64-eif-v4-matched-flags-be16-2026-11-11',
  }
}
