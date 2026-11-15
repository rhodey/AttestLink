import { execFile } from 'node:child_process'
import * as util from './util.js'

const MAX_OUTPUT = 64 * 1024
const DOCUMENT_MAX_BYTES = 24 * 1024

function validDoc(document) {
  if (typeof document !== 'string' || document.length === 0 || document.length > DOCUMENT_MAX_BYTES ||
      !/^[A-Za-z0-9+/]+={0,2}$/.test(document) ||
      Buffer.from(document, 'base64').toString('base64') !== document) {
    throw new Error('Invalid attestation document encoding')
  }
  return document
}

function childProc(args, input) {
  return new Promise((resolve, reject) => {
    const child = execFile(util.executable(), args, {
      encoding: 'utf8', timeout: 5_000, maxBuffer: MAX_OUTPUT,
    }, (error, stdout, stderr) => {
      if (error) {
        error.message = `Attestation helper failed: ${stderr.trim() || error.message}`
        return reject(error)
      }
      resolve(stdout.trim())
    })
    child.stdin.on('error', () => {})
    child.stdin.end(input ?? '')
  })
}

export async function getDoc(nonce, publicKey, userData = {}) {
  if (!userData || Object.getPrototypeOf(userData) !== Object.prototype) {
    throw new TypeError('userData must be an object')
  }
  const encoded = Buffer.from(JSON.stringify(userData)).toString('base64')
  return validDoc(await childProc([
    '-g', '--nonce', nonce, '--public-key', publicKey, '--user-data', encoded,
  ], ''))
}

export async function verifyDoc(document, nonce, publicKey, pcr0) {
  const args = ['-v', '--nonce', nonce, '--public-key', publicKey]
  if (pcr0 !== undefined) {
    util.validPCR(pcr0)
    args.push('--pcr0', pcr0)
  }
  try { validDoc(document) } catch { return false }
  try {
    const output = await childProc(args, `${document}\n`)
    return JSON.parse(output)
  } catch (error) {
    if (error.code === 2) return false
    throw error
  }
}
