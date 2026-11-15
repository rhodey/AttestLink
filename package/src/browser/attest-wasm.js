const INPUT_MAX_BYTES = 32 * 1024

let runtime

export async function verifyDoc(document, nonce, publicKey, pcr0, rootPem) {
  const input = JSON.stringify({ document, nonce, publicKey, pcr0, rootPem })
  // ccall copies this string onto the WASM stack before Rust can check its size.
  if (input.length > INPUT_MAX_BYTES) return false
  runtime ??= import('../../wasm/attest-link.js').then(({ default: createModule }) => createModule({ noInitialRun: true }))
  const wasm = await runtime
  const output = wasm.ccall('attest_link_verify', 'number', ['string'], [input])
  try {
    const result = JSON.parse(wasm.UTF8ToString(output))
    if (result?.error) throw new Error(`Attestation helper failed: ${result.error}`)
    return result
  } finally {
    wasm._attest_link_free(output)
  }
}
