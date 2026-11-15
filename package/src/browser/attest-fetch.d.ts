export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue }

export interface Evidence {
  pcrs: { 0: string; [index: number]: string | undefined }
  /** Hex-encoded handshake nonce. */
  nonce: string
  /** Base64-encoded server public key. */
  publicKey: string
  /** Decoded MessagePack; 0 when absent, 1 when decoding fails. */
  userData: JsonValue
  /** Document timestamp in milliseconds since the Unix epoch. */
  timestamp: number
}

export interface AttestResponse extends Response {
  evidence: Evidence
}

export type AttestFetch = (path: string, init?: RequestInit) => Promise<AttestResponse>

export type AttestLinkOptions = {
  extra?: JsonValue
  credentials?: RequestInit['credentials']
  /** Per-fetch timeout in milliseconds, including attestation. Defaults to 5000. */
  timeout?: number
  fetch?: (url: string, init: RequestInit) => Promise<Response>
  verify?: (
    document: string,
    nonce: string,
    publicKey: string,
    pcr0?: string,
  ) => Evidence | false | Promise<Evidence | false>
} & (
  | { pcr0: string; anyPCR?: false }
  | { pcr0?: never; anyPCR: true }
)

/** Creates a fetch function that verifies a fresh attestation for every request. */
export function attestLink(endpoint: string | URL, options: AttestLinkOptions): AttestFetch
