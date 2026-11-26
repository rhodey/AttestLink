export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue }

interface AttestationFields {
  pcrs: { 0: string; [index: number]: string | undefined }
  /** Hex-encoded handshake nonce. */
  nonce: string
  /** Document timestamp in milliseconds since the Unix epoch. */
  timestamp: number
}

/** Document fields returned by the verifier. */
export interface Evidence extends AttestationFields {
  /** Base64-encoded server public key. */
  publicKey: string
  /** Decoded MessagePack; 0 when absent, 1 when decoding fails. */
  userData: JsonValue
}

export interface ConnectionEvidence extends AttestationFields {
  /** Base64-encoded public key sent by the client in the hello. */
  clientPubKey: string
  /** Base64-encoded public key from the verified document. */
  serverPubKey: string
  /** Decoded server claims; 0 when absent, 1 when decoding fails. */
  serverClaims: JsonValue
}

export interface AttestResponse extends Response {
  /** Verified evidence from the hello that established this request's session keys. */
  evidence: ConnectionEvidence
}

export type AttestFetch = (path: string, init?: RequestInit) => Promise<AttestResponse>

export type AttestLinkOptions = {
  extra?: JsonValue
  credentials?: RequestInit['credentials']
  /** Timeout from invocation, including queueing and any handshake. Defaults to 5000 ms. */
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

/** Creates a serial fetch function that reuses its attested session across calls. */
export function attestLink(endpoint: string | URL, options: AttestLinkOptions): AttestFetch
