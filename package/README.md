# attest-link

Tunnel any TCP/HTTP protocol into and out of AWS Nitro Sandboxes. Clients
handshake with servers over HTTP/2 and exchange [libsodium](https://www.npmjs.com/package/libsodium)
keys that are bound to the Nitro attestation doc.

**Attestation = Your code/VM has a cryptographic identity. Code as contract, etc.**

## Usage

```sh
npm install -g attest-link
attest-link [-e JSON] LISTEN ENDPOINT (PCR0 | --any-pcr)
attest-link -s [-c HOOK] LISTEN BACKEND
```

`LISTEN` and `BACKEND` accept a port, `HOST:PORT`, or `[IPv6]:PORT`. Bare ports
default to `127.0.0.1` for client mode and `0.0.0.0` for server mode. Server
mode wont work outside a Nitro Enclave/Sandbox.

`ENDPOINT` is an HTTP or HTTPS URL; the client appends `/hello` and `/duplex` to
its path and uses POST. HTTPS adds pretty much no security in context but you
maybe have an HTTPS load balancer in-front of your EC2 and so we say OK and just
go along with it. Neither AWS ALB or Cloudflare support full-duplex HTTP/2 but
nginx can be made to work. `ENDPOINT` needs to route to where `attest-link -s`
is listening. `BACKEND` points to any TCP.

`PCR0` is the expected code/VM measurement: a 96 char hex-string that comes
from build time. Supply `PCR0` or use `--any-pcr` to accept anything. The any
PCR option does not skip validation of the certificate chain AKA: AWS infra is
still known to have signed the doc but what code/VM the doc corresponds to can
be anything at all.

- `LISTEN` as `0` prints the attest doc as JSON and exits. It briefly connects to
  `ENDPOINT`, which must be available.
- `LISTEN` as `stdio` opens an stdin/stdout tunnel. After attestation, stdout sees
  two JSON lines: `{"event":"listening","address":"stdio"}`, then the attest doc
  as JSON. Then all bytes are raw from `BACKEND`.

## Attestation hook

`-c HOOK` runs `bash -o pipefail -c HOOK` before obtaining any attestation document.
The program at `-c HOOK` will see JSON at stdin:

```json
{"nonce":"…","publicKey":"…","extra":{"is":"passed by -e JSON"},"cookies":"session=abc; theme=dark"}
```

It's not easy to think of a reason why you'd want `nonce` and `publicKey` but it
costs nothing to pass them so they are passed in, `extra` comes from `-e JSON` and
`cookies` is the raw HTTP header without any parsing. Read attest-server.js if you
think you want to do something with `nonce` or `publicKey`. There is no immediate
need for you to use an attestation hook, it's here because maybe you want to rate-limit
or auth-gate access even before clients/users are allowed a tunnel.

| Hook result | Server behavior |
| --- | --- |
| Exit `0`, JSON object on stdout | Include it as doc.userData and continue |
| Exit `2`, `{"code":403,"message":"Access denied"}` | Return that HTTP code and JSON body |
| Exit `1`, any other failure | Return HTTP 500 |

## Browser

HTTP/2 supports full-duplex streaming but browsers have no APIs for using it.
The `WebTransport` APIs with HTTP/3 are looking cool but adoption needs to grow
some more. Anyways we have a solution that keeps HTTP/2:

```js
import { attestLink } from 'attest-link'

const endpoint = 'https://example.com/attest'
const attestFetch = attestLink(endpoint, { pcr0: 'YOUR_IMAGE_PCR0' })
const response = await attestFetch('/inside/enclave')
const data = await response.json()
```

The library hits `ENDPOINT/hello` like the CLI to start the handshake but then
instead of moving onto `ENDPOINT/duplex` it POSTs a payload to `ENDPOINT/fetch`.
The `attest-link -s` server decrypts the payload using the libsodium session
and forwards it onto `BACKEND/inside/enclave` as unencrypted HTTP/1.

This has been tested with an AWS ALB where an EC2 is added to an HTTP/2
target group. Cloudflare and others should work since we're in a
request-response model with the browser. If you want your Nitro Sandbox
to do browser **and** CLI/streaming then you need nginx or put it behind
ALB/Cloudflare **plus** give it public DNS that doesn't load balance.

## Cookies

A decision has been made to prioritize compatibility over max security here. HTTP
method, path, body, and all headers besides `Cookie` are encrypted such that only
inside the sandbox can see them. There exist a few options to partially support
encrypted cookies but each has a weakness, and there is no workaround that can
support `HttpOnly` cookies which we do not want to break.

What does this mean? The host EC2 can spy on cookies and if the EC2 is behind a
load balancer that can spy on cookies too. What to do? If you want to keep a piece
of information secret then don't put it into a cookie, pass it as JSON.

## CORS

`Access-Control-Allow-Origin` defaults to `*`, override it like this:

```sh
CORS_ORIGIN=https://app.example.com attest-link -s 8080 8081
```

## Collaborations

This work is licensed `MIT`. Also I happen to be looking for new work opportunities:

Copyright 2026: Email:  mike@rhodey.org
