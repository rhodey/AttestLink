# attest-link-rust

Builds `attest-link-rust` which is used to request attestation docs from the AWS Nitro Hypervisor.

The same also compiles to WASM for the [js package](/package) browser code paths.

## Install

From the AttestLink root dir:

```sh
cargo install --locked --path rust
```

Then: `attest-link-rust` should be on `PATH`, or set `ATTEST_LINK_RUST` (js looks here too).

## Usage

```sh
attest-link-rust -g [-x] --nonce HEX --public-key BASE64 [--user-data BASE64_JSON]
attest-link-rust -v --nonce HEX --public-key BASE64 [--pcr0 HEX] < document.base64
```

- `-g` obtains an attest doc and prints base64.
- `-v` verifies an attest doc and prints JSON.
- `-g -x` obtains and verifies and prints JSON but uses doc.timestamp instead of sys time.

The `-g -x` behavior is used by [nitro/boot.sh](/nitro/boot.sh) to bootstrap time.

## License

Copyright 2026:  mike@rhodey.org

MIT
