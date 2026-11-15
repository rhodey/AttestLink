# Sandbox image builder

`nitro-eif` builds one explicit profile: ARM64, confidential mode, 2048 MiB,
one dedicated vCPU, PCIe virtio, no hotplug or CPU accounting/overcommit.

```sh
nitro-eif --kernel Image --initramfs initramfs.cpio.gz \
  --cmdline 'panic=1 initcall_blacklist=i8042_init' \
  --output image.eif --manifest measurements.json
nitro-eif --inspect image.eif
```

Output files must not already exist. A Nix derivation provides the kernel,
initramfs and command line; neither source paths nor the current time enter
the EIF or manifest. The memory and CPU settings are also EIF inputs.

## Upstream writer

`src/upstream.rs` is copied unchanged from
[Firecracker v1.18.0](https://github.com/firecracker-microvm/firecracker/blob/eaf83bb718a559d324613d566eaf776b31a62340/src/vmm/src/nitro_enclave/eif.rs).
The immutable source revision is
`eaf83bb718a559d324613d566eaf776b31a62340`; the Apache-2.0 license and file
copyright notice are retained. `src/main.rs` supplies its small host utility
adapter and fixes the launch profile. The upstream tests are retained too.

This avoids depending on the currently unavailable `eif_build --pcie-virtio`
CLI option. Firecracker recognizes the resulting prebuilt EIF and loads it
unchanged. The launch configuration must match the image's feature flags.

## Measurements

`measure.mjs` uses Node built-ins to check the header, section layout and CRC.
It reports SHA-256 artifact hashes and SHA-384 PCR measurements that match the
Sandbox's signed NSM attestation. With one initramfs, PCR1 covers the entire
Sandbox's kernel/command-line/userspace, and PCR2 is the measurement of empty input.
Metadata affects PCR6 and the file hash but not PCR1/PCR2.

PCR0 appends the image's matched feature flags, masked by `0xffc0` and encoded
as a two-byte big-endian integer, to the kernel, command line and initramfs
before computing the content digest. For this profile the bytes are `02 40`;
the EIF header's ARM64 architecture bit is excluded.

Let `H` be SHA-384, `Z` be 48 zero bytes, and `||` concatenate bytes:

```text
PCR0 = H(Z || H(kernel || command-line || initramfs || 02 40))
PCR1 = H(Z || H(kernel || command-line || initramfs))
PCR2 = H(Z || H(empty))
PCR6 = H(Z || H(whole-EIF))
```

The `measurementProfile` identifier names the encoding used in the manifest.
The Sandbox integration test verifies PCR0, PCR1, PCR2 and PCR6 against signed,
nonce/key-bound NSM attestation. Supply the local PCR0 to `attest-link` to
approve that image, or use `--any-pcr` to verify attestation without approving
a particular image.

The [reproducibility check](../README.md#tests-and-reproducibility) rebuilds the
project's kernel, helpers, JavaScript package and image, then compares complete
Nix outputs, artifact hashes and PCR measurements.

References:

- [AWS Sandbox measurement semantics](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitro-sandboxes-attestation.html)
- [Existing EIF measurement formulas](https://github.com/aws/aws-nitro-enclaves-image-format/blob/9cd75255c1488e1e586437eb37a6a36afc3b5743/README.md#eif-measurements)
