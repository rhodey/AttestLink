# AttestLink

This repo contains an npm tool [attest-link](https://www.npmjs.com/package/attest-link)
that allows tunneling any TCP/HTTP protocol into and out of [AWS Nitro Sandboxes](https://aws.amazon.com/blogs/compute/nitro-sandboxes-hardware-isolation-for-every-eks-pod-ecs-task-and-ec2-workload/).
Clients handshake with servers over HTTP/2 and exchange [libsodium](https://www.npmjs.com/package/libsodium)
keys that are bound to the Nitro attestation doc. This repo also has sources for
building and deploying a Nitro Sandbox demo that shows SSH over an attest-link tunnel.

**Attestation = Your code/VM has a cryptographic identity. Code as contract, etc.**

**Want to build on Nitro? Start here.**

## Examples

Inside Nitro Sandbox: serve SSH:
```
sshd -p 2223
attest-link -s 2222 2223
```

**You do:**
```
npx attest-link 2222 http://ec2.ip.addr.ess:2222 --any-pcr
ssh -p 2222 sandbox@localhost
```

Inside Nitro Sandbox: serve HTTP:
```
HTTP_PORT=8081 nodejs /app/app.js
attest-link -s 8080 8081
```

**You do:**
```
npx attest-link 8080 http://ec2.ip.add.ress:8080 --any-pcr
curl -v http://localhost:8080/test-me
```

## More docs

The [CLI docs](package/) include details like how to tunnel `stdio`, how
to add attestation hooks, and how to bind to PCRs.

The [browser docs](package/README.md#browser) show how browsers can use
`fetch` with `attest-link -s` servers.


## Sandbox demo

The demo targets ARM64 EC2 types and uses Nix for reproducible builds.
The demo starts by initializing its clock using a timestamp from a fresh
attestation doc and then starts up [Chrony](https://chrony-project.org/)
with encrypted NTS to keep the clock in sync. After this [dnsproxy](https://github.com/adguardteam/dnsproxy)
starts to resolve DNS over encrypted DoT. Then finally `sshd` starts and
`attest-link` wires up the tunnel that forwards to `sshd` after attest
flow.

**See: [nitro/boot.sh](nitro/boot.sh), then if you want: ask your agent
how to adapt the demo to an HTTP API.**

## Contents

| Directory | Contents |
| --- | --- |
| [package/](package/) | JavaScript CLI |
| [rust/](rust/) | Native attestation |
| [nitro/](nitro/) | Demo build & deploy |

## Collaborations

This work is licensed `MIT`. Also I happen to be looking for new opportunities:

Copyright 2026: Email:  mike@rhodey.org
