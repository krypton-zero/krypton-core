# Security policy

## Reporting a vulnerability

Please do not open a public issue, pull request or discussion for a security problem.

Email **support@krypton-0.com** with a subject line that starts with `[security]`.

Please include:

- the affected commit,
- a description of the issue and its impact (for example key or plaintext disclosure, forged signatures or
  envelopes, a broken recovery threshold, or memory unsafety at the C or JNI boundary),
- steps to reproduce, or a proof of concept (a failing test is ideal),
- whether and how you would like to be credited.

If you need an encrypted channel, say so in your first email and we will arrange one.

## Coordinated disclosure

We ask for a coordination period of **90 days** from the date of your report before any public disclosure.
We will work with you on a fix and agree on the disclosure date with you; if a fix ships earlier, we may
agree to disclose sooner. We will credit reporters unless they ask us not to.

## Scope

In scope: the code in this repository, including the cryptographic constructions and their use, the wire
formats, account recovery, stream encryption, zeroization, and the C ABI and JNI boundary (pointer and length
handling, panics crossing the boundary).

Vulnerabilities in upstream dependencies (for example `ed25519-dalek`, `x25519-dalek`, `voprf` or the
RustCrypto crates) should be reported to their maintainers first. Please let us know as well if you believe
Krypton Ø is affected.

Problems in other parts of Krypton Ø (the apps or the service) can be reported to the same address.
