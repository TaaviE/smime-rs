# rust-smime

This is a work-in-progress S/MIME implementation for email in Rust. It can currently verify, encrypt and decrypt S/MIME
4.0 mail with PQ additions. Verification is done following the CA/B Forum S/MIME BR.

It verifies both "clear" and "opaque" signatures, when Unobtrusive Signature RFC is more mature that support will also
likely be added.

As usual, use at your own risk, the library has not been thoroughly reviewed by third parties. There might be critical
vulnerabilities that the current test suite and interop harness does not catch.

Can be compiled into WASM for client-side validation (in browsers) and server-side encryption (Node.js), check `pkg` and
`pkg-node` respectively. The browser version also has a really rough demo application in this repository.

There's also an experimental HTTPS proxy for CRL and OCSP requests, but I haven't had the time to integrate it into the
WASM web validator.

### Extras

This project implements a few additional features compared to other clients that are worth highlighting:

* RSA-PSS, EcDSA and Ed25519, ML-DSA signatures and certificates
* UTF-8 support - SMTPUTF8 addresses, SmtpUTF8Mailbox SAN support
* SHAKE support
* Enforcement of CA/B Forum S/MIME BR
* RFC 5940 (Additional CMS Revocation Information Choices) support (for now stapled OCSP responses are used for
  revocation)

Because they're either unused or extremely rare in the S/MIME ecosystem only initial support exists for the following:

* Timestamp response parsing (but trust is not checked)
* SCT parsing (but trust is not checked)
* CRL and OCSP (no automatic fetching just yet, they're only read from CMS) - some work has been done to provide a proxy
  for these requests for WASM targets

Limited or restricted support for the following:

* RFC 9788 (Header Protection) - just the detection and some guidance is taken for the From address display, but nothing
  beyond that. The suggested mechanisms offer additional protection while introducing too much complexity or significant
  downsides. This complexity can introduce vulnerabilities or even intentionally does so by making clients display
  messages differently ("legacy" parts)

In general, most of these additions make the implementation check the structure of the content and do some basic
validation, so it's technically in more strict in some aspects. At the same time it does tolerate less frequently used
constructions that are spec-compliant - making this implementation generally more tolerant than many other
implementations out in the wild.

## RFC compliance

The `rfc` directory contains a bunch of RFCs for quick reference. Most of them are implemented. Makes it significantly
easier to search through when checking implementation details across multiple RFCs (it's tedious to `Ctrl`+`F` across
multiple standards in the browser).