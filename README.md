# TESTING

This fork of the rust-hpke project is supplemental material for the paper [Agile, Post-quantum Secure Cryptography in Avionics](https://eprint.iacr.org/2024/667).

See the [parent repository](https://github.com/rosenpass/paper-hpke-in-avionics-supplemental) to compile this or to reproduce the benchmarks.

**Do NOT use this fork for anything other than testing**

See the directory src/kem/ for our KEM implementations

- xyber768 - Basic variant of our combiner with post-quantum secrecy and pre-quantum authentication
- xyber768dilithium - Variant of our combiner with post-quantum secrecy AND post-quantum authentication
- xyber1024dilithium – Variant of our combiner with extra security (NIST level 5 KEMs and Signatures, x448 instead of x25519 for pre-quantum security)

Our initial submission used pure rust implementations of Kyber and Dilithium. These did not seem very trustworthy, so we decided to use
up-to-date implementations of ML-KEM and ML-DSA for liboqs, so there are now two variants. ML-KEM/ML-DSA are the names given to Kyber/Dilithium
after standardization through NIST. In order to be able to understand any performance impact of this change, we kept both variants around.

- *plain variants* – I.e. those without _oqs.rs are using less trustworthy pure rust implementations of the combiner
- *_oqs variants* – These with the suffix `_oqs.rs` are our updated implementations using liboqs

xyber768dilithium and xyber1024dilithium differ by the amount of additional data that is mixed into the key derivation step.
xyber1024dilithium includes the kyber ciphertext, the smaller – 768 – variant omits that value. The reasons for this are fairly
technical; you can read up on the background in the [X-Wing combiner paper](https://eprint.iacr.org/2024/039). We opted to include
the kyber ciphertext in the stronger variant, because without it we would be relying on the collision resistance of shak256 for
security. By including the ciphertext we can rely on shake256's pre-image resistance only which provides a better advantage against
quantum adversaries – according to people we know who are knowledgeable about quantum security analysis.

To estimate the impact of this change we added `_ghp` variants of `xyber768*` so we can directly compare the impact of a slightly more
involved hashing step.

Finally, we also added a fairly ad-hoc implementation of `DHKEM(X448, HKDF-SHA-512)` (see src/dhkex/x448.rs) to support `xyber1024dilithium`.
This algorithm is standardized as part of [HPKE - rfc9189](https://datatracker.ietf.org/doc/rfc9180/) but our implementation was written with
minimal effort. The only sensible use for this particular implementation is benchmarking.

rust-hpke
=========
[![Version](https://img.shields.io/crates/v/hpke.svg)](https://crates.io/crates/hpke)
[![Docs](https://docs.rs/hpke/badge.svg)](https://docs.rs/hpke)
[![CI](https://github.com/rozbb/rust-hpke/workflows/CI/badge.svg)](https://github.com/rozbb/rust-hpke/actions)

This is an implementation of the [HPKE](https://www.rfc-editor.org/rfc/rfc9180.html) hybrid encryption standard (RFC 9180).

Warning
-------

This crate has not been formally audited. Cloudflare [did a security](https://blog.cloudflare.com/using-hpke-to-encrypt-request-payloads/) review of version 0.8, though:

> The HPKE implementation we decided on comes with the caveat of not yet being
> formally audited, so we performed our own internal security review. We
> analyzed the cryptography primitives being used and the corresponding
> libraries. Between the composition of said primitives and secure programming
> practices like correctly zeroing memory and safe usage of random number
> generators, we found no security issues.

What it implements
------------------

This implementation complies with the [HPKE standard](https://www.rfc-editor.org/rfc/rfc9180.html) (RFC 9180).

Here are all the primitives listed in the spec. The primitives with checked boxes are the ones that are implemented.

* KEMs
    - [X] DHKEM(Curve25519, HKDF-SHA256)
    - [ ] DHKEM(Curve448, HKDF-SHA512)
    - [X] DHKEM(P-256, HKDF-SHA256)
    - [X] DHKEM(P-384, HKDF-SHA384)
    - [X] DHKEM(P-521, HKDF-SHA512)
* KDFs
    - [X] HKDF-SHA256
    - [X] HKDF-SHA384
    - [X] HKDF-SHA512
* AEADs
    - [X] AES-GCM-128
    - [X] AES-GCM-256
    - [X] ChaCha20Poly1305

Crate Features
--------------

Default features flags: `alloc`, `x25519`, `p256`.

Feature flag list:

* `alloc` - Includes allocating methods like `AeadCtxR::open()` and `AeadCtxS::seal()`
* `x25519` - Enables X25519-based KEMs
* `p256` - Enables NIST P-256-based KEMs
* `p384` - Enables NIST P-384-based KEMs
* `p521` - Enables NIST P-521-based KEMs
* `std` - Includes an implementation of `std::error::Error` for `HpkeError`. Also does what `alloc` does.

For info on how to omit or include feature flags, see the [cargo docs on features](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#choosing-features).

Usage Examples
--------------

See the [client-server](examples/client_server.rs) example for an idea of how to use HPKE.

Breaking changes
----------------

### Breaking changes in v0.12

The `serde_impls` feature was removed. If you were using this and require backwards compatible serialization/deserialization, see the wiki page [here](https://github.com/rozbb/rust-hpke/wiki/Migrating-away-from-the-serde_impls-feature).

MSRV
----

The current minimum supported Rust version (MSRV) is 1.65.0 (897e37553 2022-11-02).

Changelog
---------

See [CHANGELOG.md](CHANGELOG.md) for a list of changes made throughout past versions.

Tests
-----

To run all tests, execute `cargo test --all-features`. This includes known-answer tests, which test against `test-vector-COMMIT_ID.json`,where `COMMIT_ID` is the short commit of the version of the [spec](https://github.com/cfrg/draft-irtf-cfrg-hpke) that the test vectors came from. The finalized spec uses commit 5f503c5. See the [reference implementation](https://github.com/cisco/go-hpke) for information on how to generate a test vector.

Benchmarks
----------

To run all benchmarks, execute `cargo bench --all-features`. If you set your own feature flags, the benchmarks will still work, and run the subset of benches that it is able to. The results of a benchmark can be read as a neat webpage at `target/criterion/report/index.html`.

Ciphersuites benchmarked:

* NIST Ciphersuite with 128-bit security: AES-GCM-128, HKDF-SHA256, ECDH-P256
* Non-NIST Ciphersuite with 128-bit security: ChaCha20-Poly1305, HKDF-SHA256, X25519

Functions benchmarked in each ciphersuite:

* `Kem::gen_keypair`
* `setup_sender` with OpModes of Base, Auth, Psk, and AuthPsk
* `setup_receiver` with OpModes of Base, Auth, Psk, and AuthPsk
* `AeadCtxS::seal` with plaintext length 64 and AAD length 64
* `AeadCtxR::open` with ciphertext length 64 and AAD length 64

Agility
-------

A definition: *crypto agility* refers to the ability of a cryptosystem or protocol to vary its underlying primitives. For example, TLS has "crypto agility" in that you can run the protocol with many different ciphersuites.

This crate does not support crypto agility out of the box. This is because the cryptographic primitives are encoded as types satisfying certain constraints, and types need to be determined at compile time (broadly speaking). That said, there is nothing preventing you from implementing agility yourself. There is a [sample implementation](examples/agility.rs) in the examples folder. The sample implementation is messy because agility is messy.

License
-------

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
 * MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
