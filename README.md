# rustls-provider-libcrux-pq

A [rustls] crypto provider built on the [libcrux] crates, with post-quantum key exchange
(ML-KEM, FIPS 203) and post-quantum signatures (ML-DSA, FIPS 204) alongside the classical
algorithms.

libcrux is Cryspen's formally verified cryptography library: most of its code is extracted
from verified specifications (HACL\*, hax). Cryspen's own [rustls-libcrux] provider has
ChaCha20-Poly1305, X25519 and X25519MLKEM768 only; this provider is written directly against
`libcrux-ml-kem`, `libcrux-ml-dsa`, `libcrux-curve25519`, `libcrux-p256`, `libcrux-p384`,
`libcrux-ecdsa`, `libcrux-ed25519`, `libcrux-rsa`, `libcrux-aes`, `libcrux-chacha20poly1305`,
`libcrux-sha2` and `libcrux-hmac`.

## Algorithms

**Key exchange**, in the provider's order of preference:

| Group | Code point | TLS versions |
| --- | --- | --- |
| X25519MLKEM768 | `0x11ec` | 1.3 |
| SecP256r1MLKEM768 | `0x11eb` | 1.3 |
| SecP384r1MLKEM1024 | `0x11ed` | 1.3 |
| X25519 | `0x001d` | 1.2, 1.3 |
| P-256 (secp256r1) | `0x0017` | 1.2, 1.3 |
| P-384 (secp384r1) | `0x0018` | 1.2, 1.3 |
| MLKEM512 | `0x0200` | 1.3 |
| MLKEM768 | `0x0201` | 1.3 |
| MLKEM1024 | `0x0202` | 1.3 |

The hybrids follow [draft-ietf-tls-ecdhe-mlkem]: X25519MLKEM768 puts the ML-KEM share first,
the SecP groups put the elliptic-curve share first. Pure ML-KEM follows
[draft-ietf-tls-mlkem]. Received ML-KEM encapsulation keys get FIPS 203's modulus check, which
libcrux's encapsulation leaves to the caller.

**Signatures** (certificates and CertificateVerify, signing and verification):

- ML-DSA-44, ML-DSA-65, ML-DSA-87 (pure ML-DSA, empty context; signing is hedged)
- ECDSA P-256 with SHA-256 (verification also with SHA-384 and SHA-512, for certificates;
  signing uses a random nonce, not RFC 6979)
- Ed25519
- RSA-PSS with SHA-256/384/512, for moduli of 2048, 3072, 4096, 6144 or 8192 bits and the
  public exponent 65537 (what libcrux-rsa takes)

Not available, because libcrux doesn't implement them:

- **ECDSA P-384**: P-384 keys are refused, and certificates or CertificateVerify signatures
  made with P-384 keys don't verify. (P-384 key exchange is available.)
- **RSA PKCS#1 v1.5**: RSA keys sign with PSS only, and certificates signed with PKCS#1 v1.5,
  which is OpenSSL's default for RSA and what most public CAs use, don't verify.

**Cipher suites:**

- TLS 1.3: `TLS13_AES_256_GCM_SHA384`, `TLS13_AES_128_GCM_SHA256`,
  `TLS13_CHACHA20_POLY1305_SHA256`
- TLS 1.2: `TLS_ECDHE_{ECDSA,RSA}_WITH_AES_256_GCM_SHA384`,
  `TLS_ECDHE_{ECDSA,RSA}_WITH_AES_128_GCM_SHA256`,
  `TLS_ECDHE_{ECDSA,RSA}_WITH_CHACHA20_POLY1305_SHA256` (the RSA suites sign with RSA-PSS)

**Private keys:** PKCS#8 for every key type; SEC1 for P-256; PKCS#1 for RSA. ML-DSA PKCS#8
keys are read in all three forms of RFC 9881's `ML-DSA-PrivateKey`: seed only, expanded key
only, and both (OpenSSL 3.5's default). In the "both" form the seed and the expanded key must
match. An expanded key alone doesn't contain the public key and libcrux can't derive it, so
such a key reports no public key (rustls then skips its check that the key matches the
certificate).

libcrux parses no key formats: `pkcs8`, `sec1` and `der` read the key files.

Randomness comes from the operating system through `getrandom`.

## Usage

```toml
[dependencies]
rustls = { version = "0.23.45", default-features = false, features = ["std", "tls12"] }
rustls-provider-libcrux-pq = "0.1"
```

`provider()` returns a `rustls::crypto::CryptoProvider` with everything above:

```rust
use std::sync::Arc;

let provider = Arc::new(rustls_provider_libcrux_pq::provider());
let config = rustls::ClientConfig::builder_with_provider(provider)
    .with_safe_default_protocol_versions()?
    .with_root_certificates(root_store)
    .with_no_client_auth();
```

To offer fewer groups, or change their order, edit `kx_groups` before building a config. For
example, post-quantum hybrids only:

```rust
use rustls::NamedGroup;

let mut provider = rustls_provider_libcrux_pq::provider();
provider.kx_groups.retain(|g| {
    matches!(g.name(), NamedGroup::X25519MLKEM768 | NamedGroup::secp256r1MLKEM768)
        // SecP384r1MLKEM1024: rustls 0.23 has no name for it
        || g.name() == NamedGroup::Unknown(0x11ed)
});
```

To make it the process-wide default provider instead, call
`provider().install_default()` once at startup.

This crate enables rustls's `tls12` feature (it implements the TLS 1.2 suites); it does not
enable `aws-lc-rs` or `ring`.

## Status

- Not FIPS 140-validated: libcrux isn't.
- Every libcrux crate is at 0.0.x, which Cargo treats as incompatible with the next release,
  so each libcrux dependency is pinned in effect to its current release line
  (`libcrux-ml-kem` and `libcrux-ml-dsa` 0.0.11, `libcrux-aes` and
  `libcrux-chacha20poly1305` 0.0.10, `libcrux-ed25519` 0.0.10, the others 0.0.9,
  `libcrux-p384` 0.0.1). Expect version bumps, and API changes with them, as libcrux evolves.
- P-384 comes from `libcrux-p384` 0.0.1, whose own documentation calls it an internal
  dependency of other libcrux crates that should not be used directly. Its code comes from
  fiat-crypto and AU-Curves, not HACL\*.
- `cargo audit` reports `proc-macro-error2` as unmaintained ([RUSTSEC-2026-0173]). libcrux
  uses it, through `hax-lib-macros`, only in its verification builds (`cfg(hax)`); it isn't
  compiled into this provider.
- No security audit of this crate. Review it before relying on it.

## Tests

The tests check the provider against rustls's `aws-lc-rs` provider: key exchange in both roles
for every group, refusal of malformed key shares (wrong lengths, small-order and off-curve
points, ML-KEM keys failing FIPS 203's modulus check), signatures in both directions, hashes,
HKDF and the TLS 1.2 PRF, in-memory mutual-TLS handshakes for every suite × group × certificate
type, HelloRetryRequest, resumption, key updates, tampered records, and random inputs. RSA-PSS,
which the shared checks skip (they take RSA keys only with PKCS#1 v1.5 too), has tests of its
own: signatures in both directions, and handshakes with an RSA server certificate. ML-KEM and
ML-DSA are slow unoptimized, so run them in release mode:

```sh
cargo test --release
```

The keys and certificates are generated on the first run by `testdata/make.sh`, which needs
OpenSSL 3.5 or later (for ML-DSA). It uses `openssl` from the `PATH`; point `OPENSSL` at another
binary if that one is older (macOS ships LibreSSL):

```sh
OPENSSL=/opt/homebrew/opt/openssl@3/bin/openssl cargo test --release
```

`PQC_TEST_ITERATIONS` sets the rounds of the random-input tests (default 200).

## Minimum supported Rust version

1.89, set by `libcrux-p384` and the rustls provider crate conventions.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion
in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above,
without any additional terms or conditions.

[rustls]: https://github.com/rustls/rustls
[libcrux]: https://github.com/cryspen/libcrux
[rustls-libcrux]: https://github.com/cryspen/rustls-libcrux
[draft-ietf-tls-ecdhe-mlkem]: https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/
[draft-ietf-tls-mlkem]: https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem/
[RUSTSEC-2026-0173]: https://rustsec.org/advisories/RUSTSEC-2026-0173.html
