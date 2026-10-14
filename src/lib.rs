//! A [rustls] crypto provider on the libcrux crates, with post-quantum key
//! exchange (ML-KEM, FIPS 203) and signatures (ML-DSA, FIPS 204).
//!
//! - Key exchange: X25519MLKEM768, SecP256r1MLKEM768 and SecP384r1MLKEM1024
//!   (draft-ietf-tls-ecdhe-mlkem), X25519, P-256, P-384, MLKEM512/768/1024.
//!   ML-KEM and the hybrids are TLS 1.3 only.
//! - Signatures: ML-DSA-44/65/87, ECDSA P-256, Ed25519, RSA-PSS (2048 bits
//!   or more). libcrux has no ECDSA P-384 and no RSA PKCS#1 v1.5, so neither
//!   is here.
//! - TLS 1.3 and 1.2 with AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305.
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls_provider_libcrux_pq::provider()))
//!     .with_safe_default_protocol_versions()
//!     .unwrap()
//!     .with_root_certificates(rustls::RootCertStore::empty())
//!     .with_no_client_auth();
//! ```

mod aead;
mod hash;
mod hmac;
mod hybrid;
mod kx;
mod sign;
mod suites;
mod verify;

#[cfg(test)]
mod testkit;
#[cfg(test)]
mod tests;

use rustls::crypto::{CryptoProvider, GetRandomFailed, SecureRandom};

/// The provider with every cipher suite, key-exchange group and signature
/// algorithm it implements, key exchange in order of preference: the hybrids
/// first, then the classical groups, then pure ML-KEM.
pub fn provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: suites::ALL.to_vec(),
        kx_groups: kx::ALL.to_vec(),
        signature_verification_algorithms: verify::ALGORITHMS,
        secure_random: &Rng,
        key_provider: &sign::KeyLoader,
    }
}

/// the operating system's random numbers (getrandom)
#[derive(Debug)]
struct Rng;

impl SecureRandom for Rng {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        getrandom::fill(buf).map_err(|_| GetRandomFailed)
    }
}

/// N random bytes from the operating system (libcrux takes its randomness as
/// arguments)
fn random<const N: usize>() -> Result<[u8; N], rustls::Error> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|_| rustls::Error::FailedToGetRandomBytes)?;
    Ok(b)
}
