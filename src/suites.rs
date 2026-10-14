//! TLS 1.3 and TLS 1.2 (ECDHE) cipher suites, in rustls's order of preference

use rustls::crypto::tls12::PrfUsingHmac;
use rustls::crypto::tls13::HkdfUsingHmac;
use rustls::crypto::{CipherSuiteCommon, KeyExchangeAlgorithm};
use rustls::{
    CipherSuite, SignatureScheme, SupportedCipherSuite, Tls12CipherSuite, Tls13CipherSuite,
};

use super::{aead, hash, hmac};

/// a TLS 1.2 ECDHE suite (expanded in the static initializer, so the
/// references are 'static)
macro_rules! tls12 {
    ($suite:ident, $sign:expr, $hash:expr, $hmac:expr, $aead:expr, $limit:expr) => {
        SupportedCipherSuite::Tls12(&Tls12CipherSuite {
            common: CipherSuiteCommon {
                suite: CipherSuite::$suite,
                hash_provider: $hash,
                confidentiality_limit: $limit,
            },
            prf_provider: &PrfUsingHmac($hmac),
            kx: KeyExchangeAlgorithm::ECDHE,
            sign: $sign,
            aead_alg: $aead,
        })
    };
}

pub static ALL: &[SupportedCipherSuite] = &[
    TLS13_AES_256_GCM_SHA384,
    TLS13_AES_128_GCM_SHA256,
    TLS13_CHACHA20_POLY1305_SHA256,
    tls12!(
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        ECDSA,
        &hash::SHA384,
        &hmac::HMAC_SHA384,
        &aead::AES_256_GCM,
        AES_LIMIT
    ),
    tls12!(
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        ECDSA,
        &hash::SHA256,
        &hmac::HMAC_SHA256,
        &aead::AES_128_GCM,
        AES_LIMIT
    ),
    tls12!(
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        ECDSA,
        &hash::SHA256,
        &hmac::HMAC_SHA256,
        &aead::CHACHA20_POLY1305,
        u64::MAX
    ),
    tls12!(
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        RSA,
        &hash::SHA384,
        &hmac::HMAC_SHA384,
        &aead::AES_256_GCM,
        AES_LIMIT
    ),
    tls12!(
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        RSA,
        &hash::SHA256,
        &hmac::HMAC_SHA256,
        &aead::AES_128_GCM,
        AES_LIMIT
    ),
    tls12!(
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        RSA,
        &hash::SHA256,
        &hmac::HMAC_SHA256,
        &aead::CHACHA20_POLY1305,
        u64::MAX
    ),
];

const AES_LIMIT: u64 = 1 << 24;

static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
            hash_provider: &hash::SHA384,
            confidentiality_limit: AES_LIMIT,
        },
        hkdf_provider: &HkdfUsingHmac(&hmac::HMAC_SHA384),
        aead_alg: &aead::AES_256_GCM,
        quic: None,
    });

static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
            hash_provider: &hash::SHA256,
            confidentiality_limit: AES_LIMIT,
        },
        hkdf_provider: &HkdfUsingHmac(&hmac::HMAC_SHA256),
        aead_alg: &aead::AES_128_GCM,
        quic: None,
    });

static TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            hash_provider: &hash::SHA256,
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &HkdfUsingHmac(&hmac::HMAC_SHA256),
        aead_alg: &aead::CHACHA20_POLY1305,
        quic: None,
    });

/// the signature schemes of the ECDHE_ECDSA suites this provider signs with
/// (no ECDSA P-384: libcrux has none)
static ECDSA: &[SignatureScheme] = &[
    SignatureScheme::ED25519,
    SignatureScheme::ECDSA_NISTP256_SHA256,
];

/// the signature schemes of the ECDHE_RSA suites: RSA-PSS only (libcrux has
/// no PKCS#1 v1.5)
static RSA: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
];
