//! The provider against rustls's aws-lc-rs provider (crate::testkit), and
//! the parts the shared checks don't reach: MLKEM512 and SecP384r1MLKEM1024
//! against aws-lc-rs's components, RSA-PSS (the shared checks take RSA keys
//! only with PKCS#1 v1.5 too, which libcrux lacks), and our private-key
//! decoding. Run optimized (ML-KEM and ML-DSA are slow without):
//!   cargo test --release

use std::sync::Arc;

use crate::testkit::*;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{PrivateKeyDer, ServerName};
use rustls::version::{TLS12, TLS13};
use rustls::{
    CipherSuite, ClientConfig, ClientConnection, Connection, NamedGroup, RootCertStore,
    ServerConfig, ServerConnection, SignatureScheme,
};

fn ours() -> CryptoProvider {
    crate::provider()
}

#[test]
fn key_exchange_agrees_with_aws_lc_rs() {
    use NamedGroup::*;
    assert_eq!(
        kx_agrees(&ours()),
        [
            X25519MLKEM768,
            secp256r1MLKEM768,
            X25519,
            secp256r1,
            secp384r1,
            MLKEM768,
            MLKEM1024
        ]
    );
}

#[test]
fn secp384r1mlkem1024_agrees_with_aws_lc_rs_components() {
    let ours = ours();
    let g = group(&ours, NamedGroup::Unknown(0x11ed)).unwrap();
    let reference = secp384r1mlkem1024_reference();
    for _ in 0..32 {
        assert_agree(g, &reference);
        assert_agree(&reference, g);
    }
}

/// a ciphertext that isn't the one encapsulated gives a pseudorandom
/// secret, not an error (FIPS 203 implicit rejection), so a server can't
/// tell; the client's handshake then fails at Finished
#[test]
fn mlkem_rejects_altered_ciphertexts_implicitly() {
    let ours = ours();
    for name in [
        NamedGroup::MLKEM512,
        NamedGroup::MLKEM768,
        NamedGroup::MLKEM1024,
    ] {
        let g = group(&ours, name).unwrap();
        let client = g.start().unwrap();
        let server = g.start_and_complete(client.pub_key()).unwrap();
        let mut ct = server.pub_key.clone();
        let mid = ct.len() / 2;
        ct[mid] ^= 1;
        let secret = client.complete(&ct).unwrap();
        assert_eq!(secret.secret_bytes().len(), 32);
        assert_ne!(
            secret.secret_bytes(),
            server.secret.secret_bytes(),
            "{name:?}"
        );
    }
}

#[test]
fn malformed_key_shares_are_refused() {
    // per group: 5 client and 4 server share lengths; each bad point (7
    // X25519, 6 NIST) as client and as server share; 2 ML-KEM keys over q
    let x25519 = 9 + 2 * 7;
    let nist = 9 + 2 * 6;
    let mlkem = 9 + 2;
    let hybrids = (x25519 + 2) + 2 * (nist + 2);
    assert_eq!(
        malformed_shares_refused(&ours()),
        hybrids + x25519 + 2 * nist + 3 * mlkem
    );
}

/// every key type but P-384 (no ECDSA P-384 in libcrux) and RSA (no PKCS#1
/// v1.5; RSA-PSS is checked below)
#[test]
fn signatures_agree_with_aws_lc_rs() {
    assert_eq!(
        signatures_agree(&ours()),
        ["p256", "ed25519", "mldsa44", "mldsa65", "mldsa87"]
    );
}

#[test]
fn hashes_hkdf_and_prf_agree_with_aws_lc_rs() {
    use CipherSuite::*;
    assert_eq!(
        primitives_agree(&ours()),
        [
            TLS13_AES_256_GCM_SHA384,
            TLS13_AES_128_GCM_SHA256,
            TLS13_CHACHA20_POLY1305_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        ]
    );
}

#[test]
fn handshakes() {
    // TLS 1.3: 5 certificate types x 3 suites x (9 groups with itself, 7
    // with aws-lc-rs each way); TLS 1.2: 2 certificate types (P-256,
    // Ed25519) x 3 ECDSA suites x 3 groups, in each of the 3 pairs
    assert_eq!(
        handshake_matrix(&ours()),
        5 * 3 * (9 + 7 + 7) + 2 * 3 * 3 * 3
    );
}

#[test]
fn hello_retry_requests() {
    assert_eq!(hello_retry_matrix(&ours()), 9 + 7 + 7);
}

#[test]
fn sessions_resume() {
    // per pair: TLS 1.3 and 1.2, each 3 suites with ECDSA
    assert_eq!(resumption(&ours()), 3 * 2 * 3);
}

#[test]
fn bulk_data_and_key_updates() {
    // per pair: 3 TLS 1.3 and 3 TLS 1.2 (ECDSA) suites, 3 rounds of 64 KiB each way
    assert_eq!(bulk_and_key_updates(&ours()), 3 * 6 * 3 * 2 * 64 * 1024);
}

#[test]
fn tampered_records_are_refused() {
    let refused = tampered_records_refused(&ours());
    // per pair (2): TLS 1.3 records of 40 + 1 + 16 bytes after a 5-byte
    // header, 3 suites; TLS 1.2 GCM records add an 8-byte explicit nonce
    // (2 suites), ChaCha20 doesn't (1); +3 each
    let tls13 = 3 * (5 + 40 + 1 + 16 + 3);
    let tls12 = 2 * (5 + 8 + 40 + 16 + 3) + (5 + 40 + 16 + 3);
    assert_eq!(refused, 2 * (tls13 + tls12));
}

#[test]
fn random_inputs_never_panic() {
    let n = iterations();
    // 9 groups x 2 roles, 10 verification algorithms, 12 key files
    assert_eq!(random_inputs(&ours()), n * (9 * 2 + 10 + 12));
}

// ---- RSA-PSS ----

/// our RSA-PSS signatures verify with aws-lc-rs and ours, aws-lc-rs's verify
/// with ours, altered ones don't; PKCS#1 v1.5 isn't offered
#[test]
fn rsa_pss_signatures_agree_with_aws_lc_rs() {
    let (ours, reference) = (ours(), reference());
    let spki = spki("rsa2048.spki.pem");
    let msg = b"pqc-bench: the signed content of a CertificateVerify";
    let mine = ours
        .key_provider
        .load_private_key(key("rsa2048.key"))
        .unwrap();
    let theirs = reference
        .key_provider
        .load_private_key(key("rsa2048.key"))
        .unwrap();
    for scheme in [
        SignatureScheme::RSA_PSS_SHA256,
        SignatureScheme::RSA_PSS_SHA384,
        SignatureScheme::RSA_PSS_SHA512,
    ] {
        for (who, signer) in [("provider", &mine), ("aws-lc-rs", &theirs)] {
            let s = signer.choose_scheme(&[scheme]).unwrap();
            assert_eq!(s.scheme(), scheme);
            let sig = s.sign(msg).unwrap();
            let ctx = format!("{scheme:?} signed by {who}");
            verify(&ours, scheme, &spki, msg, &sig)
                .unwrap_or_else(|_| panic!("{ctx}: provider refused it"));
            verify(&reference, scheme, &spki, msg, &sig)
                .unwrap_or_else(|_| panic!("{ctx}: aws-lc-rs refused it"));
            assert!(
                verify(&ours, scheme, &spki, b"other", &sig).is_err(),
                "{ctx}"
            );
            let mut bad = sig.clone();
            bad[sig.len() / 2] ^= 0x10;
            assert!(verify(&ours, scheme, &spki, msg, &bad).is_err(), "{ctx}");
        }
    }
    for scheme in [
        SignatureScheme::RSA_PKCS1_SHA256,
        SignatureScheme::RSA_PKCS1_SHA384,
        SignatureScheme::RSA_PKCS1_SHA512,
    ] {
        assert!(mine.choose_scheme(&[scheme]).is_none(), "{scheme:?}");
    }
}

/// a server with an RSA certificate, to an aws-lc-rs client: TLS 1.3 and the
/// TLS 1.2 ECDHE_RSA suites. (The server can't check an RSA client
/// certificate: OpenSSL signs RSA certificates with PKCS#1 v1.5.)
#[test]
fn rsa_server_handshakes_with_aws_lc_rs_client() {
    let (ours, reference) = (ours(), reference());
    let mut rng = Prng(0x7273);
    let mut roots = RootCertStore::empty();
    roots.add(certs("rsa2048.ca.pem").remove(0)).unwrap();
    let mut count = 0;
    for version in [&TLS13, &TLS12] {
        let server = Arc::new(
            ServerConfig::builder_with_provider(Arc::new(ours.clone()))
                .with_protocol_versions(&[version])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(certs("rsa2048.pem"), key("rsa2048.key"))
                .unwrap(),
        );
        for suite in ours.cipher_suites.iter().filter(|s| {
            s.version().version == version.version && !s.suite().as_str().unwrap().contains("ECDSA")
        }) {
            let theirs = reference
                .cipher_suites
                .iter()
                .copied()
                .find(|t| t.suite() == suite.suite())
                .unwrap();
            let client = Arc::new(
                ClientConfig::builder_with_provider(with(
                    &reference,
                    vec![theirs],
                    reference.kx_groups.clone(),
                ))
                .with_protocol_versions(&[version])
                .unwrap()
                .with_root_certificates(roots.clone())
                .with_no_client_auth(),
            );
            let mut c = Connection::Client(
                ClientConnection::new(client, ServerName::try_from("localhost").unwrap()).unwrap(),
            );
            let mut s = Connection::Server(ServerConnection::new(server.clone()).unwrap());
            while c.is_handshaking() || s.is_handshaking() {
                transfer(&mut c, &mut s).unwrap_or_else(|e| panic!("{suite:?}: {e}"));
                transfer(&mut s, &mut c).unwrap_or_else(|e| panic!("{suite:?}: {e}"));
            }
            assert_eq!(
                c.negotiated_cipher_suite().map(|s| s.suite()),
                Some(suite.suite())
            );
            check_connection(&mut c, &mut s, 1000, &mut rng);
            count += 1;
        }
    }
    assert_eq!(count, 3 + 3);
}

// ---- our private-key decoding ----

fn public_key(file: &str) -> Option<Vec<u8>> {
    let k = ours()
        .key_provider
        .load_private_key(key(file))
        .unwrap_or_else(|e| panic!("{file}: {e}"));
    k.public_key().map(|pk| pk.as_ref().to_vec())
}

/// every encoding of a key gives the same key, with OpenSSL's
/// SubjectPublicKeyInfo; an ML-DSA expandedKey alone has no public key (the
/// expanded form doesn't hold it, and libcrux can't derive it)
#[test]
fn every_key_encoding_loads_the_same_key() {
    for (kt, alternatives) in [
        ("p256", &["p256.sec1.key"][..]),
        ("ed25519", &[]),
        ("rsa2048", &["rsa2048.pkcs1.key"]),
        ("mldsa44", &["mldsa44.seed.key"]),
        ("mldsa65", &["mldsa65.seed.key"]),
        ("mldsa87", &["mldsa87.seed.key"]),
    ] {
        let spki = spki(&format!("{kt}.spki.pem"));
        for file in [&format!("{kt}.key")[..]].iter().chain(alternatives) {
            assert_eq!(public_key(file), Some(spki.clone()), "{file}");
        }
    }
    for file in [
        "mldsa44.expanded.key",
        "mldsa65.expanded.key",
        "mldsa87.expanded.key",
    ] {
        assert_eq!(public_key(file), None, "{file}");
    }
}

/// keys libcrux can't sign with are refused when loaded: ECDSA P-384 (no
/// implementation) and RSA under 2048 bits
#[test]
fn keys_libcrux_cannot_use_are_refused() {
    let ours = ours();
    for file in ["p384.key", "p384.sec1.key", "rsa1024.key"] {
        assert!(
            ours.key_provider.load_private_key(key(file)).is_err(),
            "{file}"
        );
    }
}

/// keys decoded from the seed and from the expanded form sign alike: each
/// one's signatures verify with the public key in the certificate
#[test]
fn mldsa_keys_sign_in_every_encoding() {
    let ours = ours();
    for (kt, scheme) in [
        ("mldsa44", SignatureScheme::ML_DSA_44),
        ("mldsa65", SignatureScheme::ML_DSA_65),
        ("mldsa87", SignatureScheme::ML_DSA_87),
    ] {
        let spki = spki(&format!("{kt}.spki.pem"));
        for file in [
            format!("{kt}.key"),
            format!("{kt}.seed.key"),
            format!("{kt}.expanded.key"),
        ] {
            let k = ours.key_provider.load_private_key(key(&file)).unwrap();
            let sig = k
                .choose_scheme(&[scheme])
                .unwrap()
                .sign(b"message")
                .unwrap();
            verify(&reference(), scheme, &spki, b"message", &sig)
                .unwrap_or_else(|_| panic!("{file}"));
        }
    }
}

/// in the "both" form, a seed and an expandedKey that don't belong together
/// are refused (otherwise which one signs would decide the key)
#[test]
fn mldsa_seed_and_expanded_key_must_match() {
    let ours = ours();
    for (kt, expanded_len) in [("mldsa44", 2560), ("mldsa65", 4032), ("mldsa87", 4896)] {
        let PrivateKeyDer::Pkcs8(both) = key(&format!("{kt}.key")) else {
            panic!()
        };
        let der = both.secret_pkcs8_der().to_vec();
        // ... SEQUENCE { OCTET STRING seed (32), OCTET STRING expandedKey }: the
        // expandedKey ends the DER, after its 4-byte header and the seed
        let expanded_at = der.len() - expanded_len;
        let seed_at = expanded_at - 4 - 32;
        for (what, at) in [("expandedKey", expanded_at + 100), ("seed", seed_at + 5)] {
            let mut bad = der.clone();
            bad[at] ^= 1;
            assert!(
                ours.key_provider
                    .load_private_key(PrivateKeyDer::Pkcs8(bad.into()))
                    .is_err(),
                "{kt}: loaded a key with its {what} altered"
            );
        }
    }
}

/// an expandedKey with an s1 coefficient out of range (FIPS 204 skDecode)
/// is refused: libcrux doesn't check, and would sign with it
#[test]
fn mldsa_expanded_key_out_of_range_is_refused() {
    let ours = ours();
    for (kt, expanded_len) in [("mldsa44", 2560), ("mldsa65", 4032), ("mldsa87", 4896)] {
        let PrivateKeyDer::Pkcs8(k) = key(&format!("{kt}.expanded.key")) else {
            panic!()
        };
        let mut der = k.secret_pkcs8_der().to_vec();
        // s1 starts after rho, K and tr (128 bytes); 0xff is 7 in 3 bits, 15 in 4
        let s1 = der.len() - expanded_len + 128;
        der[s1] = 0xff;
        assert!(
            ours.key_provider
                .load_private_key(PrivateKeyDer::Pkcs8(der.into()))
                .is_err(),
            "{kt}"
        );
    }
}
