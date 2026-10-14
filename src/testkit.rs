//! Conformance checks for a rustls CryptoProvider, with rustls's aws-lc-rs
//! provider as the reference: key exchange in both roles, malformed key
//! shares, signatures both ways, hashes, HKDF and the TLS 1.2 PRF, and
//! handshakes in memory (every suite, group and certificate type in common,
//! mutual TLS), HelloRetryRequest, resumption, key updates, tampered records
//! and random inputs. Keys and certificates: testdata/ (make.sh).
//!
//! Each check returns what it covered, for the caller to compare with what
//! the provider should have, so a check can't pass by testing nothing.

use std::io::{Read, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::LazyLock;

use rustls::crypto::{aws_lc_rs, CryptoProvider, SupportedKxGroup};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{
    CertificateDer, InvalidSignature, PrivateKeyDer, ServerName, SubjectPublicKeyInfoDer,
};
use rustls::server::WebPkiClientVerifier;
use rustls::version::{TLS12, TLS13};
use rustls::{
    ClientConfig, ClientConnection, Connection, Error, HandshakeKind, NamedGroup, RootCertStore,
    ServerConfig, ServerConnection, SignatureScheme, SupportedCipherSuite,
    SupportedProtocolVersion,
};

use crate::hybrid::Hybrid;

// ---- fixtures ----

/// testdata/, which make.sh fills on first use (the repository keeps no keys
/// or certificates)
static TESTDATA: LazyLock<PathBuf> = LazyLock::new(|| {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata");
    // (the last file make.sh writes)
    if !dir.join("rsa1024.spki.pem").exists() {
        let ok = std::process::Command::new("sh")
            .arg(dir.join("make.sh"))
            .status()
            .is_ok_and(|s| s.success());
        assert!(
            ok,
            "testdata/make.sh failed: it needs OpenSSL 3.5 or later (OPENSSL=/path/to/openssl)"
        );
    }
    dir
});

pub fn data(name: &str) -> Vec<u8> {
    let path = TESTDATA.join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

pub fn key(name: &str) -> PrivateKeyDer<'static> {
    PrivateKeyDer::from_pem_slice(&data(name)).unwrap_or_else(|e| panic!("{name}: {e:?}"))
}

pub fn certs(name: &str) -> Vec<CertificateDer<'static>> {
    CertificateDer::pem_slice_iter(&data(name))
        .collect::<Result<_, _>>()
        .unwrap()
}

pub fn spki(name: &str) -> Vec<u8> {
    SubjectPublicKeyInfoDer::from_pem_slice(&data(name))
        .unwrap()
        .as_ref()
        .to_vec()
}

/// the key types in testdata, each with a CA, a leaf and its key
pub const KEY_TYPES: [&str; 7] = [
    "p256", "p384", "ed25519", "rsa2048", "mldsa44", "mldsa65", "mldsa87",
];

/// the signature schemes a key of type KT signs with
pub fn schemes(kt: &str) -> &'static [SignatureScheme] {
    use SignatureScheme::*;
    match kt {
        "p256" => &[ECDSA_NISTP256_SHA256],
        "p384" => &[ECDSA_NISTP384_SHA384],
        "ed25519" => &[ED25519],
        "rsa2048" | "rsa1024" => &[
            RSA_PSS_SHA256,
            RSA_PSS_SHA384,
            RSA_PSS_SHA512,
            RSA_PKCS1_SHA256,
            RSA_PKCS1_SHA384,
            RSA_PKCS1_SHA512,
        ],
        "mldsa44" => &[ML_DSA_44],
        "mldsa65" => &[ML_DSA_65],
        "mldsa87" => &[ML_DSA_87],
        _ => panic!("unknown key type {kt}"),
    }
}

/// the key types P loads and verifies (for every scheme of the type)
pub fn key_types(p: &CryptoProvider) -> Vec<&'static str> {
    KEY_TYPES
        .into_iter()
        .filter(|kt| {
            p.key_provider
                .load_private_key(key(&format!("{kt}.key")))
                .is_ok()
                && schemes(kt).iter().all(|s| {
                    p.signature_verification_algorithms
                        .mapping
                        .iter()
                        .any(|(m, _)| m == s)
                })
        })
        .collect()
}

/// rustls's aws-lc-rs provider with every group it implements
pub fn reference() -> CryptoProvider {
    let mut p = aws_lc_rs::default_provider();
    p.kx_groups = aws_lc_rs::ALL_KX_GROUPS.to_vec();
    p
}

/// a deterministic generator of test inputs (SplitMix64)
pub struct Prng(pub u64);

impl Prng {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }

    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }

    /// up to MAX - 1 random bytes, of a random length
    pub fn some_bytes(&mut self, max: usize) -> Vec<u8> {
        let n = self.below(max);
        self.bytes(n)
    }
}

/// rounds of the random-input checks: PQC_TEST_ITERATIONS, default 200
pub fn iterations() -> usize {
    std::env::var("PQC_TEST_ITERATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// ---- key exchange ----

pub fn group(p: &CryptoProvider, name: NamedGroup) -> Option<&'static dyn SupportedKxGroup> {
    p.kx_groups.iter().copied().find(|g| g.name() == name)
}

/// CLIENT starts, SERVER answers, CLIENT completes: both have the same secret
pub fn assert_agree(client: &dyn SupportedKxGroup, server: &dyn SupportedKxGroup) {
    let name = client.name();
    let c = client.start().unwrap();
    let s = server
        .start_and_complete(c.pub_key())
        .unwrap_or_else(|e| panic!("{name:?}: server: {e}"));
    assert_eq!(s.group, name);
    let secret = c
        .complete(&s.pub_key)
        .unwrap_or_else(|e| panic!("{name:?}: client: {e}"));
    assert_eq!(
        hex(secret.secret_bytes()),
        hex(s.secret.secret_bytes()),
        "{name:?}: secrets differ"
    );
}

/// every group of P agrees with itself, and with aws-lc-rs in both roles where
/// aws-lc-rs has it; returns the groups compared with aws-lc-rs
pub fn kx_agrees(p: &CryptoProvider) -> Vec<NamedGroup> {
    let reference = reference();
    let mut compared = Vec::new();
    for &g in &p.kx_groups {
        for _ in 0..16 {
            assert_agree(g, g);
        }
        if let Some(r) = group(&reference, g.name()) {
            for _ in 0..16 {
                assert_agree(g, r);
                assert_agree(r, g);
            }
            compared.push(g.name());
        }
    }
    compared
}

/// SecP384r1MLKEM1024 (0x11ed; rustls has no name for it) from aws-lc-rs's
/// P-384 and ML-KEM-1024, a reference for providers that implement it
pub fn secp384r1mlkem1024_reference() -> Hybrid {
    Hybrid {
        name: NamedGroup::Unknown(0x11ed),
        classical: aws_lc_rs::kx_group::SECP384R1,
        pq: aws_lc_rs::kx_group::MLKEM1024,
        pq_first: false,
        pq_client_len: 1568,
        pq_server_len: 1568,
    }
}

/// a group's key shares: (classical group and point length), ML-KEM
/// encapsulation key and ciphertext lengths (0: none), ML-KEM part first
struct Layout {
    classical: Option<(NamedGroup, usize)>,
    ek: usize,
    ct: usize,
    pq_first: bool,
}

fn layout(name: NamedGroup) -> Layout {
    use NamedGroup::*;
    let l = |classical, ek, ct, pq_first| Layout {
        classical,
        ek,
        ct,
        pq_first,
    };
    match name {
        X25519 => l(Some((X25519, 32)), 0, 0, false),
        secp256r1 => l(Some((secp256r1, 65)), 0, 0, false),
        secp384r1 => l(Some((secp384r1, 97)), 0, 0, false),
        MLKEM512 => l(None, 800, 768, false),
        MLKEM768 => l(None, 1184, 1088, false),
        MLKEM1024 => l(None, 1568, 1568, false),
        X25519MLKEM768 => l(Some((X25519, 32)), 1184, 1088, true),
        secp256r1MLKEM768 => l(Some((secp256r1, 65)), 1184, 1088, false),
        Unknown(0x11ed) => l(Some((secp384r1, 97)), 1568, 1568, false),
        _ => panic!("no key share layout for {name:?}"),
    }
}

impl Layout {
    /// (classical, ML-KEM) parts of a share whose ML-KEM part is PQ_LEN long
    fn split<'a>(&self, share: &'a [u8], pq_len: usize) -> (&'a [u8], &'a [u8]) {
        if self.pq_first {
            let (q, c) = share.split_at(pq_len);
            (c, q)
        } else {
            share.split_at(share.len() - pq_len)
        }
    }

    fn join(&self, classical: &[u8], pq: &[u8]) -> Vec<u8> {
        if self.pq_first {
            [pq, classical].concat()
        } else {
            [classical, pq].concat()
        }
    }
}

/// u-coordinates of small order on Curve25519 and its twist, with the
/// non-canonical encodings of 0 and 1 (p, p + 1): X25519 with any of them
/// gives the all-zero secret. (libsodium's blocklist also has these with bit
/// 255 set, which RFC 7748 masks off: other, ordinary points.)
const X25519_SMALL_ORDER: [&str; 7] = [
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
];

/// elliptic-curve shares to refuse, made from VALID (a valid share of GROUP)
fn invalid_classical(group: NamedGroup, valid: &[u8]) -> Vec<(String, Vec<u8>)> {
    if group == NamedGroup::X25519 {
        return X25519_SMALL_ORDER
            .iter()
            .map(|h| (format!("small-order point {h}"), unhex(h)))
            .collect();
    }
    let n = valid.len();
    let coord = (n - 1) / 2;
    let odd = valid[n - 1] & 1;
    let mut off_curve = valid.to_vec();
    off_curve[n - 1] ^= 1;
    let mut compressed = vec![2 + odd];
    compressed.extend_from_slice(&valid[1..1 + coord]);
    let mut hybrid_form = valid.to_vec();
    hybrid_form[0] = 6 + odd;
    let mut zeros = vec![0; n];
    zeros[0] = 4;
    let mut too_big = vec![0xff; n];
    too_big[0] = 4;
    vec![
        ("point off the curve".into(), off_curve),
        ("compressed point".into(), compressed),
        ("X9.62 hybrid-form point".into(), hybrid_form),
        ("point at infinity".into(), vec![0]),
        ("(0, 0)".into(), zeros),
        ("coordinates over p".into(), too_big),
    ]
}

/// ML-KEM encapsulation keys failing FIPS 203's modulus check (7.2), made
/// from VALID: a 12-bit coefficient of 0xfff (>= q = 3329), first and last
fn invalid_ek(valid: &[u8]) -> Vec<(String, Vec<u8>)> {
    let t = valid.len() - 32;
    let mut first = valid.to_vec();
    first[0] = 0xff;
    first[1] |= 0x0f;
    let mut last = valid.to_vec();
    last[t - 1] = 0xff;
    last[t - 2] |= 0xf0;
    vec![
        ("first coefficient >= q".into(), first),
        ("last coefficient >= q".into(), last),
    ]
}

/// every group of P refuses, in both roles: shares of the wrong length,
/// small-order, off-curve and non-uncompressed points, and ML-KEM
/// encapsulation keys failing the modulus check (alone and inside hybrids);
/// returns the number of refusals checked
pub fn malformed_shares_refused(p: &CryptoProvider) -> usize {
    let mut checked = 0;
    for &g in &p.kx_groups {
        let name = g.name();
        let l = layout(name);
        let client = g.start().unwrap();
        let share = client.pub_key().to_vec();
        let server_share = g.start_and_complete(&share).unwrap().pub_key;
        assert_eq!(
            share.len(),
            l.classical.map_or(0, |c| c.1) + l.ek,
            "{name:?}: client share length"
        );
        assert_eq!(
            server_share.len(),
            l.classical.map_or(0, |c| c.1) + l.ct,
            "{name:?}: server share length"
        );
        let mut refuse_client = |what: &str, bad: &[u8]| {
            assert!(
                g.start_and_complete(bad).is_err(),
                "{name:?}: accepted a client share: {what}"
            );
            checked += 1;
        };
        for len in [0, 1, share.len() - 1, share.len() + 1, 2 * share.len()] {
            refuse_client(&format!("{len} bytes"), &vec![4; len]);
        }
        let (c, q) = l.split(&share, l.ek);
        if let Some((cg, _)) = l.classical {
            for (what, bad) in invalid_classical(cg, c) {
                refuse_client(&what, &l.join(&bad, q));
            }
        }
        if l.ek > 0 {
            for (what, bad) in invalid_ek(q) {
                refuse_client(&what, &l.join(c, &bad));
            }
        }
        let mut refuse_server = |what: &str, bad: &[u8]| {
            assert!(
                g.start().unwrap().complete(bad).is_err(),
                "{name:?}: accepted a server share: {what}"
            );
            checked += 1;
        };
        for len in [0, 1, server_share.len() - 1, server_share.len() + 1] {
            refuse_server(&format!("{len} bytes"), &vec![4; len]);
        }
        let (sc, sq) = l.split(&server_share, l.ct);
        if let Some((cg, _)) = l.classical {
            for (what, bad) in invalid_classical(cg, sc) {
                refuse_server(&what, &l.join(&bad, sq));
            }
        }
    }
    checked
}

// ---- signatures ----

/// one DER TLV: (tag, contents, rest)
fn tlv(b: &[u8]) -> (u8, &[u8], &[u8]) {
    let (tag, l0) = (b[0], b[1] as usize);
    let (len, start) = match l0 {
        0..=0x7f => (l0, 2),
        0x81 => (b[2] as usize, 3),
        0x82 => ((b[2] as usize) << 8 | b[3] as usize, 4),
        _ => panic!("DER length form {l0:#x}"),
    };
    (tag, &b[start..start + len], &b[start + len..])
}

/// a SubjectPublicKeyInfo's algorithm (the AlgorithmIdentifier's contents,
/// as webpki compares them) and public key
pub fn spki_parts(spki: &[u8]) -> (&[u8], &[u8]) {
    let (_, body, _) = tlv(spki);
    let (_, alg, rest) = tlv(body);
    let (_, bits, _) = tlv(rest);
    (alg, &bits[1..])
}

/// verify as webpki would: the algorithm for SCHEME that takes this key's type
pub fn verify(
    p: &CryptoProvider,
    scheme: SignatureScheme,
    spki: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> Result<(), InvalidSignature> {
    let (alg_id, key) = spki_parts(spki);
    let algs = p
        .signature_verification_algorithms
        .mapping
        .iter()
        .find(|(s, _)| *s == scheme)
        .ok_or(InvalidSignature)?
        .1;
    let alg = algs
        .iter()
        .find(|a| a.public_key_alg_id().as_ref() == alg_id)
        .ok_or(InvalidSignature)?;
    alg.verify_signature(key, msg, sig)
}

/// for every key type P handles: its key's SubjectPublicKeyInfo is OpenSSL's;
/// it signs every scheme of the type and P and aws-lc-rs verify that;
/// aws-lc-rs's signatures verify with P; P refuses the signatures for an
/// altered message and altered, truncated or extended signatures, and
/// signatures from RSA keys under 2048 bits. Returns the key types checked.
pub fn signatures_agree(p: &CryptoProvider) -> Vec<&'static str> {
    let reference = reference();
    let msg = b"pqc-bench: the signed content of a CertificateVerify";
    let mut altered = msg.to_vec();
    altered[0] ^= 1;
    let types = key_types(p);
    for &kt in &types {
        let spki = spki(&format!("{kt}.spki.pem"));
        let mine = p
            .key_provider
            .load_private_key(key(&format!("{kt}.key")))
            .unwrap();
        if let Some(pk) = mine.public_key() {
            assert_eq!(hex(pk.as_ref()), hex(&spki), "{kt}: SubjectPublicKeyInfo");
        }
        let theirs = reference
            .key_provider
            .load_private_key(key(&format!("{kt}.key")))
            .unwrap();
        for &scheme in schemes(kt) {
            for (who, signer) in [("provider", &mine), ("aws-lc-rs", &theirs)] {
                let s = signer
                    .choose_scheme(&[scheme])
                    .unwrap_or_else(|| panic!("{who} {kt}: won't sign {scheme:?}"));
                assert_eq!(s.scheme(), scheme);
                let sig = s.sign(msg).unwrap();
                let ctx = format!("{kt} {scheme:?} signed by {who}");
                verify(p, scheme, &spki, msg, &sig)
                    .unwrap_or_else(|_| panic!("{ctx}: provider refused it"));
                verify(&reference, scheme, &spki, msg, &sig)
                    .unwrap_or_else(|_| panic!("{ctx}: aws-lc-rs refused it"));
                assert!(
                    verify(p, scheme, &spki, &altered, &sig).is_err(),
                    "{ctx}: verified an altered message"
                );
                for i in [0, 1, sig.len() / 2, sig.len() - 1] {
                    let mut bad = sig.clone();
                    bad[i] ^= 0x10;
                    assert!(
                        verify(p, scheme, &spki, msg, &bad).is_err(),
                        "{ctx}: verified with byte {i} altered"
                    );
                }
                assert!(
                    verify(p, scheme, &spki, msg, &sig[..sig.len() - 1]).is_err(),
                    "{ctx}: verified truncated"
                );
                assert!(
                    verify(p, scheme, &spki, msg, &[&sig[..], &[0]].concat()).is_err(),
                    "{ctx}: verified extended"
                );
            }
        }
        // a key of another type doesn't sign this type's schemes
        let other = if kt == "p256" { "p384" } else { "p256" };
        assert!(
            mine.choose_scheme(schemes(other)).is_none(),
            "{kt}: signs {other}'s schemes"
        );
    }
    if let Ok(small) = p.key_provider.load_private_key(key("rsa1024.key")) {
        let spki = spki("rsa1024.spki.pem");
        // (PSS with SHA-384 or SHA-512 doesn't fit a 1024-bit modulus at all)
        for scheme in [
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA512,
        ] {
            let sig = small.choose_scheme(&[scheme]).unwrap().sign(msg).unwrap();
            assert!(
                verify(p, scheme, &spki, msg, &sig).is_err(),
                "RSA-1024 {scheme:?} verified"
            );
        }
    }
    types
}

// ---- hashes, HKDF, PRF ----

/// P's hashes (one-shot and incremental, across block boundaries), HKDF
/// (extract with and without salt, zero IKM, expand to every length class,
/// HMAC) and TLS 1.2 PRF give aws-lc-rs's outputs, for every suite; returns
/// the suites compared
pub fn primitives_agree(p: &CryptoProvider) -> Vec<rustls::CipherSuite> {
    let reference = reference();
    let mut rng = Prng(0x6b64);
    let mut compared = Vec::new();
    for suite in &p.cipher_suites {
        let theirs = reference
            .cipher_suites
            .iter()
            .find(|s| s.suite() == suite.suite());
        let theirs = theirs.unwrap_or_else(|| panic!("aws-lc-rs has no {:?}", suite.suite()));
        match (suite, theirs) {
            (SupportedCipherSuite::Tls13(a), SupportedCipherSuite::Tls13(b)) => {
                let (ha, hb) = (a.common.hash_provider, b.common.hash_provider);
                for len in [
                    0, 1, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129, 1000, 70_000,
                ] {
                    let data = rng.bytes(len);
                    assert_eq!(
                        hex(ha.hash(&data).as_ref()),
                        hex(hb.hash(&data).as_ref()),
                        "{:?} hash of {len}",
                        suite.suite()
                    );
                    let (mut ca, mut cb) = (ha.start(), hb.start());
                    ca.update(&data[..len / 3]);
                    cb.update(&data[..len / 3]);
                    assert_eq!(
                        hex(ca.fork_finish().as_ref()),
                        hex(cb.fork_finish().as_ref())
                    );
                    ca.update(&data[len / 3..]);
                    cb.update(&data[len / 3..]);
                    assert_eq!(
                        hex(ca.finish().as_ref()),
                        hex(cb.finish().as_ref()),
                        "{:?} incremental hash",
                        suite.suite()
                    );
                }
                let (ka, kb) = (a.hkdf_provider, b.hkdf_provider);
                let hash_len = ha.output_len();
                for round in 0..64 {
                    // salts past the hash's block size exercise HMAC's key hashing
                    let salt = rng.some_bytes(300);
                    let ikm = rng.some_bytes(100);
                    let info = rng.some_bytes(60);
                    let salt = (round % 4 != 0).then_some(&salt[..]);
                    let (ea, eb) = if round % 8 == 1 {
                        (
                            ka.extract_from_zero_ikm(salt),
                            kb.extract_from_zero_ikm(salt),
                        )
                    } else {
                        (
                            ka.extract_from_secret(salt, &ikm),
                            kb.extract_from_secret(salt, &ikm),
                        )
                    };
                    let (oa, ob) = (
                        ea.expand_block(&[&info, b"x"]),
                        eb.expand_block(&[&info, b"x"]),
                    );
                    assert_eq!(
                        hex(oa.as_ref()),
                        hex(ob.as_ref()),
                        "{:?} HKDF expand_block",
                        suite.suite()
                    );
                    let len = [1, hash_len - 1, hash_len, hash_len + 1, 255 * hash_len][round % 5];
                    let (mut sa, mut sb) = (vec![0; len], vec![0; len]);
                    ea.expand_slice(&[&info], &mut sa).unwrap();
                    eb.expand_slice(&[&info], &mut sb).unwrap();
                    assert_eq!(
                        hex(&sa),
                        hex(&sb),
                        "{:?} HKDF expand to {len}",
                        suite.suite()
                    );
                    assert!(
                        ea.expand_slice(&[&info], &mut vec![0; 255 * hash_len + 1])
                            .is_err(),
                        "expand past 255 blocks"
                    );
                    let msg = rng.some_bytes(500);
                    assert_eq!(
                        hex(ka.hmac_sign(&oa, &msg).as_ref()),
                        hex(kb.hmac_sign(&ob, &msg).as_ref()),
                        "HMAC"
                    );
                    let (xa, xb) = (ka.expander_for_okm(&oa), kb.expander_for_okm(&ob));
                    assert_eq!(
                        hex(xa.expand_block(&[&info]).as_ref()),
                        hex(xb.expand_block(&[&info]).as_ref())
                    );
                }
            }
            (SupportedCipherSuite::Tls12(a), SupportedCipherSuite::Tls12(b)) => {
                for _ in 0..64 {
                    // (never empty in TLS; aws-lc refuses empty inputs)
                    let lens = [1 + rng.below(300), 1 + rng.below(30), 1 + rng.below(80)];
                    let (secret, label, seed) =
                        (rng.bytes(lens[0]), rng.bytes(lens[1]), rng.bytes(lens[2]));
                    let len = 1 + rng.below(300);
                    let (mut oa, mut ob) = (vec![0; len], vec![0; len]);
                    a.prf_provider.for_secret(&mut oa, &secret, &label, &seed);
                    b.prf_provider.for_secret(&mut ob, &secret, &label, &seed);
                    assert_eq!(hex(&oa), hex(&ob), "{:?} PRF", suite.suite());
                }
            }
            _ => panic!("{:?}: TLS versions differ", suite.suite()),
        }
        compared.push(suite.suite());
    }
    compared
}

// ---- handshakes in memory ----

pub fn with(
    p: &CryptoProvider,
    suites: Vec<SupportedCipherSuite>,
    groups: Vec<&'static dyn SupportedKxGroup>,
) -> Arc<CryptoProvider> {
    let mut p = p.clone();
    p.cipher_suites = suites;
    p.kx_groups = groups;
    Arc::new(p)
}

fn roots(kt: &str) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add(certs(&format!("{kt}.ca.pem")).remove(0)).unwrap();
    roots
}

/// a client that verifies KT's CA and authenticates with KT's leaf
pub fn client_config(
    p: Arc<CryptoProvider>,
    version: &'static SupportedProtocolVersion,
    kt: &str,
) -> Arc<ClientConfig> {
    Arc::new(
        ClientConfig::builder_with_provider(p)
            .with_protocol_versions(&[version])
            .unwrap()
            .with_root_certificates(roots(kt))
            .with_client_auth_cert(certs(&format!("{kt}.pem")), key(&format!("{kt}.key")))
            .unwrap(),
    )
}

/// a server with KT's leaf that requires a client certificate from KT's CA
pub fn server_config(
    p: Arc<CryptoProvider>,
    version: &'static SupportedProtocolVersion,
    kt: &str,
) -> Arc<ServerConfig> {
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots(kt)), p.clone())
        .build()
        .unwrap();
    Arc::new(
        ServerConfig::builder_with_provider(p)
            .with_protocol_versions(&[version])
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs(&format!("{kt}.pem")), key(&format!("{kt}.key")))
            .unwrap(),
    )
}

/// everything FROM has to send, as one buffer
pub fn take(from: &mut Connection) -> Vec<u8> {
    let mut buf = Vec::new();
    while from.wants_write() {
        from.write_tls(&mut buf).unwrap();
    }
    buf
}

/// TLS bytes into TO, processed
pub fn deliver(to: &mut Connection, mut data: &[u8]) -> Result<(), Error> {
    while !data.is_empty() {
        to.read_tls(&mut data).unwrap();
        to.process_new_packets()?;
    }
    Ok(())
}

pub fn transfer(from: &mut Connection, to: &mut Connection) -> Result<(), Error> {
    let data = take(from);
    deliver(to, &data)
}

/// a completed handshake (and the server's session tickets delivered)
pub fn connect(
    client: &Arc<ClientConfig>,
    server: &Arc<ServerConfig>,
) -> Result<(Connection, Connection), Error> {
    let mut c = Connection::Client(ClientConnection::new(
        client.clone(),
        ServerName::try_from("localhost").unwrap(),
    )?);
    let mut s = Connection::Server(ServerConnection::new(server.clone())?);
    for _ in 0..8 {
        transfer(&mut c, &mut s)?;
        transfer(&mut s, &mut c)?;
        if !c.is_handshaking() && !s.is_handshaking() {
            return Ok((c, s));
        }
    }
    panic!("the handshake didn't finish");
}

/// DATA from FROM to TO through TLS, in pieces TO's receive buffer takes
pub fn send(from: &mut Connection, to: &mut Connection, data: &[u8]) {
    for chunk in data.chunks(8192) {
        from.writer().write_all(chunk).unwrap();
        transfer(from, to).unwrap();
        let mut got = vec![0; chunk.len()];
        to.reader().read_exact(&mut got).unwrap();
        assert!(got == chunk, "application data changed in transit");
    }
}

/// application data both ways, and the same exported keying material
pub fn check_connection(c: &mut Connection, s: &mut Connection, len: usize, rng: &mut Prng) {
    send(c, s, &rng.bytes(len));
    send(s, c, &rng.bytes(len));
    let label = b"EXPERIMENTAL pqc-bench";
    let ec = c
        .export_keying_material([0u8; 48], label, Some(b"ctx"))
        .unwrap();
    let es = s
        .export_keying_material([0u8; 48], label, Some(b"ctx"))
        .unwrap();
    assert_eq!(ec, es, "exported keying material differs");
}

/// (client, server) pairs: P with itself and with aws-lc-rs both ways
fn pairs<'a>(
    p: &'a CryptoProvider,
    reference: &'a CryptoProvider,
) -> [(&'static str, &'a CryptoProvider, &'a CryptoProvider); 3] {
    [
        ("P -> P", p, p),
        ("P -> aws-lc-rs", p, reference),
        ("aws-lc-rs -> P", reference, p),
    ]
}

/// a suite usable with a key of type KT (TLS 1.2 suites name the signature algorithm)
fn suite_fits(suite: &SupportedCipherSuite, kt: &str) -> bool {
    match suite {
        SupportedCipherSuite::Tls12(t) => t.sign.iter().any(|s| schemes(kt).contains(s)),
        SupportedCipherSuite::Tls13(_) => true,
    }
}

/// CLIENT's suites (TLS VERSION, for KT) that SERVER has too, for KT as well
fn common_suites(
    client: &CryptoProvider,
    server: &CryptoProvider,
    version: &SupportedProtocolVersion,
    kt: &str,
) -> Vec<SupportedCipherSuite> {
    client
        .cipher_suites
        .iter()
        .copied()
        .filter(|s| s.version().version == version.version && suite_fits(s, kt))
        .filter(|s| {
            server
                .cipher_suites
                .iter()
                .any(|t| t.suite() == s.suite() && suite_fits(t, kt))
        })
        .collect()
}

/// CLIENT's groups usable in VERSION that SERVER has too
fn common_groups(
    client: &CryptoProvider,
    server: &CryptoProvider,
    version: &SupportedProtocolVersion,
) -> Vec<&'static dyn SupportedKxGroup> {
    client
        .kx_groups
        .iter()
        .copied()
        .filter(|g| g.usable_for_version(version.version))
        .filter(|g| group(server, g.name()).is_some_and(|h| h.usable_for_version(version.version)))
        .collect()
}

fn version_name(v: &SupportedProtocolVersion) -> &'static str {
    if v.version == TLS13.version {
        "TLS 1.3"
    } else {
        "TLS 1.2"
    }
}

/// mutual-TLS handshakes, P with itself and with aws-lc-rs both ways, for
/// every TLS 1.3 and 1.2 suite x group x certificate type both ends have,
/// suite and group pinned on the client: the negotiated version, suite and
/// group, application data both ways and the exporter. Returns the count.
pub fn handshake_matrix(p: &CryptoProvider) -> usize {
    let reference = reference();
    let mut rng = Prng(0x6873);
    let mut count = 0;
    for (pair, cp, sp) in pairs(p, &reference) {
        let kts: Vec<_> = key_types(cp)
            .into_iter()
            .filter(|kt| key_types(sp).contains(kt))
            .collect();
        for version in [&TLS13, &TLS12] {
            for &kt in &kts {
                let server = server_config(Arc::new(sp.clone()), version, kt);
                for suite in common_suites(cp, sp, version, kt) {
                    for g in common_groups(cp, sp, version) {
                        let what = format!(
                            "{pair} {} {kt} {:?} {:?}",
                            version_name(version),
                            suite.suite(),
                            g.name()
                        );
                        let client = client_config(with(cp, vec![suite], vec![g]), version, kt);
                        let (mut c, mut s) =
                            connect(&client, &server).unwrap_or_else(|e| panic!("{what}: {e}"));
                        for conn in [&c, &s] {
                            assert_eq!(conn.protocol_version(), Some(version.version), "{what}");
                            assert_eq!(
                                conn.negotiated_cipher_suite().map(|s| s.suite()),
                                Some(suite.suite()),
                                "{what}"
                            );
                            assert_eq!(
                                conn.negotiated_key_exchange_group().map(|g| g.name()),
                                Some(g.name()),
                                "{what}"
                            );
                            assert_eq!(conn.handshake_kind(), Some(HandshakeKind::Full), "{what}");
                        }
                        check_connection(&mut c, &mut s, 3000, &mut rng);
                        count += 1;
                    }
                }
            }
        }
    }
    count
}

/// for every TLS 1.3 group of P in each pair: the client's first key share
/// is for a group the server lacks, so the server asks for the group with a
/// HelloRetryRequest and the client's second ClientHello brings it. Returns
/// the count.
pub fn hello_retry_matrix(p: &CryptoProvider) -> usize {
    let reference = reference();
    let mut rng = Prng(0x6872);
    let mut count = 0;
    for (pair, cp, sp) in pairs(p, &reference) {
        let suite = common_suites(cp, sp, &TLS13, "p256")[0];
        for g in common_groups(cp, sp, &TLS13) {
            let first = [NamedGroup::X25519, NamedGroup::secp256r1]
                .into_iter()
                .find(|&n| n != g.name())
                .and_then(|n| group(cp, n))
                .unwrap();
            let what = format!(
                "{pair} HelloRetryRequest {:?} -> {:?}",
                first.name(),
                g.name()
            );
            let client = client_config(with(cp, vec![suite], vec![first, g]), &TLS13, "p256");
            let server = server_config(
                with(
                    sp,
                    sp.cipher_suites.clone(),
                    vec![group(sp, g.name()).unwrap()],
                ),
                &TLS13,
                "p256",
            );
            let (mut c, mut s) =
                connect(&client, &server).unwrap_or_else(|e| panic!("{what}: {e}"));
            for conn in [&c, &s] {
                assert_eq!(
                    conn.handshake_kind(),
                    Some(HandshakeKind::FullWithHelloRetryRequest),
                    "{what}"
                );
                assert_eq!(
                    conn.negotiated_key_exchange_group().map(|g| g.name()),
                    Some(g.name()),
                    "{what}"
                );
            }
            check_connection(&mut c, &mut s, 100, &mut rng);
            count += 1;
        }
    }
    count
}

/// a second connection resumes the first one's session (TLS 1.3 tickets and
/// TLS 1.2 session IDs), for every suite in each pair. Returns the count.
pub fn resumption(p: &CryptoProvider) -> usize {
    let reference = reference();
    let mut rng = Prng(0x7273);
    let mut count = 0;
    for (pair, cp, sp) in pairs(p, &reference) {
        for version in [&TLS13, &TLS12] {
            // (the certificate types both ends handle)
            for kt in ["p256", "rsa2048"]
                .into_iter()
                .filter(|kt| key_types(cp).contains(kt) && key_types(sp).contains(kt))
            {
                let server = server_config(Arc::new(sp.clone()), version, kt);
                for suite in common_suites(cp, sp, version, kt) {
                    let what = format!("{pair} {} {kt} {:?}", version_name(version), suite.suite());
                    let client =
                        client_config(with(cp, vec![suite], cp.kx_groups.clone()), version, kt);
                    connect(&client, &server).unwrap_or_else(|e| panic!("{what}: {e}"));
                    let (mut c, mut s) = connect(&client, &server)
                        .unwrap_or_else(|e| panic!("{what}: resuming: {e}"));
                    for conn in [&c, &s] {
                        assert_eq!(
                            conn.handshake_kind(),
                            Some(HandshakeKind::Resumed),
                            "{what}"
                        );
                    }
                    check_connection(&mut c, &mut s, 1000, &mut rng);
                    count += 1;
                }
            }
        }
    }
    count
}

/// 192 KiB each way per suite and pair (many full records), with TLS 1.3 key
/// updates from both sides between rounds. Returns the bytes sent.
pub fn bulk_and_key_updates(p: &CryptoProvider) -> usize {
    let reference = reference();
    let mut rng = Prng(0x6275);
    let mut bytes = 0;
    for (_, cp, sp) in pairs(p, &reference) {
        for version in [&TLS13, &TLS12] {
            let kt = "p256";
            let server = server_config(Arc::new(sp.clone()), version, kt);
            for suite in common_suites(cp, sp, version, kt) {
                let client =
                    client_config(with(cp, vec![suite], cp.kx_groups.clone()), version, kt);
                let (mut c, mut s) = connect(&client, &server).unwrap();
                for round in 0..3 {
                    if version.version == TLS13.version && round > 0 {
                        c.refresh_traffic_keys().unwrap();
                        send(&mut c, &mut s, &rng.bytes(1000));
                        s.refresh_traffic_keys().unwrap();
                        send(&mut s, &mut c, &rng.bytes(1000));
                    }
                    let data = rng.bytes(64 * 1024);
                    send(&mut c, &mut s, &data);
                    send(&mut s, &mut c, &data);
                    bytes += 2 * data.len();
                }
            }
        }
    }
    bytes
}

/// P as the receiver (from aws-lc-rs and from itself), every suite: an
/// application-data record with any one byte from its first ciphertext byte
/// on altered is refused, and one with a header byte altered never yields
/// other plaintext than was sent (rustls authenticates TLS 1.3's fixed
/// header values, not the received ones); a replayed, reordered or truncated
/// record is refused. Returns the records checked.
pub fn tampered_records_refused(p: &CryptoProvider) -> usize {
    let reference = reference();
    let mut refused = 0;
    for (pair, cp, sp) in [("aws-lc-rs -> P", &reference, p), ("P -> P", p, p)] {
        for version in [&TLS13, &TLS12] {
            // (the certificate types both ends handle)
            for kt in ["p256", "rsa2048"]
                .into_iter()
                .filter(|kt| key_types(cp).contains(kt) && key_types(sp).contains(kt))
            {
                let server = server_config(Arc::new(sp.clone()), version, kt);
                for suite in common_suites(cp, sp, version, kt) {
                    if version.version == TLS13.version && kt == "rsa2048" {
                        continue; // TLS 1.3 records don't depend on the certificate
                    }
                    let what = format!("{pair} {} {:?}", version_name(version), suite.suite());
                    let client =
                        client_config(with(cp, vec![suite], cp.kx_groups.clone()), version, kt);
                    let fresh = || {
                        let (mut c, s) = connect(&client, &server).unwrap();
                        c.writer().write_all(&[0x55; 40]).unwrap();
                        let first = take(&mut c);
                        c.writer().write_all(&[0x66; 40]).unwrap();
                        let second = take(&mut c);
                        (s, first, second)
                    };
                    let (_, template, _) = fresh();
                    for i in 0..template.len() {
                        let (mut s, mut record, _) = fresh();
                        record[i] ^= 0x01;
                        let result = deliver(&mut s, &record);
                        let mut buf = [0u8; 64];
                        if let Ok(n) = s.reader().read(&mut buf) {
                            assert!(
                                buf[..n].iter().all(|&b| b == 0x55),
                                "{what}: other plaintext with byte {i} altered"
                            );
                        }
                        if i >= 5 {
                            assert!(
                                result.is_err(),
                                "{what}: accepted a record with byte {i} altered"
                            );
                        }
                        refused += 1;
                    }
                    let (mut s, first, _) = fresh();
                    deliver(&mut s, &first).unwrap();
                    assert!(
                        deliver(&mut s, &first).is_err(),
                        "{what}: accepted a replayed record"
                    );
                    let (mut s, _, second) = fresh();
                    assert!(
                        deliver(&mut s, &second).is_err(),
                        "{what}: accepted records out of order"
                    );
                    let (mut s, mut cut, _) = fresh();
                    cut.pop();
                    let len = u16::from_be_bytes([cut[3], cut[4]]) - 1;
                    cut[3..5].copy_from_slice(&len.to_be_bytes());
                    assert!(
                        deliver(&mut s, &cut).is_err(),
                        "{what}: accepted a truncated record"
                    );
                    refused += 3;
                }
            }
        }
    }
    refused
}

// ---- random inputs ----

fn no_panic<T>(what: impl Fn() -> String, f: impl FnOnce() -> T) -> T {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|_| panic!("panicked: {}", what()))
}

/// random key shares (of the right length and of random lengths) in both
/// roles for every group, random keys and signatures for every verification
/// algorithm, and corrupted private keys (bytes altered, truncated) of every
/// key file: no panics, random signatures never verify. Returns the inputs.
pub fn random_inputs(p: &CryptoProvider) -> usize {
    let n = iterations();
    let mut rng = Prng(0x7261);
    let mut inputs = 0;
    for &g in &p.kx_groups {
        let name = g.name();
        let cl = g.start().unwrap().pub_key().len();
        let sl = g
            .start_and_complete(g.start().unwrap().pub_key())
            .unwrap()
            .pub_key
            .len();
        for i in 0..n {
            let len = if i % 2 == 0 {
                cl
            } else {
                rng.below(2 * cl + 2)
            };
            let share = rng.bytes(len);
            no_panic(
                || format!("{name:?} client share {}", hex(&share)),
                || g.start_and_complete(&share).is_ok(),
            );
            let len = if i % 2 == 0 {
                sl
            } else {
                rng.below(2 * sl + 2)
            };
            let share = rng.bytes(len);
            let active = g.start().unwrap();
            no_panic(
                || format!("{name:?} server share {}", hex(&share)),
                || active.complete(&share).is_ok(),
            );
            inputs += 2;
        }
    }
    let msg = b"message";
    for alg in p.signature_verification_algorithms.all {
        let key_of_type = KEY_TYPES
            .iter()
            .map(|kt| spki(&format!("{kt}.spki.pem")))
            .find(|s| spki_parts(s).0 == alg.public_key_alg_id().as_ref());
        for i in 0..n {
            let key = match &key_of_type {
                Some(s) if i % 2 == 0 => spki_parts(s).1.to_vec(),
                _ => rng.some_bytes(3000),
            };
            let sig = rng.some_bytes(5000);
            let ok = no_panic(
                || format!("{alg:?} key {} sig {}", hex(&key), hex(&sig)),
                || alg.verify_signature(&key, msg, &sig).is_ok(),
            );
            assert!(!ok, "{alg:?}: a random signature verified");
            inputs += 1;
        }
    }
    let files = [
        "p256.key",
        "p256.sec1.key",
        "p384.key",
        "p384.sec1.key",
        "ed25519.key",
        "rsa2048.key",
        "rsa2048.pkcs1.key",
        "mldsa44.key",
        "mldsa44.seed.key",
        "mldsa44.expanded.key",
        "mldsa65.key",
        "mldsa87.key",
    ];
    for file in files {
        let k = key(file);
        let der = k.secret_der().to_vec();
        for i in 0..n {
            let mut bad = der.clone();
            if i % 2 == 0 {
                let at = rng.below(bad.len());
                bad[at] ^= 1 << rng.below(8);
            } else {
                bad.truncate(rng.below(bad.len()));
            }
            let bad_key = match &k {
                PrivateKeyDer::Pkcs1(_) => PrivateKeyDer::Pkcs1(bad.clone().into()),
                PrivateKeyDer::Sec1(_) => PrivateKeyDer::Sec1(bad.clone().into()),
                _ => PrivateKeyDer::Pkcs8(bad.clone().into()),
            };
            no_panic(
                || format!("{file} corrupted: {}", hex(&bad)),
                || p.key_provider.load_private_key(bad_key).is_ok(),
            );
            inputs += 1;
        }
    }
    inputs
}
