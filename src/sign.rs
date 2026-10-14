//! Private keys and signing: ECDSA P-256 (libcrux-ecdsa; a random nonce per
//! signature), Ed25519 (libcrux-ed25519), RSA-PSS (libcrux-rsa) and
//! ML-DSA-44/65/87 (libcrux-ml-dsa; hedged, pure ML-DSA with an empty
//! context). libcrux has no ECDSA P-384 and no RSA PKCS#1 v1.5, so P-384 keys
//! are refused and RSA keys sign with PSS only.
//!
//! libcrux parses no key formats: PKCS#8 and SEC1 are read with the pkcs8 and
//! sec1 crates, PKCS#1 with der. ML-DSA private keys: PKCS#8 with the
//! ML-DSA-PrivateKey CHOICE of RFC 9881 in any of its three forms: seed,
//! expandedKey, or both (OpenSSL's default).

use std::sync::Arc;

use der::asn1::UintRef;
use der::Reader;
use pkcs8::ObjectIdentifier;
use rustls::pki_types::{alg_id, AlgorithmIdentifier, PrivateKeyDer, SubjectPublicKeyInfoDer};
use rustls::sign::{public_key_to_spki, Signer, SigningKey};
use rustls::{Error, SignatureAlgorithm, SignatureScheme};

use super::random;
use super::verify::{rsa_public_key, RSA_EXPONENT};

#[derive(Debug)]
pub struct KeyLoader;

impl rustls::crypto::KeyProvider for KeyLoader {
    fn load_private_key(&self, key: PrivateKeyDer<'static>) -> Result<Arc<dyn SigningKey>, Error> {
        match key {
            PrivateKeyDer::Pkcs8(k) => load_pkcs8(k.secret_pkcs8_der()),
            PrivateKeyDer::Pkcs1(k) => Rsa::load(k.secret_pkcs1_der()),
            PrivateKeyDer::Sec1(k) => load_sec1(k.secret_sec1_der(), None),
            _ => Err(Error::General("unsupported private key format".into())),
        }
    }
}

const ML_DSA_44_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.17");
const ML_DSA_65_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");
const ML_DSA_87_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19");
const EC_PUBLIC_KEY_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const P256_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const P384_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const ED25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
const RSA_ENCRYPTION_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

fn load_pkcs8(der: &[u8]) -> Result<Arc<dyn SigningKey>, Error> {
    let info = pkcs8::PrivateKeyInfoRef::try_from(der)
        .map_err(|e| Error::General(format!("PKCS#8: {e}")))?;
    let private_key = info.private_key.as_bytes();
    match info.algorithm.oid {
        ML_DSA_44_OID => MlDsa::load(private_key, MlDsaKind::Ml44),
        ML_DSA_65_OID => MlDsa::load(private_key, MlDsaKind::Ml65),
        ML_DSA_87_OID => MlDsa::load(private_key, MlDsaKind::Ml87),
        EC_PUBLIC_KEY_OID => {
            let curve = info
                .algorithm
                .parameters_oid()
                .map_err(|e| Error::General(format!("PKCS#8 EC key: {e}")))?;
            load_sec1(private_key, Some(curve))
        }
        ED25519_OID => Ed25519::load(private_key),
        RSA_ENCRYPTION_OID => Rsa::load(private_key),
        oid => Err(Error::General(format!(
            "unsupported PKCS#8 key algorithm {oid}"
        ))),
    }
}

/// a SEC1 ECPrivateKey; CURVE from the PKCS#8 wrapper, if any
fn load_sec1(der: &[u8], curve: Option<ObjectIdentifier>) -> Result<Arc<dyn SigningKey>, Error> {
    let key = sec1::EcPrivateKey::try_from(der)
        .map_err(|e| Error::General(format!("SEC1 private key: {e}")))?;
    let curve = curve
        .or_else(|| key.parameters.and_then(|p| p.named_curve()))
        .ok_or_else(|| Error::General("SEC1 private key: no curve".into()))?;
    match curve {
        P256_OID => EcdsaP256::load(key.private_key),
        P384_OID => Err(Error::General(
            "ECDSA P-384 private key: libcrux has no ECDSA P-384".into(),
        )),
        oid => Err(Error::General(format!(
            "SEC1 private key: unsupported curve {oid}"
        ))),
    }
}

fn sign_err<E: std::fmt::Debug>(e: E) -> Error {
    Error::General(format!("signing failed: {e:?}"))
}

/// one DER TLV at the start of B: (tag, contents, rest)
fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, b) = b.split_first()?;
    let (&l0, b) = b.split_first()?;
    let (len, b) = match l0 {
        0..=0x7f => (l0 as usize, b),
        0x81 => (*b.first()? as usize, &b[1..]),
        0x82 => (
            (*b.first()? as usize) << 8 | *b.get(1)? as usize,
            b.get(2..)?,
        ),
        _ => return None,
    };
    (b.len() >= len).then(|| (tag, &b[..len], &b[len..]))
}

/// a signer for keys that sign with one scheme only: the key behind an Arc,
/// shared with its signers
macro_rules! single_scheme_signer {
    ($key:ident, $scheme:expr, $alg:expr, $alg_id:expr) => {
        impl SigningKey for $key {
            fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
                offered
                    .contains(&$scheme)
                    .then(|| Box::new($key(self.0.clone())) as Box<dyn Signer>)
            }

            fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
                Some(public_key_to_spki(&$alg_id, &self.0.public))
            }

            fn algorithm(&self) -> SignatureAlgorithm {
                $alg
            }
        }

        impl Signer for $key {
            fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
                self.sign_bytes(message)
            }

            fn scheme(&self) -> SignatureScheme {
                $scheme
            }
        }

        impl std::fmt::Debug for $key {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(stringify!($key))
            }
        }
    };
}

// ---- ECDSA P-256 ----

struct EcdsaP256(Arc<EcdsaP256Key>);

struct EcdsaP256Key {
    secret: libcrux_ecdsa::p256::PrivateKey,
    /// the uncompressed point
    public: Vec<u8>,
}

impl EcdsaP256 {
    fn load(scalar: &[u8]) -> Result<Arc<dyn SigningKey>, Error> {
        let bad = || Error::General("ECDSA P-256 private key: invalid scalar".into());
        // (libcrux pads or cuts other lengths to 32 bytes; refuse them)
        let scalar: &[u8; 32] = scalar.try_into().map_err(|_| bad())?;
        let secret = libcrux_ecdsa::p256::PrivateKey::try_from(scalar).map_err(|_| bad())?;
        let raw = secret.public_key().map_err(|_| bad())?;
        let mut public = vec![0x04];
        public.extend_from_slice(raw.as_ref());
        Ok(Arc::new(EcdsaP256(Arc::new(EcdsaP256Key {
            secret,
            public,
        }))))
    }

    fn sign_bytes(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let sig = libcrux_ecdsa::p256::rand::sign(
            libcrux_ecdsa::DigestAlgorithm::Sha256,
            message,
            &self.0.secret,
            &mut getrandom::SysRng,
        )
        .map_err(sign_err)?;
        Ok(sig.to_der().to_vec())
    }
}

single_scheme_signer!(
    EcdsaP256,
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureAlgorithm::ECDSA,
    alg_id::ECDSA_P256
);

// ---- Ed25519 ----

struct Ed25519(Arc<Ed25519Key>);

struct Ed25519Key {
    seed: [u8; 32],
    public: [u8; 32],
}

impl Ed25519 {
    /// from PKCS#8's CurvePrivateKey: OCTET STRING (32-byte seed)
    fn load(private_key: &[u8]) -> Result<Arc<dyn SigningKey>, Error> {
        let seed = match tlv(private_key) {
            Some((0x04, seed, [])) => seed.try_into().ok(),
            _ => None,
        }
        .ok_or_else(|| Error::General("Ed25519 private key: not a 32-byte seed".into()))?;
        let mut public = [0u8; 32];
        libcrux_ed25519::secret_to_public(&mut public, &seed);
        Ok(Arc::new(Ed25519(Arc::new(Ed25519Key { seed, public }))))
    }

    fn sign_bytes(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(libcrux_ed25519::sign(message, &self.0.seed)
            .map_err(sign_err)?
            .to_vec())
    }
}

single_scheme_signer!(
    Ed25519,
    SignatureScheme::ED25519,
    SignatureAlgorithm::ED25519,
    alg_id::ED25519
);

// ---- RSA-PSS with SHA-512/384/256 ----

struct Rsa(Arc<RsaKey>);

struct RsaKey {
    n: Vec<u8>,
    /// the private exponent, padded to the modulus's length
    d: Vec<u8>,
    /// the PKCS#1 RSAPublicKey
    public: Vec<u8>,
}

const RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
];

impl Rsa {
    /// from a PKCS#1 RSAPrivateKey (two primes)
    fn load(der: &[u8]) -> Result<Arc<dyn SigningKey>, Error> {
        let bad = |why: &str| Error::General(format!("RSA private key: {why}"));
        let (n, e, d) = rsa_private_key(der).ok_or_else(|| bad("not a PKCS#1 RSAPrivateKey"))?;
        if e != RSA_EXPONENT {
            return Err(bad("libcrux-rsa takes the public exponent 65537 only"));
        }
        if libcrux_rsa::VarLenPublicKey::try_from(n).is_err() {
            return Err(bad(
                "libcrux-rsa takes moduli of 2048, 3072, 4096, 6144 or 8192 bits",
            ));
        }
        if d.len() > n.len() {
            return Err(bad("private exponent longer than the modulus"));
        }
        let mut padded = vec![0u8; n.len() - d.len()];
        padded.extend_from_slice(d);
        let public = der_sequence(&[&der_integer(n), &der_integer(e)]);
        Ok(Arc::new(Rsa(Arc::new(RsaKey {
            n: n.to_vec(),
            d: padded,
            public,
        }))))
    }
}

/// (n, e, d) of a DER RSAPrivateKey of version 0 (two primes), without
/// leading zeros
fn rsa_private_key(der: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let mut r = der::SliceReader::new(der).ok()?;
    let ned = r
        .sequence(|r| {
            let version: u8 = r.decode()?;
            let mut ints = [&[][..]; 8];
            for int in &mut ints {
                *int = r.decode::<UintRef<'_>>()?.as_bytes();
            }
            Ok::<_, der::Error>((version, ints))
        })
        .ok()?;
    r.finish().ok()?;
    let (version, [n, e, d, ..]) = ned;
    (version == 0).then_some((n, e, d))
}

/// a DER INTEGER of the unsigned big-endian V (no leading zeros)
fn der_integer(v: &[u8]) -> Vec<u8> {
    let mut contents = Vec::with_capacity(v.len() + 1);
    if v.first().is_none_or(|b| b & 0x80 != 0) {
        contents.push(0);
    }
    contents.extend_from_slice(v);
    der_tlv(0x02, &contents)
}

fn der_sequence(parts: &[&[u8]]) -> Vec<u8> {
    der_tlv(0x30, &parts.concat())
}

fn der_tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let len = contents.len();
    let mut out = vec![tag];
    match len {
        0..=0x7f => out.push(len as u8),
        0x80..=0xff => out.extend_from_slice(&[0x81, len as u8]),
        _ => out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]),
    }
    out.extend_from_slice(contents);
    out
}

impl SigningKey for Rsa {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        let scheme = RSA_SCHEMES.iter().find(|s| offered.contains(s))?;
        Some(Box::new(RsaSigner(self.0.clone(), *scheme)))
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        debug_assert!(rsa_public_key(&self.0.public).is_some());
        Some(public_key_to_spki(&alg_id::RSA_ENCRYPTION, &self.0.public))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }
}

impl std::fmt::Debug for Rsa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Rsa")
    }
}

struct RsaSigner(Arc<RsaKey>, SignatureScheme);

impl Signer for RsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        use libcrux_rsa::DigestAlgorithm::*;
        let k = &self.0;
        let sk = libcrux_rsa::VarLenPrivateKey::from_components(&k.n, &k.d).map_err(sign_err)?;
        let mut sig = vec![0u8; k.n.len()];
        // a salt as long as the hash, as TLS requires
        match self.1 {
            SignatureScheme::RSA_PSS_SHA256 => {
                libcrux_rsa::sign(Sha2_256, &sk, message, &random::<32>()?, &mut sig)
            }
            SignatureScheme::RSA_PSS_SHA384 => {
                libcrux_rsa::sign(Sha2_384, &sk, message, &random::<48>()?, &mut sig)
            }
            SignatureScheme::RSA_PSS_SHA512 => {
                libcrux_rsa::sign(Sha2_512, &sk, message, &random::<64>()?, &mut sig)
            }
            s => return Err(Error::General(format!("RSA: unexpected scheme {s:?}"))),
        }
        .map_err(sign_err)?;
        Ok(sig)
    }

    fn scheme(&self) -> SignatureScheme {
        self.1
    }
}

impl std::fmt::Debug for RsaSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RsaSigner({:?})", self.1)
    }
}

// ---- ML-DSA ----

#[derive(Clone, Copy)]
enum MlDsaKind {
    Ml44,
    Ml65,
    Ml87,
}

impl MlDsaKind {
    fn scheme(self) -> SignatureScheme {
        match self {
            MlDsaKind::Ml44 => SignatureScheme::ML_DSA_44,
            MlDsaKind::Ml65 => SignatureScheme::ML_DSA_65,
            MlDsaKind::Ml87 => SignatureScheme::ML_DSA_87,
        }
    }

    fn alg_id(self) -> AlgorithmIdentifier {
        match self {
            MlDsaKind::Ml44 => alg_id::ML_DSA_44,
            MlDsaKind::Ml65 => alg_id::ML_DSA_65,
            MlDsaKind::Ml87 => alg_id::ML_DSA_87,
        }
    }

    /// (k, l, η) of FIPS 204's parameter sets
    fn params(self) -> (usize, usize, u16) {
        match self {
            MlDsaKind::Ml44 => (4, 4, 2),
            MlDsaKind::Ml65 => (6, 5, 4),
            MlDsaKind::Ml87 => (8, 7, 2),
        }
    }

    /// whether an expandedKey of the right length passes FIPS 204 skDecode's
    /// range check: after ρ, K and tr (128 bytes), s1 and s2 hold (l + k) x 256
    /// coefficients, each η - s in bitlen(2η) bits, so at most 2η (t0's 13-bit
    /// fields can't be out of range). libcrux doesn't check, and would sign
    /// with such a key.
    fn expanded_in_range(self, sk: &[u8]) -> bool {
        let (k, l, eta) = self.params();
        let bits = if eta == 2 { 3 } else { 4 };
        let packed = &sk[128..128 + (k + l) * 256 * bits / 8];
        (0..(k + l) * 256).all(|i| {
            let (byte, shift) = (i * bits / 8, i * bits % 8);
            let word =
                u16::from_le_bytes([packed[byte], packed.get(byte + 1).copied().unwrap_or(0)]);
            (word >> shift) & ((1 << bits) - 1) <= 2 * eta
        })
    }
}

/// a signing key (libcrux's encoded expanded key, 2560 to 4896 bytes), kept
/// on the heap
enum MlDsaKey {
    Ml44(Box<libcrux_ml_dsa::ml_dsa_44::MLDSA44SigningKey>),
    Ml65(Box<libcrux_ml_dsa::ml_dsa_65::MLDSA65SigningKey>),
    Ml87(Box<libcrux_ml_dsa::ml_dsa_87::MLDSA87SigningKey>),
}

/// libcrux's operations on one parameter set: the key from a seed (signing
/// key and public key), the key from an expandedKey, signing
macro_rules! ml_dsa_ops {
    ($m:ident, $variant:ident, $sk:ident) => {
        mod $m {
            use super::*;
            use libcrux_ml_dsa::$m;

            pub fn from_seed(seed: [u8; 32]) -> (MlDsaKey, Vec<u8>) {
                let kp = $m::generate_key_pair(seed);
                let public = kp.verification_key.as_slice().to_vec();
                (MlDsaKey::$variant(Box::new(kp.signing_key)), public)
            }

            pub fn from_expanded(bytes: &[u8]) -> Option<MlDsaKey> {
                Some(MlDsaKey::$variant(Box::new($m::$sk::new(
                    bytes.try_into().ok()?,
                ))))
            }

            pub fn sign(sk: &$m::$sk, message: &[u8], rnd: [u8; 32]) -> Result<Vec<u8>, Error> {
                Ok($m::sign(sk, message, &[], rnd)
                    .map_err(sign_err)?
                    .as_slice()
                    .to_vec())
            }
        }
    };
}

ml_dsa_ops!(ml_dsa_44, Ml44, MLDSA44SigningKey);
ml_dsa_ops!(ml_dsa_65, Ml65, MLDSA65SigningKey);
ml_dsa_ops!(ml_dsa_87, Ml87, MLDSA87SigningKey);

impl MlDsaKey {
    fn from_seed(kind: MlDsaKind, seed: [u8; 32]) -> (Self, Vec<u8>) {
        match kind {
            MlDsaKind::Ml44 => ml_dsa_44::from_seed(seed),
            MlDsaKind::Ml65 => ml_dsa_65::from_seed(seed),
            MlDsaKind::Ml87 => ml_dsa_87::from_seed(seed),
        }
    }

    fn from_expanded(kind: MlDsaKind, bytes: &[u8]) -> Option<Self> {
        match kind {
            MlDsaKind::Ml44 => ml_dsa_44::from_expanded(bytes),
            MlDsaKind::Ml65 => ml_dsa_65::from_expanded(bytes),
            MlDsaKind::Ml87 => ml_dsa_87::from_expanded(bytes),
        }
    }

    /// the expandedKey (FIPS 204 skEncode)
    fn expanded(&self) -> &[u8] {
        match self {
            MlDsaKey::Ml44(k) => k.as_slice(),
            MlDsaKey::Ml65(k) => k.as_slice(),
            MlDsaKey::Ml87(k) => k.as_slice(),
        }
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let rnd = random::<32>()?;
        match self {
            MlDsaKey::Ml44(k) => ml_dsa_44::sign(k, message, rnd),
            MlDsaKey::Ml65(k) => ml_dsa_65::sign(k, message, rnd),
            MlDsaKey::Ml87(k) => ml_dsa_87::sign(k, message, rnd),
        }
    }
}

struct MlDsa {
    key: Arc<MlDsaKey>,
    /// the public key: from the seed; an expandedKey alone doesn't hold it
    /// (t1), and libcrux can't derive it
    public: Option<Vec<u8>>,
    kind: MlDsaKind,
}

impl MlDsa {
    /// from the ML-DSA-PrivateKey: seed [0] IMPLICIT OCTET STRING,
    /// expandedKey OCTET STRING, or both SEQUENCE { seed, expandedKey }
    fn load(private_key: &[u8], kind: MlDsaKind) -> Result<Arc<dyn SigningKey>, Error> {
        let bad = |why: &str| Error::General(format!("ML-DSA private key: {why}"));
        let seed = |b: &[u8]| -> Result<[u8; 32], Error> {
            b.try_into().map_err(|_| bad("seed is not 32 bytes"))
        };
        let from_expanded = |bytes: &[u8]| -> Result<MlDsaKey, Error> {
            let key = MlDsaKey::from_expanded(kind, bytes)
                .ok_or_else(|| bad("wrong expanded key length"))?;
            if !kind.expanded_in_range(bytes) {
                return Err(bad("expanded key coefficients out of range"));
            }
            Ok(key)
        };
        let (tag, contents, rest) = tlv(private_key).ok_or_else(|| bad("not DER"))?;
        if !rest.is_empty() {
            return Err(bad("trailing data"));
        }
        let (key, public) = match tag {
            0x80 => {
                let (key, public) = MlDsaKey::from_seed(kind, seed(contents)?);
                (key, Some(public))
            }
            0x04 => (from_expanded(contents)?, None),
            0x30 => {
                let (t1, s, rest) = tlv(contents).ok_or_else(|| bad("bad seed"))?;
                let (t2, expanded, rest) = tlv(rest).ok_or_else(|| bad("bad expandedKey"))?;
                if t1 != 0x04 || t2 != 0x04 || !rest.is_empty() {
                    return Err(bad("bad 'both' encoding"));
                }
                let (key, public) = MlDsaKey::from_seed(kind, seed(s)?);
                // the two halves must describe the same key
                if key.expanded() != expanded {
                    return Err(bad("seed and expandedKey don't match"));
                }
                (key, Some(public))
            }
            _ => return Err(bad("unknown ML-DSA-PrivateKey form")),
        };
        Ok(Arc::new(MlDsa {
            key: Arc::new(key),
            public,
            kind,
        }))
    }
}

impl SigningKey for MlDsa {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered.contains(&self.kind.scheme()).then(|| {
            Box::new(MlDsa {
                key: self.key.clone(),
                public: None,
                kind: self.kind,
            }) as Box<dyn Signer>
        })
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        let public = self.public.as_ref()?;
        Some(public_key_to_spki(&self.kind.alg_id(), public))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        // (TLS 1.2 has no code for ML-DSA, as in rustls's aws-lc-rs provider)
        SignatureAlgorithm::Unknown(0)
    }
}

impl Signer for MlDsa {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.key.sign(message)
    }

    fn scheme(&self) -> SignatureScheme {
        self.kind.scheme()
    }
}

impl std::fmt::Debug for MlDsa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlDsa({:?})", self.kind.scheme())
    }
}
