//! Signature verification for certificates and CertificateVerify: ECDSA P-256
//! with SHA-256/384/512 (libcrux-ecdsa), Ed25519 (libcrux-ed25519), RSA-PSS
//! with SHA-256/384/512 (libcrux-rsa; moduli of 2048, 3072, 4096, 6144 or
//! 8192 bits, exponent 65537) and ML-DSA-44/65/87 (libcrux-ml-dsa; pure
//! ML-DSA with an empty context, as TLS uses it). libcrux has no ECDSA P-384
//! and no RSA PKCS#1 v1.5.

use der::asn1::UintRef;
use der::Reader;
use libcrux_ecdsa::DigestAlgorithm;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{
    alg_id, AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm,
};
use rustls::SignatureScheme;

pub static ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        ECDSA_P256_SHA256,
        ECDSA_P256_SHA384,
        ECDSA_P256_SHA512,
        ED25519,
        RSA_PSS_SHA256,
        RSA_PSS_SHA384,
        RSA_PSS_SHA512,
        ML_DSA_44,
        ML_DSA_65,
        ML_DSA_87,
    ],
    mapping: &[
        (SignatureScheme::ML_DSA_87, &[ML_DSA_87]),
        (SignatureScheme::ML_DSA_65, &[ML_DSA_65]),
        (SignatureScheme::ML_DSA_44, &[ML_DSA_44]),
        (SignatureScheme::ECDSA_NISTP256_SHA256, &[ECDSA_P256_SHA256]),
        (SignatureScheme::ED25519, &[ED25519]),
        (SignatureScheme::RSA_PSS_SHA512, &[RSA_PSS_SHA512]),
        (SignatureScheme::RSA_PSS_SHA384, &[RSA_PSS_SHA384]),
        (SignatureScheme::RSA_PSS_SHA256, &[RSA_PSS_SHA256]),
    ],
};

// ---- ECDSA P-256 (DER signatures, as X.509 and TLS carry them) ----

#[derive(Debug)]
struct EcdsaP256(DigestAlgorithm, AlgorithmIdentifier);

impl SignatureVerificationAlgorithm for EcdsaP256 {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_P256
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.1
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        // uncompressed points only, as webpki's other backends
        let raw: &[u8; 64] = match public_key {
            [0x04, xy @ ..] => xy.try_into().map_err(|_| InvalidSignature)?,
            _ => return Err(InvalidSignature),
        };
        let pk = libcrux_ecdsa::p256::PublicKey::try_from(raw).map_err(|_| InvalidSignature)?;
        let sig =
            libcrux_ecdsa::p256::Signature::from_der(signature).map_err(|_| InvalidSignature)?;
        libcrux_ecdsa::p256::verify(self.0, message, &sig, &pk).map_err(|_| InvalidSignature)
    }
}

static ECDSA_P256_SHA256: &dyn SignatureVerificationAlgorithm =
    &EcdsaP256(DigestAlgorithm::Sha256, alg_id::ECDSA_SHA256);
static ECDSA_P256_SHA384: &dyn SignatureVerificationAlgorithm =
    &EcdsaP256(DigestAlgorithm::Sha384, alg_id::ECDSA_SHA384);
static ECDSA_P256_SHA512: &dyn SignatureVerificationAlgorithm =
    &EcdsaP256(DigestAlgorithm::Sha512, alg_id::ECDSA_SHA512);

// ---- Ed25519 ----

#[derive(Debug)]
struct Ed25519;

impl SignatureVerificationAlgorithm for Ed25519 {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let pk: &[u8; 32] = public_key.try_into().map_err(|_| InvalidSignature)?;
        let sig: &[u8; 64] = signature.try_into().map_err(|_| InvalidSignature)?;
        libcrux_ed25519::verify(message, pk, sig).map_err(|_| InvalidSignature)
    }
}

static ED25519: &dyn SignatureVerificationAlgorithm = &Ed25519;

// ---- RSA-PSS (the public key as webpki passes it: PKCS#1 RSAPublicKey) ----

/// (n, e) of a DER RSAPublicKey, without leading zeros
pub fn rsa_public_key(der: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut r = der::SliceReader::new(der).ok()?;
    let ne = r
        .sequence(|r| {
            let n: UintRef<'_> = r.decode()?;
            let e: UintRef<'_> = r.decode()?;
            Ok::<_, der::Error>((n.as_bytes(), e.as_bytes()))
        })
        .ok()?;
    r.finish().ok()?;
    Some(ne)
}

/// the only RSA public exponent libcrux-rsa takes
pub const RSA_EXPONENT: &[u8] = &[1, 0, 1];

/// the hash, and the salt length (TLS and X.509 use a salt as long as the
/// hash)
#[derive(Debug)]
struct RsaPss(libcrux_rsa::DigestAlgorithm, u32, AlgorithmIdentifier);

impl SignatureVerificationAlgorithm for RsaPss {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.2
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let (n, e) = rsa_public_key(public_key).ok_or(InvalidSignature)?;
        if e != RSA_EXPONENT {
            return Err(InvalidSignature);
        }
        // moduli of 2048 bits or more only, as webpki's other backends
        let pk = libcrux_rsa::VarLenPublicKey::try_from(n).map_err(|_| InvalidSignature)?;
        libcrux_rsa::verify(self.0, &pk, message, self.1, signature).map_err(|_| InvalidSignature)
    }
}

static RSA_PSS_SHA256: &dyn SignatureVerificationAlgorithm = &RsaPss(
    libcrux_rsa::DigestAlgorithm::Sha2_256,
    32,
    alg_id::RSA_PSS_SHA256,
);
static RSA_PSS_SHA384: &dyn SignatureVerificationAlgorithm = &RsaPss(
    libcrux_rsa::DigestAlgorithm::Sha2_384,
    48,
    alg_id::RSA_PSS_SHA384,
);
static RSA_PSS_SHA512: &dyn SignatureVerificationAlgorithm = &RsaPss(
    libcrux_rsa::DigestAlgorithm::Sha2_512,
    64,
    alg_id::RSA_PSS_SHA512,
);

// ---- ML-DSA (FIPS 204) ----

macro_rules! ml_dsa {
    ($name:ident, $static:ident, $m:ident, $vk:ident, $sig:ident, $alg_id:expr) => {
        #[derive(Debug)]
        struct $name;

        impl SignatureVerificationAlgorithm for $name {
            fn public_key_alg_id(&self) -> AlgorithmIdentifier {
                $alg_id
            }

            fn signature_alg_id(&self) -> AlgorithmIdentifier {
                $alg_id
            }

            fn verify_signature(
                &self,
                public_key: &[u8],
                message: &[u8],
                signature: &[u8],
            ) -> Result<(), InvalidSignature> {
                use libcrux_ml_dsa::$m;
                let vk = $m::$vk::new(public_key.try_into().map_err(|_| InvalidSignature)?);
                let sig = $m::$sig::new(signature.try_into().map_err(|_| InvalidSignature)?);
                $m::verify(&vk, message, &[], &sig).map_err(|_| InvalidSignature)
            }
        }

        static $static: &dyn SignatureVerificationAlgorithm = &$name;
    };
}

ml_dsa!(
    MlDsa44,
    ML_DSA_44,
    ml_dsa_44,
    MLDSA44VerificationKey,
    MLDSA44Signature,
    alg_id::ML_DSA_44
);
ml_dsa!(
    MlDsa65,
    ML_DSA_65,
    ml_dsa_65,
    MLDSA65VerificationKey,
    MLDSA65Signature,
    alg_id::ML_DSA_65
);
ml_dsa!(
    MlDsa87,
    ML_DSA_87,
    ml_dsa_87,
    MLDSA87VerificationKey,
    MLDSA87Signature,
    alg_id::ML_DSA_87
);
