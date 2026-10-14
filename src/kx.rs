//! Key exchange: X25519 (libcrux-curve25519), P-256 (libcrux-p256), P-384
//! (libcrux-p384), ML-KEM-512/768/1024 (libcrux-ml-kem, FIPS 203) and the
//! draft-ietf-tls-ecdhe-mlkem hybrids built from them (crate::hybrid). ML-KEM
//! and the hybrids are TLS 1.3 only.

use crate::hybrid::Hybrid;
use rustls::crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup, PeerMisbehaved, ProtocolVersion};

use super::random;

pub static ALL: &[&dyn SupportedKxGroup] = &[
    X25519MLKEM768,
    SECP256R1MLKEM768,
    SECP384R1MLKEM1024,
    &X25519,
    &P256,
    &P384,
    &MLKEM512,
    &MLKEM768,
    &MLKEM1024,
];

fn bad_share() -> Error {
    PeerMisbehaved::InvalidKeyShare.into()
}

/// rejection sampling of a nonzero scalar below a curve's order, from
/// random bytes: ACCEPT checks a candidate (the odds of a retry are 2^-32 or
/// less, so 8 failures mean the random numbers are broken)
fn sample_scalar<const N: usize, T>(
    mut accept: impl FnMut(&[u8; N]) -> Option<T>,
) -> Result<T, Error> {
    for _ in 0..8 {
        if let Some(t) = accept(&random()?) {
            return Ok(t);
        }
    }
    Err(Error::FailedToGetRandomBytes)
}

// ---- X25519 ----

#[derive(Debug)]
pub struct X25519;

impl SupportedKxGroup for X25519 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        // (any 32 bytes are a key: X25519 clamps them)
        let secret = random::<32>()?;
        let mut pub_key = [0u8; 32];
        libcrux_curve25519::secret_to_public(&mut pub_key, &secret);
        Ok(Box::new(ActiveX25519 { secret, pub_key }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

struct ActiveX25519 {
    secret: [u8; 32],
    pub_key: [u8; 32],
}

impl ActiveKeyExchange for ActiveX25519 {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        let peer: &[u8; 32] = peer.try_into().map_err(|_| bad_share())?;
        let mut shared = [0u8; 32];
        // an error is the all-zero secret: the peer sent a low-order point
        libcrux_curve25519::ecdh(&mut shared, peer, &self.secret).map_err(|_| bad_share())?;
        Ok(SharedSecret::from(&shared[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

// ---- P-256 (uncompressed points, as TLS requires) ----

#[derive(Debug)]
pub struct P256;

impl SupportedKxGroup for P256 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let mut raw = [0u8; 64];
        // dh_initiator refuses a scalar of 0 or past the order
        let secret =
            sample_scalar(|s: &[u8; 32]| libcrux_p256::dh_initiator(&mut raw, s).then_some(*s))?;
        let mut pub_key = [0u8; 65];
        libcrux_p256::raw_to_uncompressed(&raw, &mut pub_key);
        Ok(Box::new(ActiveP256 { secret, pub_key }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::secp256r1
    }
}

struct ActiveP256 {
    secret: [u8; 32],
    pub_key: [u8; 65],
}

impl ActiveKeyExchange for ActiveP256 {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        if peer.len() != 65 || peer[0] != 0x04 {
            return Err(bad_share());
        }
        // (x, y) of the shared point; dh_responder validates the peer's point
        let mut shared = [0u8; 64];
        if !libcrux_p256::dh_responder(&mut shared, &peer[1..], &self.secret) {
            return Err(bad_share());
        }
        Ok(SharedSecret::from(&shared[..32]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::secp256r1
    }
}

// ---- P-384 (uncompressed points) ----

#[derive(Debug)]
pub struct P384;

impl SupportedKxGroup for P384 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let secret = sample_scalar(|s: &[u8; 48]| libcrux_p384::PrivateKey::try_from(&s[..]).ok())?;
        let mut pub_key = [0u8; 97];
        libcrux_p384::PublicKey::from(&secret).to_uncompressed(&mut pub_key);
        Ok(Box::new(ActiveP384 { secret, pub_key }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::secp384r1
    }
}

struct ActiveP384 {
    secret: libcrux_p384::PrivateKey,
    pub_key: [u8; 97],
}

impl ActiveKeyExchange for ActiveP384 {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        // the length, the 0x04 form, coordinates below p and the curve
        // equation; such a point times a scalar in [1, n) is never the point
        // at infinity, which libcrux-p384 asserts against
        let peer = libcrux_p384::PublicKey::from_uncompressed(peer).map_err(|_| bad_share())?;
        Ok(SharedSecret::from(&peer.ecdh(&self.secret).as_ref()[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::secp384r1
    }
}

// ---- ML-KEM (FIPS 203) ----

macro_rules! ml_kem {
    ($name:ident, $active:ident, $m:ident, $pk:ident, $ct:ident, $kp:ident, $group:expr) => {
        #[derive(Debug)]
        pub struct $name;

        impl SupportedKxGroup for $name {
            fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
                let keys = Box::new(libcrux_ml_kem::$m::generate_key_pair(random()?));
                Ok(Box::new($active { keys }))
            }

            fn start_and_complete(
                &self,
                client_share: &[u8],
            ) -> Result<CompletedKeyExchange, Error> {
                let ek =
                    libcrux_ml_kem::$m::$pk::try_from(client_share).map_err(|_| bad_share())?;
                // FIPS 203's modulus check (7.2): encapsulate doesn't do it
                if !libcrux_ml_kem::$m::validate_public_key(&ek) {
                    return Err(bad_share());
                }
                let (ct, shared) = libcrux_ml_kem::$m::encapsulate(&ek, random()?);
                Ok(CompletedKeyExchange {
                    group: $group,
                    pub_key: ct.as_slice().to_vec(),
                    secret: SharedSecret::from(&shared[..]),
                })
            }

            fn name(&self) -> NamedGroup {
                $group
            }

            fn usable_for_version(&self, version: ProtocolVersion) -> bool {
                version == ProtocolVersion::TLSv1_3
            }
        }

        struct $active {
            keys: Box<libcrux_ml_kem::$m::$kp>,
        }

        impl ActiveKeyExchange for $active {
            fn complete(self: Box<Self>, ciphertext: &[u8]) -> Result<SharedSecret, Error> {
                let ct = libcrux_ml_kem::$m::$ct::try_from(ciphertext).map_err(|_| bad_share())?;
                let shared = libcrux_ml_kem::$m::decapsulate(self.keys.private_key(), &ct);
                Ok(SharedSecret::from(&shared[..]))
            }

            fn pub_key(&self) -> &[u8] {
                self.keys.public_key().as_slice()
            }

            fn group(&self) -> NamedGroup {
                $group
            }
        }
    };
}

ml_kem!(
    MlKem512,
    ActiveMlKem512,
    mlkem512,
    MlKem512PublicKey,
    MlKem512Ciphertext,
    MlKem512KeyPair,
    NamedGroup::MLKEM512
);
ml_kem!(
    MlKem768,
    ActiveMlKem768,
    mlkem768,
    MlKem768PublicKey,
    MlKem768Ciphertext,
    MlKem768KeyPair,
    NamedGroup::MLKEM768
);
ml_kem!(
    MlKem1024,
    ActiveMlKem1024,
    mlkem1024,
    MlKem1024PublicKey,
    MlKem1024Ciphertext,
    MlKem1024KeyPair,
    NamedGroup::MLKEM1024
);

static MLKEM512: MlKem512 = MlKem512;
static MLKEM768: MlKem768 = MlKem768;
static MLKEM1024: MlKem1024 = MlKem1024;

// ---- hybrids ----

/// ML-KEM encapsulation key and ciphertext lengths (FIPS 203)
const MLKEM768_EK_LEN: usize = 1184;
const MLKEM768_CT_LEN: usize = 1088;
const MLKEM1024_EK_LEN: usize = 1568;
const MLKEM1024_CT_LEN: usize = 1568;

pub static X25519MLKEM768: &dyn SupportedKxGroup = &Hybrid {
    name: NamedGroup::X25519MLKEM768,
    classical: &X25519,
    pq: &MLKEM768,
    pq_first: true,
    pq_client_len: MLKEM768_EK_LEN,
    pq_server_len: MLKEM768_CT_LEN,
};

pub static SECP256R1MLKEM768: &dyn SupportedKxGroup = &Hybrid {
    name: NamedGroup::secp256r1MLKEM768,
    classical: &P256,
    pq: &MLKEM768,
    pq_first: false,
    pq_client_len: MLKEM768_EK_LEN,
    pq_server_len: MLKEM768_CT_LEN,
};

pub static SECP384R1MLKEM1024: &dyn SupportedKxGroup = &Hybrid {
    // (rustls 0.23 has no named variant for this one)
    name: NamedGroup::Unknown(0x11ed),
    classical: &P384,
    pq: &MLKEM1024,
    pq_first: false,
    pq_client_len: MLKEM1024_EK_LEN,
    pq_server_len: MLKEM1024_CT_LEN,
};
