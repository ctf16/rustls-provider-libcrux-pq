//! AES-128-GCM, AES-256-GCM (libcrux-aes) and ChaCha20-Poly1305
//! (libcrux-chacha20poly1305) as TLS 1.3 and TLS 1.2 record protection. TLS
//! 1.3 and TLS 1.2 ChaCha20-Poly1305 use the sequence number XORed into the IV
//! as nonce; TLS 1.2 AES-GCM sends an 8-byte explicit nonce (we use the same
//! construction).
//!
//! libcrux encrypts and decrypts from one buffer into another, not in place:
//! each record's input is first copied to a scratch buffer that the
//! encrypter or decrypter keeps and reuses.

use std::marker::PhantomData;

use libcrux_traits::aead::arrayref;
use rustls::crypto::cipher::{
    make_tls12_aad, make_tls13_aad, AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv,
    KeyBlockShape, MessageDecrypter, MessageEncrypter, Nonce, OutboundOpaqueMessage,
    OutboundPlainMessage, PrefixedPayload, Tls12AeadAlgorithm, Tls13AeadAlgorithm,
    UnsupportedOperationError, NONCE_LEN,
};
use rustls::{ConnectionTrafficSecrets, ContentType, Error, ProtocolVersion};

const TAG_LEN: usize = 16;
const GCM_EXPLICIT_NONCE_LEN: usize = 8;
const MAX_FRAGMENT_LEN: usize = 16384;

#[derive(Clone, Copy, PartialEq)]
pub enum Kind {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

pub struct Aead<A: 'static, const K: usize>(Kind, PhantomData<fn() -> A>);

pub static AES_128_GCM: Aead<libcrux_aes::aes_gcm_128::AesGcm128, 16> =
    Aead(Kind::Aes128Gcm, PhantomData);
pub static AES_256_GCM: Aead<libcrux_aes::aes_gcm_256::AesGcm256, 32> =
    Aead(Kind::Aes256Gcm, PhantomData);
pub static CHACHA20_POLY1305: Aead<libcrux_chacha20poly1305::ChaCha20Poly1305, 32> =
    Aead(Kind::ChaCha20Poly1305, PhantomData);

/// the libcrux AEADs used here (K-byte key, 12-byte nonce, 16-byte tag)
pub trait Cipher<const K: usize>: arrayref::Aead<K, TAG_LEN, NONCE_LEN> + 'static {}
impl<A: arrayref::Aead<K, TAG_LEN, NONCE_LEN> + 'static, const K: usize> Cipher<K> for A {}

impl<A: Cipher<K>, const K: usize> Aead<A, K> {
    fn secrets(&self, key: AeadKey, iv: Iv) -> ConnectionTrafficSecrets {
        match self.0 {
            Kind::Aes128Gcm => ConnectionTrafficSecrets::Aes128Gcm { key, iv },
            Kind::Aes256Gcm => ConnectionTrafficSecrets::Aes256Gcm { key, iv },
            Kind::ChaCha20Poly1305 => ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv },
        }
    }
}

/// a traffic key with its IV and the scratch buffer for record input
struct Keyed<A, const K: usize> {
    key: [u8; K],
    iv: Iv,
    scratch: Vec<u8>,
    cipher: PhantomData<fn() -> A>,
}

impl<A: Cipher<K>, const K: usize> Keyed<A, K> {
    fn new(key: &AeadKey, iv: Iv) -> Self {
        Self {
            key: key
                .as_ref()
                .try_into()
                .expect("AEAD key length from the cipher suite"),
            iv,
            scratch: Vec::new(),
            cipher: PhantomData,
        }
    }

    /// encrypt BUF in place with NONCE and AAD; the tag to append
    fn seal(
        &mut self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
    ) -> Result<[u8; TAG_LEN], Error> {
        self.scratch.clear();
        self.scratch.extend_from_slice(buf);
        let mut tag = [0u8; TAG_LEN];
        A::encrypt(buf, &mut tag, &self.key, nonce, aad, &self.scratch)
            .map_err(|_| Error::EncryptError)?;
        Ok(tag)
    }

    /// decrypt BUF in place, checking TAG; BUF is zeroed if the check fails
    /// (libcrux's ChaCha20-Poly1305 writes the plaintext before checking)
    fn open(
        &mut self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8],
    ) -> Result<(), Error> {
        let tag: &[u8; TAG_LEN] = tag.try_into().map_err(|_| Error::DecryptError)?;
        self.scratch.clear();
        self.scratch.extend_from_slice(buf);
        A::decrypt(buf, &self.key, nonce, aad, &self.scratch, tag).map_err(|_| {
            buf.fill(0);
            Error::DecryptError
        })
    }

    fn nonce(&self, seq: u64) -> [u8; NONCE_LEN] {
        Nonce::new(&self.iv, seq).0
    }
}

// ---- TLS 1.3 ----

impl<A: Cipher<K>, const K: usize> Tls13AeadAlgorithm for Aead<A, K> {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Tls13Cipher(Keyed::<A, K>::new(&key, iv)))
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Tls13Cipher(Keyed::<A, K>::new(&key, iv)))
    }

    fn key_len(&self) -> usize {
        K
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(self.secrets(key, iv))
    }
}

struct Tls13Cipher<A, const K: usize>(Keyed<A, K>);

impl<A: Cipher<K>, const K: usize> MessageEncrypter for Tls13Cipher<A, K> {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);
        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&msg.typ.to_array());
        let nonce = self.0.nonce(seq);
        let tag = self
            .0
            .seal(&nonce, &make_tls13_aad(total_len), payload.as_mut())?;
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + TAG_LEN
    }
}

impl<A: Cipher<K>, const K: usize> MessageDecrypter for Tls13Cipher<A, K> {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        if payload.len() < TAG_LEN {
            return Err(Error::DecryptError);
        }
        let aad = make_tls13_aad(payload.len());
        let plain_len = payload.len() - TAG_LEN;
        let (cipher, tag) = payload.split_at_mut(plain_len);
        let nonce = self.0.nonce(seq);
        self.0.open(&nonce, &aad, cipher, tag)?;
        payload.truncate(plain_len);
        msg.into_tls13_unpadded_message()
    }
}

// ---- TLS 1.2 ----

impl<A: Cipher<K>, const K: usize> Tls12AeadAlgorithm for Aead<A, K> {
    fn encrypter(&self, key: AeadKey, iv: &[u8], explicit: &[u8]) -> Box<dyn MessageEncrypter> {
        if self.0 == Kind::ChaCha20Poly1305 {
            Box::new(Tls12ChaCha(Keyed::<A, K>::new(&key, Iv::copy(iv))))
        } else {
            Box::new(Tls12Gcm(Keyed::<A, K>::new(&key, gcm_iv(iv, explicit))))
        }
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        if self.0 == Kind::ChaCha20Poly1305 {
            Box::new(Tls12ChaCha(Keyed::<A, K>::new(&key, Iv::copy(iv))))
        } else {
            let mut salt = [0u8; NONCE_LEN];
            salt[..4].copy_from_slice(iv);
            Box::new(Tls12Gcm(Keyed::<A, K>::new(&key, Iv::new(salt))))
        }
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        if self.0 == Kind::ChaCha20Poly1305 {
            KeyBlockShape {
                enc_key_len: K,
                fixed_iv_len: NONCE_LEN,
                explicit_nonce_len: 0,
            }
        } else {
            KeyBlockShape {
                enc_key_len: K,
                fixed_iv_len: 4,
                explicit_nonce_len: GCM_EXPLICIT_NONCE_LEN,
            }
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        let iv = if self.0 == Kind::ChaCha20Poly1305 {
            Iv::copy(iv)
        } else {
            gcm_iv(iv, explicit)
        };
        Ok(self.secrets(key, iv))
    }
}

/// the 4-byte salt from the key block and the 8-byte explicit part
fn gcm_iv(salt: &[u8], explicit: &[u8]) -> Iv {
    let mut iv = [0u8; NONCE_LEN];
    iv[..4].copy_from_slice(salt);
    iv[4..].copy_from_slice(explicit);
    Iv::new(iv)
}

struct Tls12ChaCha<A, const K: usize>(Keyed<A, K>);

impl<A: Cipher<K>, const K: usize> MessageEncrypter for Tls12ChaCha<A, K> {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let mut payload =
            PrefixedPayload::with_capacity(self.encrypted_payload_len(msg.payload.len()));
        payload.extend_from_chunks(&msg.payload);
        let aad = make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len());
        let nonce = self.0.nonce(seq);
        let tag = self.0.seal(&nonce, &aad, payload.as_mut())?;
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + TAG_LEN
    }
}

impl<A: Cipher<K>, const K: usize> MessageDecrypter for Tls12ChaCha<A, K> {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        if msg.payload.len() < TAG_LEN {
            return Err(Error::DecryptError);
        }
        let plain_len = msg.payload.len() - TAG_LEN;
        let aad = make_tls12_aad(seq, msg.typ, msg.version, plain_len);
        let (cipher, tag) = msg.payload.split_at_mut(plain_len);
        let nonce = self.0.nonce(seq);
        self.0.open(&nonce, &aad, cipher, tag)?;
        msg.payload.truncate(plain_len);
        Ok(msg.into_plain_message())
    }
}

/// encrypter: the full IV (salt + explicit part); decrypter: the salt only
struct Tls12Gcm<A, const K: usize>(Keyed<A, K>);

impl<A: Cipher<K>, const K: usize> MessageEncrypter for Tls12Gcm<A, K> {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let mut payload =
            PrefixedPayload::with_capacity(self.encrypted_payload_len(msg.payload.len()));
        let nonce = self.0.nonce(seq);
        let aad = make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len());
        payload.extend_from_slice(&nonce[4..]);
        payload.extend_from_chunks(&msg.payload);
        let tag = self.0.seal(
            &nonce,
            &aad,
            &mut payload.as_mut()[GCM_EXPLICIT_NONCE_LEN..],
        )?;
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + GCM_EXPLICIT_NONCE_LEN + TAG_LEN
    }
}

impl<A: Cipher<K>, const K: usize> MessageDecrypter for Tls12Gcm<A, K> {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        if msg.payload.len() < GCM_EXPLICIT_NONCE_LEN + TAG_LEN {
            return Err(Error::DecryptError);
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..4].copy_from_slice(&self.0.iv.as_ref()[..4]);
        nonce[4..].copy_from_slice(&msg.payload[..GCM_EXPLICIT_NONCE_LEN]);
        let plain_len = msg.payload.len() - GCM_EXPLICIT_NONCE_LEN - TAG_LEN;
        let aad = make_tls12_aad(seq, msg.typ, msg.version, plain_len);
        let (_, rest) = msg.payload.split_at_mut(GCM_EXPLICIT_NONCE_LEN);
        let (cipher, tag) = rest.split_at_mut(plain_len);
        self.0.open(&nonce, &aad, cipher, tag)?;
        if plain_len > MAX_FRAGMENT_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }
        Ok(
            msg.into_plain_message_range(
                GCM_EXPLICIT_NONCE_LEN..GCM_EXPLICIT_NONCE_LEN + plain_len,
            ),
        )
    }
}
