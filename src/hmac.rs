//! HMAC-SHA-256 and HMAC-SHA-384 (libcrux-hmac); rustls derives HKDF (TLS
//! 1.3) and the PRF (TLS 1.2) from these

use libcrux_hmac::HmacState;
use rustls::crypto::hmac::{Hmac, Key, Tag};

pub struct HmacSha<H: 'static, const N: usize>(std::marker::PhantomData<fn() -> H>);

pub static HMAC_SHA256: HmacSha<libcrux_hmac::HmacSha256, 32> = HmacSha(std::marker::PhantomData);
pub static HMAC_SHA384: HmacSha<libcrux_hmac::HmacSha384, 48> = HmacSha(std::marker::PhantomData);

impl<H: HmacState<N> + 'static, const N: usize> Hmac for HmacSha<H, N> {
    fn with_key(&self, key: &[u8]) -> Box<dyn Key> {
        Box::new(HmacKey::<H, N>(key.to_vec(), std::marker::PhantomData))
    }

    fn hash_output_len(&self) -> usize {
        N
    }
}

/// the key; libcrux's keyed HMAC state can't be copied, so each tag keys a
/// fresh one
struct HmacKey<H, const N: usize>(Vec<u8>, std::marker::PhantomData<fn() -> H>);

impl<H: HmacState<N>, const N: usize> Key for HmacKey<H, N> {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> Tag {
        // (the errors are for inputs over 4 GiB, which TLS never has)
        let mut m = H::new(&self.0).expect("HMAC key under 4 GiB");
        for part in std::iter::once(first)
            .chain(middle.iter().copied())
            .chain([last])
        {
            m.update(part).expect("HMAC input under 4 GiB");
        }
        let mut tag = [0u8; N];
        m.finalize(&mut tag);
        Tag::new(&tag)
    }

    fn tag_len(&self) -> usize {
        N
    }
}
