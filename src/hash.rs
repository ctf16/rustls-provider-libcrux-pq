//! SHA-256 and SHA-384 (libcrux-sha2) for the transcript hash

use libcrux_sha2::Digest;
use rustls::crypto::hash::{Context, Hash, HashAlgorithm, Output};

pub struct Sha<D: 'static, const N: usize>(HashAlgorithm, std::marker::PhantomData<fn() -> D>);

pub static SHA256: Sha<libcrux_sha2::Sha256, 32> =
    Sha(HashAlgorithm::SHA256, std::marker::PhantomData);
pub static SHA384: Sha<libcrux_sha2::Sha384, 48> =
    Sha(HashAlgorithm::SHA384, std::marker::PhantomData);

impl<D, const N: usize> Hash for Sha<D, N>
where
    D: Digest<N> + Default + Clone + Send + Sync + 'static,
{
    fn start(&self) -> Box<dyn Context> {
        Box::new(Ctx::<D, N>(D::default()))
    }

    fn hash(&self, data: &[u8]) -> Output {
        let mut ctx = Ctx::<D, N>(D::default());
        ctx.0.update(data);
        ctx.output()
    }

    fn algorithm(&self) -> HashAlgorithm {
        self.0
    }

    fn output_len(&self) -> usize {
        N
    }
}

/// a running hash; libcrux's finish leaves the state usable, so a fork is a
/// copy of the state
struct Ctx<D, const N: usize>(D);

impl<D: Digest<N>, const N: usize> Ctx<D, N> {
    fn output(&self) -> Output {
        let mut out = [0u8; N];
        self.0.finish(&mut out);
        Output::new(&out)
    }
}

impl<D, const N: usize> Context for Ctx<D, N>
where
    D: Digest<N> + Clone + Send + Sync + 'static,
{
    fn fork_finish(&self) -> Output {
        self.output()
    }

    fn fork(&self) -> Box<dyn Context> {
        Box::new(Ctx::<D, N>(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> Output {
        self.output()
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}
