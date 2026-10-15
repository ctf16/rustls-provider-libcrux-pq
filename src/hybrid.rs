//! Hybrid key exchange (draft-ietf-tls-ecdhe-mlkem) built from two groups a
//! provider already has: an elliptic-curve group and an ML-KEM group.
//!
//! The key shares and the shared secret are the two components concatenated.
//! X25519MLKEM768 puts the ML-KEM part first; SecP256r1MLKEM768 and
//! SecP384r1MLKEM1024 put the elliptic-curve part first.

use rustls::crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup, PeerMisbehaved, ProtocolVersion};

#[derive(Debug, Clone, Copy)]
pub struct Hybrid {
    pub name: NamedGroup,
    pub classical: &'static dyn SupportedKxGroup,
    pub pq: &'static dyn SupportedKxGroup,
    /// ML-KEM part first (X25519MLKEM768) or second (the SecP*MLKEM* groups)
    pub pq_first: bool,
    /// ML-KEM encapsulation key length (client share)
    pub pq_client_len: usize,
    /// ML-KEM ciphertext length (server share)
    pub pq_server_len: usize,
}

impl Hybrid {
    /// (classical, pq) parts of a received share whose ML-KEM part is PQ_LEN long
    fn split<'a>(&self, share: &'a [u8], pq_len: usize) -> Result<(&'a [u8], &'a [u8]), Error> {
        if share.len() <= pq_len {
            return Err(PeerMisbehaved::InvalidKeyShare.into());
        }
        Ok(if self.pq_first {
            let (q, c) = share.split_at(pq_len);
            (c, q)
        } else {
            share.split_at(share.len() - pq_len)
        })
    }

    fn join(&self, classical: &[u8], pq: &[u8]) -> Vec<u8> {
        let (a, b) = if self.pq_first {
            (pq, classical)
        } else {
            (classical, pq)
        };
        let mut v = Vec::with_capacity(a.len() + b.len());
        v.extend_from_slice(a);
        v.extend_from_slice(b);
        v
    }
}

impl SupportedKxGroup for Hybrid {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let classical = self.classical.start()?;
        let pq = self.pq.start()?;
        let pub_key = self.join(classical.pub_key(), pq.pub_key());
        Ok(Box::new(Active {
            group: *self,
            classical,
            pq,
            pub_key,
        }))
    }

    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let (c, q) = self.split(client_share, self.pq_client_len)?;
        let classical = self.classical.start_and_complete(c)?;
        let pq = self.pq.start_and_complete(q)?;
        Ok(CompletedKeyExchange {
            group: self.name,
            pub_key: self.join(&classical.pub_key, &pq.pub_key),
            secret: SharedSecret::from(
                self.join(classical.secret.secret_bytes(), pq.secret.secret_bytes()),
            ),
        })
    }

    fn name(&self) -> NamedGroup {
        self.name
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

struct Active {
    group: Hybrid,
    classical: Box<dyn ActiveKeyExchange>,
    pq: Box<dyn ActiveKeyExchange>,
    pub_key: Vec<u8>,
}

impl ActiveKeyExchange for Active {
    fn complete(self: Box<Self>, server_share: &[u8]) -> Result<SharedSecret, Error> {
        let (c, q) = self.group.split(server_share, self.group.pq_server_len)?;
        let classical = self.classical.complete(c)?;
        let pq = self.pq.complete(q)?;
        Ok(SharedSecret::from(
            self.group.join(classical.secret_bytes(), pq.secret_bytes()),
        ))
    }

    /// the elliptic-curve part: rustls offers it as a key share of its own
    /// too when the client has the classical group, so a server with only
    /// that group needs no HelloRetryRequest
    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        Some((self.classical.group(), self.classical.pub_key()))
    }

    fn complete_hybrid_component(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<SharedSecret, Error> {
        self.classical.complete(peer_pub_key)
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn group(&self) -> NamedGroup {
        self.group.name
    }
}
