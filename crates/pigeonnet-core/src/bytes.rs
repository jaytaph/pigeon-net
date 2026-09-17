//! Fixed-width byte newtypes, and the CBOR plumbing they share.
//!
//! These are deliberately opaque. `pigeonnet-core` holds the *shape* of an
//! object and never interprets key material — signature verification lives in
//! `pigeonnet-crypto`, which is what keeps this crate free of a cryptography
//! dependency and trivially fuzzable.

use core::fmt;

use minicbor::{Decode, Decoder, Encode, Encoder, decode, encode};

use crate::{Error, base32};

macro_rules! fixed_bytes {
    ($(#[$meta:meta])* $name:ident, $len:literal, $prefix:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name([u8; $len]);

        impl $name {
            /// The all-zero value.
            pub const ZERO: Self = Self([0u8; $len]);

            /// Width in bytes.
            pub const LEN: usize = $len;

            /// Wrap raw bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            /// The raw bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }

            /// Parse from the canonical text form, including its prefix.
            pub fn parse(text: &str) -> Result<Self, Error> {
                let body = text.strip_prefix($prefix).ok_or(Error::BadIdentifier)?;
                let bytes = base32::decode(body).ok_or(Error::BadIdentifier)?;
                let bytes: [u8; $len] = bytes.as_slice().try_into().map_err(|_| {
                    Error::BadLength { field: stringify!($name), expected: $len, actual: bytes.len() }
                })?;
                Ok(Self(bytes))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str($prefix)?;
                f.write_str(&base32::encode(&self.0))
            }
        }

        /// Debug prints the text form: a bare byte array is unreadable in a test
        /// failure, and these appear in test failures constantly.
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(self, f)
            }
        }

        impl<C> Encode<C> for $name {
            fn encode<W: encode::Write>(
                &self,
                e: &mut Encoder<W>,
                _ctx: &mut C,
            ) -> Result<(), encode::Error<W::Error>> {
                e.bytes(&self.0)?;
                Ok(())
            }
        }

        impl<'b, C> Decode<'b, C> for $name {
            fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, decode::Error> {
                let raw = d.bytes()?;
                let bytes: [u8; $len] = raw.try_into().map_err(|_| {
                    decode::Error::message(concat!(stringify!($name), " must be ", $len, " bytes"))
                })?;
                Ok(Self(bytes))
            }
        }
    };
}

fixed_bytes! {
    /// A content address: BLAKE3-256 over an object's to-be-signed bytes (D1).
    ///
    /// The signature is deliberately *not* covered, so signature encoding
    /// malleability cannot mint two identifiers for one object.
    ObjectId, 32, "obj:b3:"
}

fixed_bytes! {
    /// An identity: the [`ObjectId`] of its genesis object (D3).
    ///
    /// Stable across every key rotation the identity ever performs, which is the
    /// entire reason identities are not named by their keys.
    IdentityId, 32, "id:b3:"
}

fixed_bytes! {
    /// An Ed25519 public key, uninterpreted.
    PublicKeyBytes, 32, "ed25519:"
}

fixed_bytes! {
    /// An X25519 public key, uninterpreted.
    AgreementKeyBytes, 32, "x25519:"
}

fixed_bytes! {
    /// An Ed25519 signature, uninterpreted.
    SignatureBytes, 64, "sig:"
}

fixed_bytes! {
    /// A node, as distinct from an identity (§17).
    ///
    /// Identity is *who*; a node is *where*. One person may be reachable through
    /// several nodes, and one node may carry traffic for people it has never
    /// heard of — which is the whole point of an untrusted relay.
    NodeId, 32, "node:"
}

impl IdentityId {
    /// The identity named by a genesis object's identifier.
    #[must_use]
    pub const fn from_genesis(id: ObjectId) -> Self {
        Self(*id.as_bytes())
    }

    /// The genesis object this identity names.
    #[must_use]
    pub const fn genesis_object(&self) -> ObjectId {
        ObjectId::from_bytes(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_form_round_trips() {
        let id = ObjectId::from_bytes([7u8; 32]);
        let text = id.to_string();
        assert!(text.starts_with("obj:b3:"));
        assert_eq!(ObjectId::parse(&text).unwrap(), id);
    }

    #[test]
    fn prefixes_are_not_interchangeable() {
        let text = ObjectId::from_bytes([7u8; 32]).to_string();
        assert_eq!(IdentityId::parse(&text), Err(Error::BadIdentifier));
    }

    #[test]
    fn identity_is_its_genesis_object() {
        let genesis = ObjectId::from_bytes([3u8; 32]);
        let identity = IdentityId::from_genesis(genesis);
        assert_eq!(identity.genesis_object(), genesis);
    }

    #[test]
    fn rejects_wrong_width() {
        assert!(matches!(
            SignatureBytes::parse(&format!("sig:{}", base32::encode(&[0u8; 32]))),
            Err(Error::BadLength { .. })
        ));
    }
}
