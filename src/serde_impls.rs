//! Optional serde support: wire types serialize as their binary encoding.
//!
//! With the `serde` feature enabled, [`Envelope`], [`HybridSignature`], and
//! [`PublicKeyBundle`] implement `Serialize`/`Deserialize` as byte sequences
//! containing exactly their `to_bytes()` form, so all format validation runs
//! on deserialization.

use crate::{Envelope, HybridSignature, PublicKeyBundle};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

macro_rules! impl_serde_via_bytes {
    ($type:ty) => {
        impl Serialize for $type {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_bytes(&self.to_bytes())
            }
        }

        impl<'de> Deserialize<'de> for $type {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let bytes = <serde_bytes_shim::ByteBuf as Deserialize>::deserialize(deserializer)?;
                <$type>::from_bytes(&bytes.0).map_err(de::Error::custom)
            }
        }
    };
}

/// Minimal stand-in for `serde_bytes`: accepts both byte buffers and
/// sequences of integers, so the impls work with self-describing formats
/// (JSON arrays) and binary formats (bincode, CBOR byte strings) alike.
mod serde_bytes_shim {
    use serde::{de, Deserialize, Deserializer};

    pub(super) struct ByteBuf(pub(super) Vec<u8>);

    impl<'de> Deserialize<'de> for ByteBuf {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct Visitor;

            impl<'de> de::Visitor<'de> for Visitor {
                type Value = ByteBuf;

                fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    f.write_str("bytes")
                }

                fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<ByteBuf, E> {
                    Ok(ByteBuf(v.to_vec()))
                }

                fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<ByteBuf, E> {
                    Ok(ByteBuf(v))
                }

                fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<ByteBuf, A::Error> {
                    let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0));
                    while let Some(b) = seq.next_element::<u8>()? {
                        out.push(b);
                    }
                    Ok(ByteBuf(out))
                }
            }

            deserializer.deserialize_byte_buf(Visitor)
        }
    }
}

impl_serde_via_bytes!(Envelope);
impl_serde_via_bytes!(HybridSignature);
impl_serde_via_bytes!(PublicKeyBundle);

#[cfg(test)]
mod tests {
    use crate::{seal, Envelope, HybridCrypto, HybridSignature, PublicKeyBundle};

    #[test]
    fn json_roundtrip_all_wire_types() {
        let kp = HybridCrypto::generate().unwrap();

        let envelope = seal(b"serde test", kp.public_keys()).unwrap();
        let json = serde_json::to_string(&envelope).unwrap();
        let back: Envelope = serde_json::from_str(&json).unwrap();
        assert_eq!(kp.open(&back).unwrap(), b"serde test");

        let sig = kp.sign(b"msg", b"").unwrap();
        let json = serde_json::to_string(&sig).unwrap();
        let back: HybridSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(back, sig);

        let json = serde_json::to_string(kp.public_keys()).unwrap();
        let back: PublicKeyBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, kp.public_keys());
    }

    #[test]
    fn deserialization_validates() {
        // A corrupted byte stream must fail through the same validation as
        // from_bytes, not produce a half-parsed object.
        let kp = HybridCrypto::generate().unwrap();
        let mut bytes = kp.public_keys().to_bytes();
        bytes[0] = b'X'; // break magic
        let json = serde_json::to_string(&bytes).unwrap();
        assert!(serde_json::from_str::<PublicKeyBundle>(&json).is_err());
    }
}
