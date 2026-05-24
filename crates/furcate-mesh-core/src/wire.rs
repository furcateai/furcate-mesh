// SPDX-License-Identifier: Apache-2.0

//! Wire-format codecs.
//!
//! `serde` by default serialises `[u8; N]` and `bytes::Bytes` as JSON
//! arrays of integers. That's not the format `furcate-protocol` specs
//! pin and not what any comparable standard (in-toto/SLSA, Sigstore,
//! JWS/JWT, COSE) emits on the wire.
//!
//! The wire formats this crate uses are:
//!
//! - **Fixed-size 32-byte values** → lowercase hexadecimal strings. Used
//!   by [`hex_array`] for [`crate::PeerId`]'s inner `[u8; 32]`.
//! - **Variable-length opaque bytes** → unpadded base64url (RFC 4648 §5).
//!   Used by [`base64url_bytes_bytes`] for `bytes::Bytes` payload fields
//!   on [`crate::MeshEvent`] (`WorkOffer.request`, `WorkResult.response`,
//!   `AgentState.state`).
//!
//! Apply with `#[serde(with = "crate::wire::hex_array")]` /
//! `#[serde(with = "crate::wire::base64url_bytes_bytes")]` on the field.

/// Serialise / deserialise `[u8; 32]` as a 64-character lowercase hex string.
///
/// Format: `[0-9a-f]{64}`. Deserialisation rejects any other length and any
/// non-hex character (case-sensitive — uppercase is rejected to keep the
/// canonical form unambiguous for digest pinning).
pub mod hex_array {
    use serde::de::{self, Deserialize as _, Deserializer};
    use serde::ser::Serializer;

    /// Serialise a 32-byte array as a 64-char lowercase hex string.
    ///
    /// # Errors
    ///
    /// Returns whatever error the underlying [`Serializer`] returns when
    /// serialising a string — typically infallible for `serde_json`.
    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    /// Deserialise a 32-byte array from a 64-char lowercase hex string.
    ///
    /// # Errors
    ///
    /// Returns a `serde` error if the input isn't a string, isn't exactly
    /// 64 characters, contains a non-hex character, or contains an
    /// uppercase hex digit. The canonical form is lowercase; uppercase is
    /// rejected so two implementations that round-trip a `PeerId` cannot
    /// produce different bytes for the same JSON.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = <&str>::deserialize(d)?;
        if s.len() != 64 {
            return Err(de::Error::invalid_length(
                s.len(),
                &"a 64-character lowercase hex string",
            ));
        }
        if s.chars().any(|c| c.is_ascii_uppercase()) {
            return Err(de::Error::invalid_value(
                de::Unexpected::Str(s),
                &"a lowercase hex string (uppercase hex is not canonical)",
            ));
        }
        let mut out = [0u8; 32];
        hex::decode_to_slice(s, &mut out).map_err(de::Error::custom)?;
        Ok(out)
    }
}

/// Serialise / deserialise [`bytes::Bytes`] as an unpadded base64url string
/// (RFC 4648 §5, alphabet `URL_SAFE_NO_PAD`).
///
/// Deserialisation tolerates trailing `=` padding for compatibility with
/// implementations that emit padded base64url; serialisation always omits
/// padding (the canonical form). This matches the JWS/JWT convention.
pub mod base64url_bytes_bytes {
    use base64::Engine as _;
    use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
    use bytes::Bytes;
    use serde::de::{self, Deserialize as _, Deserializer};
    use serde::ser::Serializer;

    /// Serialise opaque bytes as an unpadded base64url string.
    ///
    /// # Errors
    ///
    /// Returns whatever error the underlying [`Serializer`] returns when
    /// serialising a string — typically infallible for `serde_json`.
    pub fn serialize<S: Serializer>(bytes: &Bytes, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
    }

    /// Deserialise opaque bytes from a base64url string. Padded or unpadded
    /// is accepted; the canonical form on the wire is unpadded.
    ///
    /// # Errors
    ///
    /// Returns a `serde` error if the input isn't a string, or if the
    /// string isn't valid base64url under either the padded or unpadded
    /// alphabet.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Bytes, D::Error> {
        let s = <&str>::deserialize(d)?;
        let v = URL_SAFE_NO_PAD
            .decode(s)
            .or_else(|_| URL_SAFE.decode(s))
            .map_err(de::Error::custom)?;
        Ok(Bytes::from(v))
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct HexHolder(#[serde(with = "super::hex_array")] [u8; 32]);

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct B64Holder(#[serde(with = "super::base64url_bytes_bytes")] Bytes);

    #[test]
    fn hex_array_roundtrips() {
        let v = HexHolder([0xab; 32]);
        let j = serde_json::to_string(&v).unwrap();
        assert_eq!(j, format!("\"{}\"", "ab".repeat(32)));
        let back: HexHolder = serde_json::from_str(&j).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn hex_array_rejects_uppercase() {
        let r: Result<HexHolder, _> = serde_json::from_str(&format!("\"{}\"", "AB".repeat(32)));
        assert!(r.is_err());
    }

    #[test]
    fn hex_array_rejects_wrong_length() {
        let r: Result<HexHolder, _> = serde_json::from_str("\"abcd\"");
        assert!(r.is_err());
    }

    #[test]
    fn base64url_unpadded_roundtrips() {
        let v = B64Holder(Bytes::from_static(&[0x01, 0x02, 0x03, 0x04, 0x05]));
        let j = serde_json::to_string(&v).unwrap();
        assert_eq!(j, "\"AQIDBAU\"");
        let back: B64Holder = serde_json::from_str(&j).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn base64url_accepts_padded_input() {
        let back: B64Holder = serde_json::from_str("\"AQIDBAU=\"").unwrap();
        assert_eq!(
            back,
            B64Holder(Bytes::from_static(&[0x01, 0x02, 0x03, 0x04, 0x05]))
        );
    }

    #[test]
    fn base64url_rejects_standard_alphabet() {
        let r: Result<B64Holder, _> = serde_json::from_str("\"+/==\"");
        assert!(r.is_err());
    }
}
