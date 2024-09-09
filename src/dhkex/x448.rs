use core::borrow::Borrow;

use crate::{
    dhkex::{DhError, DhKeyExchange},
    kdf::{labeled_extract, Kdf as KdfTrait, LabeledExpand},
    util::{enforce_equal_len, enforce_outbuf_len, KemSuiteId},
    Deserializable, HpkeError, Serializable,
};

use generic_array::typenum::{self, Unsigned};
use subtle::{Choice, ConstantTimeEq};
use zeroize::ZeroizeOnDrop;

const X448_POINT_LEN : usize = 56;
type X448PointLen = typenum::U56;
type X448Point = [u8; X448_POINT_LEN];
const X448_ZERO_POINT : X448Point = [0u8; X448_POINT_LEN];

/// An X448 public key
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey(X448Point);

impl PublicKey {
    #[allow(dead_code)]
    fn from_bytes(bytes: X448Point) -> Option<Self> {
        x448::PublicKey::from_bytes(&bytes).and_then(Self::from_x448_crate)
    }

    fn from_x448_crate(inner: x448::PublicKey) -> Option<Self> {
        Self(*inner.as_bytes()).check_nonzero()
    }

    fn empower(&self) -> x448::PublicKey {
        x448::PublicKey::from_bytes(&self.0).unwrap()
    }

    fn check_nonzero(self) -> Option<Self> {
        let nonzero : bool = self.0.ct_ne(&X448_ZERO_POINT).into();
        nonzero.then_some(self)
    }
}

/// An X448 private key
#[derive(Clone, ZeroizeOnDrop)]
pub struct PrivateKey(X448Point);

impl PrivateKey {
    fn from_bytes(bytes: X448Point) -> Option<Self> {
        x448::Secret::from_bytes(&bytes).and_then(Self::from_x448_crate)
    }

    fn from_x448_crate(inner: x448::Secret) -> Option<Self> {
        Self(*inner.as_bytes()).check_nonzero()
    }

    fn empower(&self) -> x448::Secret {
        x448::Secret::from_bytes(&self.0).unwrap()
    }

    fn check_nonzero(self) -> Option<Self> {
        let nonzero : bool = self.0.ct_ne(&X448_ZERO_POINT).into();
        nonzero.then_some(self)
    }

    fn pk(&self) -> PublicKey {
        let pk : x448::PublicKey = self.empower().borrow().into();
        PublicKey::from_x448_crate(pk).unwrap()
    }

    fn dh(&self, pk: &PublicKey) -> Option<KexResult> {
        self.empower()
            .as_diffie_hellman(pk.empower().borrow())
            .and_then(KexResult::from_x448_crate)
    }
}

impl ConstantTimeEq for PrivateKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}
impl Eq for PrivateKey {}

// The underlying type is zeroize-on-drop
/// A bare DH computation result
pub struct KexResult(X448Point);

impl KexResult {
    #[allow(dead_code)]
    fn from_bytes(bytes: X448Point) -> Option<Self> {
        x448::SharedSecret::from_bytes(&bytes).and_then(Self::from_x448_crate)
    }

    fn from_x448_crate(inner: x448::SharedSecret) -> Option<Self> {
        Self(*inner.as_bytes()).check_nonzero()
    }

    #[allow(dead_code)]
    fn empower(&self) -> x448::SharedSecret {
        x448::PublicKey::from_bytes(&self.0).unwrap()
    }

    fn check_nonzero(self) -> Option<Self> {
        let nonzero : bool = self.0.ct_ne(&X448_ZERO_POINT).into();
        nonzero.then_some(self)
    }
}

impl ConstantTimeEq for KexResult {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for KexResult {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for KexResult {}

// Oh I love an excuse to break out type-level integers
impl Serializable for PublicKey {
    type OutputSize = X448PointLen;

    // Dalek lets us convert pubkeys to [u8; 32]
    fn write_exact(&self, buf: &mut [u8]) {
        // Check the length is correct and panic if not
        enforce_outbuf_len::<Self>(buf);

        buf.copy_from_slice(&self.0);
    }
}

impl Deserializable for PublicKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        // Pubkeys must be 32 bytes
        enforce_equal_len(Self::OutputSize::to_usize(), encoded.len())?;

        // Copy to a fixed-size array
        let pk = x448::PublicKey::from_bytes(encoded)
            .ok_or(HpkeError::ValidationError)?;
        Ok(PublicKey(*pk.as_bytes()))
    }
}

impl Serializable for PrivateKey {
    // RFC 9180 §7.1 Table 2: Nsk of DHKEM(X448, HKDF-SHA512) is 32
    type OutputSize = X448PointLen;

    // Dalek lets us convert scalars to [u8; 32]
    fn write_exact(&self, buf: &mut [u8]) {
        // Check the length is correct and panic if not
        enforce_outbuf_len::<Self>(buf);

        buf.copy_from_slice(&self.0);
    }
}
impl Deserializable for PrivateKey {
    // Dalek lets us convert [u8; 32] to scalars. Assuming the input length is correct, this
    // conversion is infallible, so no ValidationErrors are raised.
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        // Privkeys must be 32 bytes
        enforce_equal_len(Self::OutputSize::to_usize(), encoded.len())?;

        // Copy to a fixed-size array
        let sk = x448::Secret::from_bytes(encoded)
            .ok_or(HpkeError::ValidationError)?;
        Ok(PrivateKey(*sk.as_bytes()))
    }
}

impl Serializable for KexResult {
    type OutputSize = X448PointLen;

    // curve25519's point representation is our DH result. We don't have to do anything special.
    fn write_exact(&self, buf: &mut [u8]) {
        // Check the length is correct and panic if not
        enforce_outbuf_len::<Self>(buf);

        // Dalek lets us convert shared secrets to to [u8; 32]
        buf.copy_from_slice(&self.0);
    }
}

/// Represents ECDH functionality over the X448 group
pub struct X448 {}

impl DhKeyExchange for X448 {
    #[doc(hidden)]
    type PublicKey = PublicKey;
    #[doc(hidden)]
    type PrivateKey = PrivateKey;
    #[doc(hidden)]
    type KexResult = KexResult;

    /// Converts an X448 private key to a public key
    #[doc(hidden)]
    fn sk_to_pk(sk: &PrivateKey) -> PublicKey {
        sk.pk()
    }

    /// Does the DH operation. Returns an error if and only if the DH result was all zeros. This is
    /// required by the HPKE spec. The error is converted into the appropriate higher-level error
    /// by the caller, i.e., `HpkeError::EncapError` or `HpkeError::DecapError`.
    #[doc(hidden)]
    fn dh(sk: &PrivateKey, pk: &PublicKey) -> Result<KexResult, DhError> {
        sk.dh(pk).ok_or(DhError)
    }

    // RFC 9180 §7.1.3
    // def DeriveKeyPair(ikm):
    //   dkp_prk = LabeledExtract("", "dkp_prk", ikm)
    //   sk = LabeledExpand(dkp_prk, "sk", "", Nsk)
    //   return (sk, pk(sk))

    /// Deterministically derives a keypair from the given input keying material and ciphersuite
    /// ID. The keying material SHOULD have as many bits of entropy as the bit length of a secret
    /// key, i.e., 256.
    #[doc(hidden)]
    fn derive_keypair<Kdf: KdfTrait>(suite_id: &KemSuiteId, ikm: &[u8]) -> (PrivateKey, PublicKey) {
        // Write the label into a byte buffer and extract from the IKM
        let (_, hkdf_ctx) = labeled_extract::<Kdf>(&[], suite_id, b"dkp_prk", ikm);
        // The buffer we hold the candidate scalar bytes in. This is the size of a private key.
        let mut buf = [0u8; 56];
        hkdf_ctx
            .labeled_expand(suite_id, b"sk", &[], &mut buf)
            .unwrap();

        let sk = PrivateKey::from_bytes(buf).unwrap();
        let pk = sk.pk();

        (sk, pk)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        dhkex::{x448::X448, DhKeyExchange, Serializable},
        test_util::dhkex_gen_keypair,
    };
    use generic_array::typenum::Unsigned;
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    /// Tests that an serialize-deserialize round-trip ends up at the same pubkey
    #[test]
    fn test_pubkey_serialize_correctness() {
        type Kex = X448;

        let mut csprng = StdRng::from_entropy();

        // Fill a buffer with randomness
        let orig_bytes = {
            let mut buf =
                [0u8; <<Kex as DhKeyExchange>::PublicKey as Serializable>::OutputSize::USIZE];
            csprng.fill_bytes(buf.as_mut_slice());
            buf
        };

        // Make a pubkey with those random bytes. Note, that from_bytes() does not clamp the input
        // bytes. This is why this test passes.
        let pk = <Kex as DhKeyExchange>::PublicKey::from_bytes(orig_bytes).unwrap();
        let pk_bytes = pk.to_bytes();

        // See if the re-serialized bytes are the same as the input
        assert_eq!(orig_bytes.as_slice(), pk_bytes.as_slice());
    }

    /// Tests that an deserialize-serialize round trip on a DH keypair ends up at the same values
    #[test]
    fn test_dh_serialize_correctness() {
        type Kex = X448;

        let mut csprng = StdRng::from_entropy();

        // Make a random keypair and serialize it
        let (sk, pk) = dhkex_gen_keypair::<Kex, _>(&mut csprng);
        let (sk_bytes, pk_bytes) = (sk.to_bytes(), pk.to_bytes());

        // Now deserialize those bytes
        let new_sk = <Kex as DhKeyExchange>::PrivateKey::from_bytes(sk_bytes.into()).unwrap();
        let new_pk = <Kex as DhKeyExchange>::PublicKey::from_bytes(pk_bytes.into()).unwrap();

        // See if the deserialized values are the same as the initial ones
        assert!(new_sk == sk, "private key doesn't serialize correctly");
        assert!(new_pk == pk, "public key doesn't serialize correctly");
    }
}
