use core::ops::Deref;

use crate::{
    kdf::{labeled_extract, HkdfSha256, LabeledExpand}, kem::{Kem as KemTrait, SharedSecret, X25519HkdfSha256}, oqs::call_oqs, util::{enforce_equal_len, enforce_outbuf_len, kem_suite_id}, Deserializable, HpkeError, Serializable
};

use generic_array::{
    sequence::Concat,
    typenum::{self, Unsigned, ToInt},
    GenericArray,
};
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
use rand_core::{CryptoRng, RngCore};
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroizing;

type KyberPubkeyLen = <typenum::U1000 as core::ops::Add<typenum::U184>>::Output;
type KyberPrivkeyLen = <<typenum::U1000 as core::ops::Add<typenum::U1000>>::Output as core::ops::Add<
    typenum::U400,
>>::Output;
type KyberEncappedKeyLen = <typenum::U1000 as core::ops::Add<typenum::U88>>::Output;

const DOMAIN_SEPARATOR_AUTH : &str = "Karolin Varner, Wanja Zaeske, Aaron Kaiser, Sven Friedrich, Alice Bowman, August 2023; From paper: Agile post quantum cryptography in avionics; AKEM combiner built from AKEM:HPKE/X25519HkdfSha256 + KEM:ML-KEM-768  + KDF:shake256: authenticated";
const DOMAIN_SEPARATOR_NO_AUTH : &str = "Karolin Varner, Wanja Zaeske, Aaron Kaiser, Sven Friedrich, Alice Bowman, August 2023; From paper: Agile post quantum cryptography in avionics; AKEM combiner built from AKEM:HPKE/X25519HkdfSha256 + KEM:ML-KEM-768 + KDF:shake256: no authentication";

// We use GenericArray rather than normal fixed-size arrays because we need serde impls, and serde
// doesn't support generic constants yet

/// An X25519-Kyber768 public key. This holds an X25519 public key and a Kyber768 public key.
#[derive(Debug, PartialEq, Eq, Clone)]
#[doc(hidden)]
pub struct PublicKey {
    x: <X25519HkdfSha256 as KemTrait>::PublicKey,
    k: GenericArray<u8, KyberPubkeyLen>,
}

/// An X25519-Kyber768 private key. This holds an X25519 private key and a Kyber768 private key.
#[derive(Clone)]
#[doc(hidden)]
pub struct PrivateKey {
    x: <X25519HkdfSha256 as KemTrait>::PrivateKey,
    k: GenericArray<u8, KyberPrivkeyLen>,
}

/// Holds the content of an encapsulated secret. This is what the receiver uses to derive the
/// shared secret. Since this is a hybrid KEM, it holds a DH encapped key and a Kyber encapped key.
#[derive(Clone)]
#[doc(hidden)]
pub struct EncappedKey {
    x: <X25519HkdfSha256 as KemTrait>::EncappedKey,
    k: GenericArray<u8, KyberEncappedKeyLen>,
}

type XyberEncappedKeyLen = <typenum::U1000 as core::ops::Add<typenum::U120>>::Output;
type XyberPubkeyLen = <typenum::U1000 as core::ops::Add<typenum::U216>>::Output;
type XyberPrivkeyLen = <<typenum::U1000 as core::ops::Add<typenum::U1000>>::Output as core::ops::Add<
    typenum::U432,
>>::Output;

impl Serializable for EncappedKey {
    type OutputSize = XyberEncappedKeyLen;

    fn write_exact(&self, buf: &mut [u8]) {
        enforce_outbuf_len::<Self>(buf);

        let x = &self.x;
        let k = self.k.as_slice();

        let xl : usize = <<<X25519HkdfSha256 as KemTrait>::EncappedKey as Serializable>::OutputSize as ToInt<_>>::INT;

        let (xo, ko) = buf.split_at_mut(xl);

        x.write_exact(xo);
        ko.copy_from_slice(k);
    }

    fn to_bytes(&self) -> GenericArray<u8, Self::OutputSize> {
        // Output X25519 encapped key || Kyber encapped key
        self.x.to_bytes().concat(self.k)
    }
}

impl Deserializable for EncappedKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        enforce_equal_len(Self::OutputSize::to_usize(), encoded.len())?;

        // Grab the X25519 encapped key then the Kyber encapped key. The clone_from_slice(), which
        // can panic, is permitted because of the enforce_equal_len above.
        let x = <<X25519HkdfSha256 as KemTrait>::EncappedKey as Deserializable>::from_bytes(
            &encoded[..32],
        )?;
        let k = GenericArray::clone_from_slice(&encoded[32..]);

        Ok(EncappedKey { x, k })
    }
}

impl Serializable for PublicKey {
    type OutputSize = XyberPubkeyLen;

    fn write_exact(&self, buf: &mut [u8]) {
        enforce_outbuf_len::<Self>(buf);

        let x = &self.x;
        let k = self.k.as_slice();

        let xl : usize = <<<X25519HkdfSha256 as KemTrait>::EncappedKey as Serializable>::OutputSize as ToInt<_>>::INT;

        let (xo, ko) = buf.split_at_mut(xl);

        x.write_exact(xo);
        ko.copy_from_slice(k);
    }

    fn to_bytes(&self) -> GenericArray<u8, Self::OutputSize> {
        // Output X25519 pubkey || Kyber pubkey
        self.x.to_bytes().concat(self.k)
    }
}

impl Deserializable for PublicKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        enforce_equal_len(Self::OutputSize::to_usize(), encoded.len())?;

        // Grab the X25519 pubkey then the Kyber pubkey. The clone_from_slice(), which can panic,
        // is permitted because of the enforce_equal_len above.
        let x = <<X25519HkdfSha256 as KemTrait>::PublicKey as Deserializable>::from_bytes(
            &encoded[..32],
        )?;
        let k = GenericArray::clone_from_slice(&encoded[32..]);

        Ok(PublicKey { x, k })
    }
}

impl Serializable for PrivateKey {
    type OutputSize = XyberPrivkeyLen;

    fn write_exact(&self, buf: &mut [u8]) {
        enforce_outbuf_len::<Self>(buf);

        let x = &self.x;
        let k = self.k.as_slice();

        let xl : usize = <<<X25519HkdfSha256 as KemTrait>::EncappedKey as Serializable>::OutputSize as ToInt<_>>::INT;

        let (xo, ko) = buf.split_at_mut(xl);

        x.write_exact(xo);
        ko.copy_from_slice(k);
    }

    fn to_bytes(&self) -> GenericArray<u8, Self::OutputSize> {
        // Output X25519 privkey || Kyber privkey
        self.x.to_bytes().concat(self.k)
    }
}

impl Deserializable for PrivateKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        enforce_equal_len(Self::OutputSize::to_usize(), encoded.len())?;

        // Grab the X25519 privkey then the Kyber privkey. The clone_from_slice(), which can panic,
        // is permitted because of the enforce_equal_len above.
        let x = <<X25519HkdfSha256 as KemTrait>::PrivateKey as Deserializable>::from_bytes(
            &encoded[..32],
        )?;
        let k = GenericArray::clone_from_slice(&encoded[32..]);

        Ok(PrivateKey { x, k })
    }
}

impl ConstantTimeEq for PrivateKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.x.to_bytes().ct_eq(&other.x.to_bytes()) & self.k.ct_eq(&other.k)
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for PrivateKey {}

pub struct X25519Kyber768;

impl KemTrait for X25519Kyber768 {
    #[doc(hidden)]
    type NSecret = typenum::U64;

    type EncappedKey = EncappedKey;
    type PublicKey = PublicKey;
    type PrivateKey = PrivateKey;

    const KEM_ID: u16 = 0x30;

    /// ~~Deterministically~~ derives a keypair from the given input keying material and ciphersuite
    /// ID. The keying material SHOULD have at least 256 bits of entropy.
    fn derive_keypair(ikm: &[u8]) -> (Self::PrivateKey, Self::PublicKey) {
        // Hash the IKM
        let suite_id = kem_suite_id::<Self>();
        let (_, dkp_prk) = labeled_extract::<HkdfSha256>(&[], &suite_id, b"dkp_prk", ikm);

        // Expand the randomness to fill 2 seeds
        let mut buf = [0u8; 32 + 64];
        dkp_prk
            .labeled_expand(&suite_id, b"sk", &[], &mut buf)
            .unwrap();
        let (seed1, _seed2) = buf.split_at(32);

        let (skx, pkx) = X25519HkdfSha256::derive_keypair(seed1); // Todo:

        // TODO: This is nondeterministic, but since we just use the code for benchmarks, this is
        // not a problem for the paper
        let mut skk = GenericArray::<u8, KyberPrivkeyLen>::default();
        let mut pkk = GenericArray::<u8, KyberPubkeyLen>::default();
        call_oqs(|| unsafe {
            oqs_sys::kem::OQS_KEM_ml_kem_768_ipd_keypair(
                pkk.as_mut_ptr(),
                skk.as_mut_ptr(),
            )
        }).unwrap();

        (
            PrivateKey {
                x: skx,
                k: skk,
            },
            PublicKey {
                x: pkx,
                k: pkk,
            },
        )
    }

    /// Converts a X25519-Kyber768 private key to a public key
    fn sk_to_pk(_sk: &PrivateKey) -> PublicKey {
        todo!(); // Not supported by OQS
    }

    /// Does an X25519-Kyber768 encapsulation. This does not support sender authentication.
    /// `sender_id_keypair` must be `None`. Otherwise, this returns
    /// [`HpkeError::AuthnotSupportedError`].
    fn encap<R: CryptoRng + RngCore>(
        pk_recip: &Self::PublicKey,
        sender_id_keypair: Option<(&Self::PrivateKey, &Self::PublicKey)>,
        csprng: &mut R,
    ) -> Result<(SharedSecret<Self>, Self::EncappedKey), HpkeError> {
        // Encap using both KEMs
        let xsender = sender_id_keypair.map(|(sk, pk)| (&sk.x, &pk.x));

        let (ss1, enc1) = X25519HkdfSha256::encap(&pk_recip.x, xsender, csprng)?;

        // TODO: This is nondeterministic, but since we just use the code for benchmarks, this is
        // not a problem for the paper
        let mut ss2 = Zeroizing::new([0u8; 32]);
        let mut enc2 = GenericArray::<u8, KyberEncappedKeyLen>::default();
        call_oqs(|| unsafe {
            oqs_sys::kem::OQS_KEM_ml_kem_768_ipd_encaps(
                enc2.as_mut_ptr(),
                ss2.as_mut_ptr(),
                pk_recip.k.as_ptr(),
            )
        }).map_err(|_| HpkeError::EncapError)?;

        let domain_sep = match sender_id_keypair {
            Some(_) => DOMAIN_SEPARATOR_AUTH,
            None    => DOMAIN_SEPARATOR_NO_AUTH,
        };
        
        let mut ss = <SharedSecret<Self> as Default>::default();
        let mut kdf = Shake256::default(); // TODO: Should be KMAC256 
        kdf.update(domain_sep.as_bytes());
        kdf.update(&ss1.0);
        kdf.update(ss2.deref());
        kdf.update(&enc1.to_bytes());
        if let Some((_, PublicKey { ref x, .. })) = sender_id_keypair {
            kdf.update(&x.to_bytes());
        }
        kdf.update(&pk_recip.x.to_bytes());

        kdf.finalize_xof().read(&mut ss.0);

        // The clone_from_slice, which can panic, is OK because enc2 is a fixed-size array.
        Ok((
            ss,
            EncappedKey {
                x: enc1,
                k: enc2,
            },
        ))
    }

    /// Does an X25519-Kyber768 decapsulation. This does not support sender authentication.
    /// `pk_sender_id` must be `None`. Otherwise, this returns
    /// [`HpkeError::AuthnotSupportedError`].
    fn decap(
        sk_recip: &Self::PrivateKey,
        pk_sender_id: Option<&Self::PublicKey>,
        encapped_key: &Self::EncappedKey,
    ) -> Result<SharedSecret<Self>, HpkeError> {
        // Decapsulate with both KEMs
        let ss1 = X25519HkdfSha256::decap(&sk_recip.x, pk_sender_id.map(|pk| &pk.x), &encapped_key.x)?;

        let mut ss2 = Zeroizing::new([0u8; 32]);
        call_oqs(|| unsafe {
            oqs_sys::kem::OQS_KEM_ml_kem_768_ipd_decaps(
                ss2.as_mut_ptr(),
                encapped_key.k.as_ptr(),
                sk_recip.k.as_ptr(),
            )
        }).map_err(|_| HpkeError::DecapError)?;

        let domain_sep = match pk_sender_id {
            Some(_) => DOMAIN_SEPARATOR_AUTH,
            None    => DOMAIN_SEPARATOR_NO_AUTH,
        };

        // Compute X25519 shared secret || Kyber shared secret. The unwrap() is OK because ss1.0
        // and ss2 are fixed-size arrays.
        let mut ss = <SharedSecret<Self> as Default>::default();
        let mut kdf = Shake256::default(); // TODO: Should be KMAC256 
        kdf.update(domain_sep.as_bytes());
        kdf.update(&ss1.0);
        kdf.update(ss2.deref());
        kdf.update(&encapped_key.x.to_bytes());
        if let Some(PublicKey { ref x, .. }) = pk_sender_id {
            kdf.update(&x.to_bytes());
        }
        kdf.update(X25519HkdfSha256::sk_to_pk(&sk_recip.x).to_bytes().deref());

        kdf.finalize_xof().read(&mut ss.0);

        Ok(ss)
    }
}
