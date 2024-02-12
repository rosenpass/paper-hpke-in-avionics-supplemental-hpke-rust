use crate::{
    kdf::{labeled_extract, HkdfSha256, LabeledExpand},
    kem::{Kem as KemTrait, SharedSecret, X25519HkdfSha256},
    util::enforce_equal_len,
    util::kem_suite_id,
    Deserializable, HpkeError, Serializable,
};

use generic_array::{
    sequence::Concat,
    typenum::{self, Unsigned},
    GenericArray,
};
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
use pqc_kyber::Keypair as KyberKeypair;
use rand_core::{CryptoRng, RngCore};
use subtle::{Choice, ConstantTimeEq};

type DilithiumPubkeyLen = <typenum::U1000 as core::ops::Add<typenum::U952>>::Output;
type DilithiumPrivkeyLen = <<typenum::U2048
    as core::ops::Add<typenum::U1024>>::Output
    as core::ops::Add<typenum::U928>>::Output;
type DilithiumSignatureLen = <<typenum::U2048
    as core::ops::Add<typenum::U1024>>::Output
    as core::ops::Add<typenum::U221>>::Output;

type KyberPubkeyLen = <typenum::U1000 as core::ops::Add<typenum::U184>>::Output;
type KyberPrivkeyLen = <<typenum::U1000 as core::ops::Add<typenum::U1000>>::Output as core::ops::Add<
    typenum::U400,
>>::Output;
type KyberEncappedKeyLen = <typenum::U1000 as core::ops::Add<typenum::U88>>::Output;

const DOMAIN_SEPARATOR_AUTH : &str = "Karolin Varner, Wanja Zaeske, Aaron Kaiser, Sven Friedrich, Alice Bowman, August 2023; From paper: Agile post quantum cryptography in avionics; AKEM combiner built from AKEM:HPKE/X25519HkdfSha256 + KEM:Kyber768 + Sig:Dilithium3 + KDF:shake256: authenticated";
const DOMAIN_SEPARATOR_NO_AUTH : &str = "Karolin Varner, Wanja Zaeske, Aaron Kaiser, Sven Friedrich, Alice Bowman, August 2023; From paper: Agile post quantum cryptography in avionics; AKEM combiner built from AKEM:HPKE/X25519HkdfSha256 + KEM:Kyber768 + Sig:Dilithium3 + KDF:shake256: no authentication";

// We use GenericArray rather than normal fixed-size arrays because we need serde impls, and serde
// doesn't support generic constants yet

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde_impls", derive(serde::Serialize, serde::Deserialize))]
#[doc(hidden)]
pub struct PublicKey {
    x: <X25519HkdfSha256 as KemTrait>::PublicKey,
    k: GenericArray<u8, KyberPubkeyLen>,
    d: GenericArray<u8, DilithiumPubkeyLen>,
}

#[derive(Clone)]
#[cfg_attr(feature = "serde_impls", derive(serde::Serialize, serde::Deserialize))]
#[doc(hidden)]
pub struct PrivateKey {
    x: <X25519HkdfSha256 as KemTrait>::PrivateKey,
    k: GenericArray<u8, KyberPrivkeyLen>,
    d: GenericArray<u8, DilithiumPrivkeyLen>,
    d_seed: GenericArray<u8, typenum::U32>,
}

#[derive(Clone)]
#[cfg_attr(feature = "serde_impls", derive(serde::Serialize, serde::Deserialize))]
#[doc(hidden)]
pub struct EncappedKey {
    x: <X25519HkdfSha256 as KemTrait>::EncappedKey,
    k: GenericArray<u8, KyberEncappedKeyLen>,
    d: GenericArray<u8, DilithiumSignatureLen>,
}

type XyberDilithiumEncappedKeyLen = <
    typenum::U32 as core::ops::Add<<
        KyberEncappedKeyLen as core::ops::Add<
            DilithiumSignatureLen>>::Output>>::Output;
type XyberDilithiumPubkeyLen = <
    typenum::U32 as core::ops::Add<<
        KyberPubkeyLen as core::ops::Add<
            DilithiumPubkeyLen>>::Output>>::Output;
type XyberDilithiumPrivkeyLen = <
    typenum::U32 as core::ops::Add<<
        KyberPrivkeyLen as core::ops::Add<<
            DilithiumPrivkeyLen as core::ops::Add<
                typenum::U32>>::Output>>::Output>>::Output;

impl Serializable for EncappedKey {
    type OutputSize = XyberDilithiumEncappedKeyLen;

    fn to_bytes(&self) -> GenericArray<u8, Self::OutputSize> {
        // Output X25519 encapped key || Kyber encapped key
        self.x.to_bytes().concat(self.k).concat(self.d)
    }
}

impl Deserializable for EncappedKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        enforce_equal_len(Self::OutputSize::to_usize(), encoded.len())?;

        let sep1 = 32;
        let sep2 = sep1 + KyberEncappedKeyLen::to_usize();

        // Grab the X25519 encapped key then the Kyber encapped key. The clone_from_slice(), which
        // can panic, is permitted because of the enforce_equal_len above.
        let x = <<X25519HkdfSha256 as KemTrait>::EncappedKey as Deserializable>::from_bytes(
            &encoded[..sep1],
        )?;
        let k = GenericArray::clone_from_slice(&encoded[sep1..sep2]);
        let d = GenericArray::clone_from_slice(&encoded[sep2..]);

        Ok(EncappedKey { x, k, d })
    }
}

impl Serializable for PublicKey {
    type OutputSize = XyberDilithiumPubkeyLen;

    fn to_bytes(&self) -> GenericArray<u8, Self::OutputSize> {
        self.x.to_bytes().concat(self.k).concat(self.d)
    }
}

impl Deserializable for PublicKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        enforce_equal_len(Self::OutputSize::to_usize(), encoded.len())?;

        let sep1 = 32;
        let sep2 = sep1 + KyberPubkeyLen::to_usize();

        // Grab the X25519 pubkey then the Kyber pubkey. The clone_from_slice(), which can panic,
        // is permitted because of the enforce_equal_len above.
        let x = <<X25519HkdfSha256 as KemTrait>::PublicKey as Deserializable>::from_bytes(
            &encoded[..sep1],
        )?;
        let k = GenericArray::clone_from_slice(&encoded[sep1..sep2]);
        let d = GenericArray::clone_from_slice(&encoded[sep2..]);

        Ok(PublicKey { x, k, d })
    }
}

impl Serializable for PrivateKey {
    type OutputSize = XyberDilithiumPrivkeyLen;

    fn to_bytes(&self) -> GenericArray<u8, Self::OutputSize> {
        self.x.to_bytes().concat(self.k).concat(self.d).concat(self.d_seed)
    }
}

impl Deserializable for PrivateKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        enforce_equal_len(Self::OutputSize::to_usize(), encoded.len())?;

        let sep1 = 32;
        let sep2 = sep1 + KyberPrivkeyLen::to_usize();
        let sep3 = sep2 + DilithiumPrivkeyLen::to_usize();

        let x = <<X25519HkdfSha256 as KemTrait>::PrivateKey as Deserializable>::from_bytes(
            &encoded[..sep1]
        )?;
        let k = GenericArray::clone_from_slice(&encoded[sep1..sep2]);
        let d = GenericArray::clone_from_slice(&encoded[sep2..sep3]);
        let d_seed = GenericArray::clone_from_slice(&encoded[sep3..]);

        Ok(PrivateKey { x, k, d, d_seed })
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

pub struct X25519Kyber768Dilithium;

impl KemTrait for X25519Kyber768Dilithium {
    #[doc(hidden)]
    type NSecret = typenum::U64;

    type EncappedKey = EncappedKey;
    type PublicKey = PublicKey;
    type PrivateKey = PrivateKey;

    const KEM_ID: u16 = 0x31;

        // Hash the IKM
    fn derive_keypair(ikm: &[u8]) -> (Self::PrivateKey, Self::PublicKey) {
        let suite_id = kem_suite_id::<Self>();
        let (_, dkp_prk) = labeled_extract::<HkdfSha256>(&[], &suite_id, b"dkp_prk", ikm);

        // Expand the randomness to fill 2 seeds
        let mut buf = [0u8; 32 + 64 + 32];
        dkp_prk
            .labeled_expand(&suite_id, b"sk", &[], &mut buf)
            .unwrap();
        let (seed1, seed2_3) = buf.split_at(32);
        let (seed2, seed3) = seed2_3.split_at(64);

        // Generate the keypairs with the two seeds
        let (skx, pkx) = X25519HkdfSha256::derive_keypair(seed1);
        let KyberKeypair {
            public: pkk,
            secret: skk,
        } = pqc_kyber::derive(seed2).unwrap();

        let mut skd = GenericArray::<u8, DilithiumPrivkeyLen>::default();
        let mut pkd = GenericArray::<u8, DilithiumPubkeyLen>::default();
        crystals_dilithium::sign::lvl3::keypair(pkd.as_mut_slice(), skd.as_mut_slice(), Some(&seed3));

        (
            PrivateKey {
                x: skx,
                k: GenericArray::clone_from_slice(&skk),
                d: skd,
                d_seed: GenericArray::clone_from_slice(&seed3),
            },
            PublicKey {
                x: pkx,
                k: GenericArray::clone_from_slice(&pkk),
                d: pkd,
            },
        )
    }

    /// Converts a X25519-Kyber768 private key to a public key
    fn sk_to_pk(sk: &PrivateKey) -> PublicKey {
        let mut skd = GenericArray::<u8, DilithiumPrivkeyLen>::default();
        let mut pkd = GenericArray::<u8, DilithiumPubkeyLen>::default();
        crystals_dilithium::sign::lvl3::keypair(pkd.as_mut_slice(), skd.as_mut_slice(), Some(&sk.d_seed));

        PublicKey {
            x: X25519HkdfSha256::sk_to_pk(&sk.x),
            k: GenericArray::clone_from_slice(&pqc_kyber::public(&sk.k)),
            d: pkd,
        }
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
        let (enc2, ss2) =
            pqc_kyber::encapsulate(&pk_recip.k, csprng).map_err(|_| HpkeError::EncapError)?;

        let mut ss = <SharedSecret<Self> as Default>::default();
        let mut kc = [0u8; 32];

        let domain_sep = match sender_id_keypair {
            Some(_) => DOMAIN_SEPARATOR_AUTH,
            None    => DOMAIN_SEPARATOR_NO_AUTH,
        };

        let mut kdf = Shake256::default(); // TODO: Should be KMAC256 
        kdf.update(domain_sep.as_bytes());
        kdf.update(&ss1.0);
        kdf.update(&ss2);
        kdf.update(&enc1.to_bytes());
        if let Some((_, PublicKey { ref x, .. })) = sender_id_keypair {
            kdf.update(&x.to_bytes());
        }
        kdf.update(&pk_recip.x.to_bytes());

        let mut kdfr = kdf.finalize_xof();
        kdfr.read(&mut ss.0);
        kdfr.read(&mut kc);

        let mut sig = GenericArray::<u8, DilithiumSignatureLen>::default();
        if let Some((sk, _pk)) = sender_id_keypair {
            crystals_dilithium::sign::lvl3::signature(&mut sig, &kc, &sk.d, false);
        }

        // TODO: Constant time
        // TODO: Implementing our own stream cipher here saves us 16 bytes…is that worth
        // implementing a stream cipher?
        let mut buf = [0u8; 1];
        for i in 0..DilithiumSignatureLen::to_usize() {
            kdfr.read(&mut buf);
            sig[i] ^= buf[0];
        }

        // The clone_from_slice, which can panic, is OK because enc2 is a fixed-size array.
        Ok((
            ss,
            EncappedKey {
                x: enc1,
                k: GenericArray::clone_from_slice(&enc2),
                d: GenericArray::clone_from_slice(&sig),
            },
        ))
    }

    fn decap(
        sk_recip: &Self::PrivateKey,
        pk_sender_id: Option<&Self::PublicKey>,
        encapped_key: &Self::EncappedKey,
    ) -> Result<SharedSecret<Self>, HpkeError> {
        let pk_recip = Self::sk_to_pk(sk_recip);

        // Decapsulate with both KEMs
        let ss1 = X25519HkdfSha256::decap(&sk_recip.x, pk_sender_id.map(|pk| &pk.x), &encapped_key.x)?;
        let ss2 = pqc_kyber::decapsulate(&encapped_key.k, &sk_recip.k)
            .map_err(|_| HpkeError::DecapError)?;

        let mut ss = <SharedSecret<Self> as Default>::default();
        let mut kc = [0u8; 32];

        let domain_sep = match pk_sender_id {
            Some(_) => DOMAIN_SEPARATOR_AUTH,
            None    => DOMAIN_SEPARATOR_NO_AUTH,
        };

        let mut kdf = Shake256::default(); // TODO: Should be KMAC256 
        kdf.update(domain_sep.as_bytes());
        kdf.update(&ss1.0);
        kdf.update(&ss2);
        kdf.update(&encapped_key.x.to_bytes());
        if let Some(PublicKey { ref x, .. }) = pk_sender_id {
            kdf.update(&x.to_bytes());
        }
        kdf.update(&pk_recip.x.to_bytes());

        let mut kdfr = kdf.finalize_xof();
        kdfr.read(&mut ss.0);
        kdfr.read(&mut kc);

        if let Some(ref pk) = pk_sender_id {
            let mut sig = encapped_key.d.clone();

            let mut buf = [0u8; 1];
            for i in 0..DilithiumSignatureLen::to_usize() {
                kdfr.read(&mut buf);
                sig[i] ^= buf[0];
            }

            if !crystals_dilithium::sign::lvl3::verify(&sig, &kc, &pk.d) {
                return Err(HpkeError::DecapError);
            }
        }

        Ok(ss)
    }
}
