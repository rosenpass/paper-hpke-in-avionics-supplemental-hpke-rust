use core::{hint::black_box, ops::Deref};

use crate::{
    kdf::{labeled_extract, HkdfSha256, LabeledExpand}, kem::{Kem as KemTrait, SharedSecret, X25519HkdfSha256}, oqs::call_oqs, util::{enforce_equal_len, enforce_outbuf_len, kem_suite_id}, Deserializable, HpkeError, Serializable
};

use digest::typenum::ToInt;
use generic_array::{
    sequence::Concat,
    typenum::{self, Unsigned},
    GenericArray,
};
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
use rand_core::{CryptoRng, RngCore};
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroizing;

#[inline]
pub fn constant_time_xor(dst: &mut [u8], src: &[u8]){
    assert!(black_box(src.len()) == black_box(dst.len()));
    for (dv, sv) in dst.iter_mut().zip(src.iter()) {
        *black_box(dv) ^= black_box(*sv);
    }
}

type DilithiumPubkeyLen = <typenum::U1000 as core::ops::Add<typenum::U952>>::Output;
type DilithiumPrivkeyLen = <<typenum::U2048
    as core::ops::Add<typenum::U1024>>::Output
    as core::ops::Add<typenum::U960>>::Output;
type DilithiumSignatureLen = <<typenum::U2048
    as core::ops::Add<typenum::U1024>>::Output
    as core::ops::Add<typenum::U237>>::Output;

type KyberPubkeyLen = <typenum::U1000 as core::ops::Add<typenum::U184>>::Output;
type KyberPrivkeyLen = <<typenum::U1000 as core::ops::Add<typenum::U1000>>::Output as core::ops::Add<
    typenum::U400,
>>::Output;
type KyberEncappedKeyLen = <typenum::U1000 as core::ops::Add<typenum::U88>>::Output;

const DOMAIN_SEPARATOR_AUTH : &str = "Karolin Varner, Wanja Zaeske, Aaron Kaiser, Sven Friedrich, Alice Bowman, August 2023; From paper: Agile post quantum cryptography in avionics; AKEM combiner built from AKEM:HPKE/X25519HkdfSha256 + KEM:ML-KEM-768 + Sig:ML-DSA-65 + KDF:shake256: authenticated";
const DOMAIN_SEPARATOR_NO_AUTH : &str = "Karolin Varner, Wanja Zaeske, Aaron Kaiser, Sven Friedrich, Alice Bowman, August 2023; From paper: Agile post quantum cryptography in avionics; AKEM combiner built from AKEM:HPKE/X25519HkdfSha256 + KEM:ML-KEM-768 + Sig:ML-DSA-65 + KDF:shake256: no authentication";

// We use GenericArray rather than normal fixed-size arrays because we need serde impls, and serde
// doesn't support generic constants yet

#[derive(Debug, PartialEq, Eq, Clone)]
#[doc(hidden)]
pub struct PublicKey {
    x: <X25519HkdfSha256 as KemTrait>::PublicKey,
    k: GenericArray<u8, KyberPubkeyLen>,
    d: GenericArray<u8, DilithiumPubkeyLen>,
}

#[derive(Clone)]
#[doc(hidden)]
pub struct PrivateKey {
    x: <X25519HkdfSha256 as KemTrait>::PrivateKey,
    k: GenericArray<u8, KyberPrivkeyLen>,
    d: GenericArray<u8, DilithiumPrivkeyLen>,
}

#[derive(Clone)]
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
        KyberPrivkeyLen as core::ops::Add<
            DilithiumPrivkeyLen>>::Output>>::Output;

impl Serializable for EncappedKey {
    type OutputSize = XyberDilithiumEncappedKeyLen;

    fn write_exact(&self, buf: &mut [u8]) {
        enforce_outbuf_len::<Self>(buf);

        let x = &self.x;
        let k = self.k.as_slice();
        let d = self.d.as_slice();

        let xl : usize = <<<X25519HkdfSha256 as KemTrait>::EncappedKey as Serializable>::OutputSize as ToInt<_>>::INT;
        let kl : usize = k.len();

        let (xo, buf) = buf.split_at_mut(xl);
        let (ko, do_) = buf.split_at_mut(kl);

        x.write_exact(xo);
        ko.copy_from_slice(k);
        do_.copy_from_slice(d);
    }

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

    fn write_exact(&self, buf: &mut [u8]) {
        enforce_outbuf_len::<Self>(buf);

        let x = &self.x;
        let k = self.k.as_slice();
        let d = self.d.as_slice();

        let xl : usize = <<<X25519HkdfSha256 as KemTrait>::EncappedKey as Serializable>::OutputSize as ToInt<_>>::INT;
        let kl : usize = k.len();

        let (xo, buf) = buf.split_at_mut(xl);
        let (ko, do_) = buf.split_at_mut(kl);

        x.write_exact(xo);
        ko.copy_from_slice(k);
        do_.copy_from_slice(d);
    }

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

    fn write_exact(&self, buf: &mut [u8]) {
        enforce_outbuf_len::<Self>(buf);

        let x = &self.x;
        let k = self.k.as_slice();
        let d = self.d.as_slice();

        let xl : usize = <<<X25519HkdfSha256 as KemTrait>::EncappedKey as Serializable>::OutputSize as ToInt<_>>::INT;
        let kl : usize = k.len();

        let (xo, buf) = buf.split_at_mut(xl);
        let (ko, do_) = buf.split_at_mut(kl);

        x.write_exact(xo);
        ko.copy_from_slice(k);
        do_.copy_from_slice(d);
    }

    fn to_bytes(&self) -> GenericArray<u8, Self::OutputSize> {
        self.x.to_bytes().concat(self.k).concat(self.d)
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

        Ok(PrivateKey { x, k, d })
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
        let (seed1, _seed2_3) = buf.split_at(32);
        // let (_seed2, _seed3) = seed2_3.split_at(64); // Omitted – OQS has no support for
        // generating keys from a seed

        // Generate the keypairs with the two seeds
        let (skx, pkx) = X25519HkdfSha256::derive_keypair(seed1);

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

        // TODO: Again, this is nondeterministic
        let mut skd = GenericArray::<u8, DilithiumPrivkeyLen>::default();
        let mut pkd = GenericArray::<u8, DilithiumPubkeyLen>::default();
        call_oqs(|| unsafe {
            oqs_sys::sig::OQS_SIG_ml_dsa_65_ipd_keypair(
                pkd.as_mut_ptr(),
                skd.as_mut_ptr(),
            )
        }).unwrap();

        (
            PrivateKey {
                x: skx,
                k: skk,
                d: skd,
            },
            PublicKey {
                x: pkx,
                k: pkk,
                d: pkd,
            },
        )
    }

    /// Converts a X25519-Kyber768 private key to a public key
    fn sk_to_pk(_sk: &PrivateKey) -> PublicKey {
        todo!(); // Not implemented
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

        let mut ss = <SharedSecret<Self> as Default>::default();
        let mut ki = [0u8; 32];
        let mut kc = [0u8; 32];
        let mut sig_keystream = GenericArray::<u8, DilithiumSignatureLen>::default();

        let domain_sep = match sender_id_keypair {
            Some(_) => DOMAIN_SEPARATOR_AUTH,
            None    => DOMAIN_SEPARATOR_NO_AUTH,
        };

        let mut kdf = Shake256::default(); // TODO: Should be KMAC256 
        kdf.update(domain_sep.as_bytes());
        kdf.update(&[0u8; 0]);
        kdf.update(&ss1.0);
        kdf.update(ss2.deref());
        kdf.update(&enc1.to_bytes());
        if let Some((_, PublicKey { ref x, .. })) = sender_id_keypair {
            kdf.update(&x.to_bytes());
        }
        kdf.update(&pk_recip.x.to_bytes());

        let mut kdfr = kdf.finalize_xof();
        kdfr.read(&mut ki);
        kdfr.read(&mut kc);
        kdfr.read(&mut sig_keystream);

        // Calculate the signature
        // TODO: This may be nondeterministic
        let mut sig = GenericArray::<u8, DilithiumSignatureLen>::default();
        if let Some((sk, _pk)) = sender_id_keypair {
            let mut sig_len = 0usize;
            call_oqs(|| unsafe {
                oqs_sys::sig::OQS_SIG_ml_dsa_65_ipd_sign(
                    sig.as_mut_ptr(),
                    core::ptr::addr_of_mut!(sig_len),
                    kc.as_ptr(), 
                    kc.len(), 
                    sk.d.as_ptr())
            }).map(|_| {
                assert!(sig_len == sig.len(), "SIG LEN {sig_len} != {}", sig.len());
            }).map_err(|_| HpkeError::EncapError)?;
        }

        // Encrypt the signature
        constant_time_xor(&mut sig, sig_keystream.as_slice());
        let sig_ct = sig;

        // Second stage of key derivation so we can mix the signature into the output key
        let mut kdf = Shake256::default();
        kdf.update(domain_sep.as_bytes());
        kdf.update(&[0u8; 1]);
        kdf.update(&ki);
        kdf.update(sig_ct.as_slice());

        let mut kdfr = kdf.finalize_xof();
        kdfr.read(&mut ss.0);

        // The clone_from_slice, which can panic, is OK because enc2 is a fixed-size array.
        Ok((
            ss,
            EncappedKey {
                x: enc1,
                k: GenericArray::clone_from_slice(&enc2),
                d: GenericArray::clone_from_slice(&sig_ct),
            },
        ))
    }

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

        let mut ss = <SharedSecret<Self> as Default>::default();
        let mut ki = [0u8; 32];
        let mut kc = [0u8; 32];
        let mut sig_keystream = GenericArray::<u8, DilithiumSignatureLen>::default();

        let domain_sep = match pk_sender_id {
            Some(_) => DOMAIN_SEPARATOR_AUTH,
            None    => DOMAIN_SEPARATOR_NO_AUTH,
        };

        let mut kdf = Shake256::default(); // TODO: Should be KMAC256 
        kdf.update(domain_sep.as_bytes());
        kdf.update(&ss1.0);
        kdf.update(ss2.deref());
        kdf.update(&encapped_key.x.to_bytes());
        if let Some(PublicKey { ref x, .. }) = pk_sender_id {
            kdf.update(&x.to_bytes());
        }
        kdf.update(X25519HkdfSha256::sk_to_pk(&sk_recip.x).to_bytes().deref());

        let mut kdfr = kdf.finalize_xof();
        kdfr.read(&mut ki);
        kdfr.read(&mut kc);
        kdfr.read(&mut sig_keystream);

        // Decrypt the signature
        let mut sig = encapped_key.d.clone();
        constant_time_xor(&mut sig, sig_keystream.as_slice());

        // Perform the signature check
        if let Some(ref pk) = pk_sender_id {
            call_oqs(|| unsafe {
                oqs_sys::sig::OQS_SIG_ml_dsa_65_ipd_verify(
                    kc.as_ptr(),
                    kc.len(), 
                    sig.as_ptr(),
                    sig.len(),
                    pk.d.as_ptr())
            }).map_err(|_| HpkeError::DecapError)?;
        }

        // Second stage of key derivation so we can mix the signature into the output key
        let mut kdf = Shake256::default();
        kdf.update(domain_sep.as_bytes());
        kdf.update(&[0u8; 1]);
        kdf.update(&ki);
        kdf.update(&encapped_key.d); // sig_ct

        let mut kdfr = kdf.finalize_xof();
        kdfr.read(&mut ss.0);

        Ok(ss)
    }
}
