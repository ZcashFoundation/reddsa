//! FROST with RedPallas
#![allow(non_snake_case)]
#![deny(missing_docs)]

use group::GroupEncoding;
#[cfg(feature = "alloc")]
use group::{ff::Field as FFField, ff::PrimeField, Group as FFGroup};
use pasta_curves::pallas;

use rand_core::{CryptoRng, RngCore};

use frost_core::{frost, Ciphersuite, Field, Group};

pub use frost_core::Error;

use crate::{hash::HStar, orchard, private::Sealed};

#[derive(Clone, Copy)]
/// An implementation of the FROST Pallas Blake2b-512 ciphersuite scalar field.
pub struct PallasScalarField;

impl Field for PallasScalarField {
    type Scalar = pallas::Scalar;

    type Serialization = [u8; 32];

    fn zero() -> Self::Scalar {
        Self::Scalar::zero()
    }

    fn one() -> Self::Scalar {
        Self::Scalar::one()
    }

    fn invert(scalar: &Self::Scalar) -> Result<Self::Scalar, Error> {
        // [`pallas::Scalar`]'s Eq/PartialEq does a constant-time comparison using
        // `ConstantTimeEq`
        if *scalar == <Self as Field>::zero() {
            Err(Error::InvalidZeroScalar)
        } else {
            Ok(Self::Scalar::invert(scalar).unwrap())
        }
    }

    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
        Self::Scalar::random(rng)
    }

    fn random_nonzero<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
        loop {
            let scalar = Self::Scalar::random(&mut *rng);

            // This impl of `Eq` calls to `ConstantTimeEq` under the hood
            if scalar != Self::Scalar::zero() {
                return scalar;
            }
        }
    }

    fn serialize(scalar: &Self::Scalar) -> Self::Serialization {
        scalar.to_repr().into()
    }

    fn deserialize(buf: &Self::Serialization) -> Result<Self::Scalar, Error> {
        match pallas::Scalar::from_repr(*buf).into() {
            Some(s) => Ok(s),
            None => Err(Error::MalformedScalar),
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
/// An implementation of the FROST P-256 ciphersuite group.
pub struct PallasGroup;

impl Group for PallasGroup {
    type Field = PallasScalarField;

    type Element = pallas::Point;

    /// [SEC 1][1] serialization of a compressed point in P-256 takes 33 bytes
    /// (1-byte prefix and 32 bytes for the coordinate).
    ///
    /// Note that, in the P-256 spec, the identity is encoded as a single null byte;
    /// but here we pad with zeroes. This is acceptable as the identity _should_ never
    /// be serialized in FROST, else we error.
    ///
    /// [1]: https://secg.org/sec1-v2.pdf
    type Serialization = [u8; 32];

    fn cofactor() -> <Self::Field as Field>::Scalar {
        Self::Field::one()
    }

    fn identity() -> Self::Element {
        Self::Element::identity()
    }

    fn generator() -> Self::Element {
        orchard::SpendAuth::basepoint()
    }

    fn serialize(element: &Self::Element) -> Self::Serialization {
        element.to_bytes()
    }

    fn deserialize(buf: &Self::Serialization) -> Result<Self::Element, Error> {
        let point = Self::Element::from_bytes(buf);

        match Option::<_>::from(point) {
            Some(point) => Ok(point),
            None => Err(Error::MalformedElement),
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
/// An implementation of the FROST ciphersuite FROST(Pallas, BLAKE2b-512).
pub struct PallasBlake2b512;

impl Ciphersuite for PallasBlake2b512 {
    type Group = PallasGroup;

    type HashOutput = [u8; 64];

    type SignatureSerialization = [u8; 64];

    /// H1 for FROST(Pallas, BLAKE2b-512)
    fn H1(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
        HStar::<orchard::SpendAuth>::new(b"Zcash_RedPallasH")
            .update(m)
            .finalize()
    }

    /// H2 for FROST(Pallas, BLAKE2b-512)
    fn H2(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
        HStar::<orchard::SpendAuth>::default().update(m).finalize()
    }

    /// H3 for FROST(Pallas, BLAKE2b-512)
    fn H3(m: &[u8]) -> Self::HashOutput {
        let mut state = blake2b_simd::Params::new()
            .hash_length(64)
            .personal(b"FROST_RedPallasD")
            .to_state();
        *state.update(m).finalize().as_array()
    }

    /// H3 for FROST(Pallas, BLAKE2b-512)
    fn H4(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
        HStar::<orchard::SpendAuth>::new(b"Zcash_RedPallasN")
            .update(m)
            .finalize()
    }
}

// Shorthand alias for the ciphersuite
type P = PallasBlake2b512;

///
pub mod keys {
    use alloc::vec::Vec;

    use super::*;

    ///
    pub fn keygen_with_dealer<RNG: RngCore + CryptoRng>(
        num_signers: u8,
        threshold: u8,
        mut rng: RNG,
    ) -> Result<(Vec<SharePackage>, PublicKeyPackage), &'static str> {
        frost::keys::keygen_with_dealer(num_signers, threshold, &mut rng)
    }

    ///
    pub type SharePackage = frost::keys::SharePackage<P>;

    ///
    pub type KeyPackage = frost::keys::KeyPackage<P>;

    ///
    pub type PublicKeyPackage = frost::keys::PublicKeyPackage<P>;
}

///
pub mod round1 {
    use alloc::vec::Vec;

    use super::*;
    ///
    pub type SigningNonces = frost::round1::SigningNonces<P>;

    ///
    pub type SigningCommitments = frost::round1::SigningCommitments<P>;

    ///
    pub fn commit<RNG>(
        key_package: &keys::KeyPackage,
        rng: &mut RNG,
    ) -> (Vec<SigningNonces>, Vec<SigningCommitments>)
    where
        RNG: CryptoRng + RngCore,
    {
        frost::round1::commit::<P, RNG>(key_package, rng)
    }
}

///
pub type SigningPackage = frost::SigningPackage<P>;

///
pub mod round2 {
    use super::*;

    ///
    pub type SignatureShare = frost::round2::SignatureShare<P>;

    ///
    pub type SigningPackage = frost::SigningPackage<P>;

    ///
    pub fn sign(
        signing_package: &SigningPackage,
        signer_nonces: &round1::SigningNonces,
        key_package: &keys::KeyPackage,
    ) -> Result<SignatureShare, &'static str> {
        frost::round2::sign(&signing_package, signer_nonces, key_package)
    }
}

///
pub type Signature = frost_core::Signature<P>;

///
pub fn aggregate(
    signing_package: &round2::SigningPackage,
    signature_shares: &[round2::SignatureShare],
    pubkeys: &keys::PublicKeyPackage,
) -> Result<Signature, &'static str> {
    frost::aggregate(&signing_package, &signature_shares[..], &pubkeys)
}

///
pub type SigningKey = frost_core::SigningKey<P>;

///
pub type VerifyingKey = frost_core::VerifyingKey<P>;
