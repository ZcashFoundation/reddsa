//! Rerandomized FROST with RedJubjub curve.
#![allow(non_snake_case)]
#![deny(missing_docs)]

use group::GroupEncoding;
#[cfg(feature = "alloc")]
use group::{ff::Field as FFField, ff::PrimeField};

use frost_rerandomized::{
    frost_core::{frost, Ciphersuite, Field, Group},
    RandomizedParams,
};

use rand_core::{CryptoRng, RngCore};

use crate::{hash::HStar, private::Sealed, sapling};

pub use frost_rerandomized::frost_core::Error;

#[derive(Clone, Copy)]
/// An implementation of the FROST(Jubjub, BLAKE2b-512) ciphersuite scalar field.
pub struct JubjubScalarField;

impl Field for JubjubScalarField {
    type Scalar = jubjub::Scalar;

    type Serialization = [u8; 32];

    fn zero() -> Self::Scalar {
        Self::Scalar::zero()
    }

    fn one() -> Self::Scalar {
        Self::Scalar::one()
    }

    fn invert(scalar: &Self::Scalar) -> Result<Self::Scalar, Error> {
        // [`Jubjub::Scalar`]'s Eq/PartialEq does a constant-time comparison using
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

    fn serialize(scalar: &Self::Scalar) -> Self::Serialization {
        scalar.to_repr()
    }

    fn little_endian_serialize(scalar: &Self::Scalar) -> Self::Serialization {
        Self::serialize(scalar)
    }

    fn deserialize(buf: &Self::Serialization) -> Result<Self::Scalar, Error> {
        match Self::Scalar::from_repr(*buf).into() {
            Some(s) => Ok(s),
            None => Err(Error::MalformedScalar),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
/// An implementation of the FROST(Jubjub, BLAKE2b-512) ciphersuite group.
pub struct JubjubGroup;

impl Group for JubjubGroup {
    type Field = JubjubScalarField;

    type Element = jubjub::ExtendedPoint;

    type Serialization = [u8; 32];

    fn cofactor() -> <Self::Field as Field>::Scalar {
        Self::Field::one()
    }

    fn identity() -> Self::Element {
        Self::Element::identity()
    }

    fn generator() -> Self::Element {
        sapling::SpendAuth::basepoint()
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

#[derive(Clone, Copy, PartialEq, Eq)]
/// An implementation of the FROST(Jubjub, BLAKE2b-512) ciphersuite.
pub struct JubjubBlake2b512;

impl Ciphersuite for JubjubBlake2b512 {
    type Group = JubjubGroup;

    type HashOutput = [u8; 64];

    type SignatureSerialization = [u8; 64];

    /// H1 for FROST(Jubjub, BLAKE2b-512)
    fn H1(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
        HStar::<sapling::SpendAuth>::new(b"FROST_RedJubjubR")
            .update(m)
            .finalize()
    }

    /// H2 for FROST(Jubjub, BLAKE2b-512)
    fn H2(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
        HStar::<sapling::SpendAuth>::default().update(m).finalize()
    }

    /// H3 for FROST(Jubjub, BLAKE2b-512)
    fn H3(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
        HStar::<sapling::SpendAuth>::new(b"FROST_RedJubjubN")
            .update(m)
            .finalize()
    }

    /// H4 for FROST(Jubjub, BLAKE2b-512)
    fn H4(m: &[u8]) -> Self::HashOutput {
        let mut state = blake2b_simd::Params::new()
            .hash_length(64)
            .personal(b"FROST_RedJubjubM")
            .to_state();
        *state.update(m).finalize().as_array()
    }

    fn H5(m: &[u8]) -> Self::HashOutput {
        let mut state = blake2b_simd::Params::new()
            .hash_length(64)
            .personal(b"FROST_RedJubjubC")
            .to_state();
        *state.update(m).finalize().as_array()
    }

    /// HDKG for FROST(ristretto255, SHA-512)
    fn HDKG(m: &[u8]) -> Option<<<Self::Group as Group>::Field as Field>::Scalar> {
        Some(
            HStar::<sapling::SpendAuth>::new(b"FROST_RedJubjubD")
                .update(m)
                .finalize(),
        )
    }
}

// Shorthand alias for the ciphersuite
type J = JubjubBlake2b512;

/// A FROST(Jubjub, BLAKE2b-512) participant identifier.
pub type Identifier = frost::Identifier<J>;

/// FROST(Jubjub, BLAKE2b-512) keys, key generation, key shares.
pub mod keys {
    use alloc::vec::Vec;

    use super::*;

    /// Allows all participants' keys to be generated using a central, trusted
    /// dealer.
    pub fn keygen_with_dealer<RNG: RngCore + CryptoRng>(
        max_signers: u16,
        min_signers: u16,
        mut rng: RNG,
    ) -> Result<(Vec<SecretShare>, PublicKeyPackage), Error> {
        frost::keys::keygen_with_dealer(max_signers, min_signers, &mut rng)
    }

    /// Secret and public key material generated by a dealer performing
    /// [`keygen_with_dealer`].
    ///
    /// # Security
    ///
    /// To derive a FROST(Jubjub, BLAKE2b-512) keypair, the receiver of the [`SecretShare`] *must* call
    /// .into(), which under the hood also performs validation.
    pub type SecretShare = frost::keys::SecretShare<J>;

    /// A FROST(Jubjub, BLAKE2b-512) keypair, which can be generated either by a trusted dealer or using
    /// a DKG.
    ///
    /// When using a central dealer, [`SecretShare`]s are distributed to
    /// participants, who then perform verification, before deriving
    /// [`KeyPackage`]s, which they store to later use during signing.
    pub type KeyPackage = frost::keys::KeyPackage<J>;

    /// Public data that contains all the signers' public keys as well as the
    /// group public key.
    ///
    /// Used for verification purposes before publishing a signature.
    pub type PublicKeyPackage = frost::keys::PublicKeyPackage<J>;

    pub mod dkg {
        #![doc = include_str!("./frost_redjubjub/dkg.md")]
        use super::*;

        /// The secret package that must be kept in memory by the participant
        /// between the first and second parts of the DKG protocol (round 1).
        ///
        /// # Security
        ///
        /// This package MUST NOT be sent to other participants!
        pub type Round1SecretPackage = frost::keys::dkg::Round1SecretPackage<J>;

        /// The package that must be broadcast by each participant to all other participants
        /// between the first and second parts of the DKG protocol (round 1).
        pub type Round1Package = frost::keys::dkg::Round1Package<J>;

        /// The secret package that must be kept in memory by the participant
        /// between the second and third parts of the DKG protocol (round 2).
        ///
        /// # Security
        ///
        /// This package MUST NOT be sent to other participants!
        pub type Round2SecretPackage = frost::keys::dkg::Round2SecretPackage<J>;

        /// A package that must be sent by each participant to some other participants
        /// in Round 2 of the DKG protocol. Note that there is one specific package
        /// for each specific recipient, in contrast to Round 1.
        ///
        /// # Security
        ///
        /// The package must be sent on an *confidential* and *authenticated* channel.
        pub type Round2Package = frost::keys::dkg::Round2Package<J>;

        /// Performs the first part of the distributed key generation protocol
        /// for the given participant.
        ///
        /// It returns the [`Round1SecretPackage`] that must be kept in memory
        /// by the participant for the other steps, and the [`Round1Package`] that
        /// must be sent to other participants.
        pub fn keygen_part1<R: RngCore + CryptoRng>(
            identifier: Identifier,
            max_signers: u16,
            min_signers: u16,
            mut rng: R,
        ) -> Result<(Round1SecretPackage, Round1Package), Error> {
            frost::keys::dkg::keygen_part1(identifier, max_signers, min_signers, &mut rng)
        }

        /// Performs the second part of the distributed key generation protocol
        /// for the participant holding the given [`Round1SecretPackage`],
        /// given the received [`Round1Package`]s received from the other participants.
        ///
        /// It returns the [`Round2SecretPackage`] that must be kept in memory
        /// by the participant for the final step, and the [`Round2Package`]s that
        /// must be sent to other participants.
        pub fn keygen_part2(
            secret_package: Round1SecretPackage,
            round1_packages: &[Round1Package],
        ) -> Result<(Round2SecretPackage, Vec<Round2Package>), Error> {
            frost::keys::dkg::keygen_part2(secret_package, round1_packages)
        }

        /// Performs the third and final part of the distributed key generation protocol
        /// for the participant holding the given [`Round2SecretPackage`],
        /// given the received [`Round1Package`]s and [`Round2Package`]s received from
        /// the other participants.
        ///
        /// It returns the [`KeyPackage`] that has the long-lived key share for the
        /// participant, and the [`PublicKeyPackage`]s that has public information
        /// about all participants; both of which are required to compute FROST
        /// signatures.
        pub fn keygen_part3(
            round2_secret_package: &Round2SecretPackage,
            round1_packages: &[Round1Package],
            round2_packages: &[Round2Package],
        ) -> Result<(KeyPackage, PublicKeyPackage), Error> {
            frost::keys::dkg::keygen_part3(round2_secret_package, round1_packages, round2_packages)
        }
    }
}

/// FROST(Jubjub, BLAKE2b-512) Round 1 functionality and types.
pub mod round1 {
    use frost_rerandomized::frost_core::frost::keys::SigningShare;

    use super::*;
    /// Comprised of FROST(Jubjub, BLAKE2b-512) hiding and binding nonces.
    ///
    /// Note that [`SigningNonces`] must be used *only once* for a signing
    /// operation; re-using nonces will result in leakage of a signer's long-lived
    /// signing key.
    pub type SigningNonces = frost::round1::SigningNonces<J>;

    /// Published by each participant in the first round of the signing protocol.
    ///
    /// This step can be batched if desired by the implementation. Each
    /// SigningCommitment can be used for exactly *one* signature.
    pub type SigningCommitments = frost::round1::SigningCommitments<J>;

    /// Performed once by each participant selected for the signing operation.
    ///
    /// Generates the signing nonces and commitments to be used in the signing
    /// operation.
    pub fn commit<RNG>(
        participant_identifier: frost::Identifier<J>,
        secret: &SigningShare<J>,
        rng: &mut RNG,
    ) -> (SigningNonces, SigningCommitments)
    where
        RNG: CryptoRng + RngCore,
    {
        frost::round1::commit::<J, RNG>(participant_identifier, secret, rng)
    }
}

/// Generated by the coordinator of the signing operation and distributed to
/// each signing party.
pub type SigningPackage = frost::SigningPackage<J>;

/// FROST(Jubjub, BLAKE2b-512) Round 2 functionality and types, for signature share generation.
pub mod round2 {
    use super::*;

    /// A FROST(Jubjub, BLAKE2b-512) participant's signature share, which the Coordinator will aggregate with all other signer's
    /// shares into the joint signature.
    pub type SignatureShare = frost::round2::SignatureShare<J>;

    /// Generated by the coordinator of the signing operation and distributed to
    /// each signing party
    pub type SigningPackage = frost::SigningPackage<J>;

    /// Performed once by each participant selected for the signing operation.
    ///
    /// Receives the message to be signed and a set of signing commitments and a set
    /// of randomizing commitments to be used in that signing operation, including
    /// that for this participant.
    ///
    /// Assumes the participant has already determined which nonce corresponds with
    /// the commitment that was assigned by the coordinator in the SigningPackage.
    pub fn sign(
        signing_package: &SigningPackage,
        signer_nonces: &round1::SigningNonces,
        key_package: &keys::KeyPackage,
        randomizer_point: &<<J as Ciphersuite>::Group as Group>::Element,
    ) -> Result<SignatureShare, Error> {
        frost_rerandomized::sign(
            signing_package,
            signer_nonces,
            key_package,
            randomizer_point,
        )
    }
}

/// A Schnorr signature on FROST(Jubjub, BLAKE2b-512).
pub type Signature = frost_rerandomized::frost_core::Signature<J>;

/// Verifies each FROST(Jubjub, BLAKE2b-512) participant's signature share, and if all are valid,
/// aggregates the shares into a signature to publish.
///
/// Resulting signature is compatible with verification of a plain Schnorr
/// signature.
///
/// This operation is performed by a coordinator that can communicate with all
/// the signing participants before publishing the final signature. The
/// coordinator can be one of the participants or a semi-trusted third party
/// (who is trusted to not perform denial of service attacks, but does not learn
/// any secret information). Note that because the coordinator is trusted to
/// report misbehaving parties in order to avoid publishing an invalid
/// signature, if the coordinator themselves is a signer and misbehaves, they
/// can avoid that step. However, at worst, this results in a denial of
/// service attack due to publishing an invalid signature.
pub fn aggregate(
    signing_package: &round2::SigningPackage,
    signature_shares: &[round2::SignatureShare],
    pubkeys: &keys::PublicKeyPackage,
    randomized_params: &RandomizedParams<J>,
) -> Result<Signature, Error> {
    frost_rerandomized::aggregate(
        signing_package,
        signature_shares,
        pubkeys,
        randomized_params,
    )
}

/// A signing key for a Schnorr signature on FROST(Jubjub, BLAKE2b-512).
pub type SigningKey = frost_rerandomized::frost_core::SigningKey<J>;

/// A valid verifying key for Schnorr signatures on FROST(Jubjub, BLAKE2b-512).
pub type VerifyingKey = frost_rerandomized::frost_core::VerifyingKey<J>;
