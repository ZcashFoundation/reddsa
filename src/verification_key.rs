// -*- mode: rust; -*-
//
// This file is part of reddsa.
// Copyright (c) 2019-2021 Zcash Foundation
// Portions copyright (c) The Zakura Contributors, licensed under the MIT license or the
// Apache License, Version 2.0, at your option.
// See LICENSE for licensing information.
//
// Authors:
// - Deirdre Connolly <deirdre@zfnd.org>
// - Henry de Valence <hdevalence@hdevalence.ca>

use core::{
    convert::{TryFrom, TryInto},
    fmt,
    hash::Hash,
    marker::PhantomData,
};

use group::{cofactor::CofactorGroup, ff::PrimeField, GroupEncoding};

use crate::{hex_if_possible, Error, Randomizer, SigType, Signature, SpendAuth};

/// A refinement type for `[u8; 32]` indicating that the bytes represent
/// an encoding of a RedDSA verification key.
///
/// This is useful for representing a compressed verification key; the
/// [`VerificationKey`] type in this library holds other decompressed state
/// used in signature verification.
#[derive(Copy, Clone, Hash, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VerificationKeyBytes<T: SigType> {
    pub(crate) bytes: [u8; 32],
    pub(crate) _marker: PhantomData<T>,
}

impl<T: SigType> fmt::Debug for VerificationKeyBytes<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerificationKeyBytes")
            .field("bytes", &hex_if_possible(&self.bytes))
            .finish()
    }
}

impl<T: SigType> From<[u8; 32]> for VerificationKeyBytes<T> {
    fn from(bytes: [u8; 32]) -> VerificationKeyBytes<T> {
        VerificationKeyBytes {
            bytes,
            _marker: PhantomData,
        }
    }
}

impl<T: SigType> From<VerificationKeyBytes<T>> for [u8; 32] {
    fn from(refined: VerificationKeyBytes<T>) -> [u8; 32] {
        refined.bytes
    }
}

// Consensus documentation adapted from zakura-core/common:
// https://github.com/zakura-core/common/pull/675.
/// A valid RedDSA verification key.
///
/// This type holds decompressed state used in signature verification; if the
/// verification key may not be used immediately, it is probably better to use
/// [`VerificationKeyBytes`], which is a refinement type for `[u8; 32]`.
///
/// ## Consensus properties
///
/// [`TryFrom<VerificationKeyBytes<T>>`] checks that the bytes canonically encode
/// a point on the curve. Small-order points, including the identity, are
/// accepted. Sapling separately rejects small-order spend authorization keys.
#[derive(PartialEq, Copy, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "VerificationKeyBytes<T>"))]
#[cfg_attr(feature = "serde", serde(into = "VerificationKeyBytes<T>"))]
#[cfg_attr(feature = "serde", serde(bound = "T: SigType"))]
pub struct VerificationKey<T: SigType> {
    pub(crate) point: T::Point,
    pub(crate) bytes: VerificationKeyBytes<T>,
}

// Adapted from zakura-core/common (https://github.com/zakura-core/common/pull/677).
impl From<pasta_curves::pallas::Point> for VerificationKey<crate::orchard::Binding> {
    /// Retains a valid Pallas binding point and its canonical encoding, including identity.
    fn from(point: pasta_curves::pallas::Point) -> Self {
        let bytes = VerificationKeyBytes {
            bytes: point.to_bytes(),
            _marker: PhantomData,
        };
        VerificationKey { point, bytes }
    }
}

impl From<VerificationKey<crate::orchard::SpendAuth>> for pasta_curves::pallas::Point {
    /// Returns the stored point; protocol-specific identity checks remain the caller's job.
    fn from(key: VerificationKey<crate::orchard::SpendAuth>) -> Self {
        key.point
    }
}

// Adapted from zakura-core/common (https://github.com/zakura-core/common/pull/677).
impl From<jubjub::ExtendedPoint> for VerificationKey<crate::sapling::Binding> {
    /// Constructs a binding key from an existing valid Jubjub point.
    ///
    /// Retains the point and computes its canonical encoding without decoding
    /// it again. Identity and other small-order points are accepted.
    /// The point must satisfy Jubjub's curve invariants; release builds trust
    /// coordinates supplied through unchecked constructors.
    fn from(point: jubjub::ExtendedPoint) -> Self {
        let bytes = VerificationKeyBytes {
            bytes: point.to_bytes(),
            _marker: PhantomData,
        };
        debug_assert_eq!(
            Option::<jubjub::ExtendedPoint>::from(jubjub::ExtendedPoint::from_bytes(&bytes.bytes)),
            Some(point),
            "binding verification key point must match its encoding",
        );
        Self { point, bytes }
    }
}

// Adapted from zakura-core/common (https://github.com/zakura-core/common/pull/677).
impl From<VerificationKey<crate::sapling::SpendAuth>> for jubjub::AffinePoint {
    /// Normalizes the stored spend authorization point without decoding it.
    ///
    /// Small-order points are preserved; protocol-specific restrictions must
    /// still be checked by the caller.
    fn from(key: VerificationKey<crate::sapling::SpendAuth>) -> Self {
        let affine = Self::from(key.point);
        debug_assert_eq!(affine.to_bytes(), key.bytes.bytes);
        affine
    }
}

impl<T: SigType> From<VerificationKey<T>> for VerificationKeyBytes<T> {
    fn from(pk: VerificationKey<T>) -> VerificationKeyBytes<T> {
        pk.bytes
    }
}

impl<T: SigType> From<VerificationKey<T>> for [u8; 32] {
    fn from(pk: VerificationKey<T>) -> [u8; 32] {
        pk.bytes.bytes
    }
}

impl<T: SigType> TryFrom<VerificationKeyBytes<T>> for VerificationKey<T> {
    type Error = Error;

    fn try_from(bytes: VerificationKeyBytes<T>) -> Result<Self, Self::Error> {
        // XXX-jubjub: this should not use CtOption
        // XXX-jubjub: this takes ownership of bytes, while Fr doesn't.
        // This checks that the encoding is canonical...
        let mut repr = <T::Point as GroupEncoding>::Repr::default();
        repr.as_mut().copy_from_slice(&bytes.bytes);
        let maybe_point = T::Point::from_bytes(&repr);
        if maybe_point.is_some().into() {
            let point = maybe_point.unwrap();
            // Note that small-order verification keys (including the identity) are not
            // rejected here. Previously they were rejected, but this was a bug as the
            // RedDSA specification allows them. Zcash Sapling rejects small-order points
            // for the RedJubjub spend authorization key rk; this now occurs separately.
            // Meanwhile, Zcash Orchard uses a prime-order group, so the only small-order
            // point would be the identity, which is allowed in Orchard.
            Ok(VerificationKey { point, bytes })
        } else {
            Err(Error::MalformedVerificationKey)
        }
    }
}

impl<T: SigType> TryFrom<[u8; 32]> for VerificationKey<T> {
    type Error = Error;

    fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
        VerificationKeyBytes::from(bytes).try_into()
    }
}

impl<T: SpendAuth> VerificationKey<T> {
    /// Randomize this verification key with the given `randomizer`.
    ///
    /// Randomization is only supported for `SpendAuth` keys.
    pub fn randomize(&self, randomizer: &Randomizer<T>) -> VerificationKey<T> {
        let point = self.point + (T::basepoint() * randomizer);
        let bytes = VerificationKeyBytes {
            bytes: point.to_bytes().as_ref().try_into().unwrap(),
            _marker: PhantomData,
        };
        VerificationKey { bytes, point }
    }
}

impl<T: SigType> VerificationKey<T> {
    pub(crate) fn from(s: &T::Scalar) -> VerificationKey<T> {
        let point = T::basepoint() * s;
        let bytes = VerificationKeyBytes {
            bytes: point.to_bytes().as_ref().try_into().unwrap(),
            _marker: PhantomData,
        };
        VerificationKey { bytes, point }
    }

    /// Verify a purported `signature` over `msg` made by this verification key.
    // This is similar to impl signature::Verifier but without boxed errors
    pub fn verify(&self, msg: &[u8], signature: &Signature<T>) -> Result<(), Error> {
        use crate::HStar;
        let c = HStar::<T>::default()
            .update(&signature.r_bytes[..])
            .update(&self.bytes.bytes[..]) // XXX ugly
            .update(msg)
            .finalize();
        self.verify_prehashed(signature, c)
    }

    /// Verify a purported `signature` with a prehashed challenge.
    #[allow(non_snake_case)]
    pub(crate) fn verify_prehashed(
        &self,
        signature: &Signature<T>,
        c: T::Scalar,
    ) -> Result<(), Error> {
        let r = {
            // XXX-jubjub: should not use CtOption here
            // XXX-jubjub: inconsistent ownership in from_bytes
            let mut repr = <T::Point as GroupEncoding>::Repr::default();
            repr.as_mut().copy_from_slice(&signature.r_bytes);
            let maybe_point = T::Point::from_bytes(&repr);
            if maybe_point.is_some().into() {
                maybe_point.unwrap()
            } else {
                return Err(Error::InvalidSignature);
            }
        };

        let s = {
            // XXX-jubjub: should not use CtOption here
            let mut repr = <T::Scalar as PrimeField>::Repr::default();
            repr.as_mut().copy_from_slice(&signature.s_bytes);
            let maybe_scalar = T::Scalar::from_repr(repr);
            if maybe_scalar.is_some().into() {
                maybe_scalar.unwrap()
            } else {
                return Err(Error::InvalidSignature);
            }
        };

        // XXX rewrite as normal double scalar mul
        // Verify check is h * ( - s * B + R  + c * A) == 0
        //                 h * ( s * B - c * A - R) == 0
        let sB = T::basepoint() * s;
        let cA = self.point * c;
        let check = sB - cA - r;

        if check.is_small_order().into() {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}
