// -*- mode: rust; -*-
//
// This file is part of reddsa.
// Copyright (c) 2019-2021 Zcash Foundation
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

/// A valid RedDSA verification key.
///
/// This type holds decompressed state used in signature verification; if the
/// verification key may not be used immediately, it is probably better to use
/// [`VerificationKeyBytes`], which is a refinement type for `[u8; 32]`.
///
/// ## Consensus properties
///
/// The `TryFrom<VerificationKeyBytes>` conversion checks that the bytes are a canonical
/// encoding of a verification key. It accepts small order keys, including the identity, as
/// the RedDSA specification does; Zcash Sapling's check that `rk` is not of small order is
/// done separately.
///
/// Inside [`with_trusted_encodings`](crate::trusted::with_trusted_encodings), the conversion
/// accepts any bytes and defers decoding, with the canonical-encoding check, to each use.
#[derive(Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "VerificationKeyBytes<T>"))]
#[cfg_attr(feature = "serde", serde(into = "VerificationKeyBytes<T>"))]
#[cfg_attr(feature = "serde", serde(bound = "T: SigType"))]
pub struct VerificationKey<T: SigType> {
    // `None` only for keys parsed inside `trusted::with_trusted_encodings`.
    pub(crate) point: Option<T::Point>,
    pub(crate) bytes: VerificationKeyBytes<T>,
}

// The encoding determines the point, so keys with and without a decoded point compare equal.
impl<T: SigType> PartialEq for VerificationKey<T> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

// Same output for keys with and without a decoded point.
impl<T: SigType> core::fmt::Debug for VerificationKey<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut debug = f.debug_struct("VerificationKey");
        match self.point() {
            Ok(point) => debug.field("point", &point),
            Err(_) => debug.field("point", &"invalid encoding"),
        };
        debug.field("bytes", &self.bytes).finish()
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
        // The caller validated these bytes before, so decompress the point when it is used.
        if crate::trusted::encodings_are_trusted() {
            return Ok(VerificationKey { point: None, bytes });
        }
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
            Ok(VerificationKey {
                point: Some(point),
                bytes,
            })
        } else {
            Err(Error::MalformedVerificationKey)
        }
    }
}

impl<T: SigType> VerificationKey<T> {
    /// Returns the point, decoding it if the key was parsed inside the trusted scope.
    pub(crate) fn point(&self) -> Result<T::Point, Error> {
        if let Some(point) = self.point {
            return Ok(point);
        }
        let mut repr = <T::Point as GroupEncoding>::Repr::default();
        repr.as_mut().copy_from_slice(&self.bytes.bytes);
        Option::from(T::Point::from_bytes(&repr)).ok_or(Error::MalformedVerificationKey)
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
    ///
    /// # Panics
    ///
    /// Panics if this key was parsed inside
    /// [`with_trusted_encodings`](crate::trusted::with_trusted_encodings) from bytes that are not
    /// a canonical point encoding.
    pub fn randomize(&self, randomizer: &Randomizer<T>) -> VerificationKey<T> {
        let point = self
            .point()
            .expect("keys parsed in a trusted scope are canonical encodings")
            + (T::basepoint() * randomizer);
        let bytes = VerificationKeyBytes {
            bytes: point.to_bytes().as_ref().try_into().unwrap(),
            _marker: PhantomData,
        };
        VerificationKey {
            bytes,
            point: Some(point),
        }
    }
}

impl<T: SigType> VerificationKey<T> {
    pub(crate) fn from(s: &T::Scalar) -> VerificationKey<T> {
        let point = T::basepoint() * s;
        let bytes = VerificationKeyBytes {
            bytes: point.to_bytes().as_ref().try_into().unwrap(),
            _marker: PhantomData,
        };
        VerificationKey {
            bytes,
            point: Some(point),
        }
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
        // Decode the key first, so its error still takes precedence over the signature's.
        let a = self.point()?;
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
        let cA = a * c;
        let check = sB - cA - r;

        if check.is_small_order().into() {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}
