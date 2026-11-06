// -*- mode: rust; -*-
//
// This file is part of reddsa.
// Copyright (c) 2019-2021 Zcash Foundation
// See LICENSE for licensing information.
//
// Authors:
// - Deirdre Connolly <deirdre@zfnd.org>
// - Henry de Valence <hdevalence@hdevalence.ca>

//! Performs batch RedDSA signature verification.
//!
//! Batch verification asks whether *all* signatures in some set are valid,
//! rather than asking whether *each* of them is valid. This allows sharing
//! computations among all signature verifications, performing less work overall
//! at the cost of higher latency (the entire batch must complete), complexity of
//! caller code (which must assemble a batch of signatures across work-items),
//! and loss of the ability to easily pinpoint failing signatures.
//!

use alloc::vec::Vec;
use core::convert::TryFrom;

use group::{
    cofactor::CofactorGroup,
    ff::{Field, PrimeField},
    GroupEncoding,
};
use rand_core::{CryptoRng, Rng};

use crate::{private::SealedScalar, scalar_mul::VartimeMultiscalarMul, *};

/// Shim to generate a random 128 bit value in a `[u64; 4]`, without
/// importing `rand`.
///
/// The final 128 bits are zero.
fn gen_128_bits<R: Rng + CryptoRng>(mut rng: R) -> [u64; 4] {
    let mut bytes = [0u64; 4];
    bytes[0] = rng.next_u64();
    bytes[1] = rng.next_u64();
    bytes
}

/// Retain native keys without allocating or discarding their canonical bytes.
#[derive(Copy, Clone, Debug)]
enum BatchKey<T: SigType> {
    Bytes(VerificationKeyBytes<T>),
    Key(VerificationKey<T>),
}

impl<T: SigType> BatchKey<T> {
    fn bytes(&self) -> VerificationKeyBytes<T> {
        match self {
            Self::Bytes(bytes) => *bytes,
            Self::Key(key) => key.bytes,
        }
    }

    fn encoding(&self) -> Option<[u8; 32]> {
        match self {
            Self::Bytes(bytes) => Some(bytes.bytes),
            Self::Key(_) => None,
        }
    }

    fn into_key(self) -> Result<VerificationKey<T>, Error> {
        match self {
            Self::Bytes(bytes) => VerificationKey::try_from(bytes),
            Self::Key(key) => Ok(key),
        }
    }
}

/// Inner type of a batch verification item.
///
/// This struct exists to allow batch processing to be decoupled from the
/// lifetime of the message. This is useful when using the batch verification
/// API in an async context
///
/// The different enum variants are for the different signature types which use
/// different basepoints for computation: SpendAuth and Binding signatures.
#[derive(Clone, Debug)]
enum Inner<S: SpendAuth, B: Binding<Scalar = S::Scalar, Point = S::Point>> {
    /// A RedDSA signature using the SpendAuth generator group element.
    SpendAuth {
        vk: BatchKey<S>,
        sig: Signature<S>,
        c: S::Scalar,
    },
    /// A RedDSA signature using the Binding generator group element.
    Binding {
        vk: BatchKey<B>,
        sig: Signature<B>,
        c: B::Scalar,
    },
}

/// A batch verification item.
///
/// This struct exists to allow batch processing to be decoupled from the
/// lifetime of the message. This is useful when using the batch verification API
/// in an async context.
#[derive(Clone, Debug)]
pub struct Item<S: SpendAuth, B: Binding<Scalar = S::Scalar, Point = S::Point>> {
    inner: Inner<S, B>,
}

impl<S: SpendAuth, B: Binding<Scalar = S::Scalar, Point = S::Point>> Item<S, B> {
    /// Create a batch item from a `SpendAuth` signature.
    pub fn from_spendauth<M: AsRef<[u8]>>(
        vk_bytes: VerificationKeyBytes<S>,
        sig: Signature<S>,
        msg: &M,
    ) -> Self {
        Self::spendauth(BatchKey::Bytes(vk_bytes), sig, msg)
    }

    /// Creates an item retaining an existing spend authorization key's point.
    ///
    /// The challenge still hashes the key's canonical encoding.
    pub fn from_spendauth_key<M: AsRef<[u8]>>(
        vk: VerificationKey<S>,
        sig: Signature<S>,
        msg: &M,
    ) -> Self {
        Self::spendauth(BatchKey::Key(vk), sig, msg)
    }

    fn spendauth<M: AsRef<[u8]>>(vk: BatchKey<S>, sig: Signature<S>, msg: &M) -> Self {
        // Compute c now to avoid dependency on the msg lifetime.
        let c = HStar::<S>::default()
            .update(&sig.r_bytes[..])
            .update(&vk.bytes().bytes[..])
            .update(msg)
            .finalize();
        Self {
            inner: Inner::SpendAuth { vk, sig, c },
        }
    }

    /// Create a batch item from a `Binding` signature.
    pub fn from_binding<M: AsRef<[u8]>>(
        vk_bytes: VerificationKeyBytes<B>,
        sig: Signature<B>,
        msg: &M,
    ) -> Self {
        Self::binding(BatchKey::Bytes(vk_bytes), sig, msg)
    }

    /// Creates an item retaining an existing binding key's point.
    ///
    /// The challenge still hashes the key's canonical encoding.
    pub fn from_binding_key<M: AsRef<[u8]>>(
        vk: VerificationKey<B>,
        sig: Signature<B>,
        msg: &M,
    ) -> Self {
        Self::binding(BatchKey::Key(vk), sig, msg)
    }

    fn binding<M: AsRef<[u8]>>(vk: BatchKey<B>, sig: Signature<B>, msg: &M) -> Self {
        // Compute c now to avoid dependency on the msg lifetime.
        let c = HStar::<B>::default()
            .update(&sig.r_bytes[..])
            .update(&vk.bytes().bytes[..])
            .update(msg)
            .finalize();
        Self {
            inner: Inner::Binding { vk, sig, c },
        }
    }

    /// Only byte-based keys still need decoding; every signature needs its R.
    fn point_encodings(&self) -> impl Iterator<Item = [u8; 32]> {
        let (r, vk) = match &self.inner {
            Inner::SpendAuth { sig, vk, .. } => (sig.r_bytes, vk.encoding()),
            Inner::Binding { sig, vk, .. } => (sig.r_bytes, vk.encoding()),
        };
        [Some(r), vk].into_iter().flatten()
    }

    /// Perform non-batched verification of this `Item`.
    ///
    /// This is useful (in combination with `Item::clone`) for implementing fallback
    /// logic when batch verification fails. In contrast to
    /// [`VerificationKey::verify`](crate::VerificationKey::verify), which requires
    /// borrowing the message data, the `Item` type is unlinked from the lifetime of
    /// the message.
    #[allow(non_snake_case)]
    pub fn verify_single(self) -> Result<(), Error> {
        match self.inner {
            Inner::Binding { vk, sig, c } => {
                vk.into_key().and_then(|vk| vk.verify_prehashed(&sig, c))
            }
            Inner::SpendAuth { vk, sig, c } => {
                vk.into_key().and_then(|vk| vk.verify_prehashed(&sig, c))
            }
        }
    }
}

/// A batch verification context.
pub struct Verifier<S: SpendAuth, B: Binding<Scalar = S::Scalar, Point = S::Point>> {
    /// Signature data queued for verification.
    signatures: Vec<Item<S, B>>,
}

impl<S: SpendAuth, B: Binding<Scalar = S::Scalar, Point = S::Point>> Default for Verifier<S, B> {
    fn default() -> Self {
        Verifier { signatures: vec![] }
    }
}

impl<S: SpendAuth, B: Binding<Scalar = S::Scalar, Point = S::Point>> Verifier<S, B> {
    /// Construct a new batch verifier.
    pub fn new() -> Verifier<S, B> {
        Verifier::default()
    }

    /// Queue an Item for verification.
    pub fn queue<I: Into<Item<S, B>>>(&mut self, item: I) {
        self.signatures.push(item.into());
    }

    /// Perform batch verification, returning `Ok(())` if all signatures were
    /// valid and `Err` otherwise.
    ///
    /// Empty batches succeed immediately. Empty and single-signature batches
    /// do not consume randomness.
    ///
    /// The batch verification equation is:
    ///
    /// h_G * ( -[sum(z_i * s_i)]P_G + sum(\[z_i\]R_i) + sum([z_i * c_i]VK_i) ) = 0_G
    ///
    /// as given in https://zips.z.cash/protocol/protocol.pdf#reddsabatchvalidate
    /// (the terms are split out so that we can use multiscalar multiplication speedups).
    ///
    /// where for each signature i,
    /// - VK_i is the verification key;
    /// - R_i is the signature's R value;
    /// - s_i is the signature's s value;
    /// - c_i is the hash of the message and other data;
    /// - z_i is a random 128-bit Scalar;
    /// - h_G is the cofactor of the group;
    /// - P_G is the generator of the subgroup;
    ///
    /// Since RedDSA uses different subgroups for different types
    /// of signatures, SpendAuth's and Binding's, we need to have yet
    /// another point and associated scalar accumulator for all the
    /// signatures of each type in our batch, but we can still
    /// amortize computation nicely in one multiscalar multiplication:
    ///
    /// h_G * ( [-sum(z_i * s_i): i_type == SpendAuth]P_SpendAuth + [-sum(z_i * s_i): i_type == Binding]P_Binding + sum(\[z_i\]R_i) + sum([z_i * c_i]VK_i) ) = 0_G
    ///
    /// As follows elliptic curve scalar multiplication convention,
    /// scalar variables are lowercase and group point variables
    /// are uppercase. This does not exactly match the RedDSA
    /// notation in the [protocol specification §B.1][ps].
    ///
    /// [ps]: https://zips.z.cash/protocol/protocol.pdf#reddsabatchverify
    #[allow(non_snake_case)]
    pub fn verify<R: Rng + CryptoRng>(self, mut rng: R) -> Result<(), Error> {
        // https://p.z.cash/TCR:bad-txns-orchard-binding-signature-invalid?partial
        let n = self.signatures.len();

        if n == 0 {
            return Ok(());
        }

        // The single-signature path does not use the batch accumulators.
        let capacity = if n == 1 { 0 } else { n };
        let mut VK_coeffs = Vec::with_capacity(capacity);
        let mut VKs = Vec::with_capacity(capacity);
        let mut R_coeffs = Vec::with_capacity(capacity);
        let mut Rs = Vec::with_capacity(capacity);
        let mut P_spendauth_coeff = S::Scalar::ZERO;
        let mut P_binding_coeff = B::Scalar::ZERO;

        // Decode eagerly but consume results only in the original scalar/R/key
        // validation order for both RedPallas and RedJubjub.
        let mut decoded_points = if n > 1 {
            S::batch_decode_points(self.signatures.iter().flat_map(Item::point_encodings))
                .map(|points| points.into_iter())
        } else {
            None
        };

        for item in self.signatures.iter() {
            let (s_bytes, r_bytes, c) = match item.inner {
                Inner::SpendAuth { sig, c, .. } => (sig.s_bytes, sig.r_bytes, c),
                Inner::Binding { sig, c, .. } => (sig.s_bytes, sig.r_bytes, c),
            };

            let s = {
                // XXX-jubjub: should not use CtOption here
                let mut repr = <S::Scalar as PrimeField>::Repr::default();
                repr.as_mut().copy_from_slice(&s_bytes);
                let maybe_scalar = S::Scalar::from_repr(repr);
                if maybe_scalar.is_some().into() {
                    maybe_scalar.unwrap()
                } else {
                    return Err(Error::InvalidSignature);
                }
            };

            let R = if let Some(points) = decoded_points.as_mut() {
                points
                    .next()
                    .expect("one decoded result per encoding")
                    .ok_or(Error::InvalidSignature)?
            } else {
                // XXX-jubjub: should not use CtOption here
                // XXX-jubjub: inconsistent ownership in from_bytes
                let mut repr = <S::Point as GroupEncoding>::Repr::default();
                repr.as_mut().copy_from_slice(&r_bytes);
                Option::<S::Point>::from(S::Point::from_bytes(&repr))
                    .ok_or(Error::InvalidSignature)?
            };

            let VK = match item.inner {
                Inner::SpendAuth {
                    vk: BatchKey::Key(key),
                    ..
                } => key.point,
                Inner::Binding {
                    vk: BatchKey::Key(key),
                    ..
                } => key.point,
                _ => {
                    if let Some(points) = decoded_points.as_mut() {
                        points
                            .next()
                            .expect("one decoded result per encoding")
                            .ok_or(Error::MalformedVerificationKey)?
                    } else {
                        match item.inner {
                            Inner::SpendAuth { vk, .. } => vk.into_key()?.point,
                            Inner::Binding { vk, .. } => vk.into_key()?.point,
                        }
                    }
                }
            };

            if n == 1 {
                // Unlike Item::verify_single, retain the batch decoding order
                // above so malformed signatures take precedence over bad keys.
                let basepoint = match item.inner {
                    Inner::SpendAuth { .. } => S::basepoint(),
                    Inner::Binding { .. } => B::basepoint(),
                };
                // No random weighting is needed for one signature. Scalar
                // negation can add torsion for a non-prime-order key; the
                // small-order check below ignores that component.
                let check = S::Point::vartime_multiscalar_mul([s, -c], [basepoint, VK]) - R;
                return if check.is_small_order().into() {
                    Ok(())
                } else {
                    Err(Error::InvalidSignature)
                };
            }

            let z = S::Scalar::from_raw(gen_128_bits(&mut rng));

            let P_coeff = z * s;
            match item.inner {
                Inner::SpendAuth { .. } => {
                    P_spendauth_coeff -= P_coeff;
                }
                Inner::Binding { .. } => {
                    P_binding_coeff -= P_coeff;
                }
            };

            R_coeffs.push(z);
            Rs.push(R);

            VK_coeffs.push(S::Scalar::ZERO + (z * c));
            VKs.push(VK);
        }

        use core::iter::once;

        let scalars = once(&P_spendauth_coeff)
            .chain(once(&P_binding_coeff))
            .chain(VK_coeffs.iter())
            .chain(R_coeffs.iter());

        let basepoints = [S::basepoint(), B::basepoint()];
        let points = basepoints.iter().chain(VKs.iter()).chain(Rs.iter());

        let check = S::Point::vartime_multiscalar_mul(scalars, points);

        if check.is_small_order().into() {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

#[cfg(test)]
mod tests;
