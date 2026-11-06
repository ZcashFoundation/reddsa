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
mod tests {
    use super::*;
    use crate::private::Sealed;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    type SaplingItem = Item<sapling::SpendAuth, sapling::Binding>;

    #[test]
    fn retained_keys_are_omitted_from_batch_decoding() {
        let bytes = jubjub::AffinePoint::identity().to_bytes();
        let key = VerificationKey::<sapling::Binding>::try_from(bytes).unwrap();
        let sig = Signature::from([42; 64]);
        let retained = SaplingItem::from_binding_key(key, sig, b"message");
        let encoded = SaplingItem::from_binding(key.into(), sig, b"message");
        let spend = SaplingItem::from_spendauth(bytes.into(), [43; 64].into(), b"message");
        let spend_key = VerificationKey::<sapling::SpendAuth>::try_from(bytes).unwrap();
        let retained_spend =
            SaplingItem::from_spendauth_key(spend_key, [44; 64].into(), b"message");
        let encodings: Vec<_> = [retained, encoded, spend, retained_spend]
            .iter()
            .flat_map(Item::point_encodings)
            .collect();
        assert_eq!(
            encodings,
            [[42; 32], [42; 32], bytes, [43; 32], bytes, [44; 32]]
        );
        // Retaining a native point should not require boxing or a large stack item.
        assert!(core::mem::size_of::<SaplingItem>() <= 320);
    }

    #[test]
    fn batch_decoding_matches_individual_decoding_including_zip216() {
        let mut rng = ChaChaRng::from_seed([91; 32]);
        let mut encodings = vec![[0xff; 32], jubjub::AffinePoint::identity().to_bytes()];
        let minus_one =
            jubjub::AffinePoint::from_raw_unchecked(jubjub::Fq::zero(), -jubjub::Fq::one());
        encodings.push(minus_one.to_bytes());
        // ZIP 216 rejects a set sign bit when u is zero, for both v = +/-1.
        for mut bytes in [encodings[1], encodings[2]] {
            bytes[31] |= 0x80;
            assert!(bool::from(
                jubjub::ExtendedPoint::from_bytes(&bytes).is_none()
            ));
            encodings.push(bytes);
        }
        for _ in 0..256 {
            let mut bytes = [0; 32];
            rng.fill_bytes(&mut bytes);
            encodings.push(bytes);
        }
        let decoded = sapling::SpendAuth::batch_decode_points(encodings.iter().copied()).unwrap();
        for (bytes, batch_point) in encodings.into_iter().zip(decoded) {
            assert_eq!(
                batch_point,
                Option::<jubjub::ExtendedPoint>::from(jubjub::ExtendedPoint::from_bytes(&bytes))
            );
        }
    }

    #[test]
    fn retained_and_byte_keys_preserve_nontrivial_torsion_components() {
        // The canonical v = 0 encoding is an order-four point on Jubjub.
        let torsion = jubjub::AffinePoint::from_bytes([0; 32])
            .unwrap()
            .to_extended();
        let secret = jubjub::Scalar::from(7);
        let nonce = jubjub::Scalar::from(11);
        let point = sapling::SpendAuth::basepoint() * secret + torsion;
        let bytes = point.to_bytes();
        let key = VerificationKey::<sapling::SpendAuth>::try_from(bytes).unwrap();
        let r_bytes = (sapling::SpendAuth::basepoint() * nonce + torsion).to_bytes();
        let c = HStar::<sapling::SpendAuth>::default()
            .update(r_bytes)
            .update(bytes)
            .update(b"torsion")
            .finalize();
        let mut signature = [0; 64];
        signature[..32].copy_from_slice(&r_bytes);
        signature[32..].copy_from_slice(&(nonce + c * secret).to_bytes());
        let items = [
            SaplingItem::from_spendauth(bytes.into(), signature.into(), b"torsion"),
            SaplingItem::from_spendauth_key(key, signature.into(), b"torsion"),
        ];
        for item in &items {
            assert_eq!(item.clone().verify_single(), Ok(()));
        }
        assert_eq!(legacy_verify(&items), Ok(()));
        let mut verifier = Verifier::new();
        for item in items {
            verifier.queue(item);
        }
        assert_eq!(verifier.verify(ChaChaRng::from_seed([42; 32])), Ok(()));
    }

    // Original per-point decoding and arithmetic, without the batch decoder or MSM.
    fn legacy_verify(items: &[SaplingItem]) -> Result<(), Error> {
        let mut rng = ChaChaRng::from_seed([42; 32]);
        let mut check = jubjub::ExtendedPoint::identity();
        for item in items {
            let (s_bytes, r_bytes, c, basepoint, bytes) = match &item.inner {
                Inner::SpendAuth { vk, sig, c } => (
                    sig.s_bytes,
                    sig.r_bytes,
                    *c,
                    sapling::SpendAuth::basepoint(),
                    vk.bytes().bytes,
                ),
                Inner::Binding { vk, sig, c } => (
                    sig.s_bytes,
                    sig.r_bytes,
                    *c,
                    sapling::Binding::basepoint(),
                    vk.bytes().bytes,
                ),
            };
            let s = Option::<jubjub::Scalar>::from(jubjub::Scalar::from_repr(s_bytes))
                .ok_or(Error::InvalidSignature)?;
            let r =
                Option::<jubjub::ExtendedPoint>::from(jubjub::ExtendedPoint::from_bytes(&r_bytes))
                    .ok_or(Error::InvalidSignature)?;
            let vk =
                Option::<jubjub::ExtendedPoint>::from(jubjub::ExtendedPoint::from_bytes(&bytes))
                    .ok_or(Error::MalformedVerificationKey)?;
            let z = if items.len() == 1 {
                jubjub::Scalar::ONE
            } else {
                jubjub::Scalar::from_raw(gen_128_bits(&mut rng))
            };
            check += r * z + vk * (z * c) - basepoint * (z * s);
        }
        if bool::from(check.is_small_order()) {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }

    #[test]
    fn mixed_retained_and_byte_keys_match_legacy_arithmetic() {
        let mut rng = ChaChaRng::from_seed([73; 32]);
        let msg = b"retained key differential";
        let mut items = Vec::new();
        for i in 0..16 {
            let spend = SigningKey::<sapling::SpendAuth>::new(&mut rng);
            let binding = SigningKey::<sapling::Binding>::new(&mut rng);
            let spend_key: VerificationKey<_> = (&spend).into();
            let binding_key: VerificationKey<_> = (&binding).into();
            let spend_sig = spend.sign(&mut rng, msg);
            let binding_sig = binding.sign(&mut rng, msg);
            items.push(if i % 2 == 0 {
                SaplingItem::from_spendauth_key(spend_key, spend_sig, msg)
            } else {
                SaplingItem::from_spendauth(spend_key.into(), spend_sig, msg)
            });
            items.push(if i % 2 == 0 {
                SaplingItem::from_binding(binding_key.into(), binding_sig, msg)
            } else {
                SaplingItem::from_binding_key(binding_key, binding_sig, msg)
            });
        }
        let compare = |items: &[SaplingItem]| {
            let mut verifier = Verifier::new();
            for item in items {
                verifier.queue(item.clone());
            }
            assert_eq!(
                verifier.verify(ChaChaRng::from_seed([42; 32])),
                legacy_verify(items)
            );
        };
        compare(&[]);
        for n in [1, 2, 8, 32] {
            compare(&items[..n]);
            for index in [0, n - 1] {
                // Exercise malformed R, noncanonical s, bad keys, and an
                // algebraically invalid signature at both ends of each batch.
                for mutation in 0..5 {
                    let mut changed = items[..n].to_vec();
                    match &mut changed[index].inner {
                        Inner::SpendAuth { vk, sig, c } => match mutation {
                            0 => sig.r_bytes.fill(0xff),
                            1 => sig.s_bytes.fill(0xff),
                            2 => *vk = BatchKey::Bytes([0xff; 32].into()),
                            3 => {
                                *vk = BatchKey::Bytes([0xff; 32].into());
                                sig.r_bytes.fill(0xff);
                            }
                            _ => *c += jubjub::Scalar::ONE,
                        },
                        Inner::Binding { vk, sig, c } => match mutation {
                            0 => sig.r_bytes.fill(0xff),
                            1 => sig.s_bytes.fill(0xff),
                            2 => *vk = BatchKey::Bytes([0xff; 32].into()),
                            3 => {
                                *vk = BatchKey::Bytes([0xff; 32].into());
                                sig.r_bytes.fill(0xff);
                            }
                            _ => *c += jubjub::Scalar::ONE,
                        },
                    }
                    compare(&changed);
                }
            }
        }
    }
}
