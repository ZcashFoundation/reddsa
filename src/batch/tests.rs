use super::*;
use crate::private::Sealed;
use group::Group;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;

fn verify<S: SpendAuth, B: Binding<Scalar = S::Scalar, Point = S::Point>>(
    items: &[Item<S, B>],
) -> (Result<(), Error>, u128) {
    let mut verifier = Verifier::new();
    for item in items {
        verifier.queue(item.clone());
    }
    let mut rng = ChaChaRng::from_seed([42; 32]);
    let result = verifier.verify(&mut rng);
    (result, rng.get_word_pos())
}

fn retained_keys_match_bytes<S: SpendAuth, B: Binding<Scalar = S::Scalar, Point = S::Point>>() {
    let mut rng = ChaChaRng::from_seed([73; 32]);
    let msg = b"canonical challenge";
    let mut retained = Vec::new();
    let mut encoded = Vec::new();
    for _ in 0..8 {
        let spend = SigningKey::<S>::new(&mut rng);
        let binding = SigningKey::<B>::new(&mut rng);
        let spend_key: VerificationKey<_> = (&spend).into();
        let binding_key: VerificationKey<_> = (&binding).into();
        let spend_sig = spend.sign(&mut rng, msg);
        let binding_sig = binding.sign(&mut rng, msg);
        retained.push(Item::<S, B>::from_spendauth_key(spend_key, spend_sig, msg));
        retained.push(Item::<S, B>::from_binding_key(
            binding_key,
            binding_sig,
            msg,
        ));
        encoded.push(Item::<S, B>::from_spendauth(
            spend_key.into(),
            spend_sig,
            msg,
        ));
        encoded.push(Item::<S, B>::from_binding(
            binding_key.into(),
            binding_sig,
            msg,
        ));
    }
    for n in [0, 1, 2, 8, 16] {
        assert_eq!(verify(&retained[..n]), verify(&encoded[..n]));
        assert_eq!(retained[..n].iter().flat_map(Item::point_encodings).count(), n);
        assert_eq!(
            encoded[..n].iter().flat_map(Item::point_encodings).count(),
            2 * n
        );
        assert_eq!(verify(&retained[..n]).0, Ok(()));
        let mixed: Vec<_> = retained[..n]
            .iter()
            .zip(&encoded[..n])
            .enumerate()
            .map(|(i, (key, bytes))| {
                if i % 2 == 0 {
                    key.clone()
                } else {
                    bytes.clone()
                }
            })
            .collect();
        assert_eq!(verify(&mixed), verify(&encoded[..n]));
        for index in 0..n {
            assert_eq!(retained[index].clone().verify_single(), Ok(()));
            for mutation in 0..4 {
                let mutate = |item: &mut Item<S, B>| {
                    let (sig, c) = match &mut item.inner {
                        Inner::SpendAuth { sig, c, .. } => (&mut sig.s_bytes, c),
                        Inner::Binding { sig, c, .. } => (&mut sig.s_bytes, c),
                    };
                    match mutation {
                        0 => sig.fill(0xff),
                        1 => *c += S::Scalar::ONE,
                        _ => match &mut item.inner {
                            Inner::SpendAuth { sig, vk, .. } => {
                                sig.r_bytes.fill(0xff);
                                if mutation == 3 {
                                    *vk = BatchKey::Bytes([0xff; 32].into());
                                }
                            }
                            Inner::Binding { sig, vk, .. } => {
                                sig.r_bytes.fill(0xff);
                                if mutation == 3 {
                                    *vk = BatchKey::Bytes([0xff; 32].into());
                                }
                            }
                        },
                    }
                };
                let mut keys = retained[..n].to_vec();
                let mut bytes = encoded[..n].to_vec();
                mutate(&mut keys[index]);
                mutate(&mut bytes[index]);
                assert_eq!(verify(&keys), verify(&bytes));
                assert_eq!(
                    keys[index].clone().verify_single(),
                    bytes[index].clone().verify_single()
                );
                assert!(verify(&keys).0.is_err());
            }
        }
    }
}

#[test]
fn redjubjub_retained_keys_match_bytes() {
    retained_keys_match_bytes::<sapling::SpendAuth, sapling::Binding>();
}

#[test]
fn redpallas_retained_keys_match_bytes() {
    retained_keys_match_bytes::<orchard::SpendAuth, orchard::Binding>();
}

#[test]
fn native_points_preserve_canonical_encodings_and_small_order_points() {
    use group::Group;
    for point in [
        pasta_curves::pallas::Point::identity(),
        pasta_curves::pallas::Point::generator(),
        -pasta_curves::pallas::Point::generator(),
    ] {
        let key: VerificationKey<orchard::Binding> = point.into();
        assert_eq!(key, VerificationKey::try_from(point.to_bytes()).unwrap());
        let spend = VerificationKey::<orchard::SpendAuth>::try_from(point.to_bytes()).unwrap();
        assert_eq!(pasta_curves::pallas::Point::from(spend), point);
    }
    let torsion = jubjub::AffinePoint::from_bytes([0; 32])
        .unwrap()
        .to_extended();
    for point in [
        jubjub::ExtendedPoint::identity(),
        torsion,
        sapling::SpendAuth::basepoint() + torsion,
    ] {
        let key: VerificationKey<sapling::Binding> = point.into();
        assert_eq!(key, VerificationKey::try_from(point.to_bytes()).unwrap());
        let spend = VerificationKey::<sapling::SpendAuth>::try_from(point.to_bytes()).unwrap();
        assert_eq!(jubjub::AffinePoint::from(spend).to_extended(), point);
    }
}

#[test]
fn retained_keys_preserve_jubjub_torsion_in_verification() {
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
        Item::<sapling::SpendAuth, sapling::Binding>::from_spendauth(
            bytes.into(),
            signature.into(),
            b"torsion",
        ),
        Item::from_spendauth_key(key, signature.into(), b"torsion"),
    ];
    for item in &items {
        assert_eq!(item.clone().verify_single(), Ok(()));
    }
    assert_eq!(verify(&items).0, Ok(()));
}

// Original per-point batch equation: all signatures, including the first, get random weights.
fn reference<S: SpendAuth, B: Binding<Scalar = S::Scalar, Point = S::Point>>(
    items: &[Item<S, B>],
) -> (Result<(), Error>, u128) {
    let mut rng = ChaChaRng::from_seed([42; 32]);
    let result = (|| {
        let mut check = S::Point::identity();
        for item in items {
            let (sig_s, sig_r, c, vk, basepoint) = match &item.inner {
                Inner::SpendAuth { sig, c, vk } => {
                    (sig.s_bytes, sig.r_bytes, *c, vk.bytes().bytes, S::basepoint())
                }
                Inner::Binding { sig, c, vk } => {
                    (sig.s_bytes, sig.r_bytes, *c, vk.bytes().bytes, B::basepoint())
                }
            };
            let mut repr = <S::Scalar as PrimeField>::Repr::default();
            repr.as_mut().copy_from_slice(&sig_s);
            let s = Option::<S::Scalar>::from(S::Scalar::from_repr(repr))
                .ok_or(Error::InvalidSignature)?;
            let mut repr = <S::Point as GroupEncoding>::Repr::default();
            repr.as_mut().copy_from_slice(&sig_r);
            let r = Option::<S::Point>::from(S::Point::from_bytes(&repr))
                .ok_or(Error::InvalidSignature)?;
            repr.as_mut().copy_from_slice(&vk);
            let vk = Option::<S::Point>::from(S::Point::from_bytes(&repr))
                .ok_or(Error::MalformedVerificationKey)?;
            let z = if items.len() == 1 {
                S::Scalar::ONE
            } else {
                S::Scalar::from_raw(gen_128_bits(&mut rng))
            };
            check += r * z + vk * (z * c) - basepoint * (z * s);
        }
        if bool::from(check.is_small_order()) {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    })();
    (result, rng.get_word_pos())
}

fn compare<S: SpendAuth, B: Binding<Scalar = S::Scalar, Point = S::Point>>(items: &[Item<S, B>]) {
    let mut verifier = Verifier::new();
    for item in items {
        verifier.queue(item.clone());
    }
    let mut rng = ChaChaRng::from_seed([42; 32]);
    let result = verifier.verify(&mut rng);
    let (original_result, original_words) = reference(items);
    assert_eq!(result, original_result);
    // The optimized verifier skips exactly the first random weight when it
    // reaches the first valid item; malformed first items consume none.
    let saved_words = if items.len() > 1 && original_words > 0 {
        4
    } else {
        0
    };
    assert_eq!(rng.get_word_pos(), original_words - saved_words);
}

fn batches_match_individual_decoding<
    S: SpendAuth,
    B: Binding<Scalar = S::Scalar, Point = S::Point>,
>() {
    let mut rng = ChaChaRng::from_seed([73; 32]);
    let msg = b"batch decoder differential";
    let mut items = Vec::new();
    for _ in 0..16 {
        let spend = SigningKey::<S>::new(&mut rng);
        let binding = SigningKey::<B>::new(&mut rng);
        let spend_key: VerificationKey<_> = (&spend).into();
        let binding_key: VerificationKey<_> = (&binding).into();
        items.push(Item::<S, B>::from_spendauth(
            spend_key.into(),
            spend.sign(&mut rng, msg),
            msg,
        ));
        items.push(Item::<S, B>::from_binding(
            binding_key.into(),
            binding.sign(&mut rng, msg),
            msg,
        ));
    }
    for n in [0, 1, 2, 8, 32] {
        compare(&items[..n]);
        for index in 0..n {
            for mutation in 0..6 {
                let mut changed = items[..n].to_vec();
                match &mut changed[index].inner {
                    Inner::SpendAuth { sig, c, vk } => match mutation {
                        0 => sig.r_bytes.fill(0xff),
                        1 => sig.s_bytes.fill(0xff),
                        2 => *vk = BatchKey::Bytes([0xff; 32].into()),
                        3 => {
                            *vk = BatchKey::Bytes([0xff; 32].into());
                            sig.r_bytes.fill(0xff);
                        }
                        4 => {
                            *vk = BatchKey::Bytes([0xff; 32].into());
                            sig.s_bytes.fill(0xff);
                        }
                        _ => *c += S::Scalar::ONE,
                    },
                    Inner::Binding { sig, c, vk } => match mutation {
                        0 => sig.r_bytes.fill(0xff),
                        1 => sig.s_bytes.fill(0xff),
                        2 => *vk = BatchKey::Bytes([0xff; 32].into()),
                        3 => {
                            *vk = BatchKey::Bytes([0xff; 32].into());
                            sig.r_bytes.fill(0xff);
                        }
                        4 => {
                            *vk = BatchKey::Bytes([0xff; 32].into());
                            sig.s_bytes.fill(0xff);
                        }
                        _ => *c += S::Scalar::ONE,
                    },
                }
                compare(&changed);
            }
        }
        if n > 1 {
            for reverse in [false, true] {
                let mut changed = items[..n].to_vec();
                let key_index = if reverse { n - 1 } else { 0 };
                let scalar_index = if reverse { 0 } else { n - 1 };
                match &mut changed[key_index].inner {
                    Inner::SpendAuth { vk, .. } => *vk = BatchKey::Bytes([0xff; 32].into()),
                    Inner::Binding { vk, .. } => *vk = BatchKey::Bytes([0xff; 32].into()),
                }
                match &mut changed[scalar_index].inner {
                    Inner::SpendAuth { sig, .. } => sig.s_bytes.fill(0xff),
                    Inner::Binding { sig, .. } => sig.s_bytes.fill(0xff),
                }
                compare(&changed);
            }
        }
    }
}

#[test]
fn redjubjub_batches_match_individual_decoding() {
    batches_match_individual_decoding::<sapling::SpendAuth, sapling::Binding>();
}

#[test]
fn redpallas_batch_weights_match_original_for_random_signatures() {
    batches_match_individual_decoding::<orchard::SpendAuth, orchard::Binding>();
}

#[test]
fn jubjub_batch_decoding_preserves_zip216_and_torsion() {
    let mut rng = ChaChaRng::from_seed([91; 32]);
    let torsion = jubjub::AffinePoint::from_bytes([0; 32])
        .unwrap()
        .to_extended();
    let mut encodings = vec![
        [0xff; 32],
        jubjub::AffinePoint::identity().to_bytes(),
        jubjub::AffinePoint::from_raw_unchecked(jubjub::Fq::zero(), -jubjub::Fq::one()).to_bytes(),
        torsion.to_bytes(),
        (sapling::SpendAuth::basepoint() + torsion).to_bytes(),
    ];
    // ZIP 216 forbids a set sign bit when u is zero, for both v = +/-1.
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
    for n in [0, 1, 2, 7, 8, 9, 16, 33, encodings.len()] {
        let decoded =
            sapling::SpendAuth::batch_decode_points(encodings[..n].iter().copied()).unwrap();
        assert_eq!(decoded.len(), n);
        for (bytes, point) in encodings[..n].iter().zip(decoded) {
            assert_eq!(
                point,
                Option::<jubjub::ExtendedPoint>::from(jubjub::ExtendedPoint::from_bytes(bytes))
            );
        }
    }
}

#[test]
fn pallas_batch_decoding_matches_individual_points() {
    use pasta_curves::pallas;

    let mut rng = ChaChaRng::from_seed([73; 32]);
    for n in [0, 1, 2, 7, 8, 9, 15, 16, 17, 33, 66, 258] {
        let encodings: Vec<_> = (0..n)
            .map(|i| match i % 5 {
                0 => pallas::Point::random(&mut rng).to_bytes(),
                1 => [0; 32],
                2 => [0xff; 32],
                3 => {
                    let mut bytes = [0; 32];
                    bytes[31] = 0x80; // Noncanonical signed identity.
                    bytes
                }
                _ => {
                    let mut bytes = [0; 32];
                    rng.fill_bytes(&mut bytes);
                    bytes
                }
            })
            .collect();
        let expected: Vec<_> = encodings
            .iter()
            .map(|bytes| Option::<pallas::Point>::from(pallas::Point::from_bytes(bytes)))
            .collect();
        let check = || {
            assert_eq!(
                orchard::SpendAuth::batch_decode_points(encodings.iter().copied()).unwrap(),
                expected
            );
            assert_eq!(
                orchard::Binding::batch_decode_points(encodings.iter().copied()).unwrap(),
                expected
            );
        };
        check();
        #[cfg(feature = "multicore")]
        for threads in [1, 2, 4, 8] {
            maybe_rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap()
                .install(check);
        }
    }
}
