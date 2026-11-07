use super::*;
use crate::private::Sealed;
use group::Group;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;

// Independent per-point decoding and group arithmetic, preserving main's random weights.
fn reference<S: SpendAuth, B: Binding<Scalar = S::Scalar, Point = S::Point>>(
    items: &[Item<S, B>],
) -> (Result<(), Error>, u128) {
    let mut rng = ChaChaRng::from_seed([42; 32]);
    let result = (|| {
        let mut check = S::Point::identity();
        for item in items {
            let (sig_s, sig_r, c, vk, basepoint) = match &item.inner {
                Inner::SpendAuth { sig, c, vk_bytes } => {
                    (sig.s_bytes, sig.r_bytes, *c, vk_bytes.bytes, S::basepoint())
                }
                Inner::Binding { sig, c, vk_bytes } => {
                    (sig.s_bytes, sig.r_bytes, *c, vk_bytes.bytes, B::basepoint())
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
            let z = S::Scalar::from_raw(gen_128_bits(&mut rng));
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
    assert_eq!((result, rng.get_word_pos()), reference(items));
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
                    Inner::SpendAuth { sig, c, vk_bytes } => match mutation {
                        0 => sig.r_bytes.fill(0xff),
                        1 => sig.s_bytes.fill(0xff),
                        2 => vk_bytes.bytes.fill(0xff),
                        3 => {
                            vk_bytes.bytes.fill(0xff);
                            sig.r_bytes.fill(0xff);
                        }
                        4 => {
                            vk_bytes.bytes.fill(0xff);
                            sig.s_bytes.fill(0xff);
                        }
                        _ => *c += S::Scalar::ONE,
                    },
                    Inner::Binding { sig, c, vk_bytes } => match mutation {
                        0 => sig.r_bytes.fill(0xff),
                        1 => sig.s_bytes.fill(0xff),
                        2 => vk_bytes.bytes.fill(0xff),
                        3 => {
                            vk_bytes.bytes.fill(0xff);
                            sig.r_bytes.fill(0xff);
                        }
                        4 => {
                            vk_bytes.bytes.fill(0xff);
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
                    Inner::SpendAuth { vk_bytes, .. } => vk_bytes.bytes.fill(0xff),
                    Inner::Binding { vk_bytes, .. } => vk_bytes.bytes.fill(0xff),
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
fn redpallas_batches_match_individual_decoding() {
    batches_match_individual_decoding::<orchard::SpendAuth, orchard::Binding>();
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
