#![cfg(feature = "alloc")]

use rand::rng as thread_rng;
use rand_chacha::ChaChaRng;
use rand_core::{Rng, SeedableRng};

use reddsa::*;

#[test]
fn spendauth_batch_verify() {
    let mut rng = thread_rng();
    let mut batch = batch::Verifier::<_, sapling::Binding>::new();
    for _ in 0..32 {
        let sk = SigningKey::<sapling::SpendAuth>::new(&mut rng);
        let vk = VerificationKey::from(&sk);
        let msg = b"BatchVerifyTest";
        let sig = sk.sign(&mut rng, &msg[..]);
        batch.queue(batch::Item::from_spendauth(vk.into(), sig, msg));
    }
    assert!(batch.verify(rng).is_ok());
}

#[test]
fn binding_batch_verify() {
    let mut rng = thread_rng();
    let mut batch = batch::Verifier::<sapling::SpendAuth, _>::new();
    for _ in 0..32 {
        let sk = SigningKey::<sapling::Binding>::new(&mut rng);
        let vk = VerificationKey::from(&sk);
        let msg = b"BatchVerifyTest";
        let sig = sk.sign(&mut rng, &msg[..]);
        batch.queue(batch::Item::from_binding(vk.into(), sig, msg));
    }
    assert!(batch.verify(rng).is_ok());
}

#[test]
fn alternating_batch_verify() {
    let mut rng = thread_rng();
    let mut batch = batch::Verifier::new();
    for i in 0..32 {
        let item = match i % 2 {
            0 => {
                let sk = SigningKey::<sapling::SpendAuth>::new(&mut rng);
                let vk = VerificationKey::from(&sk);
                let msg = b"BatchVerifyTest";
                let sig = sk.sign(&mut rng, &msg[..]);
                batch::Item::from_spendauth(vk.into(), sig, msg)
            }
            1 => {
                let sk = SigningKey::<sapling::Binding>::new(&mut rng);
                let vk = VerificationKey::from(&sk);
                let msg = b"BatchVerifyTest";
                let sig = sk.sign(&mut rng, &msg[..]);
                batch::Item::from_binding(vk.into(), sig, msg)
            }
            _ => unreachable!(),
        };
        batch.queue(item);
    }
    assert!(batch.verify(rng).is_ok());
}

#[test]
fn bad_batch_verify() {
    let mut rng = thread_rng();
    let bad_index = 4; // must be even
    let mut batch = batch::Verifier::new();
    let mut items = Vec::new();
    for i in 0..32 {
        let item = match i % 2 {
            0 => {
                let sk = SigningKey::<sapling::SpendAuth>::new(&mut rng);
                let vk = VerificationKey::from(&sk);
                let msg = b"BatchVerifyTest";
                let sig = if i != bad_index {
                    sk.sign(&mut rng, &msg[..])
                } else {
                    sk.sign(&mut rng, b"bad")
                };
                batch::Item::from_spendauth(vk.into(), sig, msg)
            }
            1 => {
                let sk = SigningKey::<sapling::Binding>::new(&mut rng);
                let vk = VerificationKey::from(&sk);
                let msg = b"BatchVerifyTest";
                let sig = sk.sign(&mut rng, &msg[..]);
                batch::Item::from_binding(vk.into(), sig, msg)
            }
            _ => unreachable!(),
        };
        items.push(item.clone());
        batch.queue(item);
    }
    assert!(batch.verify(rng).is_err());
    for (i, item) in items.drain(..).enumerate() {
        if i != bad_index {
            assert!(item.verify_single().is_ok());
        } else {
            assert!(item.verify_single().is_err());
        }
    }
}

fn verify_batch<S, B>(items: &[batch::Item<S, B>]) -> (Result<(), Error>, u128)
where
    S: SpendAuth,
    B: Binding<Scalar = S::Scalar, Point = S::Point>,
{
    let mut verifier = batch::Verifier::new();
    for item in items {
        verifier.queue(item.clone());
    }
    let mut rng = ChaChaRng::from_seed([42; 32]);
    let result = verifier.verify(&mut rng);
    (result, rng.get_word_pos())
}

fn check_item<S, B>(item: batch::Item<S, B>, expected: Result<(), Error>)
where
    S: SpendAuth,
    B: Binding<Scalar = S::Scalar, Point = S::Point>,
{
    assert_eq!(item.clone().verify_single(), expected);
    assert_eq!(verify_batch(core::slice::from_ref(&item)), (expected, 0));
    // Two copies exercise the unchanged randomized batch equation.
    assert_eq!(verify_batch(&[item.clone(), item]).0, expected);
}

fn check_batches<S, B>()
where
    S: SpendAuth,
    B: Binding<Scalar = S::Scalar, Point = S::Point>,
{
    assert_eq!(verify_batch::<S, B>(&[]), (Ok(()), 0));

    let mut rng = ChaChaRng::from_seed([7; 32]);
    let mut valid_items = Vec::new();
    let mut invalid_items = Vec::new();
    for _ in 0..16 {
        let mut msg = [0; 32];
        rng.fill_bytes(&mut msg);
        let spend_sk = SigningKey::<S>::new(&mut rng);
        let binding_sk = SigningKey::<B>::new(&mut rng);
        let signatures: [(bool, [u8; 32], [u8; 64]); 2] = [
            (
                false,
                VerificationKey::from(&spend_sk).into(),
                spend_sk.sign(&mut rng, &msg).into(),
            ),
            (
                true,
                VerificationKey::from(&binding_sk).into(),
                binding_sk.sign(&mut rng, &msg).into(),
            ),
        ];
        for (binding, vk, sig) in signatures {
            let make_item = |vk: [u8; 32], sig: [u8; 64], msg: &[u8]| {
                if binding {
                    batch::Item::<S, B>::from_binding(vk.into(), sig.into(), &msg)
                } else {
                    batch::Item::<S, B>::from_spendauth(vk.into(), sig.into(), &msg)
                }
            };
            let valid = make_item(vk, sig, &msg);
            check_item(valid.clone(), Ok(()));
            valid_items.push(valid);
            let invalid = make_item(vk, sig, b"wrong message");
            check_item(invalid.clone(), Err(Error::InvalidSignature));
            invalid_items.push(invalid);

            let mut bad_s = sig;
            bad_s[32..].fill(0xff);
            let mut bad_r = sig;
            bad_r[..32].fill(0xff);
            check_item(make_item(vk, bad_s, &msg), Err(Error::InvalidSignature));
            check_item(make_item(vk, bad_r, &msg), Err(Error::InvalidSignature));
            check_item(
                make_item([0xff; 32], sig, &msg),
                Err(Error::MalformedVerificationKey),
            );

            // Batch decoding checks the signature before the key, unlike
            // verify_single. Preserve that precedence when both are malformed.
            for bad_sig in [bad_s, bad_r, [0xff; 64]] {
                let item = make_item([0xff; 32], bad_sig, &msg);
                assert_eq!(
                    item.clone().verify_single(),
                    Err(Error::MalformedVerificationKey)
                );
                assert_eq!(
                    verify_batch(core::slice::from_ref(&item)),
                    (Err(Error::InvalidSignature), 0)
                );
                assert_eq!(
                    verify_batch(&[item.clone(), item]),
                    (Err(Error::InvalidSignature), 0)
                );
            }
        }
    }

    for n in [2, 8, 32] {
        // Each random 128-bit weight consumes four ChaCha u32 words.
        let words = u128::try_from(n).unwrap() * 4;
        assert_eq!(verify_batch(&valid_items[..n]), (Ok(()), words));
        for bad_index in [0, n - 1] {
            let mut items = valid_items[..n].to_vec();
            items[bad_index] = invalid_items[bad_index].clone();
            assert_eq!(verify_batch(&items), (Err(Error::InvalidSignature), words));
        }
    }
}

#[test]
fn sapling_small_batches_match_single_verification() {
    check_batches::<sapling::SpendAuth, sapling::Binding>();
}

#[test]
fn orchard_small_batches_match_single_verification() {
    check_batches::<orchard::SpendAuth, orchard::Binding>();
}

fn check_small_order<S, B>(points: &[[u8; 32]])
where
    S: SpendAuth,
    B: Binding<Scalar = S::Scalar, Point = S::Point>,
{
    for &vk in points {
        for r in points {
            let mut sig = [0; 64];
            sig[..32].copy_from_slice(r);
            for (s, expected) in [(0, Ok(())), (1, Err(Error::InvalidSignature))] {
                sig[32] = s;
                check_item(
                    batch::Item::<S, B>::from_spendauth(vk.into(), sig.into(), b"small order"),
                    expected,
                );
                check_item(
                    batch::Item::<S, B>::from_binding(vk.into(), sig.into(), b"small order"),
                    expected,
                );
            }
        }
    }
}

#[test]
fn sapling_small_batches_preserve_cofactor_checks() {
    use jubjub::{AffinePoint, Fq};

    // (1, 0) has order four; neither keys nor nonce commitments of small
    // order should be rejected by RedDSA itself.
    check_small_order::<sapling::SpendAuth, sapling::Binding>(&[
        AffinePoint::identity().to_bytes(),
        AffinePoint::from_raw_unchecked(Fq::one(), Fq::zero()).to_bytes(),
    ]);
}

#[test]
fn orchard_small_batches_accept_identity() {
    use group::{Group, GroupEncoding};

    check_small_order::<orchard::SpendAuth, orchard::Binding>(&[
        pasta_curves::pallas::Point::identity().to_bytes(),
    ]);
}
