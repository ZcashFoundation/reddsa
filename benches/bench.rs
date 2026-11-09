use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use rand::{rng as thread_rng, RngExt};
use reddsa::*;
use std::convert::TryFrom;

enum Item<S: SpendAuth, B: Binding> {
    SpendAuth {
        vk_bytes: VerificationKeyBytes<S>,
        sig: Signature<S>,
    },
    Binding {
        vk_bytes: VerificationKeyBytes<B>,
        sig: Signature<B>,
    },
}

fn sigs_with_distinct_keys<S: SpendAuth, B: Binding>() -> impl Iterator<Item = Item<S, B>> {
    std::iter::repeat_with(|| {
        let mut rng = thread_rng();
        let msg = b"Bench";
        match rng.random::<u8>() % 2 {
            0 => {
                let sk = SigningKey::<S>::new(thread_rng());
                let vk_bytes = VerificationKey::from(&sk).into();
                let sig = sk.sign(thread_rng(), &msg[..]);
                Item::SpendAuth { vk_bytes, sig }
            }
            1 => {
                let sk = SigningKey::<B>::new(thread_rng());
                let vk_bytes = VerificationKey::from(&sk).into();
                let sig = sk.sign(thread_rng(), &msg[..]);
                Item::Binding { vk_bytes, sig }
            }
            _ => panic!(),
        }
    })
}

fn bench_batch_verify_for<S, B>(c: &mut Criterion, name: &str)
where
    S: SpendAuth,
    B: Binding<Scalar = S::Scalar, Point = S::Point>,
{
    let mut group = c.benchmark_group(name);
    for &n in [0usize, 1, 2, 8, 16, 24, 32, 40, 48, 56, 64].iter() {
        // The empty batch has no per-signature throughput.
        if n > 0 {
            group.throughput(Throughput::Elements(u64::try_from(n).unwrap()));
        }

        let sigs = sigs_with_distinct_keys::<S, B>()
            .take(n)
            .collect::<Vec<_>>();

        group.bench_with_input(
            BenchmarkId::new("Unbatched verification", n),
            &sigs,
            |b, sigs| {
                b.iter(|| {
                    for item in sigs.iter() {
                        let msg = b"Bench";
                        match item {
                            Item::SpendAuth { vk_bytes, sig } => {
                                let _ = VerificationKey::try_from(*vk_bytes)
                                    .and_then(|vk| vk.verify(msg, sig));
                            }
                            Item::Binding { vk_bytes, sig } => {
                                let _ = VerificationKey::try_from(*vk_bytes)
                                    .and_then(|vk| vk.verify(msg, sig));
                            }
                        }
                    }
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("Batched verification", n),
            &sigs,
            |b, sigs| {
                b.iter(|| {
                    let mut batch = batch::Verifier::new();
                    for item in sigs.iter() {
                        let msg = b"Bench";
                        match item {
                            Item::SpendAuth { vk_bytes, sig } => {
                                batch.queue(batch::Item::from_spendauth(*vk_bytes, *sig, msg));
                            }
                            Item::Binding { vk_bytes, sig } => {
                                batch.queue(batch::Item::from_binding(*vk_bytes, *sig, msg));
                            }
                        }
                    }
                    batch.verify(thread_rng())
                })
            },
        );
    }
    group.finish();
}

fn bench_batch_verify(c: &mut Criterion) {
    bench_batch_verify_for::<sapling::SpendAuth, sapling::Binding>(c, "Batch Verification");
    bench_batch_verify_for::<orchard::SpendAuth, orchard::Binding>(c, "Orchard Batch Verification");
}

criterion_group!(benches, bench_batch_verify);
criterion_main!(benches);
