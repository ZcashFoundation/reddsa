use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::thread_rng;
use reddsa::frost::redpallas::PallasBlake2b512;

use std::collections::BTreeMap;

use rand_core::{CryptoRng, RngCore};

use frost_rerandomized::frost_core::Ciphersuite;
use frost_rerandomized::{frost_core as frost, RandomizedParams};

/// Benchmark FROST signing with the specified ciphersuite.
fn bench_rerandomized_sign<
    C: Ciphersuite + frost_rerandomized::RandomizedCiphersuite,
    R: RngCore + CryptoRng + Clone,
>(
    c: &mut Criterion,
    name: &str,
    mut rng: &mut R,
) {
    let mut group = c.benchmark_group(format!("Rerandomized FROST Signing {name}"));
    for &n in [3u16, 10, 100, 1000].iter() {
        let max_signers = n;
        let min_signers = (n * 2 + 2) / 3;

        group.bench_with_input(
            BenchmarkId::new("Key Generation with Dealer", max_signers),
            &(max_signers, min_signers),
            |b, (max_signers, min_signers)| {
                let mut rng = rng.clone();
                b.iter(|| {
                    frost::keys::generate_with_dealer::<C, R>(
                        *max_signers,
                        *min_signers,
                        frost::keys::IdentifierList::Default,
                        &mut rng,
                    )
                    .unwrap();
                })
            },
        );

        let (shares, pubkeys) = frost::keys::generate_with_dealer::<C, R>(
            max_signers,
            min_signers,
            frost::keys::IdentifierList::Default,
            rng,
        )
        .unwrap();

        // Verifies the secret shares from the dealer
        let mut key_packages: BTreeMap<frost::Identifier<C>, frost::keys::KeyPackage<C>> =
            BTreeMap::new();

        for (k, v) in shares {
            key_packages.insert(k, frost::keys::KeyPackage::try_from(v).unwrap());
        }

        group.bench_with_input(
            BenchmarkId::new("Round 1", min_signers),
            &key_packages,
            |b, key_packages| {
                let mut rng = rng.clone();
                b.iter(|| {
                    let participant_identifier = 1u16.try_into().expect("should be nonzero");
                    frost::round1::commit(
                        key_packages
                            .get(&participant_identifier)
                            .unwrap()
                            .signing_share(),
                        &mut rng,
                    );
                })
            },
        );

        let mut nonces: BTreeMap<_, _> = BTreeMap::new();
        let mut commitments: BTreeMap<_, _> = BTreeMap::new();

        for participant_index in 1..=min_signers {
            let participant_identifier = participant_index.try_into().expect("should be nonzero");
            let (nonce, commitment) = frost::round1::commit(
                key_packages
                    .get(&participant_identifier)
                    .unwrap()
                    .signing_share(),
                &mut rng,
            );
            nonces.insert(participant_identifier, nonce);
            commitments.insert(participant_identifier, commitment);
        }

        let message = "message to sign".as_bytes();
        let signing_package = frost::SigningPackage::new(commitments, message);
        let randomizer_params = frost_rerandomized::RandomizedParams::new(
            pubkeys.verifying_key(),
            &signing_package,
            &mut rng,
        )
        .unwrap();
        let randomizer = *randomizer_params.randomizer();

        group.bench_with_input(
            BenchmarkId::new("Round 2", min_signers),
            &(
                key_packages.clone(),
                nonces.clone(),
                signing_package.clone(),
            ),
            |b, (key_packages, nonces, signing_package)| {
                b.iter(|| {
                    let participant_identifier = 1u16.try_into().expect("should be nonzero");
                    let key_package = key_packages.get(&participant_identifier).unwrap();
                    let nonces_to_use = &nonces.get(&participant_identifier).unwrap();
                    frost_rerandomized::sign(
                        signing_package,
                        nonces_to_use,
                        key_package,
                        *randomizer_params.randomizer(),
                    )
                    .unwrap();
                })
            },
        );

        let mut signature_shares = BTreeMap::new();
        for participant_identifier in nonces.keys() {
            let key_package = key_packages.get(participant_identifier).unwrap();
            let nonces_to_use = &nonces.get(participant_identifier).unwrap();
            let signature_share = frost_rerandomized::sign(
                &signing_package,
                nonces_to_use,
                key_package,
                *randomizer_params.randomizer(),
            )
            .unwrap();
            signature_shares.insert(*key_package.identifier(), signature_share);
        }

        group.bench_with_input(
            BenchmarkId::new("Aggregate", min_signers),
            &(signing_package.clone(), signature_shares.clone(), pubkeys),
            |b, (signing_package, signature_shares, pubkeys)| {
                b.iter(|| {
                    // We want to include the time to generate the randomizer
                    // params for the Coordinator. Since Aggregate is the only
                    // Coordinator timing, we include it here.
                    let randomizer_params =
                        RandomizedParams::from_randomizer(pubkeys.verifying_key(), randomizer);
                    frost_rerandomized::aggregate(
                        signing_package,
                        signature_shares,
                        pubkeys,
                        &randomizer_params,
                    )
                    .unwrap();
                })
            },
        );
    }
    group.finish();
}

fn bench_sign_redpallas(c: &mut Criterion) {
    let mut rng = thread_rng();

    frost_rerandomized::frost_core::benches::bench_sign::<PallasBlake2b512, _>(
        c,
        "redpallas",
        &mut rng,
    );
}

fn bench_rerandomized_sign_redpallas(c: &mut Criterion) {
    let mut rng = thread_rng();

    bench_rerandomized_sign::<PallasBlake2b512, _>(c, "redpallas", &mut rng);
}

criterion_group!(
    benches,
    bench_sign_redpallas,
    bench_rerandomized_sign_redpallas
);
criterion_main!(benches);
