use rand::thread_rng;
use reddsa::frost_redpallas::PallasBlake2b512;

mod frost;

#[test]
fn check_sign_with_dealer() {
    let rng = thread_rng();

    frost_core::tests::check_sign_with_dealer::<PallasBlake2b512, _>(rng);
}

#[test]
fn check_randomized_sign_with_dealer() {
    let rng = thread_rng();

    frost::check_randomized_sign_with_dealer::<PallasBlake2b512, _>(rng);
}
