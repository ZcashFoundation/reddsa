//! Opt-in deferral of verification key decompression for encodings the caller already validated.

/// Runs `f` with decompression of verification keys parsed on this thread deferred to their use.
///
/// Inside the scope, converting bytes to a [`VerificationKey`] always succeeds and skips the
/// canonical-encoding check. The key is decoded, with that check, each time it is used, because
/// `VerificationKey` is `Copy` and does not keep the result: so the saving is only for keys that
/// are parsed but used at most once. [`VerificationKey::verify`] and batch verification return
/// [`Error::MalformedVerificationKey`] for an invalid key, and [`VerificationKey::randomize`]
/// panics. Parsing has never rejected small order keys, inside the
/// scope or not.
///
/// Only use it for encodings this library accepted before, such as transactions a node reads
/// back from its own verified state. Never parse network input inside it.
///
/// The flag is per thread, so `f` must not block on rayon (`join`, `scope`, `par_iter`) or drive
/// an executor, or other jobs run on this thread meanwhile would parse with trust on.
///
/// Without the `std` feature this is a no-op: `f` runs and keys are decoded eagerly.
///
/// [`VerificationKey`]: crate::VerificationKey
/// [`VerificationKey::verify`]: crate::VerificationKey::verify
/// [`VerificationKey::randomize`]: crate::VerificationKey::randomize
/// [`Error::MalformedVerificationKey`]: crate::Error::MalformedVerificationKey
pub fn with_trusted_encodings<R>(f: impl FnOnce() -> R) -> R {
    #[cfg(feature = "std")]
    {
        struct Restore(bool);
        impl Drop for Restore {
            fn drop(&mut self) {
                TRUSTED.with(|trusted| trusted.set(self.0));
            }
        }
        let _restore = Restore(TRUSTED.with(|trusted| trusted.replace(true)));
        f()
    }
    #[cfg(not(feature = "std"))]
    f()
}

/// Returns true inside [`with_trusted_encodings`] on this thread.
pub(crate) fn encodings_are_trusted() -> bool {
    #[cfg(feature = "std")]
    {
        TRUSTED.with(|trusted| trusted.get())
    }
    #[cfg(not(feature = "std"))]
    false
}

#[cfg(feature = "std")]
std::thread_local! {
    static TRUSTED: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use rand_core::SeedableRng;

    use crate::{
        batch, orchard, sapling, Binding, Error, SigType, Signature, SigningKey, SpendAuth,
        VerificationKey,
    };

    #[test]
    fn malformed_keys_are_rejected_unless_trusted() {
        let bytes = [0xff; 32];
        assert_eq!(
            VerificationKey::<sapling::SpendAuth>::try_from(bytes),
            Err(Error::MalformedVerificationKey)
        );
        let key = with_trusted_encodings(|| VerificationKey::<sapling::SpendAuth>::try_from(bytes))
            .expect("trusted keys are not decoded");
        let sig = Signature::<sapling::SpendAuth>::from([0; 64]);
        assert_eq!(
            key.verify(b"msg", &sig),
            Err(Error::MalformedVerificationKey)
        );
        assert!(!encodings_are_trusted());
    }

    #[test]
    fn trusted_keys_verify_like_decoded_keys() {
        let mut rng = rand_chacha::ChaChaRng::from_seed([7; 32]);
        let sk = SigningKey::<sapling::SpendAuth>::new(&mut rng);
        let key: VerificationKey<sapling::SpendAuth> = (&sk).into();
        let bytes: [u8; 32] = key.into();
        let sig = sk.sign(&mut rng, b"msg");
        let decoded = VerificationKey::<sapling::SpendAuth>::try_from(bytes).unwrap();
        let trusted =
            with_trusted_encodings(|| VerificationKey::<sapling::SpendAuth>::try_from(bytes))
                .unwrap();
        assert_eq!(decoded, trusted);
        assert_eq!(trusted.verify(b"msg", &sig), Ok(()));
        assert_eq!(
            trusted.verify(b"other", &sig),
            decoded.verify(b"other", &sig)
        );
    }

    fn lazy<T: SigType>(bytes: [u8; 32]) -> VerificationKey<T> {
        with_trusted_encodings(|| VerificationKey::<T>::try_from(bytes))
            .expect("trusted keys are not decoded")
    }

    // Checks single and batch verification with keys parsed inside the scope.
    fn check_lazy_keys<S: SpendAuth, B: Binding<Scalar = S::Scalar, Point = S::Point>>() {
        let mut rng = rand_chacha::ChaChaRng::from_seed([7; 32]);
        let msg = b"msg";
        let spend_sk = SigningKey::<S>::new(&mut rng);
        let binding_sk = SigningKey::<B>::new(&mut rng);
        let spend_sig = spend_sk.sign(&mut rng, msg);
        let binding_sig = binding_sk.sign(&mut rng, msg);
        let spend_vk: VerificationKey<S> = (&spend_sk).into();
        let binding_vk: VerificationKey<B> = (&binding_sk).into();
        let spend_vk = lazy::<S>(spend_vk.into());
        let binding_vk = lazy::<B>(binding_vk.into());
        assert_eq!(spend_vk.verify(msg, &spend_sig), Ok(()));
        assert_eq!(binding_vk.verify(msg, &binding_sig), Ok(()));

        let batch = |spend_vk: VerificationKey<S>, rng: &mut rand_chacha::ChaChaRng| {
            let mut batch = batch::Verifier::<S, B>::new();
            batch.queue(batch::Item::from_spendauth(spend_vk.into(), spend_sig, msg));
            batch.queue(batch::Item::from_binding(
                binding_vk.into(),
                binding_sig,
                msg,
            ));
            with_trusted_encodings(|| batch.verify(rng))
        };
        assert_eq!(batch(spend_vk, &mut rng), Ok(()));

        let invalid = lazy::<S>([0xff; 32]);
        assert_eq!(
            invalid.verify(msg, &spend_sig),
            Err(Error::MalformedVerificationKey)
        );
        assert_eq!(
            batch(invalid, &mut rng),
            Err(Error::MalformedVerificationKey)
        );
        let randomizer = <S::Scalar as group::ff::Field>::random(&mut rng);
        let randomize = std::panic::AssertUnwindSafe(|| invalid.randomize(&randomizer));
        assert!(std::panic::catch_unwind(randomize).is_err());
        assert!(!encodings_are_trusted());
    }

    #[test]
    fn lazy_sapling_keys_verify() {
        check_lazy_keys::<sapling::SpendAuth, sapling::Binding>();
    }

    #[test]
    fn lazy_orchard_keys_verify() {
        check_lazy_keys::<orchard::SpendAuth, orchard::Binding>();
    }

    #[test]
    fn the_scope_ends_even_after_a_panic() {
        let result = std::panic::catch_unwind(|| with_trusted_encodings(|| panic!("inside")));
        assert!(result.is_err());
        assert!(!encodings_are_trusted());
        with_trusted_encodings(|| {
            with_trusted_encodings(|| assert!(encodings_are_trusted()));
            assert!(
                encodings_are_trusted(),
                "nested scopes restore the outer one"
            );
        });
        assert!(!encodings_are_trusted());
    }
}
