//! Opt-in deferral of point decompression for encodings the caller already validated.

/// Runs `f` with point decompression deferred for keys and commitments parsed on this thread.
///
/// Only use it for encodings this library accepted before, such as transactions a node reads
/// back from its own verified state. Never parse network input inside it: the canonical-encoding
/// and small-order checks are skipped, and an invalid point panics when it is first used.
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

    use crate::{sapling, Error, Signature, SigningKey, VerificationKey};

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
