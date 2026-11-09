use core::convert::TryFrom;

use reddsa::*;

/// With decompression deferred, a non-canonical key parses, but verifying with it still fails.
#[test]
fn malformed_key_is_rejected_on_verify() {
    // Not a valid Jubjub point encoding: the y-coordinate is above the field modulus.
    let bytes = [0xff; 32];
    let vk = VerificationKey::<sapling::SpendAuth>::try_from(bytes)
        .expect("parsing no longer decompresses the point");
    let sig = Signature::<sapling::SpendAuth>::from([0u8; 64]);

    assert!(matches!(
        vk.verify(b"msg", &sig),
        Err(Error::MalformedVerificationKey)
    ));
}
