# Changelog

Entries are listed in reverse chronological order.

## 0.1.0

Initial release of the `reddsa` crate, extracted from `redjubjub`. Changes
relative to `redjubjub 0.4.0`:

* Generalised the codebase, to enable usage for both RedJubjub and RedPallas.

  * Introduce `SpendAuth: SigType` and `Binding: SigType` traits.
  * The prior `SpendAuth` and `Binding` enums have been renamed to
    `sapling::{SpendAuth, Binding}`.
  * Added `orchard::{SpendAuth, Binding}` enums.

* Migrated to `group 0.11`, `jubjub 0.8`.

* Fixed a bug where small-order verification keys (including the identity) were
  handled inconsistently: the `VerificationKey` parsing logic rejected them, but
  the identity `VerificationKey` could be produced from the zero `SigningKey`.
  The behaviour is now to consistently accept all small-order verification keys,
  matching the RedDSA specification.

  * Downstream users who currently rely on the inconsistent behaviour (for e.g.
    consensus compatibility, either explicitly wanting to reject small-order
    verification keys, or on the belief that this crate implemented the RedDSA
    specification) should continue to use previous versions of this crate, until
    they can either move the checks into their own code, or migrate their
    consensus rules to match the RedDSA specification.

