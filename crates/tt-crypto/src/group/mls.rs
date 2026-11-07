//! MLS (RFC 9420) backend, planned on top of the `openmls` crate.
//!
//! MLS needs one agreed order of commits. The relay that hosts a community
//! orders them (it sees only ciphertext and commit order, not content).
//!
//! TODO: add `openmls` as an optional dependency behind the `mls` feature.
