//! Sovereign messenger core. Messages, sessions and ratchet state live in RAM only.
//! There is no database, no cache file and no write path for them to flash storage.
//! The one exception is `vault`: the long-term identity and pinned contacts, sealed
//! under a data key, which Kotlin may store (owner decision 2026-10-25).

pub mod apk_transfer;
pub mod double_ratchet;
pub mod error;
pub mod ffi;
pub mod handshake;
pub mod onion;
pub mod pairing;
pub mod ratchet;
pub mod secret;
pub mod store;
#[cfg(feature = "tor")]
pub mod tor;
pub mod transport;
pub mod update;
pub mod vault;
pub mod wire;

pub use error::CoreError;

uniffi::setup_scaffolding!();
