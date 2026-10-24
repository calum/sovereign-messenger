//! Sovereign messenger core. Everything here lives in RAM only.
//! There is no database, no cache file and no write path to flash storage.

pub mod double_ratchet;
pub mod error;
pub mod ffi;
pub mod handshake;
pub mod pairing;
pub mod ratchet;
pub mod secret;
pub mod store;
pub mod transport;
pub mod update;
pub mod wire;

pub use error::CoreError;

uniffi::setup_scaffolding!();
