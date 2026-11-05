//! The production crypto core of Krypton Ø.
//!
//! Key boundary rule: private keys and content keys never leave this crate for the app's JavaScript layer.
//! Callers outside only ever see public keys, ciphertexts, envelopes and opaque handles. The only exceptions
//! are the native wrappers (Swift on iOS, Kotlin on Android), which take private keys out through
//! [`core::Core::slot_secret`] to store them in platform secure storage (the iOS Keychain, the Android Keystore);
//! there is no path from there to JavaScript.
//!
//! Formats shared with the JavaScript reference implementation match it byte for byte. **Since the
//! post-quantum format ([`pq`]), the Account and Enc slots hold seeds, and there is an outer envelope v2.**
//!
//! `unsafe` code exists only at the native boundaries: the C ABI in [`ffi`], and the Android JNI layer in `src/jni.rs`
//! (compiled only for Android).
#![deny(unsafe_code)]

pub mod bip39_en;
pub mod bot;
pub mod core;
pub mod crypto;
pub mod error;
pub mod ffi;
pub mod hint;
#[cfg(target_os = "android")]
pub mod jni;
pub mod oprf;
pub mod phrase;
pub mod pq;
pub mod shamir;
pub mod stream;
pub mod ticket;

pub use crate::core::{Core, RecoveryKit, SelfRecoveryKit, Slot};
pub use crate::error::Error;
