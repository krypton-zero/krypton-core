//! C interface. Called by the iOS wrapper (Swift) and, on Android, by the JNI layer (`src/jni.rs`, which the Kotlin
//! wrapper calls). Header: `include/gori_core.h`
//!
//! Conventions
//! - The return value is a status code: 0 = success, otherwise an [`Error`] value. `gori_error_message` gives the message
//! - Variable-length results allocated by Rust are returned as a [`GoriBuf`]. The caller must always hand it back
//!   with `gori_buf_free`, which zeroes it before freeing
//! - Fixed-length results (public key 32, signature 64, handle 33 = 32 chars + NUL) are written into caller buffers
//! - Every entry point that touches core state or caller memory is wrapped in `catch_unwind`, so no panic crosses the
//!   boundary (`gori_error_message` and `gori_slot_vault_name` only return static strings)
//! - Output pointers are checked **before any state changes**
//! - Only `gori_slot_secret` exports a private key. It exists for platform secure storage (iOS Keychain, Android Keystore) and the key is **never passed to JavaScript**
//! - Store a key in the vault under the name from `gori_slot_vault_name` and load it with `gori_load_vault` under the same name: the name identifies the format
//!   (since the post-quantum version, Account and Enc hold seeds; the legacy names "account" and "enc" give `StaleKey`)
#![allow(unsafe_code)]

use std::ffi::{c_char, CStr};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::ptr;
use std::slice;
use std::sync::{Mutex, MutexGuard};

use zeroize::Zeroize;

use crate::core::{self as core_fns, Core, OuterPurpose, Slot};
use crate::error::Error;
use crate::pq::{DSA_SIG_LEN, HEK_LEN, PK_D_LEN};
use crate::oprf::{ELEMENT_LEN, OUTPUT_LEN, PROOF_LEN};
use crate::ticket::{TICKET_BATCH_MAX, TICKET_INPUT_LEN};

pub const HANDLE_BUF_LEN: usize = 33;

/// Opaque core. Create it with `gori_core_new` and release it with `gori_core_free`
pub struct GoriCore {
    inner: Mutex<Core>,
}

impl GoriCore {
    fn lock(&self) -> MutexGuard<'_, Core> {
        // Even if a panic poisoned the lock, the state is consistent (no operation leaves the state half-modified)
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }
}

#[repr(C)]
pub struct GoriBuf {
    pub ptr: *mut u8,
    pub len: usize,
}

impl GoriBuf {
    fn from_vec(v: Vec<u8>) -> GoriBuf {
        let boxed = v.into_boxed_slice();
        let len = boxed.len();
        let ptr = Box::into_raw(boxed) as *mut u8;
        GoriBuf { ptr, len }
    }
}

fn run<F: FnOnce() -> Result<(), Error>>(f: F) -> i32 {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => 0,
        Ok(Err(e)) => e.code(),
        Err(_) => Error::Internal.code(),
    }
}

unsafe fn bytes<'a>(p: *const u8, len: usize) -> Result<&'a [u8], Error> {
    if len == 0 {
        return Ok(&[]);
    }
    if p.is_null() {
        return Err(Error::InvalidArgument);
    }
    Ok(slice::from_raw_parts(p, len))
}

unsafe fn core<'a>(c: *const GoriCore) -> Result<&'a GoriCore, Error> {
    c.as_ref().ok_or(Error::InvalidArgument)
}

unsafe fn text<'a>(p: *const c_char) -> Result<&'a str, Error> {
    if p.is_null() {
        return Err(Error::InvalidArgument);
    }
    CStr::from_ptr(p).to_str().map_err(|_| Error::InvalidArgument)
}

/// Checks that an output pointer is not NULL. Called before any operation that changes state
fn need<T>(out: *mut T) -> Result<(), Error> {
    if out.is_null() {
        Err(Error::InvalidArgument)
    } else {
        Ok(())
    }
}

unsafe fn put<const N: usize>(out: *mut u8, v: &[u8; N]) -> Result<(), Error> {
    if out.is_null() {
        return Err(Error::InvalidArgument);
    }
    ptr::copy_nonoverlapping(v.as_ptr(), out, N);
    Ok(())
}

unsafe fn put_buf(out: *mut GoriBuf, v: Vec<u8>) -> Result<(), Error> {
    if out.is_null() {
        return Err(Error::InvalidArgument);
    }
    *out = GoriBuf::from_vec(v);
    Ok(())
}

unsafe fn put_handle(out: *mut c_char, handle: &str) -> Result<(), Error> {
    if out.is_null() || handle.len() + 1 > HANDLE_BUF_LEN {
        return Err(Error::InvalidArgument);
    }
    ptr::copy_nonoverlapping(handle.as_ptr() as *const c_char, out, handle.len());
    *out.add(handle.len()) = 0;
    Ok(())
}

// ── Lifetime ──

#[no_mangle]
pub extern "C" fn gori_core_new() -> *mut GoriCore {
    match catch_unwind(|| Box::into_raw(Box::new(GoriCore { inner: Mutex::new(Core::new()) }))) {
        Ok(p) => p,
        Err(_) => ptr::null_mut(),
    }
}

/// # Safety
/// `c` is a pointer returned by `gori_core_new`, or NULL. Do not call twice
#[no_mangle]
pub unsafe extern "C" fn gori_core_free(c: *mut GoriCore) {
    if !c.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let b = Box::from_raw(c);
            b.lock().forget_all();
            drop(b);
        }));
    }
}

/// # Safety
/// `buf` must have been returned by this library. Do not call twice
#[no_mangle]
pub unsafe extern "C" fn gori_buf_free(buf: GoriBuf) {
    if buf.ptr.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let s = slice::from_raw_parts_mut(buf.ptr, buf.len);
        s.zeroize();
        drop(Box::from_raw(s as *mut [u8]));
    }));
}

/// Human-readable message for a status code. A static string, so it is not freed. NULL for an unknown code
#[no_mangle]
pub extern "C" fn gori_error_message(code: i32) -> *const c_char {
    Error::from_code(code).map_or(ptr::null(), |e| e.message().as_ptr())
}

// ── Private key slots (wrapper only) ──

/// # Safety
/// `out_pub` is 32 bytes
#[no_mangle]
pub unsafe extern "C" fn gori_generate(c: *const GoriCore, slot: u32, out_pub: *mut u8) -> i32 {
    run(|| {
        let slot = Slot::from_u32(slot)?;
        need(out_pub)?;
        let p = core(c)?.lock().generate(slot);
        put(out_pub, &p)
    })
}

/// Vault entry name for a slot (NUL-terminated static string, not to be freed). NULL for an unknown slot.
/// Account and Enc hold seeds, so their names differ from the legacy ones ("account-seed-v2", "enc-seed-v2")
#[no_mangle]
pub extern "C" fn gori_slot_vault_name(slot: u32) -> *const c_char {
    let name: &'static CStr = match Slot::from_u32(slot) {
        Ok(Slot::Account) => c"account-seed-v2",
        Ok(Slot::Device) => c"device",
        Ok(Slot::Enc) => c"enc-seed-v2",
        Ok(Slot::Recovery) => c"recovery",
        Err(_) => return ptr::null(),
    };
    debug_assert_eq!(Slot::from_u32(slot).map(|s| s.vault_name()).ok(), name.to_str().ok());
    name.as_ptr()
}

/// Loads a stored private key by its vault entry name. A legacy-format name ("account", "enc") gives `StaleKey` (35) and loads nothing;
/// the wrapper then deletes that entry and re-creates the account. An unknown name gives `InvalidArgument`
/// # Safety
/// `name` is a NUL-terminated string, `secret` is `len` bytes, `out_pub` is 32 bytes (not written if NULL)
#[no_mangle]
pub unsafe extern "C" fn gori_load_vault(
    c: *const GoriCore,
    name: *const c_char,
    secret: *const u8,
    len: usize,
    out_pub: *mut u8,
) -> i32 {
    run(|| {
        let (_, p) = core(c)?.lock().load_vault(text(name)?, bytes(secret, len)?)?;
        if !out_pub.is_null() {
            put(out_pub, &p)?;
        }
        Ok(())
    })
}

/// Exports a private key for platform secure storage. **Only the native wrappers call this (the Swift wrapper directly, the
/// Kotlin wrapper through `src/jni.rs`), and the caller zeroes the buffer as soon as it has stored the key**
/// # Safety
/// `out_secret` is 32 bytes
#[no_mangle]
pub unsafe extern "C" fn gori_slot_secret(c: *const GoriCore, slot: u32, out_secret: *mut u8) -> i32 {
    run(|| {
        let slot = Slot::from_u32(slot)?;
        need(out_secret)?;
        let s = core(c)?.lock().slot_secret(slot).ok_or(match slot {
            Slot::Account => Error::NoAccountKey,
            Slot::Device => Error::NoDeviceKey,
            Slot::Enc => Error::NoEncryptionKey,
            Slot::Recovery => Error::RecoveryNotStarted,
        })?;
        put(out_secret, &s)
    })
}

/// # Safety
/// `c` is a valid core
#[no_mangle]
pub unsafe extern "C" fn gori_clear(c: *const GoriCore, slot: u32) -> i32 {
    run(|| {
        let slot = Slot::from_u32(slot)?;
        core(c)?.lock().clear(slot);
        Ok(())
    })
}

/// # Safety
/// `out_has` is 1 byte (1 = present)
#[no_mangle]
pub unsafe extern "C" fn gori_has(c: *const GoriCore, slot: u32, out_has: *mut u8) -> i32 {
    run(|| {
        let slot = Slot::from_u32(slot)?;
        let h = core(c)?.lock().has(slot) as u8;
        put(out_has, &[h])
    })
}

/// # Safety
/// `out_pub` is 32 bytes
#[no_mangle]
pub unsafe extern "C" fn gori_public_key(c: *const GoriCore, slot: u32, out_pub: *mut u8) -> i32 {
    run(|| {
        let slot = Slot::from_u32(slot)?;
        let p = core(c)?.lock().public_key(slot)?;
        put(out_pub, &p)
    })
}

// ── Signing ──

/// `slot` is account (0) or device (1).
/// # Safety
/// `msg` is `len` bytes, `out_sig` is 64 bytes
#[no_mangle]
pub unsafe extern "C" fn gori_sign(
    c: *const GoriCore,
    slot: u32,
    msg: *const u8,
    len: usize,
    out_sig: *mut u8,
) -> i32 {
    run(|| {
        let slot = Slot::from_u32(slot)?;
        need(out_sig)?;
        let s = core(c)?.lock().sign(slot, bytes(msg, len)?)?;
        put(out_sig, &s)
    })
}

/// Device certificate v2: the account key signs this core's device key, `sign(account, "gori-core/device-cert-v2\0" ‖ device_pub)`
/// # Safety
/// `out_sig` is 64 bytes
#[no_mangle]
pub unsafe extern "C" fn gori_sign_device_certificate(c: *const GoriCore, out_sig: *mut u8) -> i32 {
    run(|| {
        need(out_sig)?;
        let s = core(c)?.lock().sign_device_certificate()?;
        put(out_sig, &s)
    })
}

/// Encryption key signature v2: the account key signs this core's encryption key, `sign(account, "gori-core/enc-key-v2\0" ‖ enc_pub)`
/// # Safety
/// `out_sig` is 64 bytes
#[no_mangle]
pub unsafe extern "C" fn gori_sign_encryption_key(c: *const GoriCore, out_sig: *mut u8) -> i32 {
    run(|| {
        need(out_sig)?;
        let s = core(c)?.lock().sign_encryption_key()?;
        put(out_sig, &s)
    })
}

/// Encryption key signature v3 (`es3`): the account key signs this core's HEK, `sign(account, "gori-core/enc-key-v3\0" ‖ pk_X ‖ pk_M)`
/// # Safety
/// `out_sig` is 64 bytes
#[no_mangle]
pub unsafe extern "C" fn gori_sign_encryption_key_v3(c: *const GoriCore, out_sig: *mut u8) -> i32 {
    run(|| {
        need(out_sig)?;
        let s = core(c)?.lock().sign_encryption_key_v3()?;
        put(out_sig, &s)
    })
}

/// This core's hybrid public key HEK = pk_M(1184) ‖ pk_X(32)
/// # Safety
/// `out_hek` is 1216 bytes
#[no_mangle]
pub unsafe extern "C" fn gori_encryption_hybrid_key(c: *const GoriCore, out_hek: *mut u8) -> i32 {
    run(|| {
        need(out_hek)?;
        let k = core(c)?.lock().encryption_hybrid_key()?;
        put::<HEK_LEN>(out_hek, &k)
    })
}

/// Checks a received HEK: 0 = usable, `NeedHybridKey` (36) = not 1216 bytes, `WeakKey` (27) = failed the strict pk_X check or the pk_M modulus
/// check (FIPS 203 §7.2). No core needed
/// # Safety
/// `hek` is `len` bytes
#[no_mangle]
pub unsafe extern "C" fn gori_check_hybrid_key(hek: *const u8, len: usize) -> i32 {
    run(|| Core::check_hybrid_key(bytes(hek, len)?))
}

/// Tries to open a notification hint with each key in the ring ([`crate::hint`]). No core needed (the notification extension and call push do not use core state).
/// `ring` = key ring (version 1: `0x01 ‖ (kind 1 ‖ peer 16 ‖ key 32)*`, up to 1,024 records), `kinds` = bitmask of kinds to try (1 << kind: pair 2, talk 4, call 8),
/// `sealed` = base64-decoded g (nonce 24 ‖ ciphertext). On success the plaintext goes to `out` (`gori_buf_free` zeroes it) and the kind ‖ peer (17) of the
/// record that opened it goes to `out_tag`. If no key opens it, `DecryptFailed`; a malformed ring or kinds gives `InvalidArgument`; a too-short g gives `BadCiphertext`
/// # Safety
/// `ring` is `ring_len` bytes, `sealed` is `sealed_len` bytes. `out_tag` is 17 bytes
#[no_mangle]
pub unsafe extern "C" fn gori_open_hint(
    ring: *const u8,
    ring_len: usize,
    kinds: u32,
    sealed: *const u8,
    sealed_len: usize,
    out: *mut GoriBuf,
    out_tag: *mut u8,
) -> i32 {
    run(|| {
        need(out)?;
        need(out_tag)?;
        let (pt, tag) = crate::hint::open_hint(bytes(ring, ring_len)?, kinds, bytes(sealed, sealed_len)?)?;
        put(out_tag, &tag)?;
        put_buf(out, pt.to_vec())
    })
}

/// Identity key binding: ML-DSA-65 public key pk_D (1952), dh (32), ds (64, Ed25519), dq (3309, ML-DSA-65). Public values only
/// # Safety
/// The outputs are 1952, 32, 64 and 3309 bytes respectively
#[no_mangle]
pub unsafe extern "C" fn gori_pq_sig_binding(
    c: *const GoriCore,
    out_pk_d: *mut u8,
    out_dh: *mut u8,
    out_ds: *mut u8,
    out_dq: *mut u8,
) -> i32 {
    run(|| {
        need(out_pk_d)?;
        need(out_dh)?;
        need(out_ds)?;
        need(out_dq)?;
        let b = core(c)?.lock().pq_sig_binding()?;
        put::<PK_D_LEN>(out_pk_d, &b.pk_d)?;
        put(out_dh, &b.dh)?;
        put(out_ds, &b.ds)?;
        put::<DSA_SIG_LEN>(out_dq, &b.dq)
    })
}

/// 1 = the binding is valid (lengths, dh = SHA3-256(label ‖ pk_D), ds verified under ik, dq verified under pk_D), 0 = not (also 0 for malformed input)
/// # Safety
/// Each pointer is readable for its given length
#[no_mangle]
pub unsafe extern "C" fn gori_verify_pq_sig_binding(
    ik: *const u8,
    ik_len: usize,
    pk_d: *const u8,
    pk_d_len: usize,
    dh: *const u8,
    dh_len: usize,
    ds: *const u8,
    ds_len: usize,
    dq: *const u8,
    dq_len: usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        match (bytes(ik, ik_len), bytes(pk_d, pk_d_len), bytes(dh, dh_len), bytes(ds, ds_len), bytes(dq, dq_len)) {
            (Ok(a), Ok(b), Ok(c), Ok(d), Ok(e)) => Core::verify_pq_sig_binding(a, b, c, d, e) as i32,
            _ => 0,
        }
    }))
    .unwrap_or(0)
}

/// 1 = valid signature, 0 = not (also 0 for malformed input). Strict verification: small-order, non-canonical or torsion-containing public keys give 0
/// # Safety
/// Each pointer is readable for its given length
#[no_mangle]
pub unsafe extern "C" fn gori_verify(
    pubkey: *const u8,
    pub_len: usize,
    msg: *const u8,
    msg_len: usize,
    sig: *const u8,
    sig_len: usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        match (bytes(pubkey, pub_len), bytes(msg, msg_len), bytes(sig, sig_len)) {
            (Ok(p), Ok(m), Ok(s)) => Core::verify(p, m, s) as i32,
            _ => 0,
        }
    }))
    .unwrap_or(0)
}

// ── Content keys ──

/// # Safety
/// `out_handle` is 33 bytes
#[no_mangle]
pub unsafe extern "C" fn gori_create_content_key(c: *const GoriCore, out_handle: *mut c_char) -> i32 {
    run(|| {
        need(out_handle)?;
        let h = core(c)?.lock().create_content_key();
        put_handle(out_handle, &h)
    })
}

/// # Safety
/// `handle` is a NUL-terminated string, `pt` is `len` bytes
#[no_mangle]
pub unsafe extern "C" fn gori_encrypt(
    c: *const GoriCore,
    handle: *const c_char,
    pt: *const u8,
    len: usize,
    out: *mut GoriBuf,
) -> i32 {
    run(|| {
        need(out)?;
        let v = core(c)?.lock().encrypt(text(handle)?, bytes(pt, len)?)?;
        put_buf(out, v)
    })
}

/// Returns the plaintext (`gori_buf_free` zeroes it)
/// # Safety
/// `handle` is a NUL-terminated string, `ct` is `len` bytes
#[no_mangle]
pub unsafe extern "C" fn gori_decrypt(
    c: *const GoriCore,
    handle: *const c_char,
    ct: *const u8,
    len: usize,
    out: *mut GoriBuf,
) -> i32 {
    run(|| {
        need(out)?;
        // Copy only the key and release the lock at once, so other decryptions do not queue behind this one
        let key = core(c)?.lock().content_key_copy(text(handle)?)?;
        let pt = core_fns::decrypt_with(&key, bytes(ct, len)?)?;
        put_buf(out, pt.to_vec())
    })
}

/// Seals a content key in an outer envelope v2 (hybrid, 1201 bytes). `purpose` 0 = key envelope, 1 = body sealing (notes), 2 = inbox copy / pair bundle
/// (each uses a different HKDF context). If the recipient key is not an HEK (1216), `NeedHybridKey`: the outer layer is never sealed to a 32-byte key
/// # Safety
/// `handle` is a NUL-terminated string, `hek` is `len` bytes
#[no_mangle]
pub unsafe extern "C" fn gori_seal_outer(
    c: *const GoriCore,
    handle: *const c_char,
    purpose: u32,
    hek: *const u8,
    len: usize,
    out: *mut GoriBuf,
) -> i32 {
    run(|| {
        need(out)?;
        let purpose = OuterPurpose::from_u32(purpose)?;
        let v = core(c)?.lock().seal_outer(text(handle)?, purpose, bytes(hek, len)?)?;
        put_buf(out, v)
    })
}

/// Opens an outer envelope v2. Exactly 1201 bytes only (otherwise `BadEnvelope`). Opens only with the same `purpose` used for sealing
/// # Safety
/// `envelope` is `len` bytes, `out_handle` is 33 bytes
#[no_mangle]
pub unsafe extern "C" fn gori_open_outer(
    c: *const GoriCore,
    purpose: u32,
    envelope: *const u8,
    len: usize,
    out_handle: *mut c_char,
) -> i32 {
    run(|| {
        need(out_handle)?;
        let purpose = OuterPurpose::from_u32(purpose)?;
        let h = core(c)?.lock().open_outer(purpose, bytes(envelope, len)?)?;
        put_handle(out_handle, &h)
    })
}

/// Inner envelope (X25519, 104 bytes; same bytes as the earlier `gori_seal_to`). The recipient key is pk_X (32). Used only inside notes sealed with a pair secret
/// # Safety
/// `recipient` is `len` bytes
#[no_mangle]
pub unsafe extern "C" fn gori_seal_inner(
    c: *const GoriCore,
    handle: *const c_char,
    recipient: *const u8,
    len: usize,
    out: *mut GoriBuf,
) -> i32 {
    run(|| {
        need(out)?;
        let v = core(c)?.lock().seal_inner(text(handle)?, bytes(recipient, len)?)?;
        put_buf(out, v)
    })
}

/// Opens an inner envelope. Exactly 104 bytes only (otherwise `BadEnvelope`)
/// # Safety
/// `envelope` is `len` bytes, `out_handle` is 33 bytes
#[no_mangle]
pub unsafe extern "C" fn gori_open_inner(
    c: *const GoriCore,
    envelope: *const u8,
    len: usize,
    out_handle: *mut c_char,
) -> i32 {
    run(|| {
        need(out_handle)?;
        let h = core(c)?.lock().open_inner(bytes(envelope, len)?)?;
        put_handle(out_handle, &h)
    })
}

/// # Safety
/// `kek` and `key` are NUL-terminated strings
#[no_mangle]
pub unsafe extern "C" fn gori_wrap_key(
    c: *const GoriCore,
    kek: *const c_char,
    key: *const c_char,
    out: *mut GoriBuf,
) -> i32 {
    run(|| {
        need(out)?;
        let v = core(c)?.lock().wrap_key(text(kek)?, text(key)?)?;
        put_buf(out, v)
    })
}

/// # Safety
/// `wrapped` is `len` bytes, `out_handle` is 33 bytes
#[no_mangle]
pub unsafe extern "C" fn gori_unwrap_key(
    c: *const GoriCore,
    kek: *const c_char,
    wrapped: *const u8,
    len: usize,
    out_handle: *mut c_char,
) -> i32 {
    run(|| {
        need(out_handle)?;
        let h = core(c)?.lock().unwrap_key(text(kek)?, bytes(wrapped, len)?)?;
        put_handle(out_handle, &h)
    })
}

// ── Chunked files ──

/// # Safety
/// Paths are NUL-terminated UTF-8 file system paths (not file:// URLs)
#[no_mangle]
pub unsafe extern "C" fn gori_encrypt_file(
    c: *const GoriCore,
    handle: *const c_char,
    in_path: *const c_char,
    out_path: *const c_char,
) -> i32 {
    run(|| {
        let (h, i, o) = (text(handle)?, text(in_path)?, text(out_path)?);
        core(c)?.lock().encrypt_file(h, Path::new(i), Path::new(o)).map(|_| ())
    })
}

/// # Safety
/// Paths are NUL-terminated UTF-8 file system paths
#[no_mangle]
pub unsafe extern "C" fn gori_decrypt_file(
    c: *const GoriCore,
    handle: *const c_char,
    in_path: *const c_char,
    out_path: *const c_char,
) -> i32 {
    run(|| {
        let (h, i, o) = (text(handle)?, text(in_path)?, text(out_path)?);
        // Copy only the key, release the lock, then decrypt, so a long file does not block other decryptions.
        // The copy is zeroed when this call returns (Zeroizing) and never leaves process memory
        let key = core(c)?.lock().content_key_copy(h)?;
        core_fns::decrypt_file_with(&key, Path::new(i), Path::new(o), core_fns::Durability::Synced).map(|_| ())
    })
}

/// Like [`gori_decrypt_file`], but decrypts to a **cache file that can be downloaded again**: no fsync after writing.
/// As there, `out_path` appears only after authentication completes.
/// If `out_path` + ".part" already exists, it is truncated and written to (the iOS wrapper pre-creates it with a data protection class)
/// # Safety
/// Paths are NUL-terminated UTF-8 file system paths
#[no_mangle]
pub unsafe extern "C" fn gori_decrypt_cache_file(
    c: *const GoriCore,
    handle: *const c_char,
    in_path: *const c_char,
    out_path: *const c_char,
) -> i32 {
    run(|| {
        let (h, i, o) = (text(handle)?, text(in_path)?, text(out_path)?);
        let key = core(c)?.lock().content_key_copy(h)?;
        core_fns::decrypt_file_with(&key, Path::new(i), Path::new(o), core_fns::Durability::Cache).map(|_| ())
    })
}


/// **Decrypt while downloading**: returns in `out` the plaintext `[start, start+len)` of the chunked file `in_path` that is still being downloaded
/// (its current size is the received prefix, `total` is the full ciphertext length; `gori_buf_free` zeroes `out`). If that range has not arrived yet, `StreamNotYet` (37):
/// the player calls again after more data arrives. Never writes plaintext to disk. Copies only the key and releases the lock before decrypting (same reason as gori_decrypt_file)
/// # Safety
/// `handle` and `in_path` are NUL-terminated UTF-8 strings (the path is not a file:// URL)
#[no_mangle]
pub unsafe extern "C" fn gori_decrypt_file_range(
    c: *const GoriCore,
    handle: *const c_char,
    in_path: *const c_char,
    total: u64,
    start: u64,
    len: u64,
    out: *mut GoriBuf,
) -> i32 {
    run(|| {
        need(out)?;
        let (h, i) = (text(handle)?, text(in_path)?);
        let key = core(c)?.lock().content_key_copy(h)?;
        let pt = core_fns::decrypt_file_range_with(&key, Path::new(i), total, start, len)?;
        put_buf(out, pt.to_vec())
    })
}


// ── Account recovery ──

/// Prepares recovery for `count` guardian public keys (32 bytes each, concatenated).
/// `out_shares` is the concatenation of the sealed shares; the length of one share is `out_share_len`.
/// # Safety
/// `pubkeys` is `32 * count` bytes, `out_server_share` is 32 bytes
#[no_mangle]
pub unsafe extern "C" fn gori_prepare_recovery(
    c: *const GoriCore,
    pubkeys: *const u8,
    count: usize,
    threshold: usize,
    out_backup: *mut GoriBuf,
    out_server_share: *mut u8,
    out_shares: *mut GoriBuf,
    out_share_len: *mut usize,
) -> i32 {
    run(|| {
        need(out_backup)?;
        need(out_server_share)?;
        need(out_shares)?;
        need(out_share_len)?;
        if count > core_fns::MAX_GUARDIANS {
            return Err(Error::BadShareCount);
        }
        let all = bytes(pubkeys, count.checked_mul(32).ok_or(Error::InvalidArgument)?)?;
        let pubs: Vec<&[u8]> = all.chunks(32).collect();
        let kit = core(c)?.lock().prepare_recovery(&pubs, threshold)?;
        // kit.server_share (U) is Zeroizing: whether we return early on a failure below or hand everything over, it is zeroed when kit is dropped.
        // The copy written to the caller's buffer (out_server_share) belongs to the caller
        let share_len = kit.guardian_shares.first().map_or(0, |s| s.len());
        let joined: Vec<u8> = kit.guardian_shares.concat();
        put(out_server_share, &kit.server_share)?;
        *out_share_len = share_len;
        put_buf(out_backup, kit.backup)?;
        put_buf(out_shares, joined)
    })
}

/// # Safety
/// `out_pub` is 32 bytes, `out_created` is 1 byte (1 = newly created, so the wrapper should store it)
#[no_mangle]
pub unsafe extern "C" fn gori_begin_recovery(c: *const GoriCore, out_pub: *mut u8, out_created: *mut u8) -> i32 {
    run(|| {
        need(out_pub)?;
        need(out_created)?;
        let (p, created) = core(c)?.lock().begin_recovery();
        put(out_pub, &p)?;
        put(out_created, &[created as u8])
    })
}

/// # Safety
/// Each pointer is readable for its given length
#[no_mangle]
pub unsafe extern "C" fn gori_reseal_share(
    c: *const GoriCore,
    sealed: *const u8,
    sealed_len: usize,
    to_pub: *const u8,
    to_len: usize,
    out: *mut GoriBuf,
) -> i32 {
    run(|| {
        need(out)?;
        let v = core(c)?.lock().reseal_share(bytes(sealed, sealed_len)?, bytes(to_pub, to_len)?)?;
        put_buf(out, v)
    })
}

/// Restores the two private keys from the collected shares. If the restored account public key differs from `expected_account_pub` (32 bytes, the
/// identity public key of the account being recovered) (`AccountMismatch`), or it would overwrite a different key already loaded (`KeyConflict`), nothing is loaded.
/// 1 to 16 shares of 105 bytes each; the server share is 32 bytes.
/// # Safety
/// `shares` and `share_lens` are `count` pointers and lengths, `expected_account_pub` is `expected_len` bytes,
/// `out_account_pub` and `out_enc_pub` are 32 bytes
#[no_mangle]
pub unsafe extern "C" fn gori_complete_recovery(
    c: *const GoriCore,
    backup: *const u8,
    backup_len: usize,
    shares: *const *const u8,
    share_lens: *const usize,
    count: usize,
    server_share: *const u8,
    server_share_len: usize,
    expected_account_pub: *const u8,
    expected_len: usize,
    out_account_pub: *mut u8,
    out_enc_pub: *mut u8,
) -> i32 {
    run(|| {
        need(out_account_pub)?;
        need(out_enc_pub)?;
        if count > core_fns::MAX_GUARDIANS {
            return Err(Error::BadShareCount);
        }
        let ptrs = if count == 0 { &[][..] } else {
            if shares.is_null() || share_lens.is_null() {
                return Err(Error::InvalidArgument);
            }
            slice::from_raw_parts(shares, count)
        };
        let lens = if count == 0 { &[][..] } else { slice::from_raw_parts(share_lens, count) };
        let list = ptrs
            .iter()
            .zip(lens)
            .map(|(p, l)| bytes(*p, *l))
            .collect::<Result<Vec<_>, _>>()?;
        let (a, e) = core(c)?.lock().complete_recovery(
            bytes(backup, backup_len)?,
            &list,
            bytes(server_share, server_share_len)?,
            bytes(expected_account_pub, expected_len)?,
        )?;
        put(out_account_pub, &a)?;
        put(out_enc_pub, &e)
    })
}

// ── Recovery v3: paper phrase ──
//
// The phrase is exchanged as UTF-8 bytes, words separated by ASCII whitespace. Input may contain repeated, leading or trailing whitespace and uppercase;
// output is 18 lowercase words joined by single spaces. NUL-terminated C strings are not used so that the wrapper can zero the byte
// array holding the phrase right after use (Swift `[UInt8]`, Kotlin `ByteArray`)

/// Upper bound on phrase bytes, comfortably above 18 words × (8 letters + space). Longer input gives `BadPhrase` before splitting
const PHRASE_MAX_BYTES: usize = 1024;

unsafe fn phrase_words<'a>(p: *const u8, len: usize) -> Result<Vec<&'a str>, Error> {
    if len > PHRASE_MAX_BYTES {
        return Err(Error::BadPhrase);
    }
    let text = std::str::from_utf8(bytes(p, len)?).map_err(|_| Error::BadPhrase)?;
    Ok(text.split_ascii_whitespace().collect())
}

/// Prepares paper-phrase recovery (requires the account and encryption keys). `out_phrase` is UTF-8, 18 lowercase words joined by single spaces
/// (no NUL); the wrapper keeps it only long enough to show it once on screen, then zeroes it. `out_backup` is the 105-byte backup (version 4: two seeds)
/// # Safety
/// `out_server_share` and `out_locator` are 32 bytes
#[no_mangle]
pub unsafe extern "C" fn gori_prepare_self_recovery(
    c: *const GoriCore,
    out_phrase: *mut GoriBuf,
    out_backup: *mut GoriBuf,
    out_server_share: *mut u8,
    out_locator: *mut u8,
) -> i32 {
    run(|| {
        need(out_phrase)?;
        need(out_backup)?;
        need(out_server_share)?;
        need(out_locator)?;
        let mut kit = core(c)?.lock().prepare_self_recovery()?;
        // Allocate the exact length once (so growth never relocates it) and hand that same buffer over as the GoriBuf; gori_buf_free zeroes it
        let len = kit.words.iter().map(|w| w.len()).sum::<usize>() + kit.words.len() - 1;
        let mut joined = zeroize::Zeroizing::new(Vec::with_capacity(len));
        for (i, w) in kit.words.iter().enumerate() {
            if i > 0 {
                joined.push(b' ');
            }
            joined.extend_from_slice(w.as_bytes());
        }
        put(out_server_share, &kit.server_share)?;
        put(out_locator, &kit.locator)?;
        put_buf(out_backup, std::mem::take(&mut kit.backup))?;
        put_buf(out_phrase, std::mem::take(&mut *joined))
    })
}

/// Phrase → locator L (32). No core needed (new device). An invalid phrase gives `BadPhrase`
/// # Safety
/// `phrase` is `phrase_len` bytes, `out_locator` is 32 bytes
#[no_mangle]
pub unsafe extern "C" fn gori_recovery_locator(phrase: *const u8, phrase_len: usize, out_locator: *mut u8) -> i32 {
    run(|| {
        need(out_locator)?;
        let l = Core::recovery_locator(&phrase_words(phrase, phrase_len)?)?;
        put(out_locator, &l)
    })
}

/// scrypt (RFC 7914): computes the app's PIN hash (N=2^14 r=8 p=1, 32 bytes) in place of JavaScript. No core needed (stateless).
/// `log_n` 10..=20, `r` 1..=16, `p` 1..=4, `out_len` 16..=64; outside these ranges `InvalidArgument`. On failure nothing is written to `out`.
/// The secret (pw) is borrowed and read, never copied (it stays in, and is owned by, the caller's buffer). The result is first computed into a scratch buffer that is zeroed afterwards
/// # Safety
/// `pw` is `pw_len` bytes, `salt` is `salt_len` bytes. `out` is `out_len` bytes
#[no_mangle]
pub unsafe extern "C" fn gori_scrypt(
    pw: *const u8,
    pw_len: usize,
    salt: *const u8,
    salt_len: usize,
    log_n: u32,
    r: u32,
    p: u32,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    run(|| {
        need(out)?;
        if !crate::crypto::SCRYPT_LEN.contains(&out_len) {
            return Err(Error::InvalidArgument);
        }
        let mut tmp = zeroize::Zeroizing::new([0u8; 64]);
        crate::crypto::scrypt(bytes(pw, pw_len)?, bytes(salt, salt_len)?, log_n, r, p, &mut tmp[..out_len])?;
        ptr::copy_nonoverlapping(tmp.as_ptr(), out, out_len);
        Ok(())
    })
}

/// Restores the two seeds from the phrase, the server half U (32) and the backup (105, version 4); version 3 (before the post-quantum upgrade) gives `StaleKey`.
/// If the restored account public key differs from `expected_account_pub` (`AccountMismatch`) or it would overwrite a different key already loaded (`KeyConflict`),
/// nothing is loaded (same rule as `gori_complete_recovery`). The Recovery slot is not touched
/// # Safety
/// Each input pointer is readable for its given length. `out_account_pub` and `out_enc_pub` are 32 bytes
#[no_mangle]
pub unsafe extern "C" fn gori_complete_self_recovery(
    c: *const GoriCore,
    phrase: *const u8,
    phrase_len: usize,
    backup: *const u8,
    backup_len: usize,
    server_share: *const u8,
    server_share_len: usize,
    expected_account_pub: *const u8,
    expected_len: usize,
    out_account_pub: *mut u8,
    out_enc_pub: *mut u8,
) -> i32 {
    run(|| {
        need(out_account_pub)?;
        need(out_enc_pub)?;
        let words = phrase_words(phrase, phrase_len)?;
        let (a, e) = core(c)?.lock().complete_self_recovery(
            &words,
            bytes(backup, backup_len)?,
            bytes(server_share, server_share_len)?,
            bytes(expected_account_pub, expected_len)?,
        )?;
        put(out_account_pub, &a)?;
        put(out_enc_pub, &e)
    })
}

// ── Invite tickets (RFC 9497 VOPRF, ristretto255-SHA512) ──

/// Index list. Zero or more than 64 entries gives `TicketInput` (checked before building the slice); NULL or misaligned gives `InvalidArgument`
unsafe fn ticket_indices<'a>(p: *const u32, count: usize) -> Result<&'a [u32], Error> {
    if count == 0 || count > TICKET_BATCH_MAX {
        return Err(Error::TicketInput);
    }
    if p.is_null() || !(p as usize).is_multiple_of(std::mem::align_of::<u32>()) {
        return Err(Error::InvalidArgument);
    }
    Ok(slice::from_raw_parts(p, count))
}

/// 32-byte period salt. The wrapper reads it from the vault (iOS Keychain, Android Vault), passes it in and zeroes it right away (it never reaches JavaScript)
unsafe fn ticket_salt<'a>(p: *const u8) -> Result<&'a [u8; 32], Error> {
    bytes(p, 32)?.try_into().map_err(|_| Error::InvalidArgument)
}

/// Writes one blinded element per index to `out_blinded` (32 × count). Does not change core state (same arguments, same result).
/// On failure nothing is written to the output buffer
/// # Safety
/// `period_salt` is 32 bytes, `indices` is `count` u32 values, `out_blinded` is 32 × count bytes
#[no_mangle]
pub unsafe extern "C" fn gori_ticket_blind(
    c: *const GoriCore,
    kind: u8,
    period: u32,
    period_salt: *const u8,
    indices: *const u32,
    count: usize,
    out_blinded: *mut u8,
) -> i32 {
    run(|| {
        need(out_blinded)?;
        let idx = ticket_indices(indices, count)?;
        let salt = ticket_salt(period_salt)?;
        let blinded = core(c)?.lock().ticket_blind(kind, period, salt, idx)?;
        let out = slice::from_raw_parts_mut(out_blinded, count * ELEMENT_LEN);
        for (dst, b) in out.as_chunks_mut::<ELEMENT_LEN>().0.iter_mut().zip(&blinded) {
            dst.copy_from_slice(b);
        }
        Ok(())
    })
}

/// Verifies the server response and writes the tickets: `out_inputs` 32 × count, `out_outputs` 64 × count (in index order).
/// On failure nothing is written to either output buffer
/// # Safety
/// `period_salt` 32, `indices` is `count` u32 values, `server_pub` 32, `evaluated` 32 × count, `proof` 64 bytes; outputs have the lengths above
#[no_mangle]
pub unsafe extern "C" fn gori_ticket_finalize(
    c: *const GoriCore,
    kind: u8,
    period: u32,
    period_salt: *const u8,
    indices: *const u32,
    count: usize,
    server_pub: *const u8,
    evaluated: *const u8,
    proof: *const u8,
    out_inputs: *mut u8,
    out_outputs: *mut u8,
) -> i32 {
    run(|| {
        need(out_inputs)?;
        need(out_outputs)?;
        let idx = ticket_indices(indices, count)?;
        let salt = ticket_salt(period_salt)?;
        let pk: &[u8; ELEMENT_LEN] = bytes(server_pub, ELEMENT_LEN)?.try_into().map_err(|_| Error::InvalidArgument)?;
        let ev = bytes(evaluated, count * ELEMENT_LEN)?.as_chunks::<ELEMENT_LEN>().0;
        let pr: &[u8; PROOF_LEN] = bytes(proof, PROOF_LEN)?.try_into().map_err(|_| Error::InvalidArgument)?;
        let tickets = core(c)?.lock().ticket_finalize(kind, period, salt, idx, pk, ev, pr)?;
        let ins = slice::from_raw_parts_mut(out_inputs, count * TICKET_INPUT_LEN);
        let outs = slice::from_raw_parts_mut(out_outputs, count * OUTPUT_LEN);
        let (ins, outs) = (ins.as_chunks_mut::<TICKET_INPUT_LEN>().0, outs.as_chunks_mut::<OUTPUT_LEN>().0);
        for ((t, i), o) in tickets.iter().zip(ins.iter_mut()).zip(outs.iter_mut()) {
            i.copy_from_slice(&t.input);
            o.copy_from_slice(&t.output);
        }
        Ok(())
    })
}

/// Erases all private keys and content keys held in memory (the wrapper clears the Keychain)
/// # Safety
/// `c` is a valid core
#[no_mangle]
pub unsafe extern "C" fn gori_forget_all(c: *const GoriCore) -> i32 {
    run(|| {
        core(c)?.lock().forget_all();
        Ok(())
    })
}

// ── Bot keys (src/bot.rs) ──

/// Creates a new bot key set: a handle (33) and the public bundle (`out`, [`crate::bot::BOT_PUBLIC_LEN`] bytes, public values only). The seeds are not stored in the vault
/// # Safety
/// `out_handle` is 33 bytes, `out` is one GoriBuf
#[no_mangle]
pub unsafe extern "C" fn gori_bot_create(c: *const GoriCore, out_handle: *mut c_char, out: *mut GoriBuf) -> i32 {
    run(|| {
        need(out_handle)?;
        need(out)?;
        let (h, blob) = core(c)?.lock().bot_create();
        put_handle(out_handle, &h)?;
        put_buf(out, blob)
    })
}

/// Writes the bot key file to `path`: one line, `meta` (UTF-8 JSON object with seed-free fields) plus the three seeds. This file is the only way seeds leave the crate
/// # Safety
/// `handle` and `path` are NUL-terminated strings, `meta` is `len` bytes
#[no_mangle]
pub unsafe extern "C" fn gori_bot_key_file(
    c: *const GoriCore,
    handle: *const c_char,
    meta: *const u8,
    len: usize,
    path: *const c_char,
) -> i32 {
    run(|| {
        let (h, p) = (text(handle)?, text(path)?);
        core(c)?.lock().bot_key_file(h, bytes(meta, len)?, Path::new(p))
    })
}

/// Erases a bot key set (it is zeroed). Does nothing for an unknown handle
/// # Safety
/// `handle` is a NUL-terminated string
#[no_mangle]
pub unsafe extern "C" fn gori_bot_forget(c: *const GoriCore, handle: *const c_char) -> i32 {
    run(|| {
        let h = text(handle)?;
        core(c)?.lock().bot_forget(h);
        Ok(())
    })
}

/// Owner's bot signatures: op 0 bot certificate, 1 admin key public key, 2 delete bot, 3 key rotation ([`Core::bot_sign`]). The result goes to `out`
/// # Safety
/// `salt` is `salt_len` bytes, `payload` is `payload_len` bytes
#[no_mangle]
pub unsafe extern "C" fn gori_bot_sign(
    c: *const GoriCore,
    op: u32,
    salt: *const u8,
    salt_len: usize,
    payload: *const u8,
    payload_len: usize,
    out: *mut GoriBuf,
) -> i32 {
    run(|| {
        need(out)?;
        let v = core(c)?.lock().bot_sign(op, bytes(salt, salt_len)?, bytes(payload, payload_len)?)?;
        put_buf(out, v)
    })
}
