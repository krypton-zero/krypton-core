//! Android JNI boundary. Called only by the Kotlin wrapper (`one.gori.securecore.RustCore`).
//!
//! Calls straight through to the C boundary ([`crate::ffi`]), so locking, zeroization and error codes are the same as on iOS
//! (Swift). This file only marshals byte arrays and strings. On failure it throws
//! `one.gori.securecore.GoriCoreException("<code>|<message>")`.
//!
//! As on iOS, a private key reaches Kotlin by exactly two paths: `slotSecret`, which exports it for storage under the Android
//! Keystore, and `loadVault`, which loads the stored key back. **Private keys never reach JavaScript**.
//! Vault entry names come from `slotVaultName`; the name doubles as a format tag (from the post-quantum version on, Account
//! and Enc hold seeds; legacy names give `StaleKey`).
#![allow(unsafe_code)]

use std::ffi::{c_char, CStr, CString};
use std::ptr;

use jni::objects::{JByteArray, JClass, JIntArray, JObjectArray, JString};
use jni::sys::{jboolean, jbyteArray, jint, jlong, jstring, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;
use zeroize::Zeroizing;

use crate::core::MAX_GUARDIANS;
use crate::error::Error;
use crate::ffi::{self, GoriBuf, GoriCore, HANDLE_BUF_LEN};
use crate::pq::{DSA_SIG_LEN, HEK_LEN, PK_D_LEN};
use crate::oprf::{ELEMENT_LEN, OUTPUT_LEN, PROOF_LEN};
use crate::ticket::{TICKET_BATCH_MAX, TICKET_INPUT_LEN};

const EXCEPTION: &str = "one/gori/securecore/GoriCoreException";
const BAD: i32 = Error::InvalidArgument as i32;

type R<T> = Result<T, i32>;

fn throw(env: &mut JNIEnv, code: i32) {
    let msg = Error::from_code(code)
        .and_then(|e| e.message().to_str().ok())
        .unwrap_or("Security core error");
    let _ = env.throw_new(EXCEPTION, format!("{code}|{msg}"));
}

/// On failure, throws an exception and returns `default` (a JNI call that returns with a pending exception throws it on the Kotlin side)
fn guard<T>(env: &mut JNIEnv, default: T, f: impl FnOnce(&mut JNIEnv) -> R<T>) -> T {
    match f(env) {
        Ok(v) => v,
        Err(code) => {
            throw(env, code);
            default
        }
    }
}

fn check(status: i32) -> R<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(status)
    }
}

fn core(c: jlong) -> R<*const GoriCore> {
    if c == 0 {
        Err(BAD)
    } else {
        Ok(c as *const GoriCore)
    }
}

fn bytes(env: &mut JNIEnv, a: &JByteArray) -> R<Vec<u8>> {
    env.convert_byte_array(a).map_err(|_| BAD)
}

/// Copies a secret (private key, plaintext, recovery share) in from Kotlin. It is zeroed when dropped on every return path
/// (including early returns through `?`). `convert_byte_array` allocates once at the exact length, so no other copy is left behind
fn secret_bytes(env: &mut JNIEnv, a: &JByteArray) -> R<Zeroizing<Vec<u8>>> {
    bytes(env, a).map(Zeroizing::new)
}

fn text(env: &mut JNIEnv, s: &JString) -> R<CString> {
    let st: String = env.get_string(s).map_err(|_| BAD)?.into();
    CString::new(st).map_err(|_| BAD)
}

fn out(env: &mut JNIEnv, v: &[u8]) -> R<jbyteArray> {
    env.byte_array_from_slice(v).map(|a| a.into_raw()).map_err(|_| BAD)
}

/// Copies a buffer returned by the Rust core into a Kotlin array and frees it (zeroing it on free)
fn take(env: &mut JNIEnv, buf: GoriBuf) -> R<jbyteArray> {
    let r = if buf.ptr.is_null() || buf.len == 0 {
        out(env, &[])
    } else {
        // SAFETY: buf was just filled by this library
        let s = unsafe { std::slice::from_raw_parts(buf.ptr, buf.len) };
        out(env, s)
    };
    // SAFETY: freed exactly once
    unsafe { ffi::gori_buf_free(buf) };
    r
}

fn handle_string(env: &mut JNIEnv, h: &[c_char; HANDLE_BUF_LEN]) -> R<jstring> {
    // SAFETY: the core wrote a NUL-terminated string
    let s = unsafe { CStr::from_ptr(h.as_ptr()) }.to_str().map_err(|_| BAD)?;
    env.new_string(s).map(|j| j.into_raw()).map_err(|_| BAD)
}

const fn empty_buf() -> GoriBuf {
    GoriBuf { ptr: ptr::null_mut(), len: 0 }
}

// ── Lifetime ──

#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_coreNew(_env: JNIEnv, _: JClass) -> jlong {
    ffi::gori_core_new() as jlong
}

#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_coreFree(_env: JNIEnv, _: JClass, c: jlong) {
    if c != 0 {
        // SAFETY: frees the pointer returned by coreNew exactly once (Kotlin keeps it until the app exits)
        unsafe { ffi::gori_core_free(c as *mut GoriCore) };
    }
}

// ── Private key slots ──

#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_generate(
    mut env: JNIEnv,
    _: JClass,
    c: jlong,
    slot: jint,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let mut pubk = [0u8; 32];
        check(unsafe { ffi::gori_generate(core(c)?, slot as u32, pubk.as_mut_ptr()) })?;
        out(env, &pubk)
    })
}

/// Vault entry name for a slot (ffi::gori_slot_vault_name). `InvalidArgument` for an unknown slot
#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_slotVaultName(
    mut env: JNIEnv,
    _: JClass,
    slot: jint,
) -> jstring {
    guard(&mut env, ptr::null_mut(), |env| {
        let p = ffi::gori_slot_vault_name(slot as u32);
        if p.is_null() {
            return Err(BAD);
        }
        // SAFETY: a static NUL-terminated string owned by the core
        let name = unsafe { CStr::from_ptr(p) }.to_str().map_err(|_| BAD)?;
        env.new_string(name).map(|j| j.into_raw()).map_err(|_| BAD)
    })
}

/// Loads a stored private key by its vault entry name (ffi::gori_load_vault). Legacy names ("account", "enc") give `StaleKey`
#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_loadVault(
    mut env: JNIEnv,
    _: JClass,
    c: jlong,
    name: JString,
    secret: JByteArray,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        // Validate the core handle before copying the secret in
        let p = core(c)?;
        let n = text(env, &name)?;
        let s = secret_bytes(env, &secret)?;
        let mut pubk = [0u8; 32];
        check(unsafe { ffi::gori_load_vault(p, n.as_ptr(), s.as_ptr(), s.len(), pubk.as_mut_ptr()) })?;
        out(env, &pubk)
    })
}

/// Briefly exports a private key so it can be stored under the Android Keystore
#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_slotSecret(
    mut env: JNIEnv,
    _: JClass,
    c: jlong,
    slot: jint,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let p = core(c)?;
        let mut s = Zeroizing::new([0u8; 32]);
        check(unsafe { ffi::gori_slot_secret(p, slot as u32, s.as_mut_ptr()) })?;
        out(env, &*s)
    })
}

#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_clear(_env: JNIEnv, _: JClass, c: jlong, slot: jint) {
    if let Ok(p) = core(c) {
        unsafe { ffi::gori_clear(p, slot as u32) };
    }
}

#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_has(
    mut env: JNIEnv,
    _: JClass,
    c: jlong,
    slot: jint,
) -> jboolean {
    guard(&mut env, JNI_FALSE, |_| {
        let mut o = 0u8;
        check(unsafe { ffi::gori_has(core(c)?, slot as u32, &mut o) })?;
        Ok(if o == 1 { JNI_TRUE } else { JNI_FALSE })
    })
}

#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_publicKey(
    mut env: JNIEnv,
    _: JClass,
    c: jlong,
    slot: jint,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let mut pubk = [0u8; 32];
        check(unsafe { ffi::gori_public_key(core(c)?, slot as u32, pubk.as_mut_ptr()) })?;
        out(env, &pubk)
    })
}

// ── Signing ──

#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_sign(
    mut env: JNIEnv,
    _: JClass,
    c: jlong,
    slot: jint,
    msg: JByteArray,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let m = bytes(env, &msg)?;
        let mut sig = [0u8; 64];
        check(unsafe { ffi::gori_sign(core(c)?, slot as u32, m.as_ptr(), m.len(), sig.as_mut_ptr()) })?;
        out(env, &sig)
    })
}

/// Device certificate v2: signs this core's device key with the account key (ffi::gori_sign_device_certificate)
#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_signDeviceCertificate(
    mut env: JNIEnv,
    _: JClass,
    c: jlong,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let mut sig = [0u8; 64];
        check(unsafe { ffi::gori_sign_device_certificate(core(c)?, sig.as_mut_ptr()) })?;
        out(env, &sig)
    })
}

/// Encryption key signature v2: signs this core's encryption key with the account key (ffi::gori_sign_encryption_key)
#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_signEncryptionKey(
    mut env: JNIEnv,
    _: JClass,
    c: jlong,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let mut sig = [0u8; 64];
        check(unsafe { ffi::gori_sign_encryption_key(core(c)?, sig.as_mut_ptr()) })?;
        out(env, &sig)
    })
}

/// Encryption key signature v3 (es3): signs this core's HEK with the account key (ffi::gori_sign_encryption_key_v3)
#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_signEncryptionKeyV3(
    mut env: JNIEnv,
    _: JClass,
    c: jlong,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let mut sig = [0u8; 64];
        check(unsafe { ffi::gori_sign_encryption_key_v3(core(c)?, sig.as_mut_ptr()) })?;
        out(env, &sig)
    })
}

/// This core's HEK(1216) = pk_M ‖ pk_X
#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_encryptionHybridKey(
    mut env: JNIEnv,
    _: JClass,
    c: jlong,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let mut k = [0u8; HEK_LEN];
        check(unsafe { ffi::gori_encryption_hybrid_key(core(c)?, k.as_mut_ptr()) })?;
        out(env, &k)
    })
}

/// Validates a received HEK; throws `NeedHybridKey` or `WeakKey` if it is invalid
#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_checkHybridKey(mut env: JNIEnv, _: JClass, hek: JByteArray) {
    guard(&mut env, (), |env| {
        let k = bytes(env, &hek)?;
        check(unsafe { ffi::gori_check_hybrid_key(k.as_ptr(), k.len()) })
    })
}

/// Opens a notification hint by trying each key in the key ring (no core instance needed). Returns `kind(1) ‖ peer(16) ‖ plaintext`
/// (Kotlin splits it). Throws (6) if no key opens it. The ring holds keys, so it is copied with [`secret_bytes`] (zeroed when dropped)
#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_openHint(
    mut env: JNIEnv,
    _: JClass,
    ring: JByteArray,
    kinds: jint,
    sealed: JByteArray,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let r = secret_bytes(env, &ring)?;
        let g = bytes(env, &sealed)?;
        let mut o = empty_buf();
        let mut tag = [0u8; crate::hint::HINT_TAG_LEN];
        check(unsafe { ffi::gori_open_hint(r.as_ptr(), r.len(), kinds as u32, g.as_ptr(), g.len(), &mut o, tag.as_mut_ptr()) })?;
        let plain = if o.ptr.is_null() || o.len == 0 {
            Zeroizing::new(Vec::new())
        } else {
            // SAFETY: o was just filled by this library
            Zeroizing::new(unsafe { std::slice::from_raw_parts(o.ptr, o.len) }.to_vec())
        };
        // SAFETY: freed exactly once (zeroed on free)
        unsafe { ffi::gori_buf_free(o) };
        let mut all = Zeroizing::new(Vec::with_capacity(tag.len() + plain.len()));
        all.extend_from_slice(&tag);
        all.extend_from_slice(&plain);
        out(env, &all)
    })
}

/// Identity key binding: pk_D(1952) ‖ dh(32) ‖ ds(64) ‖ dq(3309) concatenated, 5,357 bytes (Kotlin splits it). Public values only
#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_pqSigBinding(
    mut env: JNIEnv,
    _: JClass,
    c: jlong,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let mut all = vec![0u8; PK_D_LEN + 32 + 64 + DSA_SIG_LEN];
        let (pk_d, rest) = all.split_at_mut(PK_D_LEN);
        let (dh, rest) = rest.split_at_mut(32);
        let (ds, dq) = rest.split_at_mut(64);
        check(unsafe {
            ffi::gori_pq_sig_binding(core(c)?, pk_d.as_mut_ptr(), dh.as_mut_ptr(), ds.as_mut_ptr(), dq.as_mut_ptr())
        })?;
        out(env, &all)
    })
}

#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_verifyPqSigBinding(
    mut env: JNIEnv,
    _: JClass,
    ik: JByteArray,
    pk_d: JByteArray,
    dh: JByteArray,
    ds: JByteArray,
    dq: JByteArray,
) -> jboolean {
    guard(&mut env, JNI_FALSE, |env| {
        let (a, b, c, d, e) = (bytes(env, &ik)?, bytes(env, &pk_d)?, bytes(env, &dh)?, bytes(env, &ds)?, bytes(env, &dq)?);
        let ok = unsafe {
            ffi::gori_verify_pq_sig_binding(
                a.as_ptr(),
                a.len(),
                b.as_ptr(),
                b.len(),
                c.as_ptr(),
                c.len(),
                d.as_ptr(),
                d.len(),
                e.as_ptr(),
                e.len(),
            )
        };
        Ok(if ok == 1 { JNI_TRUE } else { JNI_FALSE })
    })
}

#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_verify(
    mut env: JNIEnv,
    _: JClass,
    pubkey: JByteArray,
    msg: JByteArray,
    sig: JByteArray,
) -> jboolean {
    guard(&mut env, JNI_FALSE, |env| {
        let (p, m, s) = (bytes(env, &pubkey)?, bytes(env, &msg)?, bytes(env, &sig)?);
        let ok = unsafe { ffi::gori_verify(p.as_ptr(), p.len(), m.as_ptr(), m.len(), s.as_ptr(), s.len()) };
        Ok(if ok == 1 { JNI_TRUE } else { JNI_FALSE })
    })
}

// ── Content keys ──

#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_createContentKey(
    mut env: JNIEnv,
    _: JClass,
    c: jlong,
) -> jstring {
    guard(&mut env, ptr::null_mut(), |env| {
        let mut h = [0 as c_char; HANDLE_BUF_LEN];
        check(unsafe { ffi::gori_create_content_key(core(c)?, h.as_mut_ptr()) })?;
        handle_string(env, &h)
    })
}

#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_encrypt(
    mut env: JNIEnv,
    _: JClass,
    c: jlong,
    handle: JString,
    pt: JByteArray,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let h = text(env, &handle)?;
        // Plaintext copy: wiped when dropped, like decrypted plaintext returned through take → gori_buf_free
        let p = secret_bytes(env, &pt)?;
        let mut o = empty_buf();
        check(unsafe { ffi::gori_encrypt(core(c)?, h.as_ptr(), p.as_ptr(), p.len(), &mut o) })?;
        take(env, o)
    })
}

#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_decrypt(
    mut env: JNIEnv,
    _: JClass,
    c: jlong,
    handle: JString,
    ct: JByteArray,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let h = text(env, &handle)?;
        let x = bytes(env, &ct)?;
        let mut o = empty_buf();
        check(unsafe { ffi::gori_decrypt(core(c)?, h.as_ptr(), x.as_ptr(), x.len(), &mut o) })?;
        take(env, o)
    })
}

/// Outer envelope v2 (1201 B); the recipient key is a HEK(1216). `purpose`: 0 key envelope, 1 body seal, 2 inbox copy or pair bundle
#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_sealOuter(
    mut env: JNIEnv,
    _: JClass,
    c: jlong,
    handle: JString,
    purpose: jint,
    hek: JByteArray,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let h = text(env, &handle)?;
        let r = bytes(env, &hek)?;
        let mut o = empty_buf();
        check(unsafe { ffi::gori_seal_outer(core(c)?, h.as_ptr(), purpose as u32, r.as_ptr(), r.len(), &mut o) })?;
        take(env, o)
    })
}

/// Opens outer envelope v2 (1201 B only)
#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_openOuter(
    mut env: JNIEnv,
    _: JClass,
    c: jlong,
    purpose: jint,
    envelope: JByteArray,
) -> jstring {
    guard(&mut env, ptr::null_mut(), |env| {
        let e = bytes(env, &envelope)?;
        let mut h = [0 as c_char; HANDLE_BUF_LEN];
        check(unsafe { ffi::gori_open_outer(core(c)?, purpose as u32, e.as_ptr(), e.len(), h.as_mut_ptr()) })?;
        handle_string(env, &h)
    })
}

/// Inner envelope (X25519, 104 B; the same bytes as the earlier sealTo). Used only inside pair notes
#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_sealInner(
    mut env: JNIEnv,
    _: JClass,
    c: jlong,
    handle: JString,
    recipient: JByteArray,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let h = text(env, &handle)?;
        let r = bytes(env, &recipient)?;
        let mut o = empty_buf();
        check(unsafe { ffi::gori_seal_inner(core(c)?, h.as_ptr(), r.as_ptr(), r.len(), &mut o) })?;
        take(env, o)
    })
}

/// Opens an inner envelope (104 B only)
#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_openInner(
    mut env: JNIEnv,
    _: JClass,
    c: jlong,
    envelope: JByteArray,
) -> jstring {
    guard(&mut env, ptr::null_mut(), |env| {
        let e = bytes(env, &envelope)?;
        let mut h = [0 as c_char; HANDLE_BUF_LEN];
        check(unsafe { ffi::gori_open_inner(core(c)?, e.as_ptr(), e.len(), h.as_mut_ptr()) })?;
        handle_string(env, &h)
    })
}

#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_wrapKey(
    mut env: JNIEnv,
    _: JClass,
    c: jlong,
    kek: JString,
    key: JString,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let (a, b) = (text(env, &kek)?, text(env, &key)?);
        let mut o = empty_buf();
        check(unsafe { ffi::gori_wrap_key(core(c)?, a.as_ptr(), b.as_ptr(), &mut o) })?;
        take(env, o)
    })
}

#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_unwrapKey(
    mut env: JNIEnv,
    _: JClass,
    c: jlong,
    kek: JString,
    wrapped: JByteArray,
) -> jstring {
    guard(&mut env, ptr::null_mut(), |env| {
        let a = text(env, &kek)?;
        let w = bytes(env, &wrapped)?;
        let mut h = [0 as c_char; HANDLE_BUF_LEN];
        check(unsafe { ffi::gori_unwrap_key(core(c)?, a.as_ptr(), w.as_ptr(), w.len(), h.as_mut_ptr()) })?;
        handle_string(env, &h)
    })
}

// ── Chunked files (paths are file system paths, not file:// URIs) ──

#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_encryptFile(
    mut env: JNIEnv,
    _: JClass,
    c: jlong,
    handle: JString,
    input: JString,
    output: JString,
) {
    guard(&mut env, (), |env| {
        let (h, i, o) = (text(env, &handle)?, text(env, &input)?, text(env, &output)?);
        check(unsafe { ffi::gori_encrypt_file(core(c)?, h.as_ptr(), i.as_ptr(), o.as_ptr()) })
    })
}

#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_decryptFile(
    mut env: JNIEnv,
    _: JClass,
    c: jlong,
    handle: JString,
    input: JString,
    output: JString,
) {
    guard(&mut env, (), |env| {
        let (h, i, o) = (text(env, &handle)?, text(env, &input)?, text(env, &output)?);
        check(unsafe { ffi::gori_decrypt_file(core(c)?, h.as_ptr(), i.as_ptr(), o.as_ptr()) })
    })
}

/// Decrypts to a cache file, without fsync (ffi::gori_decrypt_cache_file)
#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_decryptCacheFile(
    mut env: JNIEnv,
    _: JClass,
    c: jlong,
    handle: JString,
    input: JString,
    output: JString,
) {
    guard(&mut env, (), |env| {
        let (h, i, o) = (text(env, &handle)?, text(env, &input)?, text(env, &output)?);
        check(unsafe { ffi::gori_decrypt_cache_file(core(c)?, h.as_ptr(), i.as_ptr(), o.as_ptr()) })
    })
}

/// Decrypt while downloading (ffi::gori_decrypt_file_range): writes plaintext from the start of `out` and returns the number of
/// bytes written (straight into the array handed over by Kotlin's `ProxyFileDescriptorCallback.onRead`, so no extra copy is made on
/// the Java heap). The requested length is the length of `out`. Throws 37 (StreamNotYet) if that range has not been received yet
#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_decryptFileRange(
    mut env: JNIEnv,
    _: JClass,
    c: jlong,
    handle: JString,
    input: JString,
    total: jlong,
    start: jlong,
    out: JByteArray,
) -> jint {
    guard(&mut env, -1, |env| {
        if total < 0 || start < 0 {
            return Err(BAD);
        }
        let (h, i) = (text(env, &handle)?, text(env, &input)?);
        let want = env.get_array_length(&out).map_err(|_| BAD)? as u64;
        let mut o = empty_buf();
        check(unsafe { ffi::gori_decrypt_file_range(core(c)?, h.as_ptr(), i.as_ptr(), total as u64, start as u64, want, &mut o) })?;
        let n = o.len;
        let r = if o.ptr.is_null() || n == 0 {
            Ok(0)
        } else {
            // SAFETY: o was just filled by the core. Viewing it as i8 matches JNI's jbyte type (same bytes)
            let s = unsafe { std::slice::from_raw_parts(o.ptr as *const i8, n) };
            env.set_byte_array_region(&out, 0, s).map(|_| n as jint).map_err(|_| BAD)
        };
        // SAFETY: freed exactly once (zeroed on free)
        unsafe { ffi::gori_buf_free(o) };
        r
    })
}

// ── Account recovery ──

/// Prepares recovery for the given guardian public keys (32 bytes each, concatenated).
/// Returns `share length(4, BE) ‖ backup length(4, BE) ‖ backup ‖ server share(32) ‖ sealed shares`
#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_prepareRecovery(
    mut env: JNIEnv,
    _: JClass,
    c: jlong,
    pubkeys: JByteArray,
    count: jint,
    threshold: jint,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let p = bytes(env, &pubkeys)?;
        // checked_mul: on 32-bit targets (armv7), count × 32 must not overflow and slip past the length check
        if count < 0 || threshold < 0 || Some(p.len()) != (count as usize).checked_mul(32) {
            return Err(BAD);
        }
        let (mut backup, mut shares) = (empty_buf(), empty_buf());
        // The server share U and the packed output that contains it are both Zeroizing
        let mut server = Zeroizing::new([0u8; 32]);
        let mut share_len: usize = 0;
        check(unsafe {
            ffi::gori_prepare_recovery(
                core(c)?,
                p.as_ptr(),
                count as usize,
                threshold as usize,
                &mut backup,
                server.as_mut_ptr(),
                &mut shares,
                &mut share_len,
            )
        })?;
        let view = |b: &GoriBuf| -> Vec<u8> {
            if b.ptr.is_null() || b.len == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(b.ptr, b.len) }.to_vec()
            }
        };
        let (b, s) = (view(&backup), view(&shares));
        unsafe {
            ffi::gori_buf_free(backup);
            ffi::gori_buf_free(shares);
        }
        // Allocate the exact length up front so the buffer never grows (a realloc would free the old buffer without wiping it)
        let mut packed = Zeroizing::new(Vec::with_capacity(8 + b.len() + 32 + s.len()));
        packed.extend_from_slice(&(share_len as u32).to_be_bytes());
        packed.extend_from_slice(&(b.len() as u32).to_be_bytes());
        packed.extend_from_slice(&b);
        packed.extend_from_slice(&*server);
        packed.extend_from_slice(&s);
        out(env, &packed)
    })
}

/// Temporary receiving key for a new device: `public key(32) ‖ newly created(1)`
#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_beginRecovery(
    mut env: JNIEnv,
    _: JClass,
    c: jlong,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let mut pubk = [0u8; 32];
        let mut created = 0u8;
        check(unsafe { ffi::gori_begin_recovery(core(c)?, pubk.as_mut_ptr(), &mut created) })?;
        let mut o = pubk.to_vec();
        o.push(created);
        out(env, &o)
    })
}

#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_resealShare(
    mut env: JNIEnv,
    _: JClass,
    c: jlong,
    sealed: JByteArray,
    to: JByteArray,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let (s, t) = (bytes(env, &sealed)?, bytes(env, &to)?);
        let mut o = empty_buf();
        check(unsafe { ffi::gori_reseal_share(core(c)?, s.as_ptr(), s.len(), t.as_ptr(), t.len(), &mut o) })?;
        take(env, o)
    })
}

/// Recovers both private keys from the collected shares; returns `account public key(32) ‖ encryption public key(32)`.
/// If the recovered account public key differs from `expected_account`(32), or would overwrite a different key already present,
/// nothing is imported and it throws (30, 22)
#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_completeRecovery(
    mut env: JNIEnv,
    _: JClass,
    c: jlong,
    backup: JByteArray,
    shares: JObjectArray,
    server: JByteArray,
    expected_account: JByteArray,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let b = bytes(env, &backup)?;
        let expected = bytes(env, &expected_account)?;
        // Copies of the server share U and of the sealed shares are wiped even on an early return after a failure
        let sv = secret_bytes(env, &server)?;
        let n = env.get_array_length(&shares).map_err(|_| BAD)?;
        // Reject too many shares before copying them in (the C boundary checks the same limit again)
        if n < 0 || n as usize > MAX_GUARDIANS {
            return Err(Error::BadShareCount as i32);
        }
        let mut copies: Vec<Zeroizing<Vec<u8>>> = Vec::with_capacity(n.max(0) as usize);
        for i in 0..n {
            let el = env.get_object_array_element(&shares, i).map_err(|_| BAD)?;
            copies.push(secret_bytes(env, &JByteArray::from(el))?);
        }
        let ptrs: Vec<*const u8> = copies.iter().map(|v| v.as_ptr()).collect();
        let lens: Vec<usize> = copies.iter().map(|v| v.len()).collect();
        let (mut acc, mut enc) = ([0u8; 32], [0u8; 32]);
        check(unsafe {
            ffi::gori_complete_recovery(
                core(c)?,
                b.as_ptr(),
                b.len(),
                ptrs.as_ptr(),
                lens.as_ptr(),
                copies.len(),
                sv.as_ptr(),
                sv.len(),
                expected.as_ptr(),
                expected.len(),
                acc.as_mut_ptr(),
                enc.as_mut_ptr(),
            )
        })?;
        let mut o = acc.to_vec();
        o.extend_from_slice(&enc);
        out(env, &o)
    })
}

// ── Self-recovery v3: paper phrase ──
//
// Phrases are passed as UTF-8 byte arrays (words separated by spaces) rather than strings, so they can be overwritten with
// fill(0) after use (a String cannot be wiped). The copies made here are Zeroizing

/// Prepares paper-phrase self-recovery; returns `phrase length(4, BE) ‖ phrase(UTF-8) ‖ backup length(4, BE) ‖ backup ‖ U(32) ‖ L(32)`
#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_prepareSelfRecovery(
    mut env: JNIEnv,
    _: JClass,
    c: jlong,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let (mut phrase, mut backup) = (empty_buf(), empty_buf());
        let mut server = Zeroizing::new([0u8; 32]);
        let mut locator = [0u8; 32];
        check(unsafe {
            ffi::gori_prepare_self_recovery(core(c)?, &mut phrase, &mut backup, server.as_mut_ptr(), locator.as_mut_ptr())
        })?;
        let view = |b: &GoriBuf| -> &[u8] {
            if b.ptr.is_null() || b.len == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(b.ptr, b.len) }
            }
        };
        // Allocate the exact length up front so the buffer never grows (a realloc would free the old buffer without wiping it)
        let (p, b) = (view(&phrase), view(&backup));
        let mut packed = Zeroizing::new(Vec::with_capacity(8 + p.len() + b.len() + 64));
        packed.extend_from_slice(&(p.len() as u32).to_be_bytes());
        packed.extend_from_slice(p);
        packed.extend_from_slice(&(b.len() as u32).to_be_bytes());
        packed.extend_from_slice(b);
        packed.extend_from_slice(&*server);
        packed.extend_from_slice(&locator);
        unsafe {
            ffi::gori_buf_free(phrase);
            ffi::gori_buf_free(backup);
        }
        out(env, &packed)
    })
}

/// Phrase → locator L(32). No core instance needed
#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_recoveryLocator(
    mut env: JNIEnv,
    _: JClass,
    phrase: JByteArray,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let p = secret_bytes(env, &phrase)?;
        let mut l = [0u8; 32];
        check(unsafe { ffi::gori_recovery_locator(p.as_ptr(), p.len(), l.as_mut_ptr()) })?;
        out(env, &l)
    })
}

/// scrypt (RFC 7914) for the app's PIN hash. No core instance needed. Throws (18) if a parameter is out of range. The PIN is copied
/// with [`secret_bytes`] (zeroed when dropped), and the result is also wiped after it is copied into the Kotlin array
#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_scrypt(
    mut env: JNIEnv,
    _: JClass,
    pw: JByteArray,
    salt: JByteArray,
    log_n: jint,
    r: jint,
    p: jint,
    len: jint,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let pw = secret_bytes(env, &pw)?;
        let salt = bytes(env, &salt)?;
        // Negative values become large u32 values and fail the range check
        let n = usize::try_from(len).map_err(|_| BAD)?;
        if !crate::crypto::SCRYPT_LEN.contains(&n) {
            return Err(BAD);
        }
        let mut o = Zeroizing::new(vec![0u8; n]);
        check(unsafe {
            ffi::gori_scrypt(pw.as_ptr(), pw.len(), salt.as_ptr(), salt.len(), log_n as u32, r as u32, p as u32, o.as_mut_ptr(), n)
        })?;
        out(env, &o)
    })
}

/// Recovers both private keys from the phrase, U and the backup; returns `account public key(32) ‖ encryption public key(32)`.
/// If the recovered account public key differs from `expected_account`(32), or would overwrite a different key already present,
/// nothing is imported and it throws (30, 22)
#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_completeSelfRecovery(
    mut env: JNIEnv,
    _: JClass,
    c: jlong,
    phrase: JByteArray,
    backup: JByteArray,
    server: JByteArray,
    expected_account: JByteArray,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let p = secret_bytes(env, &phrase)?;
        let b = bytes(env, &backup)?;
        let sv = secret_bytes(env, &server)?;
        let expected = bytes(env, &expected_account)?;
        let (mut acc, mut enc) = ([0u8; 32], [0u8; 32]);
        check(unsafe {
            ffi::gori_complete_self_recovery(
                core(c)?,
                p.as_ptr(),
                p.len(),
                b.as_ptr(),
                b.len(),
                sv.as_ptr(),
                sv.len(),
                expected.as_ptr(),
                expected.len(),
                acc.as_mut_ptr(),
                enc.as_mut_ptr(),
            )
        })?;
        let mut o = acc.to_vec();
        o.extend_from_slice(&enc);
        out(env, &o)
    })
}

#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_forgetAll(mut env: JNIEnv, _: JClass, c: jlong) {
    guard(&mut env, (), |_| check(unsafe { ffi::gori_forget_all(core(c)?) }))
}

// ── Invite tickets (RFC 9497 VOPRF ristretto255-SHA512) ──

const TICKET_INPUT: i32 = Error::TicketInput as i32;

/// Kotlin Int indices → u32, bit for bit (indices of 2^31 or more arrive as negative Ints). `TicketInput` for zero or more than 64 indices
fn ticket_indices(env: &mut JNIEnv, a: &JIntArray) -> R<Vec<u32>> {
    let n = env.get_array_length(a).map_err(|_| BAD)?;
    if n <= 0 || n as usize > TICKET_BATCH_MAX {
        return Err(TICKET_INPUT);
    }
    let mut v = vec![0 as jint; n as usize];
    env.get_int_array_region(a, 0, &mut v).map_err(|_| BAD)?;
    Ok(v.into_iter().map(|i| i as u32).collect())
}

/// 32-byte period salt. The copy made here is wiped when dropped
fn ticket_salt(env: &mut JNIEnv, a: &JByteArray) -> R<Zeroizing<Vec<u8>>> {
    let s = secret_bytes(env, a)?;
    if s.len() != 32 {
        return Err(BAD);
    }
    Ok(s)
}

/// Kind (0 to 255) and period (0 to 2^32-1); `TicketInput` if out of range
fn ticket_kind_period(kind: jint, period: jlong) -> R<(u8, u32)> {
    let k = u8::try_from(kind).map_err(|_| TICKET_INPUT)?;
    let p = u32::try_from(period).map_err(|_| TICKET_INPUT)?;
    Ok((k, p))
}

/// One blinded element per index; returns the 32 × count bytes concatenated
#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_ticketBlind(
    mut env: JNIEnv,
    _: JClass,
    c: jlong,
    kind: jint,
    period: jlong,
    period_salt: JByteArray,
    indices: JIntArray,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let (k, p) = ticket_kind_period(kind, period)?;
        let salt = ticket_salt(env, &period_salt)?;
        let idx = ticket_indices(env, &indices)?;
        let mut blinded = vec![0u8; idx.len() * ELEMENT_LEN];
        check(unsafe {
            ffi::gori_ticket_blind(core(c)?, k, p, salt.as_ptr(), idx.as_ptr(), idx.len(), blinded.as_mut_ptr())
        })?;
        out(env, &blinded)
    })
}

/// Verifies the server's response and produces the tickets; returns `input(32) ‖ output(64)` per ticket, concatenated
#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_ticketFinalize(
    mut env: JNIEnv,
    _: JClass,
    c: jlong,
    kind: jint,
    period: jlong,
    period_salt: JByteArray,
    indices: JIntArray,
    server_pub: JByteArray,
    evaluated: JByteArray,
    proof: JByteArray,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let (k, p) = ticket_kind_period(kind, period)?;
        let salt = ticket_salt(env, &period_salt)?;
        let idx = ticket_indices(env, &indices)?;
        let n = idx.len();
        let pk = bytes(env, &server_pub)?;
        let ev = bytes(env, &evaluated)?;
        let pr = bytes(env, &proof)?;
        if pk.len() != ELEMENT_LEN || pr.len() != PROOF_LEN {
            return Err(BAD);
        }
        if ev.len() != n * ELEMENT_LEN {
            return Err(TICKET_INPUT);
        }
        // Tickets are bearer tokens, so they are wiped when dropped. Allocated at the exact length so the buffers never grow and move
        let mut ins = Zeroizing::new(vec![0u8; n * TICKET_INPUT_LEN]);
        let mut outs = Zeroizing::new(vec![0u8; n * OUTPUT_LEN]);
        check(unsafe {
            ffi::gori_ticket_finalize(
                core(c)?,
                k,
                p,
                salt.as_ptr(),
                idx.as_ptr(),
                n,
                pk.as_ptr(),
                ev.as_ptr(),
                pr.as_ptr(),
                ins.as_mut_ptr(),
                outs.as_mut_ptr(),
            )
        })?;
        let mut packed = Zeroizing::new(Vec::with_capacity(n * (TICKET_INPUT_LEN + OUTPUT_LEN)));
        for (i, o) in ins.as_chunks::<TICKET_INPUT_LEN>().0.iter().zip(outs.as_chunks::<OUTPUT_LEN>().0) {
            packed.extend_from_slice(i);
            packed.extend_from_slice(o);
        }
        out(env, &packed)
    })
}

// ── Bot keys (src/bot.rs) ──

/// handle ‖ public bundle. Kotlin splits off the first 32 bytes (the handle, always 32 hex characters encoding 16 bytes) from the rest
#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_botCreate(mut env: JNIEnv, _: JClass, c: jlong) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let mut h = [0 as c_char; HANDLE_BUF_LEN];
        let mut o = empty_buf();
        check(unsafe { ffi::gori_bot_create(core(c)?, h.as_mut_ptr(), &mut o) })?;
        // SAFETY: the core wrote a NUL-terminated string
        let mut all = unsafe { CStr::from_ptr(h.as_ptr()) }.to_bytes().to_vec();
        if !o.ptr.is_null() && o.len > 0 {
            // SAFETY: o was just filled by this library
            all.extend_from_slice(unsafe { std::slice::from_raw_parts(o.ptr, o.len) });
        }
        // SAFETY: freed exactly once
        unsafe { ffi::gori_buf_free(o) };
        out(env, &all)
    })
}

#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_botKeyFile(
    mut env: JNIEnv,
    _: JClass,
    c: jlong,
    handle: JString,
    meta: JByteArray,
    path: JString,
) {
    guard(&mut env, (), |env| {
        let (h, p) = (text(env, &handle)?, text(env, &path)?);
        let m = bytes(env, &meta)?;
        check(unsafe { ffi::gori_bot_key_file(core(c)?, h.as_ptr(), m.as_ptr(), m.len(), p.as_ptr()) })
    })
}

#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_botForget(mut env: JNIEnv, _: JClass, c: jlong, handle: JString) {
    guard(&mut env, (), |env| {
        let h = text(env, &handle)?;
        check(unsafe { ffi::gori_bot_forget(core(c)?, h.as_ptr()) })
    })
}

#[no_mangle]
pub extern "system" fn Java_one_gori_securecore_RustCore_botSign(
    mut env: JNIEnv,
    _: JClass,
    c: jlong,
    op: jint,
    salt: JByteArray,
    payload: JByteArray,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let s = bytes(env, &salt)?;
        let p = bytes(env, &payload)?;
        let op = u32::try_from(op).map_err(|_| BAD)?;
        let mut o = empty_buf();
        check(unsafe { ffi::gori_bot_sign(core(c)?, op, s.as_ptr(), s.len(), p.as_ptr(), p.len(), &mut o) })?;
        take(env, o)
    })
}
