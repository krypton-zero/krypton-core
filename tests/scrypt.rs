//! scrypt (RFC 7914): checks that the native port of the app's PIN hash is byte-for-byte identical to @noble/hashes.
//! Existing PIN hashes must keep matching exactly.
//! The JavaScript reference implementation recomputes the same expected values with @noble.
use gori_core::crypto;
use gori_core::ffi::gori_scrypt;
use gori_core::Error;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn ffi_scrypt(pw: &[u8], salt: &[u8], log_n: u32, r: u32, p: u32, len: usize) -> Result<Vec<u8>, i32> {
    let mut out = vec![0u8; len];
    let st = unsafe { gori_scrypt(pw.as_ptr(), pw.len(), salt.as_ptr(), salt.len(), log_n, r, p, out.as_mut_ptr(), len) };
    if st == 0 {
        Ok(out)
    } else {
        Err(st)
    }
}

/// RFC 7914 §12, fourth vector: P="pleaseletmein", S="SodiumChloride", N=16384, r=8, p=1, dkLen=64
#[test]
fn rfc7914_vector() {
    let got = ffi_scrypt(b"pleaseletmein", b"SodiumChloride", 14, 8, 1, 64).unwrap();
    assert_eq!(
        hex(&got),
        "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2\
         d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887"
    );
}

/// Same parameters as the app (N=2^14, r=8, p=1, 32 bytes): PIN "123456", salt 00..0f. The expected value was produced by
/// @noble/hashes 2.x scrypt (the JavaScript reference implementation recomputes it with @noble).
const PIN_123456_SALT_0_15: &str = "53e59f1f9f56c2317d99f7a1e76fd1d43677ccb19c2c125e054f9a81281e0aec";

#[test]
fn same_as_noble_for_app_pin() {
    let salt: Vec<u8> = (0u8..16).collect();
    assert_eq!(hex(&ffi_scrypt(b"123456", &salt, 14, 8, 1, 32).unwrap()), PIN_123456_SALT_0_15);
    let mut out = [0u8; 32];
    crypto::scrypt(b"123456", &salt, 14, 8, 1, &mut out).unwrap();
    assert_eq!(hex(&out), PIN_123456_SALT_0_15);
}

#[test]
fn out_of_range_is_invalid_argument_and_writes_nothing() {
    let bad = Error::InvalidArgument.code();
    let salt = [7u8; 16];
    // RFC 7914's third vector (N=1024, r=8, p=16) exceeds the upper bound on p (4)
    for (log_n, r, p, len) in [(9, 8, 1, 32), (21, 8, 1, 32), (14, 0, 1, 32), (14, 17, 1, 32), (14, 8, 0, 32), (10, 8, 16, 64), (14, 8, 1, 15), (14, 8, 1, 65)] {
        let mut out = vec![0xaau8; len.max(1)];
        let st = unsafe { gori_scrypt(b"pw".as_ptr(), 2, salt.as_ptr(), salt.len(), log_n, r, p, out.as_mut_ptr(), len) };
        assert_eq!(st, bad, "log_n={log_n} r={r} p={p} len={len}");
        assert!(out.iter().all(|&b| b == 0xaa), "nothing is written to out on failure");
    }
}

#[test]
fn null_out_and_null_inputs() {
    let bad = Error::InvalidArgument.code();
    let salt = [1u8; 16];
    assert_eq!(unsafe { gori_scrypt(b"pw".as_ptr(), 2, salt.as_ptr(), 16, 10, 1, 1, std::ptr::null_mut(), 32) }, bad);
    let mut out = [0u8; 32];
    // NULL with a nonzero length is rejected
    assert_eq!(unsafe { gori_scrypt(std::ptr::null(), 2, salt.as_ptr(), 16, 10, 1, 1, out.as_mut_ptr(), 32) }, bad);
    // Empty input (length 0) may be NULL: P and S in RFC 7914's first vector are empty strings
    assert_eq!(unsafe { gori_scrypt(std::ptr::null(), 0, std::ptr::null(), 0, 10, 1, 1, out.as_mut_ptr(), 32) }, 0);
    let mut again = [0u8; 32];
    crypto::scrypt(b"", b"", 10, 1, 1, &mut again).unwrap();
    assert_eq!(out, again);
}

#[test]
fn deterministic_and_salt_sensitive() {
    let a = ffi_scrypt(b"123456", &[0u8; 16], 10, 8, 1, 32).unwrap();
    let b = ffi_scrypt(b"123456", &[0u8; 16], 10, 8, 1, 32).unwrap();
    let c = ffi_scrypt(b"123456", &[1u8; 16], 10, 8, 1, 32).unwrap();
    assert_eq!(a, b);
    assert_ne!(a, c);
}
