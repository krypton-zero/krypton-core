//! Bot keys (src/bot.rs): creation, public blob, key file, bot mailbox, owner signatures, and the C boundary.
#![allow(unsafe_code)]

use std::ffi::{c_char, CStr, CString};

use gori_core::bot::{
    self, box_write, BotKeys, BOT_PUBLIC_LEN, BOT_SIGN_ADMIN_KEY, BOT_SIGN_CERT, BOT_SIGN_DELETE, BOT_SIGN_REKEY,
};
use gori_core::crypto::{self, ed25519_verify};
use gori_core::ffi;
use gori_core::pq::{self, DSA_SIG_LEN, HEK_LEN, PK_D_LEN};
use gori_core::{Core, Error, Slot};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

const OWNER: [u8; 32] = [7u8; 32];
/// Admin payloads as the server builds them: bot id 0a0a0a0a-1111-4222-8333-944455566601, timestamp 1790000000000 (u64, big-endian),
/// and for rekey a new 32-byte key (9×32). The JavaScript reference implementation uses the same values.
const DELETE_PAYLOAD: &str = "0a0a0a0a111142228333944455566601000001a0c4506c00";
const REKEY_PAYLOAD: &str = "0a0a0a0a111142228333944455566601000001a0c4506c000909090909090909090909090909090909090909090909090909090909090909";

fn owner() -> Core {
    let mut c = Core::new();
    c.load(Slot::Account, &OWNER).unwrap();
    c
}

fn unb64(s: &str) -> Vec<u8> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for ch in s.bytes().filter(|&b| b != b'=') {
        acc = (acc << 6) | T.iter().position(|&t| t == ch).unwrap() as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

fn arr32(b: &[u8]) -> [u8; 32] {
    b.try_into().unwrap()
}

/// Splits the public blob into its fields (in the order of BotKeys::public_blob in src/bot.rs)
struct Pub<'a> {
    ik: &'a [u8],
    dev: &'a [u8],
    cert: &'a [u8],
    ek: &'a [u8],
    es: &'a [u8],
    hek: &'a [u8],
    es3: &'a [u8],
    pk_d: &'a [u8],
    dh: &'a [u8],
    ds: &'a [u8],
    dq: &'a [u8],
    box_id: &'a [u8],
}
fn split(b: &[u8]) -> Pub<'_> {
    let mut at = 0;
    let mut take = |n: usize| {
        let s = &b[at..at + n];
        at += n;
        s
    };
    Pub {
        ik: take(32),
        dev: take(32),
        cert: take(64),
        ek: take(32),
        es: take(64),
        hek: take(HEK_LEN),
        es3: take(64),
        pk_d: take(PK_D_LEN),
        dh: take(32),
        ds: take(64),
        dq: take(DSA_SIG_LEN),
        box_id: take(32),
    }
}

#[test]
fn create_gives_public_blob_signed_by_bot_identity() {
    let mut c = owner();
    let (h, blob) = c.bot_create();
    assert_eq!(h.len(), 32);
    assert_eq!(blob.len(), BOT_PUBLIC_LEN);
    assert_eq!(BOT_PUBLIC_LEN, 6893);
    let p = split(&blob);
    // Not the owner's identity key: the bot gets a fresh identity
    assert_ne!(p.ik, &c.public_key(Slot::Account).unwrap()[..]);
    assert!(ed25519_verify(p.ik, &crypto::device_cert_message(&arr32(p.dev)), p.cert), "device certificate v2");
    assert!(ed25519_verify(p.ik, &crypto::enc_key_message(&arr32(p.ek)), p.es), "encryption key signature v2");
    assert!(ed25519_verify(p.ik, &crypto::enc_key_v3_message(p.hek.try_into().unwrap()), p.es3), "es3");
    assert_eq!(&p.hek[HEK_LEN - 32..], p.ek, "last 32 bytes of HEK = X25519");
    assert!(pq::verify_binding(p.ik, p.pk_d, p.dh, p.ds, p.dq), "identity key binding");
    // The owner's slots are unchanged (bot keys never occupy vault slots)
    assert!(c.has(Slot::Account) && !c.has(Slot::Device) && !c.has(Slot::Enc));
    // Creating again yields a different bot
    let (h2, blob2) = c.bot_create();
    assert_ne!(h, h2);
    assert_ne!(&blob[..32], &blob2[..32]);
}

#[test]
fn key_file_holds_meta_and_three_seeds_and_matches_public_blob() {
    let mut c = owner();
    let (h, blob) = c.bot_create();
    let p = split(&blob);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("krypton-bot-signal.key");
    // Non-ASCII bot name (test data)
    let meta = "{\"v\":1,\"k\":\"krypton-bot\",\"bot\":\"0a0a0a0a-1111-4222-8333-944455566601\",\"name\":\"Se\u{f1}al\"}";
    c.bot_key_file(&h, meta.as_bytes(), &path).unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.ends_with("}\n") && text.matches('\n').count() == 1, "single line");
    assert!(!dir.path().join("krypton-bot-signal.key.part").exists());
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["v"], 1);
    assert_eq!(v["name"], "Se\u{f1}al");
    let seeds = &v["seeds"];
    let (id, dev, enc) = (unb64(seeds["id"].as_str().unwrap()), unb64(seeds["device"].as_str().unwrap()), unb64(seeds["enc"].as_str().unwrap()));
    assert_eq!((id.len(), dev.len(), enc.len()), (32, 32, 32));
    // Public values re-derived from the seeds match the public blob (the bot runner performs the same computation)
    let k = BotKeys::from_seeds(&arr32(&id), &arr32(&dev), &arr32(&enc));
    assert_eq!(&k.ik()[..], p.ik);
    assert_eq!(&crypto::ed25519_public(&arr32(&dev))[..], p.dev);
    assert_eq!(&Slot::Enc.public_from(&arr32(&enc))[..], p.ek);
    assert_eq!(&k.box_id()[..], p.box_id);
    // Bot mailbox: read key R = HKDF(isd, 'gori-bot-box-v1/read'), box id = SHA-256(R), write key = HKDF(ik, 'gori-bot-box-v1/write')
    let mut r = [0u8; 32];
    Hkdf::<Sha256>::new(None, &id).expand(b"gori-bot-box-v1/read", &mut r).unwrap();
    assert_eq!(&Sha256::digest(r)[..], p.box_id);
    let mut w = [0u8; 32];
    Hkdf::<Sha256>::new(None, p.ik).expand(b"gori-bot-box-v1/write", &mut w).unwrap();
    assert_eq!(box_write(&arr32(p.ik)), w);
}

#[test]
fn key_file_refuses_bad_meta_and_forgotten_handle() {
    let mut c = owner();
    let (h, _) = c.bot_create();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("b.key");
    for bad in [&b"[]"[..], b"{}", b"{\"seeds\":1}", b"{\"a\":1}\n", b"\"x\"", b"{\"a\":\xff}"] {
        assert_eq!(c.bot_key_file(&h, bad, &path).err(), Some(Error::InvalidArgument), "{:?}", String::from_utf8_lossy(bad));
    }
    assert!(!path.exists());
    c.bot_forget(&h);
    assert_eq!(c.bot_key_file(&h, b"{\"a\":1}", &path).err(), Some(Error::UnknownHandle));
    let (h2, _) = c.bot_create();
    c.forget_all();
    assert_eq!(c.bot_key_file(&h2, b"{\"a\":1}", &path).err(), Some(Error::UnknownHandle), "forget_all also erases bot keys");
}

#[test]
fn owner_signs_certificate_and_admin_statements() {
    let c = owner();
    let owner_ik = c.public_key(Slot::Account).unwrap();
    // Bot certificate: the owner's identity key signs 'gori-core/bot-cert-v1' 0 ‖ payload
    let payload: Vec<u8> = (0..80u8).collect();
    let sig = c.bot_sign(BOT_SIGN_CERT, &[], &payload).unwrap();
    let mut msg = b"gori-core/bot-cert-v1\0".to_vec();
    msg.extend_from_slice(&payload);
    assert!(ed25519_verify(&owner_ik, &msg, &sig));
    assert_eq!(c.bot_sign(BOT_SIGN_CERT, &[], &payload[..79]).err(), Some(Error::InvalidArgument));
    // A plain signature cannot produce the same statement (reserved gori-core/ prefix)
    assert_eq!(c.sign(Slot::Account, &msg).err(), Some(Error::ReservedStatement));

    // Admin key: deterministic per salt, distinct from the owner's identity key
    let salt = [3u8; 16];
    let admin = c.bot_sign(BOT_SIGN_ADMIN_KEY, &salt, &[]).unwrap();
    assert_eq!(admin.len(), 32);
    assert_eq!(admin, c.bot_sign(BOT_SIGN_ADMIN_KEY, &salt, &[]).unwrap());
    assert_ne!(admin, c.bot_sign(BOT_SIGN_ADMIN_KEY, &[4u8; 16], &[]).unwrap());
    assert_ne!(&admin[..], &owner_ik[..]);
    let mut seed = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&salt), &OWNER).expand(b"gori-core/bot-admin-key-v1", &mut seed).unwrap();
    assert_eq!(&admin[..], &crypto::ed25519_public(&seed)[..]);
    assert_eq!(c.bot_sign(BOT_SIGN_ADMIN_KEY, &[3u8; 15], &[]).err(), Some(Error::InvalidArgument));

    // Delete and rekey: payload bytes identical to the server's, output is public key ‖ signature
    for (op, code, hex_payload) in [(BOT_SIGN_DELETE, 1u8, DELETE_PAYLOAD), (BOT_SIGN_REKEY, 2u8, REKEY_PAYLOAD)] {
        let payload = hex::decode(hex_payload).unwrap();
        let out = c.bot_sign(op, &salt, &payload).unwrap();
        assert_eq!(out.len(), 96);
        assert_eq!(&out[..32], &admin[..]);
        let mut m = b"gori-core/bot-admin-v1\0".to_vec();
        m.push(code);
        m.extend_from_slice(&payload);
        assert_eq!(bot::admin_message(code, &payload).unwrap(), m);
        assert!(ed25519_verify(&admin, &m, &out[32..]));
        assert_eq!(c.bot_sign(op, &salt, &payload[1..]).err(), Some(Error::InvalidArgument));
    }
    assert_eq!(c.bot_sign(9, &salt, &[]).err(), Some(Error::InvalidArgument));
    // Without an owner key
    assert_eq!(Core::new().bot_sign(BOT_SIGN_ADMIN_KEY, &salt, &[]).err(), Some(Error::NoAccountKey));
}

#[test]
fn c_boundary() {
    let c = ffi::gori_core_new();
    let mut pubk = [0u8; 32];
    unsafe {
        assert_eq!(ffi::gori_generate(c, Slot::Account as u32, pubk.as_mut_ptr()), 0);
        let mut h = [0 as c_char; ffi::HANDLE_BUF_LEN];
        let mut out = ffi::GoriBuf { ptr: std::ptr::null_mut(), len: 0 };
        assert_eq!(ffi::gori_bot_create(c, h.as_mut_ptr(), &mut out), 0);
        assert_eq!(out.len, BOT_PUBLIC_LEN);
        ffi::gori_buf_free(out);
        assert_eq!(ffi::gori_bot_create(c, h.as_mut_ptr(), std::ptr::null_mut()), Error::InvalidArgument.code());
        let dir = tempfile::tempdir().unwrap();
        let path = CString::new(dir.path().join("x.key").to_str().unwrap()).unwrap();
        let meta = b"{\"v\":1}";
        assert_eq!(ffi::gori_bot_key_file(c, h.as_ptr(), meta.as_ptr(), meta.len(), path.as_ptr()), 0);
        assert!(dir.path().join("x.key").exists());
        assert_eq!(ffi::gori_bot_forget(c, h.as_ptr()), 0);
        assert_eq!(ffi::gori_bot_key_file(c, h.as_ptr(), meta.as_ptr(), meta.len(), path.as_ptr()), Error::UnknownHandle.code());
        let salt = [1u8; 16];
        let mut sig = ffi::GoriBuf { ptr: std::ptr::null_mut(), len: 0 };
        assert_eq!(ffi::gori_bot_sign(c, BOT_SIGN_ADMIN_KEY, salt.as_ptr(), 16, std::ptr::null(), 0, &mut sig), 0);
        assert_eq!(sig.len, 32);
        ffi::gori_buf_free(sig);
        assert!(CStr::from_ptr(h.as_ptr()).to_str().unwrap().len() == 32);
        ffi::gori_core_free(c);
    }
}
