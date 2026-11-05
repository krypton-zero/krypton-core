//! Notification hint key ring (post-quantum): opens vectors sealed by the app's JavaScript layer (@noble),
//! tests/vectors/hint-js.json, through the C boundary gori_open_hint.
//! The iOS wrapper (notification extension and call notice) and the JavaScript reference implementation open the same file.
use std::path::PathBuf;

use gori_core::ffi::{gori_buf_free, gori_open_hint, GoriBuf};
use gori_core::hint::{hint_key, HINT_CALL, HINT_PAIR, HINT_RECORD_LEN, HINT_TALK};
use serde_json::Value;

fn vectors() -> Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/hint-js.json");
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn b64(s: &str) -> Vec<u8> {
    // Standard base64 (test only: the crate has no base64 dependency)
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for c in s.bytes().filter(|&c| c != b'=') {
        acc = (acc << 6) | T.iter().position(|&t| t == c).unwrap() as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

fn open(ring: &[u8], kinds: u32, g: &[u8]) -> Result<(Vec<u8>, [u8; 17]), i32> {
    let mut out = GoriBuf { ptr: std::ptr::null_mut(), len: 0 };
    let mut tag = [0u8; 17];
    let rc = unsafe { gori_open_hint(ring.as_ptr(), ring.len(), kinds, g.as_ptr(), g.len(), &mut out, tag.as_mut_ptr()) };
    if rc != 0 {
        return Err(rc);
    }
    let v = unsafe { std::slice::from_raw_parts(out.ptr, out.len) }.to_vec();
    unsafe { gori_buf_free(out) };
    Ok((v, tag))
}

const TALK_KINDS: u32 = (1 << HINT_PAIR) | (1 << HINT_TALK);
const CALL_KINDS: u32 = 1 << HINT_CALL;

#[test]
fn ring_matches_app_derivation() {
    let v = vectors();
    let ring = hex::decode(v["ring"].as_str().unwrap()).unwrap();
    assert_eq!(ring[0], 1);
    assert_eq!((ring.len() - 1) % HINT_RECORD_LEN, 0);
    // Same derivation as the app's hintKey: a pair and a call record for each pair, a talk record for each conversation secret
    let mut want = vec![1u8];
    for p in v["pairs"].as_array().unwrap() {
        let s: [u8; 32] = hex::decode(p["secret"].as_str().unwrap()).unwrap().try_into().unwrap();
        let id = hex::decode(p["id"].as_str().unwrap().replace('-', "")).unwrap();
        for k in [HINT_PAIR, HINT_CALL] {
            want.push(k);
            want.extend_from_slice(&id);
            want.extend_from_slice(&*hint_key(&s, k).unwrap());
        }
    }
    for t in v["talks"].as_array().unwrap() {
        for s in t["secrets"].as_array().unwrap() {
            let s: [u8; 32] = hex::decode(s.as_str().unwrap()).unwrap().try_into().unwrap();
            want.push(HINT_TALK);
            want.extend_from_slice(&[0u8; 16]);
            want.extend_from_slice(&*hint_key(&s, HINT_TALK).unwrap());
        }
    }
    assert_eq!(ring, want);
}

#[test]
fn opens_app_sealed_hints() {
    let v = vectors();
    let ring = hex::decode(v["ring"].as_str().unwrap()).unwrap();
    let c = &v["cases"];
    let a = hex::decode(v["pairs"][0]["id"].as_str().unwrap().replace('-', "")).unwrap();
    let b = hex::decode(v["pairs"][1]["id"].as_str().unwrap().replace('-', "")).unwrap();
    let starts = |pt: &[u8], case: &str| {
        let want = c[case]["plain"].as_str().unwrap().as_bytes();
        assert_eq!(&pt[..want.len()], want, "{case}");
        assert!(pt[want.len()..].iter().all(|&x| x == b' '), "{case} padding");
    };

    let (pt, tag) = open(&ring, TALK_KINDS, &b64(c["talkHeart"]["g"].as_str().unwrap())).unwrap();
    starts(&pt, "talkHeart");
    assert_eq!(pt.len(), 352);
    assert_eq!(tag, [HINT_TALK, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

    let (pt, _) = open(&ring, TALK_KINDS, &b64(c["talkOld"]["g"].as_str().unwrap())).unwrap();
    starts(&pt, "talkOld");

    let (pt, tag) = open(&ring, TALK_KINDS, &b64(c["pairInvite"]["g"].as_str().unwrap())).unwrap();
    starts(&pt, "pairInvite");
    assert_eq!(tag[0], HINT_PAIR);
    assert_eq!(&tag[1..], &b[..]);

    let (pt, tag) = open(&ring, CALL_KINDS, &b64(c["callA"]["g"].as_str().unwrap())).unwrap();
    starts(&pt, "callA");
    assert_eq!(pt.len(), 512);
    assert_eq!(tag[0], HINT_CALL);
    assert_eq!(&tag[1..], &a[..]);
    // A call hint does not open under the talk purposes (the AD differs)
    assert_eq!(open(&ring, TALK_KINDS, &b64(c["callA"]["g"].as_str().unwrap())).unwrap_err(), 6);

    // A call hint sealed by B that claims to come from A: it opens with B's call key, and the returned tag names B, not A
    let (_, tag) = open(&ring, CALL_KINDS, &b64(c["callForgedByB"]["g"].as_str().unwrap())).unwrap();
    assert_eq!(&tag[1..], &b[..]);

    // A conversation that is not in the ring
    assert_eq!(open(&ring, TALK_KINDS, &b64(c["unknownTalk"]["g"].as_str().unwrap())).unwrap_err(), 6);
}

#[test]
fn null_outputs_are_rejected() {
    let v = vectors();
    let ring = hex::decode(v["ring"].as_str().unwrap()).unwrap();
    let g = b64(v["cases"]["talkHeart"]["g"].as_str().unwrap());
    let mut out = GoriBuf { ptr: std::ptr::null_mut(), len: 0 };
    let rc = unsafe { gori_open_hint(ring.as_ptr(), ring.len(), TALK_KINDS, g.as_ptr(), g.len(), &mut out, std::ptr::null_mut()) };
    assert_eq!(rc, 18);
    let mut tag = [0u8; 17];
    let rc = unsafe { gori_open_hint(ring.as_ptr(), ring.len(), TALK_KINDS, g.as_ptr(), g.len(), std::ptr::null_mut(), tag.as_mut_ptr()) };
    assert_eq!(rc, 18);
    let rc = unsafe { gori_open_hint(std::ptr::null(), 10, TALK_KINDS, g.as_ptr(), g.len(), &mut out, tag.as_mut_ptr()) };
    assert_eq!(rc, 18);
}
