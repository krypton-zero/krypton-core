//! Invitation tickets (src/ticket.rs): deterministic derivation, round trip, forgery, input checks, the C boundary,
//! and the cross-implementation vectors in `tests/vectors/ticket.json`.
//!
//! ticket.json is the reference that the issuing service, which implements the same formulas, and the JavaScript reference
//! implementation are checked against to make sure they produce the same bytes.
//! To regenerate: `GORI_WRITE_VECTORS=1 cargo test --test ticket`
#![allow(unsafe_code)]

use std::path::PathBuf;

use curve25519_dalek::scalar::Scalar;
use gori_core::ffi;
use gori_core::oprf::{blind_with, ServerKey};
use gori_core::ticket::{formula, Ticket, TICKET_BATCH_MAX, TICKET_KIND_BOX, TICKET_KIND_INVITE};
use gori_core::{Core, Error, Slot};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

const ACCOUNT: [u8; 32] = [7u8; 32];
const SALT: [u8; 32] = [0x5a; 32];

fn core_with(account: &[u8; 32]) -> Core {
    let mut c = Core::new();
    c.load(Slot::Account, account).unwrap();
    c
}

fn server(kind: u8, period: u32) -> ServerKey {
    ServerKey::derive(&[0xa3; 32], formula::server_key_info(kind, period).as_bytes()).unwrap()
}

fn x(b: &[u8]) -> String {
    hex::encode(b)
}

/// Recomputes the ticket derivation without this crate's formula module, to check that the code matches the written formula
fn independent(account: &[u8; 32], salt: &[u8; 32], kind: u8, period: u32, index: u32) -> ([u8; 32], [u8; 32]) {
    let mut seed_t = [0u8; 32];
    Hkdf::<Sha256>::new(Some(salt), account).expand(b"gori-core/ticket-seed-v1", &mut seed_t).unwrap();
    let mut ctx = vec![kind];
    ctx.extend_from_slice(&period.to_be_bytes());
    ctx.extend_from_slice(&index.to_be_bytes());
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&seed_t).unwrap();
    m.update(b"gori-ticket-input-v1\0");
    m.update(&ctx);
    let input: [u8; 32] = m.finalize().into_bytes().into();
    let mut m = <Hmac<Sha512> as Mac>::new_from_slice(&seed_t).unwrap();
    m.update(b"gori-ticket-blind-v1\0");
    m.update(&ctx);
    let wide: [u8; 64] = m.finalize().into_bytes().into();
    (input, Scalar::from_bytes_mod_order_wide(&wide).to_bytes())
}

// ── Deterministic derivation ──

#[test]
fn blind_matches_the_written_formula() {
    let c = core_with(&ACCOUNT);
    let idx = [0u32, 1, 63, u32::MAX];
    let got = c.ticket_blind(TICKET_KIND_INVITE, 3, &SALT, &idx).unwrap();
    for (i, g) in idx.iter().zip(&got) {
        let (input, blind) = independent(&ACCOUNT, &SALT, TICKET_KIND_INVITE, 3, *i);
        assert_eq!(*g, blind_with(&input, &blind).unwrap(), "index {i}");
    }
}

#[test]
fn blind_is_deterministic_and_separated() {
    let c = core_with(&ACCOUNT);
    let a = c.ticket_blind(TICKET_KIND_INVITE, 3, &SALT, &[0, 1]).unwrap();
    assert_eq!(a, c.ticket_blind(TICKET_KIND_INVITE, 3, &SALT, &[0, 1]).unwrap(), "same arguments → same elements (resending is idempotent)");
    assert_eq!(a[1], c.ticket_blind(TICKET_KIND_INVITE, 3, &SALT, &[1]).unwrap()[0], "each index is derived on its own, independent of the batch");
    assert_ne!(a[0], a[1]);
    assert_ne!(a[0], c.ticket_blind(TICKET_KIND_INVITE, 4, &SALT, &[0]).unwrap()[0], "period");
    assert_ne!(a[0], c.ticket_blind(TICKET_KIND_BOX, 3, &SALT, &[0]).unwrap()[0], "kind");
    assert_ne!(a[0], c.ticket_blind(TICKET_KIND_INVITE, 3, &[0x5b; 32], &[0]).unwrap()[0], "period salt");
    assert_ne!(a[0], core_with(&[8u8; 32]).ticket_blind(TICKET_KIND_INVITE, 3, &SALT, &[0]).unwrap()[0], "account");
}

#[test]
fn request_checks() {
    let c = core_with(&ACCOUNT);
    for kind in [0u8, 8, 255] {
        assert_eq!(c.ticket_blind(kind, 0, &SALT, &[0]).err(), Some(Error::TicketInput), "kind {kind}");
    }
    // Kinds 5 and 6: subscription purchase (yearly, lifetime). Kind 7: bot creation
    for kind in [5u8, 6, 7] {
        assert!(c.ticket_blind(kind, 0, &SALT, &[0]).is_ok(), "kind {kind}");
    }
    assert_eq!(c.ticket_blind(1, 0, &SALT, &[]).err(), Some(Error::TicketInput));
    assert_eq!(c.ticket_blind(1, 0, &SALT, &[1, 1]).err(), Some(Error::TicketInput));
    assert_eq!(c.ticket_blind(1, 0, &SALT, &[3, 1, 2, 1]).err(), Some(Error::TicketInput), "non-adjacent duplicate");
    let many: Vec<u32> = (0..TICKET_BATCH_MAX as u32 + 1).collect();
    assert_eq!(c.ticket_blind(1, 0, &SALT, &many).err(), Some(Error::TicketInput));
    assert!(c.ticket_blind(1, 0, &SALT, &many[..TICKET_BATCH_MAX]).is_ok());
    assert_eq!(c.ticket_blind(1, 0, &[0u8; 32], &[0]).err(), Some(Error::TicketInput), "missing salt (all zeros)");
    assert_eq!(Core::new().ticket_blind(1, 0, &SALT, &[0]).err(), Some(Error::NoAccountKey));
}

// ── Round trip and forgery ──

#[test]
fn round_trip_and_tamper() {
    let c = core_with(&ACCOUNT);
    let k = server(1, 3);
    let pk = k.public_key();
    let idx = [0u32, 5, 63];
    let blinded = c.ticket_blind(1, 3, &SALT, &idx).unwrap();
    let (ev, proof) = k.blind_evaluate_with(&blinded, &[0x11; 32]).unwrap();
    let t = c.ticket_finalize(1, 3, &SALT, &idx, &pk, &ev, &proof).unwrap();
    assert_eq!(t.len(), 3);
    for (ticket, i) in t.iter().zip(idx) {
        assert_eq!(ticket.input, independent(&ACCOUNT, &SALT, 1, 3, i).0);
        assert!(k.verify_output(&ticket.input, &ticket.output), "matches the server's Evaluate");
    }
    // The same evaluation yields the same tickets (even with a different random proof scalar)
    let (ev2, proof2) = k.blind_evaluate_with(&blinded, &[0x22; 32]).unwrap();
    assert_ne!(proof, proof2);
    assert_eq!(c.ticket_finalize(1, 3, &SALT, &idx, &pk, &ev2, &proof2).unwrap(), t);

    let mut bad = proof;
    bad[0] ^= 1;
    assert_eq!(c.ticket_finalize(1, 3, &SALT, &idx, &pk, &ev, &bad).err(), Some(Error::TicketProof));
    let other_pk = ServerKey::derive(&[0xa4; 32], b"x").unwrap().public_key();
    assert_eq!(c.ticket_finalize(1, 3, &SALT, &idx, &other_pk, &ev, &proof).err(), Some(Error::TicketProof), "key differs from the pinned public key");
    assert_eq!(c.ticket_finalize(1, 3, &SALT, &idx, &server(1, 4).public_key(), &ev, &proof).err(), Some(Error::TicketProof), "key from another period");
    let mut ev_id = ev.clone();
    ev_id[1] = [0u8; 32];
    assert_eq!(c.ticket_finalize(1, 3, &SALT, &idx, &pk, &ev_id, &proof).err(), Some(Error::TicketPoint), "identity element");
    assert_eq!(c.ticket_finalize(1, 3, &SALT, &idx, &[0u8; 32], &ev, &proof).err(), Some(Error::TicketPoint), "identity public key");
    let mut swapped = ev.clone();
    swapped.swap(0, 2);
    assert_eq!(c.ticket_finalize(1, 3, &SALT, &idx, &pk, &swapped, &proof).err(), Some(Error::TicketProof), "order");
    assert_eq!(c.ticket_finalize(1, 3, &SALT, &idx, &pk, &ev[..2], &proof).err(), Some(Error::TicketInput), "two elements for three indices");
    assert_eq!(c.ticket_finalize(1, 3, &SALT, &[0, 5, 62], &pk, &ev, &proof).err(), Some(Error::TicketProof), "different indices");
    assert_eq!(c.ticket_finalize(1, 3, &[0x5b; 32], &idx, &pk, &ev, &proof).err(), Some(Error::TicketProof), "different salt");
    assert_eq!(c.ticket_finalize(2, 3, &SALT, &idx, &pk, &ev, &proof).err(), Some(Error::TicketProof), "different kind");
    assert_eq!(core_with(&[8u8; 32]).ticket_finalize(1, 3, &SALT, &idx, &pk, &ev, &proof).err(), Some(Error::TicketProof), "different account");
    assert_eq!(Core::new().ticket_finalize(1, 3, &SALT, &idx, &pk, &ev, &proof).err(), Some(Error::NoAccountKey));
}

#[test]
fn nullifier_binds_kind_period_input() {
    let x = [9u8; 32];
    let n = formula::nullifier(1, 0, &x);
    assert_ne!(n, formula::nullifier(2, 0, &x));
    assert_ne!(n, formula::nullifier(1, 1, &x));
    assert_ne!(n, formula::nullifier(1, 0, &[8u8; 32]));
    let mut m = Sha256::new();
    m.update(b"gori-ticket-spent-v1\0\x01\x00\x00\x00\x00");
    m.update(x);
    assert_eq!(n, <[u8; 32]>::from(m.finalize()));
    assert_eq!(formula::server_key_info(2, 17), "gori-ticket-key-v1|2|17");
}

/// Tickets, server keys and core errors never print secrets through {:?}. (voprf's VoprfClient and VoprfServer print
/// scalars in their Debug output; our types that wrap them either do not implement Debug or redact it.)
#[test]
fn debug_does_not_print_secrets() {
    let c = core_with(&ACCOUNT);
    let k = server(1, 0);
    let blinded = c.ticket_blind(1, 0, &SALT, &[0]).unwrap();
    let (ev, proof) = k.blind_evaluate_with(&blinded, &[0x11; 32]).unwrap();
    let t = c.ticket_finalize(1, 0, &SALT, &[0], &k.public_key(), &ev, &proof).unwrap();
    let shown = format!("{:?} {:?}", t, t[0]);
    assert_eq!(shown, "[Ticket(..)] Ticket(..)");
    assert!(!shown.contains(&x(&t[0].output[..4])));
    assert_eq!(format!("{:?}", Error::TicketProof), "TicketProof");

    // Comparison is constant time (ConstantTimeEq): a difference in any byte of input or output makes them unequal
    let mut other = t[0].clone();
    assert!(other == t[0]);
    other.output[63] ^= 1;
    assert!(other != t[0]);
    let mut other = t[0].clone();
    other.input[0] ^= 1;
    assert!(other != t[0]);
}

// ── C boundary ──

unsafe fn with_account() -> *mut ffi::GoriCore {
    let c = ffi::gori_core_new();
    assert_eq!(ffi::gori_load_vault(c, c"account-seed-v2".as_ptr(), ACCOUNT.as_ptr(), 32, std::ptr::null_mut()), 0);
    c
}

#[test]
fn ffi_round_trip_and_argument_checks() {
    let k = server(1, 2);
    let pk = k.public_key();
    let idx = [0u32, 1, 2];
    let inv = Error::InvalidArgument.code();
    let tin = Error::TicketInput.code();
    unsafe {
        let c = with_account();
        let mut blinded = [0u8; 96];
        assert_eq!(ffi::gori_ticket_blind(c, 1, 2, SALT.as_ptr(), idx.as_ptr(), 3, blinded.as_mut_ptr()), 0);
        let el: Vec<[u8; 32]> = blinded.chunks(32).map(|b| b.try_into().unwrap()).collect();
        assert_eq!(el, core_with(&ACCOUNT).ticket_blind(1, 2, &SALT, &idx).unwrap(), "same as the Rust API");
        let (ev, proof) = k.blind_evaluate_with(&el, &[0x33; 32]).unwrap();
        let evf: Vec<u8> = ev.concat();
        let (mut ins, mut outs) = ([0u8; 96], [0u8; 192]);
        let fin = |c, salt: *const u8, idx: *const u32, n, pk: *const u8, ev: *const u8, pr: *const u8, i: *mut u8, o: *mut u8| {
            ffi::gori_ticket_finalize(c, 1, 2, salt, idx, n, pk, ev, pr, i, o)
        };
        assert_eq!(fin(c, SALT.as_ptr(), idx.as_ptr(), 3, pk.as_ptr(), evf.as_ptr(), proof.as_ptr(), ins.as_mut_ptr(), outs.as_mut_ptr()), 0);
        for i in 0..3 {
            assert!(k.verify_output(&ins[i * 32..(i + 1) * 32], &outs[i * 64..(i + 1) * 64]));
        }

        // A bad proof leaves the output buffers untouched
        let mut bad = proof;
        bad[9] ^= 1;
        let (mut ins2, mut outs2) = ([0xaau8; 96], [0xaau8; 192]);
        let st = fin(c, SALT.as_ptr(), idx.as_ptr(), 3, pk.as_ptr(), evf.as_ptr(), bad.as_ptr(), ins2.as_mut_ptr(), outs2.as_mut_ptr());
        assert_eq!(st, Error::TicketProof.code());
        assert!(ins2.iter().chain(outs2.iter()).all(|&b| b == 0xaa), "a failed finalize wrote to the output");
        let mut bl2 = [0xaau8; 96];
        assert_eq!(ffi::gori_ticket_blind(c, 9, 2, SALT.as_ptr(), idx.as_ptr(), 3, bl2.as_mut_ptr()), tin);
        assert!(bl2.iter().all(|&b| b == 0xaa));

        // Argument checks: NULL gives InvalidArgument, a bad count gives TicketInput
        let mut o = [0u8; 32 * 65];
        assert_eq!(ffi::gori_ticket_blind(c, 1, 2, SALT.as_ptr(), idx.as_ptr(), 3, std::ptr::null_mut()), inv);
        assert_eq!(ffi::gori_ticket_blind(c, 1, 2, std::ptr::null(), idx.as_ptr(), 3, o.as_mut_ptr()), inv);
        assert_eq!(ffi::gori_ticket_blind(c, 1, 2, SALT.as_ptr(), std::ptr::null(), 3, o.as_mut_ptr()), inv);
        assert_eq!(ffi::gori_ticket_blind(std::ptr::null(), 1, 2, SALT.as_ptr(), idx.as_ptr(), 3, o.as_mut_ptr()), inv);
        assert_eq!(ffi::gori_ticket_blind(c, 1, 2, SALT.as_ptr(), idx.as_ptr(), 0, o.as_mut_ptr()), tin);
        let many: Vec<u32> = (0..65).collect();
        assert_eq!(ffi::gori_ticket_blind(c, 1, 2, SALT.as_ptr(), many.as_ptr(), 65, o.as_mut_ptr()), tin);
        assert_eq!(ffi::gori_ticket_blind(c, 1, 2, SALT.as_ptr(), idx.as_ptr(), usize::MAX, o.as_mut_ptr()), tin, "absurd count");
        // Misaligned index pointer
        let raw = [0u8; 16];
        let odd = raw.as_ptr().add(if (raw.as_ptr() as usize).is_multiple_of(4) { 1 } else { 0 }) as *const u32;
        assert_eq!(ffi::gori_ticket_blind(c, 1, 2, SALT.as_ptr(), odd, 1, o.as_mut_ptr()), inv);
        let (mut i3, mut o3) = ([0u8; 96], [0u8; 192]);
        assert_eq!(fin(c, SALT.as_ptr(), idx.as_ptr(), 3, pk.as_ptr(), evf.as_ptr(), proof.as_ptr(), std::ptr::null_mut(), o3.as_mut_ptr()), inv);
        assert_eq!(fin(c, SALT.as_ptr(), idx.as_ptr(), 3, pk.as_ptr(), evf.as_ptr(), proof.as_ptr(), i3.as_mut_ptr(), std::ptr::null_mut()), inv);
        assert_eq!(fin(c, SALT.as_ptr(), idx.as_ptr(), 3, std::ptr::null(), evf.as_ptr(), proof.as_ptr(), i3.as_mut_ptr(), o3.as_mut_ptr()), inv);
        assert_eq!(fin(c, SALT.as_ptr(), idx.as_ptr(), 3, pk.as_ptr(), std::ptr::null(), proof.as_ptr(), i3.as_mut_ptr(), o3.as_mut_ptr()), inv);
        assert_eq!(fin(c, SALT.as_ptr(), idx.as_ptr(), 3, pk.as_ptr(), evf.as_ptr(), std::ptr::null(), i3.as_mut_ptr(), o3.as_mut_ptr()), inv);
        assert_eq!(fin(c, std::ptr::null(), idx.as_ptr(), 3, pk.as_ptr(), evf.as_ptr(), proof.as_ptr(), i3.as_mut_ptr(), o3.as_mut_ptr()), inv);
        assert_eq!(fin(c, SALT.as_ptr(), idx.as_ptr(), 0, pk.as_ptr(), evf.as_ptr(), proof.as_ptr(), i3.as_mut_ptr(), o3.as_mut_ptr()), tin);
        // A core without an account key
        let empty = ffi::gori_core_new();
        assert_eq!(ffi::gori_ticket_blind(empty, 1, 2, SALT.as_ptr(), idx.as_ptr(), 3, o.as_mut_ptr()), Error::NoAccountKey.code());
        // Error messages
        for e in [Error::TicketInput, Error::TicketPoint, Error::TicketProof] {
            let m = std::ffi::CStr::from_ptr(ffi::gori_error_message(e.code())).to_str().unwrap();
            assert!(m.starts_with("Invite ticket:"), "{m}");
        }
        ffi::gori_core_free(empty);
        ffi::gori_core_free(c);
    }
}

// ── Cross-implementation vectors: ticket.json ──

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
struct Case {
    account_seed: String,
    kind: u8,
    period: u32,
    period_salt: String,
    indices: Vec<u32>,
    blinded: Vec<String>,
    server_seed: String,
    server_key_info: String,
    server_pk: String,
    proof_random_scalar: String,
    evaluated: Vec<String>,
    proof: String,
    inputs: Vec<String>,
    outputs: Vec<String>,
    nullifiers: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
struct TicketFile {
    generator: String,
    formula: Vec<String>,
    cases: Vec<Case>,
}

fn make_case(kind: u8, period: u32, salt: [u8; 32], indices: &[u32], proof_r: [u8; 32]) -> Case {
    let c = core_with(&ACCOUNT);
    let server_seed = [0xa3u8; 32];
    let info = formula::server_key_info(kind, period);
    let k = ServerKey::derive(&server_seed, info.as_bytes()).unwrap();
    let blinded = c.ticket_blind(kind, period, &salt, indices).unwrap();
    let (evaluated, proof) = k.blind_evaluate_with(&blinded, &proof_r).unwrap();
    let t: Vec<Ticket> = c.ticket_finalize(kind, period, &salt, indices, &k.public_key(), &evaluated, &proof).unwrap();
    for ticket in &t {
        assert!(k.verify_output(&ticket.input, &ticket.output));
    }
    Case {
        account_seed: x(&ACCOUNT),
        kind,
        period,
        period_salt: x(&salt),
        indices: indices.to_vec(),
        blinded: blinded.iter().map(|b| x(b)).collect(),
        server_seed: x(&server_seed),
        server_key_info: info,
        server_pk: x(&k.public_key()),
        proof_random_scalar: x(&proof_r),
        evaluated: evaluated.iter().map(|e| x(e)).collect(),
        proof: x(&proof),
        inputs: t.iter().map(|t| x(&t.input)).collect(),
        outputs: t.iter().map(|t| x(&t.output)).collect(),
        nullifiers: t.iter().map(|t| x(&formula::nullifier(kind, period, &t.input))).collect(),
    }
}

fn generate() -> TicketFile {
    let r = |b: u8| {
        let mut wide = [b; 64];
        wide[63] = 0;
        Scalar::from_bytes_mod_order_wide(&wide).to_bytes()
    };
    TicketFile {
        generator: "gori-core tests/ticket.rs (Core::ticket_blind, Core::ticket_finalize and oprf::ServerKey, voprf 0.5.0)".into(),
        formula: vec![
            "ctx(i) = kind(1) || period(4, BE) || index(4, BE)".into(),
            "seed_t = HKDF-SHA256(ikm = account_seed, salt = period_salt, info = 'gori-core/ticket-seed-v1')".into(),
            "input_i = HMAC-SHA256(seed_t, 'gori-ticket-input-v1' || 0x00 || ctx(i))".into(),
            "blind_i = LE512(HMAC-SHA512(seed_t, 'gori-ticket-blind-v1' || 0x00 || ctx(i))) mod l".into(),
            "server key = DeriveKeyPair(server_seed, utf8('gori-ticket-key-v1|' + kind + '|' + period))".into(),
            "nullifier = SHA-256('gori-ticket-spent-v1' || 0x00 || kind(1) || period(4, BE) || input)".into(),
        ],
        cases: vec![
            make_case(1, 0, [0x5a; 32], &[0, 1, 2, 63], r(0x11)),
            make_case(2, 5, [0x6b; 32], &[9], r(0x22)),
            make_case(3, 7, [0x7c; 32], &[0, 599], r(0x33)),
            make_case(4, 7, [0x8d; 32], &[4], r(0x44)),
        ],
    }
}

#[test]
fn ticket_vectors_are_stable() {
    let f = generate();
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/ticket.json");
    if std::env::var("GORI_WRITE_VECTORS").as_deref() == Ok("1") {
        std::fs::write(&path, serde_json::to_string_pretty(&f).unwrap() + "\n").unwrap();
    }
    let on_disk: TicketFile = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(on_disk, f, "ticket.json differs from the generator. Regenerate it with GORI_WRITE_VECTORS=1");
}
