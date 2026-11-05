//! Zeroization tests: check whether secrets remain intact in heap blocks being freed (dealloc).
//!
//! Only this test binary wraps the global allocator (each file in `tests/` is compiled separately). Once the secrets to
//! watch are armed in 16-byte pieces, every freed block is scanned for those pieces. `Zeroizing` wipes before freeing,
//! so it is not flagged; a plain `Vec`, standard library buffers, and tables moved while growing are flagged.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::UnsafeCell;
use std::ffi::CString;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

use gori_core::ffi::{self, GoriBuf};
use gori_core::{crypto, shamir, Core, Error, Slot};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

const W: usize = 16;
const MAX: usize = 64;

struct Patterns(UnsafeCell<[[u8; W]; MAX]>);
// SAFETY: written only while arming (ARMED = false) and only read while scanning (ARMED = true). Tests run one at a
// time under LOCK
unsafe impl Sync for Patterns {}

static PATTERNS: Patterns = Patterns(UnsafeCell::new([[0; W]; MAX]));
static COUNT: AtomicUsize = AtomicUsize::new(0);
static ARMED: AtomicBool = AtomicBool::new(false);
static HITS: AtomicUsize = AtomicUsize::new(0);
static LOCK: Mutex<()> = Mutex::new(());

struct Spy;

// realloc uses the default implementation (allocate new → copy → self.dealloc), so old buffers freed while growing are
// scanned too
unsafe impl GlobalAlloc for Spy {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::Acquire) {
            // No allocation here
            let block = std::slice::from_raw_parts(ptr, layout.size());
            let pats = &*PATTERNS.0.get();
            let n = COUNT.load(Ordering::Acquire);
            if pats[..n].iter().any(|p| block.windows(W).any(|w| w == p)) {
                HITS.fetch_add(1, Ordering::SeqCst);
            }
        }
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static GLOBAL: Spy = Spy;

fn lock() -> MutexGuard<'static, ()> {
    LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

/// Arm `secrets` in 16-byte pieces and run `f`. Returns how many blocks freed meanwhile still contained a secret.
/// The value `f` returns must hold nothing that needs wiping (only blocks freed while armed are scanned)
fn freed_with_secrets<T>(secrets: &[&[u8]], f: impl FnOnce() -> T) -> (T, usize) {
    // SAFETY: ARMED = false and LOCK is held, so dealloc does not read
    let pats = unsafe { &mut *PATTERNS.0.get() };
    let mut n = 0;
    for s in secrets {
        for i in 0..s.len() / W {
            pats[n].copy_from_slice(&s[i * W..(i + 1) * W]);
            n += 1;
        }
    }
    assert!(n > 0);
    COUNT.store(n, Ordering::Release);
    HITS.store(0, Ordering::SeqCst);
    ARMED.store(true, Ordering::Release);
    let r = f();
    ARMED.store(false, Ordering::Release);
    (r, HITS.load(Ordering::SeqCst))
}

fn seeded(seed: u64) -> Core {
    Core::with_rng(Box::new(ChaCha20Rng::seed_from_u64(seed)))
}

fn random<const N: usize>(r: &mut ChaCha20Rng) -> [u8; N] {
    let mut a = [0u8; N];
    r.fill_bytes(&mut a);
    a
}

/// Recovery preparation leaves no secrets (T, U, shares) on the freed heap, both on success and on failure because a
/// guardian key in the middle is rejected
#[test]
fn recovery_secrets_do_not_survive_in_freed_heap() {
    let _g = lock();
    const SEED: u64 = 0x7a65_726f;
    let mut keys = ChaCha20Rng::seed_from_u64(1);
    let (account, enc): ([u8; 32], [u8; 32]) = (random(&mut keys), random(&mut keys));
    let guardians: Vec<[u8; 32]> = (0..3).map(|_| crypto::x25519_public(&random(&mut keys))).collect();
    let core = || {
        let mut c = seeded(SEED);
        c.load(Slot::Account, &account).unwrap();
        c.load(Slot::Enc, &enc).unwrap();
        c
    };

    // T(32), U(32), nonce(24), coefficients(32 * (k-1)) drawn by prepare_recovery in this order, redrawn here from the same seed
    let mut r = ChaCha20Rng::seed_from_u64(SEED);
    let t: [u8; 32] = random(&mut r);
    let u: [u8; 32] = random(&mut r);
    let nonce: [u8; 24] = random(&mut r);
    let coeffs: [u8; 32] = random(&mut r);
    let shares: Vec<Vec<u8>> = shamir::split(&t, 3, 2, &coeffs).unwrap().iter().map(|s| s[1..].to_vec()).collect();
    let mut watch: Vec<&[u8]> = vec![&t, &u, &account, &enc];
    watch.extend(shares.iter().map(|s| s.as_slice()));

    // Success: confirm the redrawn values (U, nonce) match, and nothing remains after the kit is dropped
    let mut c = core();
    let (_, hits) = freed_with_secrets(&watch, || {
        let kit = c.prepare_recovery(&guardians, 2).unwrap();
        assert_eq!(&kit.server_share[..], &u[..]);
        assert_eq!(&kit.backup[1..25], &nonce[..]);
        drop(kit);
    });
    assert_eq!(hits, 0, "secrets remained on the freed heap after a successful recovery preparation");

    // Failure: the middle guardian's public key is 0 (small order), giving WeakKey. All guardian keys are checked before T
    // and the shares are created, so sealing never fails halfway; this still checks that a failed preparation leaves no
    // secrets
    let mut c = core();
    let bad = [guardians[0], [0u8; 32], guardians[2]];
    let (err, hits) = freed_with_secrets(&watch, || c.prepare_recovery(&bad, 2).err());
    assert_eq!(err, Some(Error::WeakKey));
    assert_eq!(hits, 0, "a recovery preparation that failed while sealing freed the remaining Shamir shares without wiping them");
}

/// Content keys do not remain in the old table when the content key table grows (rehash), nor after everything is
/// cleared (forget_all, drop)
#[test]
fn content_keys_do_not_survive_table_growth() {
    let _g = lock();
    const SEED: u64 = 0x6b65_7973;
    // create_content_key draws the key (32) then the handle (16)
    let mut r = ChaCha20Rng::seed_from_u64(SEED);
    let first: Vec<[u8; 32]> = (0..8)
        .map(|_| {
            let k: [u8; 32] = random(&mut r);
            let _id: [u8; 16] = random(&mut r);
            k
        })
        .collect();
    let watch: Vec<&[u8]> = first.iter().map(|k| k.as_slice()).collect();

    let mut c = seeded(SEED);
    let (h0, hits) = freed_with_secrets(&watch, || {
        let h0 = c.create_content_key();
        for _ in 0..300 {
            c.create_content_key();
        }
        h0
    });
    assert_eq!(hits, 0, "the content key table left keys in the old table while growing");
    // Check the redrawn key is right: what was sealed under the handle opens with that key
    let sealed = c.encrypt(&h0, b"photo").unwrap();
    assert_eq!(&crypto::open(&first[0], &sealed[..24], &[], &sealed[24..]).unwrap()[..], b"photo");

    let (_, hits) = freed_with_secrets(&watch, || {
        c.forget_all();
        drop(c);
    });
    assert_eq!(hits, 0, "cleared content keys remained on the freed heap");
}

fn plaintext(seed: u64, len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    ChaCha20Rng::seed_from_u64(seed).fill_bytes(&mut v);
    v
}

/// One 64 KiB chunk plus a short final chunk (1000 bytes)
const FILE_LEN: usize = (1 << 16) + 1000;

fn file_watch(data: &[u8]) -> Vec<&[u8]> {
    [0usize, 4096, 1 << 16, (1 << 16) + 500, FILE_LEN - W].iter().map(|&o| &data[o..o + W]).collect()
}

/// Encrypting and decrypting a file leaves no plaintext on the freed heap (Core)
#[test]
fn file_plaintext_does_not_survive_in_freed_heap() {
    let _g = lock();
    let dir = tempfile::tempdir().unwrap();
    let (input, sealed, out) = (dir.path().join("v.mov"), dir.path().join("v.gors"), dir.path().join("v.mp4"));
    let data = plaintext(0x66696c65, FILE_LEN);
    std::fs::write(&input, &data).unwrap();
    let watch = file_watch(&data);

    let mut c = seeded(9);
    let h = c.create_content_key();
    let (_, hits) = freed_with_secrets(&watch, || c.encrypt_file(&h, &input, &sealed).unwrap());
    assert_eq!(hits, 0, "file encryption left plaintext on the freed heap");
    let (_, hits) = freed_with_secrets(&watch, || c.decrypt_file(&h, &sealed, &out).unwrap());
    assert_eq!(hits, 0, "file decryption left plaintext on the freed heap (in a buffer such as BufWriter)");
    assert_eq!(std::fs::read(&out).unwrap(), data);
}

/// Decrypting across the C boundary (in one piece → gori_buf_free, and to a cache file) leaves no plaintext either
#[test]
fn ffi_decrypt_does_not_leave_plaintext_in_freed_heap() {
    let _g = lock();
    let dir = tempfile::tempdir().unwrap();
    let p = |name: &str| CString::new(dir.path().join(name).to_str().unwrap()).unwrap();
    let (input, sealed, out) = (p("in.mov"), p("in.gors"), p("cache.mp4"));
    let data = plaintext(0x63616368, FILE_LEN);
    std::fs::write(dir.path().join("in.mov"), &data).unwrap();
    let watch = file_watch(&data);

    unsafe {
        let c = ffi::gori_core_new();
        let mut h = [0 as std::ffi::c_char; ffi::HANDLE_BUF_LEN];
        assert_eq!(ffi::gori_create_content_key(c, h.as_mut_ptr()), 0);
        assert_eq!(ffi::gori_encrypt_file(c, h.as_ptr(), input.as_ptr(), sealed.as_ptr()), 0);

        let (st, hits) = freed_with_secrets(&watch, || {
            ffi::gori_decrypt_cache_file(c, h.as_ptr(), sealed.as_ptr(), out.as_ptr())
        });
        assert_eq!(st, 0);
        assert_eq!(hits, 0, "cache file decryption left plaintext on the freed heap");
        assert_eq!(std::fs::read(dir.path().join("cache.mp4")).unwrap(), data);

        let mut ct = GoriBuf { ptr: std::ptr::null_mut(), len: 0 };
        assert_eq!(ffi::gori_encrypt(c, h.as_ptr(), data.as_ptr(), data.len(), &mut ct), 0);
        let (st, hits) = freed_with_secrets(&watch, || {
            let mut pt = GoriBuf { ptr: std::ptr::null_mut(), len: 0 };
            let st = ffi::gori_decrypt(c, h.as_ptr(), ct.ptr, ct.len, &mut pt);
            let same = std::slice::from_raw_parts(pt.ptr, pt.len) == data.as_slice();
            ffi::gori_buf_free(pt);
            (st, same)
        });
        assert_eq!(st, (0, true));
        assert_eq!(hits, 0, "gori_decrypt → gori_buf_free left plaintext behind");
        ffi::gori_buf_free(ct);
        ffi::gori_core_free(c);
    }
}

/// Invite tickets: the ticket seed (seed_t), blinding scalars and tickets (input and output) do not remain on the freed
/// heap, on success, on a failed proof, and when blinding
#[test]
fn ticket_secrets_do_not_survive_in_freed_heap() {
    use curve25519_dalek::scalar::Scalar;
    use gori_core::oprf::ServerKey;
    use gori_core::ticket::formula;

    let _g = lock();
    let account: [u8; 32] = [0x41; 32];
    let salt: [u8; 32] = [0x5a; 32];
    let (kind, period, idx) = (1u8, 3u32, [0u32, 1, 2]);
    // Recompute outside with the same formula and arm the results (formula is public; the formula itself is not secret)
    let seed_t = formula::seed_t(&account, &salt);
    let ctxs: Vec<[u8; 9]> = idx.iter().map(|&i| formula::ctx(kind, period, i)).collect();
    let blinds: Vec<[u8; 32]> = ctxs.iter().map(|c| formula::blind(&seed_t, c).unwrap().to_bytes()).collect();
    let server = ServerKey::derive(&[7u8; 32], b"zeroize").unwrap();
    let pk = server.public_key();

    let mut c = seeded(1);
    c.load(Slot::Account, &account).unwrap();
    let blinded = c.ticket_blind(kind, period, &salt, &idx).unwrap();
    // Check the recomputed blinds: blinding with the same scalar gives the same element
    for ((ctx, b), e) in ctxs.iter().zip(&blinds).zip(&blinded) {
        let input = formula::input(&seed_t, ctx);
        let again = voprf::VoprfClient::<voprf::Ristretto255>::deterministic_blind_unchecked(
            &input,
            Scalar::from_canonical_bytes(*b).unwrap(),
        )
        .unwrap();
        assert_eq!(&again.message.serialize()[..], &e[..]);
    }
    let (ev, proof) = server.blind_evaluate(&mut ChaCha20Rng::seed_from_u64(1), &blinded).unwrap();
    let tickets = c.ticket_finalize(kind, period, &salt, &idx, &pk, &ev, &proof).unwrap();
    let ins: Vec<[u8; 32]> = tickets.iter().map(|t| t.input).collect();
    let outs: Vec<[u8; 64]> = tickets.iter().map(|t| t.output).collect();
    drop(tickets);

    let mut watch: Vec<&[u8]> = vec![&seed_t[..]];
    watch.extend(blinds.iter().map(|b| b.as_slice()));
    watch.extend(ins.iter().map(|i| i.as_slice()));
    watch.extend(outs.iter().map(|o| o.as_slice()));

    let (_, hits) = freed_with_secrets(&watch, || c.ticket_blind(kind, period, &salt, &idx).unwrap().len());
    assert_eq!(hits, 0, "the ticket seed or blinds remained on the freed heap after ticket_blind");
    let (n, hits) = freed_with_secrets(&watch, || c.ticket_finalize(kind, period, &salt, &idx, &pk, &ev, &proof).unwrap().len());
    assert_eq!(n, 3);
    assert_eq!(hits, 0, "the ticket seed, blinds or tickets remained on the freed heap after ticket_finalize");
    let mut bad = proof;
    bad[3] ^= 1;
    let (err, hits) = freed_with_secrets(&watch, || c.ticket_finalize(kind, period, &salt, &idx, &pk, &ev, &bad).err());
    assert_eq!(err, Some(Error::TicketProof));
    assert_eq!(hits, 0, "ticket_finalize with a bad proof left the ticket seed or blinds behind");
}

/// Paper phrase recovery (v3): R, U, S and both private keys do not remain on the freed heap (prepare and recover). For
/// the C boundary, checks that recovery does not copy the phrase or keys onto the heap, and that gori_buf_free wipes the
/// returned phrase buffer
#[test]
fn self_recovery_secrets_do_not_survive_in_freed_heap() {
    use gori_core::phrase;

    let _g = lock();
    const SEED: u64 = 0x7633_7a72;
    let mut keys = ChaCha20Rng::seed_from_u64(2);
    let (account, enc): ([u8; 32], [u8; 32]) = (random(&mut keys), random(&mut keys));
    // R(24), U(32), nonce(24) drawn by prepare_self_recovery in this order, redrawn here from the same seed
    let mut r = ChaCha20Rng::seed_from_u64(SEED);
    let entropy: [u8; phrase::ENTROPY_LEN] = random(&mut r);
    let u: [u8; 32] = random(&mut r);
    let nonce: [u8; 24] = random(&mut r);
    let mut ikm = entropy.to_vec();
    ikm.extend_from_slice(&u);
    let s = crypto::hkdf32(&ikm, None, crypto::SELF_RECOVERY_INFO);
    // Post-quantum version: the two 32-byte values are seeds, and recovery derives the Ed25519 and X25519 secrets from
    // them; those must not remain either
    let ed = *gori_core::pq::IdSeeds::from_seed(&account).ed_secret;
    let xs = *gori_core::pq::x_secret_from_seed(&enc);
    let watch: Vec<&[u8]> = vec![&entropy, &u, &s[..], &account, &enc, &ed, &xs];
    let acc_pub = Slot::Account.public_from(&account);

    // Prepare: confirm the redrawn values (U, nonce) match, and nothing remains after the kit is dropped
    let mut c = seeded(SEED);
    c.load(Slot::Account, &account).unwrap();
    c.load(Slot::Enc, &enc).unwrap();
    let (kit, hits) = freed_with_secrets(&watch, || {
        let kit = c.prepare_self_recovery().unwrap();
        assert_eq!(&kit.server_share[..], &u[..]);
        assert_eq!(&kit.backup[1..25], &nonce[..]);
        (kit.backup.clone(), kit.words.join(" "))
    });
    assert_eq!(hits, 0, "secrets remained on the freed heap after paper phrase preparation");
    let (backup, joined) = kit;
    let words: Vec<&str> = joined.split(' ').collect();
    assert_eq!(&phrase::decode(&words).unwrap()[..], &entropy[..]);

    // Recover: nothing remains after a successful recovery once the core is cleared and dropped, nor after failing with
    // a wrong U
    let (_, hits) = freed_with_secrets(&watch, || {
        let mut fresh = seeded(1);
        fresh.complete_self_recovery(&words, &backup, &u, &acc_pub).unwrap();
        let mut wrong = seeded(2);
        assert_eq!(wrong.complete_self_recovery(&words, &backup, &[7u8; 32], &acc_pub).unwrap_err(), Error::RecoveryFailed);
        fresh.forget_all();
        drop(fresh);
    });
    assert_eq!(hits, 0, "secrets remained on the freed heap after paper phrase recovery");

    unsafe {
        // Recover across the C boundary: the phrase (space-joined bytes) and keys are not copied onto the heap
        let jb = joined.as_bytes();
        let mut with_phrase = watch.clone();
        with_phrase.extend((0..jb.len() / W).map(|i| &jb[i * W..(i + 1) * W]));
        let (st, hits) = freed_with_secrets(&with_phrase, || {
            let fc = ffi::gori_core_new();
            let (mut a, mut e) = ([0u8; 32], [0u8; 32]);
            let st = ffi::gori_complete_self_recovery(
                fc, jb.as_ptr(), jb.len(), backup.as_ptr(), backup.len(), u.as_ptr(), 32, acc_pub.as_ptr(), 32,
                a.as_mut_ptr(), e.as_mut_ptr(),
            );
            ffi::gori_core_free(fc);
            st
        });
        assert_eq!(st, 0);
        assert_eq!(hits, 0, "gori_complete_self_recovery left the phrase or keys on the freed heap");

        // Prepare across the C boundary: the returned phrase buffer is wiped when freed (the core uses OS randomness, so
        // the phrase is armed after it is returned)
        let fc = ffi::gori_core_new();
        assert_eq!(ffi::gori_load_vault(fc, c"account-seed-v2".as_ptr(), account.as_ptr(), 32, std::ptr::null_mut()), 0);
        assert_eq!(ffi::gori_load_vault(fc, c"enc-seed-v2".as_ptr(), enc.as_ptr(), 32, std::ptr::null_mut()), 0);
        let (mut p, mut b) = (GoriBuf { ptr: std::ptr::null_mut(), len: 0 }, GoriBuf { ptr: std::ptr::null_mut(), len: 0 });
        let (mut uo, mut lo) = ([0u8; 32], [0u8; 32]);
        assert_eq!(ffi::gori_prepare_self_recovery(fc, &mut p, &mut b, uo.as_mut_ptr(), lo.as_mut_ptr()), 0);
        let got = std::slice::from_raw_parts(p.ptr, p.len).to_vec();
        let pats: Vec<&[u8]> = (0..got.len() / W).map(|i| &got[i * W..(i + 1) * W]).collect();
        let (_, hits) = freed_with_secrets(&pats, || ffi::gori_buf_free(p));
        assert_eq!(hits, 0, "the returned phrase buffer was freed without being wiped");
        ffi::gori_buf_free(b);
        ffi::gori_core_free(fc);
    }
}

/// Post-quantum sealing and identity keys: seeds, expanded seeds (ML-KEM d‖z, X25519 secret, Ed25519 secret, ML-DSA ξ),
/// encapsulation randomness, ss and wrap_key do not remain on the freed heap. The ML-KEM decapsulation key and the ML-DSA
/// signing key are boxed by the upstream crate's `alloc` feature and wiped by `zeroize` before being freed; the seed
/// copies (d, z, ξ) inside that box are caught here as well
#[test]
fn pq_secrets_do_not_survive_in_freed_heap() {
    use gori_core::core::OuterPurpose;
    use gori_core::pq::{self, RecipientKey};

    let _g = lock();
    let enc_seed = [0x31u8; 32];
    let isd = [0x32u8; 32];
    let ee = pq::enc_expanded_for_tests(&enc_seed);
    let ie = pq::id_expanded_for_tests(&isd);

    let mut recv = seeded(1);
    recv.load(Slot::Enc, &enc_seed).unwrap();
    recv.load(Slot::Account, &isd).unwrap();
    let hek = recv.encryption_hybrid_key().unwrap();

    // Randomness the sender will draw, in order: content key (32), handle (16), eseed (64), nonce (24). Redrawn from the
    // same seed to compute ss and wrap_key
    const SEED: u64 = 0x7071_7a72;
    let mut r = ChaCha20Rng::seed_from_u64(SEED);
    let key: [u8; 32] = random(&mut r);
    let _handle: [u8; 16] = random(&mut r);
    let eseed: [u8; 64] = random(&mut r);
    let (ct, ss) = RecipientKey::parse(&hek).unwrap().encapsulate_derand(&eseed).unwrap();
    let mut info = OuterPurpose::Keep.info().to_vec();
    info.extend_from_slice(&[0, 2]);
    let wrap = crypto::hkdf32(&ss[..], None, &info);
    let watch: Vec<&[u8]> = vec![&enc_seed, &isd, &ee, &ie, &key, &eseed, &ss[..], &wrap[..]];

    let mut sender = seeded(SEED);
    let k = sender.create_content_key();
    let (env, hits) = freed_with_secrets(&watch, || sender.seal_outer(&k, OuterPurpose::Keep, &hek).unwrap());
    assert_eq!(hits, 0, "encapsulation randomness, ss or keys remained on the freed heap after seal_outer");
    assert_eq!(&env[1..1 + ct.len()], &ct[..], "the redrawn eseed matches");

    let (_, hits) = freed_with_secrets(&watch, || {
        let h = recv.open_outer(OuterPurpose::Keep, &env).unwrap();
        assert_eq!(recv.open_outer(OuterPurpose::Note, &env).unwrap_err(), Error::NotForMe);
        let mut bad = env.clone();
        bad[50] ^= 1;
        assert_eq!(recv.open_outer(OuterPurpose::Keep, &bad).unwrap_err(), Error::NotForMe);
        let _ = recv.encryption_hybrid_key().unwrap();
        let _ = recv.public_key(Slot::Enc).unwrap();
        h
    });
    assert_eq!(hits, 0, "expanded seeds, the ML-KEM decapsulation key or ss remained on the freed heap after open_outer and HEK");

    let (_, hits) = freed_with_secrets(&watch, || {
        let b = recv.pq_sig_binding().unwrap();
        assert!(Core::verify_pq_sig_binding(&recv.public_key(Slot::Account).unwrap(), &b.pk_d, &b.dh, &b.ds, &b.dq));
        let _ = recv.sign(Slot::Account, b"m").unwrap();
        let _ = recv.sign_encryption_key_v3().unwrap();
    });
    assert_eq!(hits, 0, "the Ed25519 secret or ξ remained on the freed heap after the identity binding and signing");

    let (_, hits) = freed_with_secrets(&watch, || {
        recv.forget_all();
        sender.forget_all();
    });
    assert_eq!(hits, 0);
}
