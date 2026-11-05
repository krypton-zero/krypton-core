//! Notification hint key ring. Lets the native layer (the iOS notification service extension and CallKit, the Android
//! FCM service) open notification hints sealed with a pair or conversation secret while the app is not running.
//!
//! How the app seals a hint:
//!   key hk = HKDF-SHA256(ikm = pair or conversation secret, salt = 0×32, info = "gori/hint-v1|<purpose>")
//!   g      = nonce(24) ‖ XChaCha20-Poly1305(hk, plaintext, AD = "gori/hint-v1|<purpose>")
//! The purpose is pair (hints for the pair mailbox), talk (hints for the conversation mailbox) or call (call wake-up hints).
//!
//! **The ring holds only the per-purpose keys hk, never the secrets themselves.** The app derives them and the native
//! wrapper stores the ring in platform secure storage. An hk can only open and seal hints of its own purpose: pair mailbox
//! notes, conversation bodies and call signalling keys (`gori/call-sig-v1|…`) are derived from the pair or conversation
//! secret with different info strings, so hk does not yield them (HKDF domain separation).
//!
//! Ring format (version 1): `0x01 ‖ record*`, where record = purpose(1) ‖ peer(16) ‖ hk(32), 49 bytes, at most
//! [`HINT_RING_MAX`] records.
//!   Purpose 1 = pair, 2 = talk, 3 = call. Peer = the pair partner's account id (16-byte UUID), zero for talk records. The
//!   peer is returned with the plaintext so that whoever opens a call hint can check that the caller named inside the
//!   sealed hint is this peer (so one contact cannot claim to be another, the same check the app performs).
//! A push carries no marker of which pair or conversation it belongs to (so neither the server nor the push provider can
//! link notifications of the same pair). The opener therefore tries every key in the ring. One AEAD attempt takes
//! microseconds, so even 1,024 records take a few milliseconds.
use zeroize::Zeroizing;

use crate::crypto::{self, NONCE_LEN};
use crate::error::Error;

/// Ring format version
pub const HINT_RING_VERSION: u8 = 1;
/// One record: purpose(1) ‖ peer(16) ‖ key(32)
pub const HINT_RECORD_LEN: usize = 49;
/// Maximum number of records: two per contact (pair and call) plus the current and previous secret per conversation. Larger rings are rejected (the app trims the ring to fit)
pub const HINT_RING_MAX: usize = 1024;
/// Tag of the record that opened a hint: purpose(1) ‖ peer(16)
pub const HINT_TAG_LEN: usize = 17;
/// AEAD tag length (16)
const TAG_LEN: usize = 16;

pub const HINT_PAIR: u8 = 1;
pub const HINT_TALK: u8 = 2;
pub const HINT_CALL: u8 = 3;

/// AD and HKDF info for a purpose, identical to the labels the app uses
pub fn hint_label(kind: u8) -> Option<&'static [u8]> {
    match kind {
        HINT_PAIR => Some(b"gori/hint-v1|pair"),
        HINT_TALK => Some(b"gori/hint-v1|talk"),
        HINT_CALL => Some(b"gori/hint-v1|call"),
        _ => None,
    }
}

/// Derives the key for a purpose from a secret, with the same formula as the app. **The core does not expose this across the C boundary** (it exists for tests and cross-checks)
pub fn hint_key(secret: &[u8; 32], kind: u8) -> Result<Zeroizing<[u8; 32]>, Error> {
    let label = hint_label(kind).ok_or(Error::InvalidArgument)?;
    Ok(crypto::hkdf32(secret, Some(&[0u8; 32]), label))
}

/// Parses a ring and returns its record count. A wrong version, length, record limit or purpose gives `InvalidArgument`
fn ring_records(ring: &[u8]) -> Result<usize, Error> {
    let (&v, rest) = ring.split_first().ok_or(Error::InvalidArgument)?;
    if v != HINT_RING_VERSION || rest.len() % HINT_RECORD_LEN != 0 {
        return Err(Error::InvalidArgument);
    }
    let n = rest.len() / HINT_RECORD_LEN;
    if n > HINT_RING_MAX {
        return Err(Error::InvalidArgument);
    }
    if rest.chunks_exact(HINT_RECORD_LEN).any(|r| hint_label(r[0]).is_none()) {
        return Err(Error::InvalidArgument);
    }
    Ok(n)
}

/// Tries every key in the ring. `kinds` is a bit mask of the purposes to try (1 << purpose: pair 2, talk 4, call 8). Returns the plaintext and the tag (purpose ‖ peer) of the first record that opens it.
/// A malformed ring or `kinds` gives `InvalidArgument`, a too-short g gives `BadCiphertext`, and if no key opens it, `DecryptFailed`
pub fn open_hint(ring: &[u8], kinds: u32, sealed: &[u8]) -> Result<(Zeroizing<Vec<u8>>, [u8; HINT_TAG_LEN]), Error> {
    const KNOWN: u32 = (1 << HINT_PAIR) | (1 << HINT_TALK) | (1 << HINT_CALL);
    if kinds == 0 || kinds & !KNOWN != 0 {
        return Err(Error::InvalidArgument);
    }
    ring_records(ring)?;
    // The plaintext is at least one byte (the same lower bound the app uses)
    if sealed.len() < NONCE_LEN + TAG_LEN + 1 {
        return Err(Error::BadCiphertext);
    }
    let (nonce, ct) = sealed.split_at(NONCE_LEN);
    for r in ring[1..].chunks_exact(HINT_RECORD_LEN) {
        let kind = r[0];
        if kinds & (1 << kind) == 0 {
            continue;
        }
        let label = hint_label(kind).ok_or(Error::InvalidArgument)?;
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&r[17..49]);
        if let Some(plain) = crypto::open(&key, nonce, label, ct) {
            let mut tag = [0u8; HINT_TAG_LEN];
            tag.copy_from_slice(&r[..HINT_TAG_LEN]);
            return Ok((plain, tag));
        }
    }
    Err(Error::DecryptFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ring(records: &[(u8, [u8; 16], [u8; 32])]) -> Vec<u8> {
        let mut v = vec![HINT_RING_VERSION];
        for (k, p, key) in records {
            v.push(*k);
            v.extend_from_slice(p);
            v.extend_from_slice(key);
        }
        v
    }

    fn seal(key: &[u8; 32], kind: u8, pt: &[u8]) -> Vec<u8> {
        let nonce = [9u8; NONCE_LEN];
        let mut out = nonce.to_vec();
        out.extend(crypto::seal(key, &nonce, hint_label(kind).unwrap(), pt));
        out
    }

    #[test]
    fn opens_with_matching_kind_only() {
        let s = [7u8; 32];
        let pair = *hint_key(&s, HINT_PAIR).unwrap();
        let call = *hint_key(&s, HINT_CALL).unwrap();
        let peer = [0xabu8; 16];
        let r = ring(&[(HINT_PAIR, peer, pair), (HINT_CALL, peer, call)]);
        let g = seal(&call, HINT_CALL, b"hello");
        let (pt, tag) = open_hint(&r, 1 << HINT_CALL, &g).unwrap();
        assert_eq!(&pt[..], b"hello");
        assert_eq!(tag[0], HINT_CALL);
        assert_eq!(&tag[1..], &peer);
        // A call hint does not open when only pair and talk are tried
        assert_eq!(open_hint(&r, (1 << HINT_PAIR) | (1 << HINT_TALK), &g).unwrap_err(), Error::DecryptFailed);
        // The same key does not open under a different purpose (AD): a ring with the call key in a pair record
        let swapped = ring(&[(HINT_PAIR, peer, call)]);
        assert_eq!(open_hint(&swapped, 1 << HINT_PAIR, &g).unwrap_err(), Error::DecryptFailed);
    }

    /// Same bytes as the JavaScript reference implementation (hkdf and xchacha20poly1305 from @noble), whose tests check the same values
    #[test]
    fn matches_app_vectors() {
        let secret: [u8; 32] = core::array::from_fn(|i| i as u8);
        let want = [
            (HINT_PAIR, "d0bed0012b79a574c32d4dee2cfb9de5d276f254068afca34ccbbca00cd53f06"),
            (HINT_TALK, "f88c9796053c0573798afee9bf7551357682bb692793514646cbbf71d2d58523"),
            (HINT_CALL, "35cbc68ab138d8018ca5e71bbe4cb962d57fa8d369addfb4e7e25a774a4d3d90"),
        ];
        for (k, h) in want {
            assert_eq!(hex::encode(*hint_key(&secret, k).unwrap()), h);
        }
        let g = hex::decode("4242424242424242424242424242424242424242424242423f53df0bcd862481f8f5f4b6ac7a274ec764c3dfccd75957bf5ee4734f5572").unwrap();
        let talk = *hint_key(&secret, HINT_TALK).unwrap();
        let pair = *hint_key(&secret, HINT_PAIR).unwrap();
        let r = ring(&[(HINT_PAIR, [1; 16], pair), (HINT_TALK, [0; 16], talk)]);
        let (pt, tag) = open_hint(&r, (1 << HINT_PAIR) | (1 << HINT_TALK), &g).unwrap();
        assert_eq!(&pt[..], br#"{"v":1,"n":"a"}"#);
        assert_eq!(tag, [HINT_TALK, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn rejects_bad_rings() {
        let g = seal(&[1u8; 32], HINT_TALK, b"x");
        assert_eq!(open_hint(&[], 4, &g).unwrap_err(), Error::InvalidArgument);
        assert_eq!(open_hint(&[2], 4, &g).unwrap_err(), Error::InvalidArgument);
        assert_eq!(open_hint(&[1, 2, 3], 4, &g).unwrap_err(), Error::InvalidArgument);
        assert_eq!(open_hint(&ring(&[(4, [0; 16], [1; 32])]), 4, &g).unwrap_err(), Error::InvalidArgument);
        assert_eq!(open_hint(&ring(&[(HINT_TALK, [0; 16], [1; 32])]), 0, &g).unwrap_err(), Error::InvalidArgument);
        assert_eq!(open_hint(&ring(&[(HINT_TALK, [0; 16], [1; 32])]), 1, &g).unwrap_err(), Error::InvalidArgument);
        assert_eq!(open_hint(&ring(&[(HINT_TALK, [0; 16], [1; 32])]), 4, &g[..40]).unwrap_err(), Error::BadCiphertext);
        // Empty ring: no key to try
        assert_eq!(open_hint(&[1], 4, &g).unwrap_err(), Error::DecryptFailed);
        let over: Vec<_> = (0..=HINT_RING_MAX).map(|_| (HINT_TALK, [0u8; 16], [1u8; 32])).collect();
        assert_eq!(open_hint(&ring(&over), 4, &g).unwrap_err(), Error::InvalidArgument);
        let max: Vec<_> = (0..HINT_RING_MAX).map(|_| (HINT_TALK, [0u8; 16], [1u8; 32])).collect();
        assert_eq!(&open_hint(&ring(&max), 4, &g).unwrap().0[..], b"x");
    }
}
