//! Recovery phrase: the 192-bit secret R written as 18 BIP39 English words.
//!
//! Only the standard BIP39 18-word encoding is used: `R (192 bits) ‖ first 6 bits of SHA-256(R)` = 198 bits,
//! split into 11-bit word indices.
//! Why 192 bits: if Grover's algorithm reduces brute force to a square root, 128 bits corresponds to NIST
//! post-quantum category 1 and 192 bits to category 3, which matches the app's ML-KEM-768. 12 words (128 bits)
//! or any other length is rejected with `BadPhrase`.
//! **No seed derivation (PBKDF2 "mnemonic", 2048 rounds) is applied**: R itself is the secret, and entering
//! this phrase into another wallet does not yield the same keys. The phrase is shown on screen exactly once
//! so the user can write it on paper (the one deliberate exception to the key boundary).
//!
//! Word lookup always scans the whole list to the end (it does not stop at a match), because the phrase is
//! secret: the lookup time does not reveal a word's position in the list. The normalized word lives only in
//! an 8-byte stack buffer (no copy is left on the heap).

use sha2::{Digest, Sha256};
use subtle::{ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroizing;

use crate::bip39_en::{MAX_WORD_LEN, WORDS};
use crate::error::Error;

/// Number of words in the phrase
pub const PHRASE_WORDS: usize = 18;
/// Length of R in bytes (192 bits)
pub const ENTROPY_LEN: usize = 24;
/// Checksum bits = bits of R / 32 (BIP39). 18 × 11 = 192 + 6
const CHECKSUM_BITS: usize = ENTROPY_LEN * 8 / 32;
const CHECKSUM_MASK: u8 = 0xffu8 << (8 - CHECKSUM_BITS);
const _: () = assert!(PHRASE_WORDS * 11 == ENTROPY_LEN * 8 + CHECKSUM_BITS);

type Padded = [u8; MAX_WORD_LEN];

fn pad(word: &[u8]) -> Padded {
    let mut p = [0u8; MAX_WORD_LEN];
    p[..word.len()].copy_from_slice(word);
    p
}

/// Trims surrounding whitespace and lowercases. A word containing anything other than ASCII letters, or
/// longer than 8 letters, cannot be in the list
fn normalize(word: &str) -> Option<Zeroizing<Padded>> {
    let w = word.trim().as_bytes();
    if w.is_empty() || w.len() > MAX_WORD_LEN || !w.iter().all(u8::is_ascii_alphabetic) {
        return None;
    }
    let mut p = Zeroizing::new([0u8; MAX_WORD_LEN]);
    for (d, s) in p.iter_mut().zip(w) {
        *d = s.to_ascii_lowercase();
    }
    Some(p)
}

/// Index in the list (0 to 2047). Always scans the whole list in the same order
fn word_index(word: &str) -> Option<u16> {
    let w = normalize(word)?;
    let mut index = 0u16;
    let mut found = subtle::Choice::from(0);
    for (i, cand) in WORDS.iter().enumerate() {
        let eq = pad(cand.as_bytes()).ct_eq(&*w);
        index.conditional_assign(&(i as u16), eq);
        found |= eq;
    }
    bool::from(found).then_some(index)
}

/// 6-bit checksum: the top six bits of the first byte of SHA-256(R)
fn checksum(entropy: &[u8; ENTROPY_LEN]) -> u8 {
    Sha256::digest(entropy)[0] & CHECKSUM_MASK
}

/// R → 18 words (lowercase, exactly as in the list)
pub fn encode(entropy: &[u8; ENTROPY_LEN]) -> Zeroizing<Vec<String>> {
    // 198 bits (25 bytes) + 1 spare byte for reading (the last word reads a 3-byte window)
    let mut bits = Zeroizing::new([0u8; ENTROPY_LEN + 2]);
    bits[..ENTROPY_LEN].copy_from_slice(entropy);
    bits[ENTROPY_LEN] = checksum(entropy);
    let mut words = Zeroizing::new(Vec::with_capacity(PHRASE_WORDS));
    for i in 0..PHRASE_WORDS {
        let (byte, shift) = (11 * i / 8, 11 * i % 8);
        let window = (u32::from(bits[byte]) << 16) | (u32::from(bits[byte + 1]) << 8) | u32::from(bits[byte + 2]);
        let index = (window >> (24 - 11 - shift)) & 0x7ff;
        words.push(WORDS[index as usize].to_string());
    }
    words
}

/// 18 words → R. Each word is trimmed and lowercased. Returns `BadPhrase` if there are not exactly 18 words,
/// any word is not in the list, or the checksum is wrong
pub fn decode<S: AsRef<str>>(words: &[S]) -> Result<Zeroizing<[u8; ENTROPY_LEN]>, Error> {
    if words.len() != PHRASE_WORDS {
        return Err(Error::BadPhrase);
    }
    let mut bits = Zeroizing::new([0u8; ENTROPY_LEN + 2]);
    for (i, w) in words.iter().enumerate() {
        let index = word_index(w.as_ref()).ok_or(Error::BadPhrase)?;
        for j in 0..11 {
            if (index >> (10 - j)) & 1 == 1 {
                let at = 11 * i + j;
                bits[at / 8] |= 0x80 >> (at % 8);
            }
        }
    }
    let mut entropy = Zeroizing::new([0u8; ENTROPY_LEN]);
    entropy.copy_from_slice(&bits[..ENTROPY_LEN]);
    if bool::from(checksum(&entropy).ct_eq(&bits[ENTROPY_LEN])) {
        Ok(entropy)
    } else {
        Err(Error::BadPhrase)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_and_normalize() {
        assert_eq!(word_index("abandon"), Some(0));
        assert_eq!(word_index("zoo"), Some(2047));
        assert_eq!(word_index("  Zoo\n"), Some(2047));
        assert_eq!(word_index("ABANDON"), Some(0));
        assert_eq!(word_index("abando"), None);
        assert_eq!(word_index("abandonn"), None);
        assert_eq!(word_index("abandoned"), None, "9 letters");
        assert_eq!(word_index(""), None);
        assert_eq!(word_index("ab and"), None);
        assert_eq!(word_index("äbandon"), None);
    }
}
