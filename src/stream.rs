//! Chunked (streaming) encryption: encrypts large files such as videos without loading them fully into memory.
//!
//! Format v1:
//!
//! ```text
//! header(32) = "GORS" ‖ version 1 ‖ chunk size exponent e ‖ reserved 0x0000 ‖ base nonce N(24)
//! chunk i    = XChaCha20-Poly1305(key, N ⊕ (0^16 ‖ u64_be(i)), AAD = header ‖ (last ? 1 : 0), plaintext i)
//! ```
//!
//! The last-chunk flag is in the AAD, so truncation and extension are detected; the chunk index is in the
//! nonce, so reordering is detected. The whole header is in the AAD, so chunks from different files cannot be mixed.

use std::io::{Read, Write};

use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

use crate::crypto::{self, NONCE_LEN, TAG_LEN};
use crate::error::Error;

pub const MAGIC: &[u8; 4] = b"GORS";
pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 32;
/// 64 KiB
pub const DEFAULT_CHUNK_EXP: u8 = 16;
const MIN_CHUNK_EXP: u8 = 10;
const MAX_CHUNK_EXP: u8 = 24;

pub struct Header {
    pub bytes: [u8; HEADER_LEN],
}

impl Header {
    pub fn new(chunk_exp: u8, base_nonce: [u8; NONCE_LEN]) -> Result<Header, Error> {
        if !(MIN_CHUNK_EXP..=MAX_CHUNK_EXP).contains(&chunk_exp) {
            return Err(Error::InvalidArgument);
        }
        let mut bytes = [0u8; HEADER_LEN];
        bytes[..4].copy_from_slice(MAGIC);
        bytes[4] = VERSION;
        bytes[5] = chunk_exp;
        bytes[8..].copy_from_slice(&base_nonce);
        Ok(Header { bytes })
    }

    pub fn parse(bytes: &[u8]) -> Result<Header, Error> {
        if bytes.len() != HEADER_LEN
            || &bytes[..4] != MAGIC
            || bytes[4] != VERSION
            || !(MIN_CHUNK_EXP..=MAX_CHUNK_EXP).contains(&bytes[5])
            || bytes[6] != 0
            || bytes[7] != 0
        {
            return Err(Error::BadStream);
        }
        let mut h = [0u8; HEADER_LEN];
        h.copy_from_slice(bytes);
        Ok(Header { bytes: h })
    }

    pub fn chunk_size(&self) -> usize {
        1usize << self.bytes[5]
    }

    pub fn nonce(&self, index: u64) -> [u8; NONCE_LEN] {
        let mut n = [0u8; NONCE_LEN];
        n.copy_from_slice(&self.bytes[8..]);
        for (b, c) in n[16..].iter_mut().zip(index.to_be_bytes()) {
            *b ^= c;
        }
        n
    }

    pub fn aad(&self, last: bool) -> [u8; HEADER_LEN + 1] {
        let mut a = [0u8; HEADER_LEN + 1];
        a[..HEADER_LEN].copy_from_slice(&self.bytes);
        a[HEADER_LEN] = last as u8;
        a
    }
}

/// Reads until the buffer is full or the input ends
fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<usize, Error> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(Error::Io),
        }
    }
    Ok(n)
}

/// Encrypts a plaintext stream and writes the ciphertext. Returns the number of bytes written
pub fn encrypt<R: Read, W: Write>(
    key: &[u8; 32],
    rng: &mut dyn CryptoRngCore,
    chunk_exp: u8,
    reader: &mut R,
    writer: &mut W,
) -> Result<u64, Error> {
    let header = Header::new(chunk_exp, crypto::random_array(rng))?;
    let cs = header.chunk_size();
    writer.write_all(&header.bytes)?;
    let mut written = HEADER_LEN as u64;

    let mut cur = Zeroizing::new(vec![0u8; cs]);
    let mut next = Zeroizing::new(vec![0u8; cs]);
    let mut n = read_full(reader, &mut cur)?;
    let mut index: u64 = 0;
    loop {
        // Read ahead only when this chunk is full; if the next read is empty, this chunk is the last one
        let m = if n == cs { read_full(reader, &mut next)? } else { 0 };
        let last = m == 0;
        let ct = crypto::seal(key, &header.nonce(index), &header.aad(last), &cur[..n]);
        writer.write_all(&ct)?;
        written += ct.len() as u64;
        if last {
            break;
        }
        std::mem::swap(&mut cur, &mut next);
        n = m;
        index = index.checked_add(1).ok_or(Error::InvalidArgument)?;
    }
    writer.flush()?;
    Ok(written)
}

/// Decrypts a ciphertext stream and writes the plaintext. **On failure, plaintext already written must not be trusted**: the
/// caller discards it. Each decrypted chunk is `Zeroizing` and is wiped once written. The core's file decryption writes straight
/// to a `File` (no `BufWriter`), so the writer keeps no buffered plaintext copy
pub fn decrypt<R: Read, W: Write>(key: &[u8; 32], reader: &mut R, writer: &mut W) -> Result<u64, Error> {
    let mut hb = [0u8; HEADER_LEN];
    if read_full(reader, &mut hb)? != HEADER_LEN {
        return Err(Error::BadStream);
    }
    let header = Header::parse(&hb)?;
    let full = header.chunk_size() + TAG_LEN;

    let mut cur = vec![0u8; full];
    let mut next = vec![0u8; full];
    let mut n = read_full(reader, &mut cur)?;
    let mut index: u64 = 0;
    let mut written = 0u64;
    loop {
        if n < TAG_LEN {
            return Err(Error::BadStream);
        }
        let m = if n == full { read_full(reader, &mut next)? } else { 0 };
        let last = m == 0;
        let pt = crypto::open(key, &header.nonce(index), &header.aad(last), &cur[..n])
            .ok_or(Error::StreamAuth)?;
        writer.write_all(&pt)?;
        written += pt.len() as u64;
        if last {
            break;
        }
        std::mem::swap(&mut cur, &mut next);
        n = m;
        index = index.checked_add(1).ok_or(Error::BadStream)?;
    }
    writer.flush()?;
    Ok(written)
}

/// Ciphertext length for plaintext length L and chunk size 2^e
pub fn ciphertext_len(plain_len: u64, chunk_exp: u8) -> u64 {
    let cs = 1u64 << chunk_exp;
    let chunks = if plain_len == 0 { 1 } else { plain_len.div_ceil(cs) };
    HEADER_LEN as u64 + plain_len + chunks * TAG_LEN as u64
}

/// Plaintext length for a total ciphertext length `total` (header included); `BadStream` if no GORS file can have that length.
/// There is always at least one chunk (an empty plaintext gives one tag-only chunk), and the last chunk is never empty (if the
/// plaintext length is a multiple of the chunk size, the last chunk is full, as `encrypt` produces it)
pub fn plain_len_of(total: u64, chunk_exp: u8) -> Result<u64, Error> {
    if !(MIN_CHUNK_EXP..=MAX_CHUNK_EXP).contains(&chunk_exp) {
        return Err(Error::BadStream);
    }
    let cs = 1u64 << chunk_exp;
    let full = cs + TAG_LEN as u64;
    let body = total.checked_sub(HEADER_LEN as u64).ok_or(Error::BadStream)?;
    let (k, r) = (body / full, body % full);
    match (k, r) {
        (0, 0) => Err(Error::BadStream),
        (_, 0) => Ok(k * cs),
        (0, r) if r == TAG_LEN as u64 => Ok(0),
        (_, r) if r > TAG_LEN as u64 => Ok(k * cs + (r - TAG_LEN as u64)),
        _ => Err(Error::BadStream),
    }
}

/// **Decrypt while downloading**: decrypts the plaintext range `[start, start+len)` of a GORS file whose total ciphertext length
/// is `total`. `file` only needs to hold the first `available` bytes received so far; if a chunk covering the range has not been
/// fully received yet, returns `StreamNotYet` (retry after receiving more). A range running past the end of the plaintext is cut
/// at the end (a start at or past the end gives an empty result).
///
/// Each chunk is authenticated on its own: chunk i's nonce contains i, and its AAD contains the "is last" flag (determined from
/// `total`). A false `total` (truncation or extension) therefore breaks authentication of the chunk judged to be last, and moving
/// or replacing a chunk breaks that chunk. This is the same guarantee as [`decrypt`] over the complete file (only the point of
/// failure differs). Decrypted plaintext is `Zeroizing`
pub fn decrypt_range<R: Read + std::io::Seek>(
    key: &[u8; 32],
    file: &mut R,
    available: u64,
    total: u64,
    start: u64,
    len: u64,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    use std::io::SeekFrom;
    if available < HEADER_LEN as u64 {
        return Err(Error::StreamNotYet);
    }
    if available > total {
        return Err(Error::BadStream);
    }
    let mut hb = [0u8; HEADER_LEN];
    file.seek(SeekFrom::Start(0)).map_err(|_| Error::Io)?;
    if read_full(file, &mut hb)? != HEADER_LEN {
        return Err(Error::StreamNotYet);
    }
    let header = Header::parse(&hb)?;
    let exp = hb[5];
    let plain = plain_len_of(total, exp)?;
    let end = start.saturating_add(len).min(plain);
    let mut out = Zeroizing::new(Vec::with_capacity(end.saturating_sub(start) as usize));
    if start >= end {
        return Ok(out);
    }
    let cs = header.chunk_size() as u64;
    let full = cs + TAG_LEN as u64;
    let chunks = if plain == 0 { 1 } else { plain.div_ceil(cs) };
    let (first, last) = (start / cs, (end - 1) / cs);
    let mut buf = Zeroizing::new(vec![0u8; full as usize]);
    for i in first..=last {
        let at = HEADER_LEN as u64 + i * full;
        let is_last = i + 1 == chunks;
        let clen = if is_last { total - at } else { full };
        if at + clen > available {
            return Err(Error::StreamNotYet);
        }
        file.seek(SeekFrom::Start(at)).map_err(|_| Error::Io)?;
        let ct = &mut buf[..clen as usize];
        if read_full(file, ct)? != clen as usize {
            return Err(Error::StreamNotYet);
        }
        let pt = crypto::open(key, &header.nonce(i), &header.aad(is_last), ct).ok_or(Error::StreamAuth)?;
        let pt = Zeroizing::new(pt);
        let base = i * cs;
        let from = start.max(base) - base;
        let to = end.min(base + pt.len() as u64) - base;
        out.extend_from_slice(&pt[from as usize..to as usize]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(7)
    }

    fn roundtrip(len: usize, exp: u8) {
        let key = [9u8; 32];
        let pt: Vec<u8> = (0..len).map(|i| (i * 31 % 251) as u8).collect();
        let mut ct = Vec::new();
        let n = encrypt(&key, &mut rng(), exp, &mut &pt[..], &mut ct).unwrap();
        assert_eq!(n as usize, ct.len());
        assert_eq!(ct.len() as u64, ciphertext_len(len as u64, exp), "len {len}");
        let mut out = Vec::new();
        decrypt(&key, &mut &ct[..], &mut out).unwrap();
        assert_eq!(out, pt, "len {len}");
    }

    #[test]
    fn roundtrips_edge_lengths() {
        let cs = 1usize << 10;
        for len in [0, 1, cs - 1, cs, cs + 1, 2 * cs, 3 * cs + 17] {
            roundtrip(len, 10);
        }
        roundtrip(200_000, DEFAULT_CHUNK_EXP);
        roundtrip(1 << 17, DEFAULT_CHUNK_EXP);
    }

    fn sample(len: usize) -> (Vec<u8>, Vec<u8>) {
        let pt: Vec<u8> = (0..len).map(|i| i as u8).collect();
        let mut ct = Vec::new();
        encrypt(&[1u8; 32], &mut rng(), 10, &mut &pt[..], &mut ct).unwrap();
        (pt, ct)
    }

    fn fails(ct: &[u8]) -> Error {
        decrypt(&[1u8; 32], &mut &ct[..], &mut Vec::new()).unwrap_err()
    }

    #[test]
    fn detects_truncation_at_chunk_boundary() {
        let (_, ct) = sample(3000); // 3 chunks
        let chunk = 1024 + TAG_LEN;
        assert_eq!(fails(&ct[..HEADER_LEN + 2 * chunk]), Error::StreamAuth);
        assert_eq!(fails(&ct[..HEADER_LEN + chunk]), Error::StreamAuth);
        assert_eq!(fails(&ct[..HEADER_LEN]), Error::BadStream);
        assert_eq!(fails(&ct[..ct.len() - 1]), Error::StreamAuth);
    }

    #[test]
    fn detects_extension_reorder_and_tamper() {
        let (_, ct) = sample(3000);
        let chunk = 1024 + TAG_LEN;
        // Extension: append the first chunk at the end
        let mut ext = ct.clone();
        ext.extend_from_slice(&ct[HEADER_LEN..HEADER_LEN + chunk]);
        assert_eq!(fails(&ext), Error::StreamAuth);
        // Reordering
        let mut swapped = ct[..HEADER_LEN].to_vec();
        swapped.extend_from_slice(&ct[HEADER_LEN + chunk..HEADER_LEN + 2 * chunk]);
        swapped.extend_from_slice(&ct[HEADER_LEN..HEADER_LEN + chunk]);
        swapped.extend_from_slice(&ct[HEADER_LEN + 2 * chunk..]);
        assert_eq!(fails(&swapped), Error::StreamAuth);
        // Header tampering (chunk size exponent changed to another valid value)
        let mut hdr = ct.clone();
        hdr[5] = 11;
        assert!(matches!(fails(&hdr), Error::StreamAuth | Error::BadStream));
        // Flip one bit of the body
        let mut flip = ct.clone();
        flip[HEADER_LEN + 5] ^= 1;
        assert_eq!(fails(&flip), Error::StreamAuth);
        // Wrong magic
        let mut magic = ct.clone();
        magic[0] = b'X';
        assert_eq!(fails(&magic), Error::BadStream);
    }

    #[test]
    fn exact_multiple_has_no_empty_tail_and_wrong_key_fails() {
        let (_, ct) = sample(2048);
        assert_eq!(ct.len(), HEADER_LEN + 2 * (1024 + TAG_LEN));
        assert_eq!(
            decrypt(&[2u8; 32], &mut &ct[..], &mut Vec::new()).unwrap_err(),
            Error::StreamAuth
        );
    }

    fn range(ct: &[u8], available: usize, total: u64, start: u64, len: u64) -> Result<Vec<u8>, Error> {
        let mut c = std::io::Cursor::new(&ct[..available]);
        decrypt_range(&[1u8; 32], &mut c, available as u64, total, start, len).map(|v| v.to_vec())
    }

    #[test]
    fn plain_len_matches_ciphertext_len() {
        for exp in [10u8, 16] {
            let cs = 1u64 << exp;
            for l in [0, 1, cs - 1, cs, cs + 1, 2 * cs, 3 * cs + 17] {
                assert_eq!(plain_len_of(ciphertext_len(l, exp), exp).unwrap(), l, "exp {exp} len {l}");
            }
        }
        // Impossible lengths: shorter than the header, a tail shorter than a tag, an empty last chunk, no chunks
        assert_eq!(plain_len_of(10, 10).unwrap_err(), Error::BadStream);
        assert_eq!(plain_len_of(32, 10).unwrap_err(), Error::BadStream);
        assert_eq!(plain_len_of(32 + 1040 + 5, 10).unwrap_err(), Error::BadStream);
        assert_eq!(plain_len_of(32 + 1040 + 16, 10).unwrap_err(), Error::BadStream);
        assert_eq!(plain_len_of(1000, 9).unwrap_err(), Error::BadStream);
    }

    #[test]
    fn range_reads_any_slice_like_full_decrypt() {
        let (pt, ct) = sample(3000); // chunks: 1024 ×2 + 952
        let total = ct.len() as u64;
        for (s, l) in [(0u64, 3000u64), (0, 1), (1023, 2), (1024, 1024), (100, 2500), (2999, 10), (2048, 952)] {
            let got = range(&ct, ct.len(), total, s, l).unwrap();
            let e = (s + l).min(3000) as usize;
            assert_eq!(got, pt[s as usize..e].to_vec(), "{s}+{l}");
        }
        // Past the end gives an empty result
        assert!(range(&ct, ct.len(), total, 3000, 5).unwrap().is_empty());
        assert!(range(&ct, ct.len(), total, 5000, 5).unwrap().is_empty());
        // Empty plaintext
        let mut e = Vec::new();
        encrypt(&[1u8; 32], &mut rng(), 10, &mut &[][..], &mut e).unwrap();
        assert!(range(&e, e.len(), e.len() as u64, 0, 10).unwrap().is_empty());
    }

    #[test]
    fn range_waits_for_bytes_not_yet_received() {
        let (pt, ct) = sample(3000);
        let total = ct.len() as u64;
        let chunk = 1024 + TAG_LEN;
        // Not even the header has arrived
        assert_eq!(range(&ct, 10, total, 0, 1).unwrap_err(), Error::StreamNotYet);
        // Only the first chunk has arrived: a range in the first chunk decrypts, the second chunk is not available yet
        let got = range(&ct, HEADER_LEN + chunk, total, 0, 1024).unwrap();
        assert_eq!(got, pt[..1024].to_vec());
        assert_eq!(range(&ct, HEADER_LEN + chunk, total, 1000, 100).unwrap_err(), Error::StreamNotYet);
        // The last chunk is one byte short
        assert_eq!(range(&ct, ct.len() - 1, total, 2990, 5).unwrap_err(), Error::StreamNotYet);
        // More bytes available than the claimed total: malformed
        let mut longer = ct.clone();
        longer.push(0);
        assert_eq!(range(&longer, longer.len(), total, 0, 1).unwrap_err(), Error::BadStream);
    }

    #[test]
    fn range_detects_lying_total_tamper_and_swap() {
        let (_, ct) = sample(3000);
        let total = ct.len() as u64;
        let chunk = 1024 + TAG_LEN;
        // Truncation: claim there are only two chunks; decrypting the second chunk as "last" fails
        let cut = (HEADER_LEN + 2 * chunk) as u64;
        assert_eq!(range(&ct[..cut as usize], cut as usize, cut, 1024, 10).unwrap_err(), Error::StreamAuth);
        // The first chunk is not the last, so a range inside it still decrypts (the failure shows up at the last chunk)
        assert!(range(&ct[..cut as usize], cut as usize, cut, 0, 10).is_ok());
        // Extension: claim there is one more chunk; the real last chunk is decrypted as "not last" and fails
        let mut ext = ct.clone();
        ext.extend_from_slice(&ct[HEADER_LEN..HEADER_LEN + chunk]);
        assert_eq!(range(&ext, ext.len(), ext.len() as u64, 2048, 10).unwrap_err(), Error::StreamAuth);
        // One-bit tamper: only that chunk fails
        let mut flip = ct.clone();
        flip[HEADER_LEN + chunk + 3] ^= 1;
        assert_eq!(range(&flip, flip.len(), total, 1024, 10).unwrap_err(), Error::StreamAuth);
        assert!(range(&flip, flip.len(), total, 0, 10).is_ok());
        // Chunk swap (1 ↔ 0)
        let mut sw = ct[..HEADER_LEN].to_vec();
        sw.extend_from_slice(&ct[HEADER_LEN + chunk..HEADER_LEN + 2 * chunk]);
        sw.extend_from_slice(&ct[HEADER_LEN..HEADER_LEN + chunk]);
        sw.extend_from_slice(&ct[HEADER_LEN + 2 * chunk..]);
        assert_eq!(range(&sw, sw.len(), total, 0, 10).unwrap_err(), Error::StreamAuth);
        // Wrong key
        let mut c = std::io::Cursor::new(&ct[..]);
        assert_eq!(decrypt_range(&[2u8; 32], &mut c, total, total, 0, 10).unwrap_err(), Error::StreamAuth);
    }

    #[test]
    fn chunk_nonce_is_base_xor_counter() {
        let h = Header::new(16, [0xAA; NONCE_LEN]).unwrap();
        let n = h.nonce(0x0102);
        assert_eq!(&n[..22], &[0xAA; 22]);
        assert_eq!(n[22], 0xAA ^ 0x01);
        assert_eq!(n[23], 0xAA ^ 0x02);
    }
}
