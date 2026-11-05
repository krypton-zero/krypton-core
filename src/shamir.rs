//! Shamir secret sharing over GF(2^8). Given the same coefficients, it produces the same shares as the
//! JavaScript reference implementation.
//!
//! Share format: `[x (1..=255)] ‖ y (same length as the secret)`
//!
//! Table lookups would use secret-dependent memory addresses, which can leak through cache timing. Instead
//! of log/exp tables this module uses constant-time bitwise multiplication; the results are identical to the
//! table method.

use zeroize::Zeroizing;

use crate::error::Error;

/// GF(2^8) multiplication with the irreducible polynomial 0x11b. Does not branch on its inputs
fn mul(a: u8, b: u8) -> u8 {
    let mut a = a;
    let mut b = b;
    let mut p = 0u8;
    for _ in 0..8 {
        p ^= a & (0u8.wrapping_sub(b & 1));
        let hi = 0u8.wrapping_sub(a >> 7);
        a = (a << 1) ^ (0x1b & hi);
        b >>= 1;
    }
    p
}

/// a^254 = a^-1 (a ≠ 0). Returns 0 for 0
fn inv(a: u8) -> u8 {
    // 254 = 0b11111110: square-and-multiply
    let a2 = mul(a, a);
    let a4 = mul(a2, a2);
    let a8 = mul(a4, a4);
    let a16 = mul(a8, a8);
    let a32 = mul(a16, a16);
    let a64 = mul(a32, a32);
    let a128 = mul(a64, a64);
    mul(mul(mul(mul(mul(mul(a128, a64), a32), a16), a8), a4), a2)
}

/// Splits the secret into n shares; any k of them recover it.
/// `coefficients` holds (k-1) bytes per secret byte, so its length is `secret.len() * (k-1)`.
///
/// Shares are `Zeroizing` from creation: if the caller fails midway (for example while sealing) and drops
/// the remaining shares, they are zeroed before being freed
pub fn split(secret: &[u8], n: usize, k: usize, coefficients: &[u8]) -> Result<Vec<Zeroizing<Vec<u8>>>, Error> {
    if k < 1 || n < k || n > 255 {
        return Err(Error::BadShareCount);
    }
    if coefficients.len() != secret.len() * (k - 1) {
        return Err(Error::InvalidArgument);
    }
    let mut shares = Vec::with_capacity(n);
    for s in 0..n {
        let x = (s + 1) as u8;
        let mut share = Zeroizing::new(vec![0u8; secret.len() + 1]);
        share[0] = x;
        for i in 0..secret.len() {
            let mut y = 0u8;
            for d in (0..k - 1).rev() {
                y = mul(y, x) ^ coefficients[i * (k - 1) + d];
            }
            y = mul(y, x) ^ secret[i];
            share[i + 1] = y;
        }
        shares.push(share);
    }
    Ok(shares)
}

/// Recombines shares into the secret. With fewer than k shares the result is an unrelated value (not an error)
pub fn combine<S: AsRef<[u8]>>(shares: &[S]) -> Result<Zeroizing<Vec<u8>>, Error> {
    if shares.is_empty() {
        return Err(Error::NoShares);
    }
    let first = shares[0].as_ref();
    if first.is_empty() {
        return Err(Error::ShareLength);
    }
    let len = first.len() - 1;
    if shares.iter().any(|s| s.as_ref().len() != len + 1) {
        return Err(Error::ShareLength);
    }
    let xs: Vec<u8> = shares.iter().map(|s| s.as_ref()[0]).collect();
    for (i, &x) in xs.iter().enumerate() {
        if x == 0 || xs[..i].contains(&x) {
            return Err(Error::ShareIndex);
        }
    }
    let mut out = Zeroizing::new(vec![0u8; len]);
    for i in 0..len {
        let mut acc = 0u8;
        for j in 0..shares.len() {
            let mut num = 1u8;
            let mut den = 1u8;
            for m in 0..shares.len() {
                if m == j {
                    continue;
                }
                num = mul(num, xs[m]);
                den = mul(den, xs[m] ^ xs[j]);
            }
            acc ^= mul(shares[j].as_ref()[i + 1], mul(num, inv(den)));
        }
        out[i] = acc;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Table method, as in the JavaScript reference implementation; checks that the constant-time
    /// multiplication gives the same values
    #[allow(clippy::needless_range_loop)]
    fn table_mul(a: u8, b: u8) -> u8 {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        for i in 0..255 {
            exp[i] = x as u8;
            log[x as usize] = i as u8;
            x ^= (x << 1) ^ if x & 0x80 != 0 { 0x11b } else { 0 };
            x &= 0xff;
        }
        for i in 255..512 {
            exp[i] = exp[i - 255];
        }
        if a == 0 || b == 0 {
            return 0;
        }
        exp[log[a as usize] as usize + log[b as usize] as usize]
    }

    #[test]
    fn mul_matches_table_for_every_pair() {
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                assert_eq!(mul(a, b), table_mul(a, b), "{a} * {b}");
            }
        }
    }

    #[test]
    fn inverse_is_inverse() {
        for a in 1..=255u8 {
            assert_eq!(mul(a, inv(a)), 1, "{a}");
        }
    }

    #[test]
    fn any_k_shares_recover() {
        let secret: Vec<u8> = (0..32).collect();
        let coeffs: Vec<u8> = (0..64).map(|i| (i * 7 + 3) as u8).collect();
        let shares = split(&secret, 5, 3, &coeffs).unwrap();
        for a in 0..5 {
            for b in a + 1..5 {
                for c in b + 1..5 {
                    let got = combine(&[&shares[a], &shares[b], &shares[c]]).unwrap();
                    assert_eq!(&got[..], &secret[..]);
                }
            }
        }
        let two = combine(&[&shares[0], &shares[1]]).unwrap();
        assert_ne!(&two[..], &secret[..]);
    }

    /// Shares are `Zeroizing` from the start: if the type ever changes to a plain Vec, this test no longer compiles
    #[test]
    fn split_shares_are_zeroizing() {
        let shares: Vec<Zeroizing<Vec<u8>>> = split(&[7u8; 32], 3, 2, &[1u8; 32]).unwrap();
        assert_eq!(shares.len(), 3);
        assert!(shares.iter().all(|s| s.len() == 33));
        assert_eq!(&combine(&shares[1..]).unwrap()[..], &[7u8; 32][..]);
    }

    #[test]
    fn rejects_bad_inputs() {
        assert_eq!(split(&[1], 1, 2, &[0]).unwrap_err(), Error::BadShareCount);
        assert_eq!(split(&[1], 3, 2, &[]).unwrap_err(), Error::InvalidArgument);
        let empty: [&[u8]; 0] = [];
        assert_eq!(combine(&empty).unwrap_err(), Error::NoShares);
        assert_eq!(combine(&[&[1u8, 2][..], &[2u8][..]]).unwrap_err(), Error::ShareLength);
        assert_eq!(combine(&[&[1u8, 2][..], &[1u8, 3][..]]).unwrap_err(), Error::ShareIndex);
        assert_eq!(combine(&[&[0u8, 2][..]]).unwrap_err(), Error::ShareIndex);
    }
}
