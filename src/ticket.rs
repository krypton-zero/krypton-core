//! Anonymous invite tickets: VOPRF tickets derived deterministically from the account key seed.
//!
//! - For each `(kind, period, index)` the input x and the blind r are derived with HKDF and HMAC from the account's
//!   Ed25519 secret seed and a **period salt**. The core holds **no state**: no handles, no secure-store slots. An
//!   interrupted issuance is simply resent with the same elements (idempotent)
//! - Why the period salt exists (32 random bytes, created once per period by the native wrapper, kept in platform secure
//!   storage and **deleted when the period ends**; the JavaScript layer never sees it): the account seed can be
//!   reconstructed from its Shamir recovery shares. If tickets depended on the seed alone, whoever reassembled the seed
//!   could match it against the blinded elements and redeemed tickets in the server database and **recompute past
//!   invitations**. A deleted salt cannot be recovered, so a finished period stays closed. A recovered device cannot
//!   regenerate tickets of past periods
//! - Blinds and seeds never leave the core. Only the blinded elements (to the server) and the tickets
//!   `(input 32 B, output 64 B)` leave it. A ticket is a **bearer token** meant to be handed to someone else, so it is not
//!   key material (it is handled with the same care as an invite link secret)
//! - All byte formulas live in [`formula`]. If a formula changes, only that module changes and
//!   `tests/vectors/ticket.json` is regenerated

use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::core::Core;
use crate::error::Error;
use crate::oprf::{self, ELEMENT_LEN, OUTPUT_LEN, PROOF_LEN};

/// Ticket kind 1: invitation (every type of inviting account uses the same key, to enlarge the anonymity set)
pub const TICKET_KIND_INVITE: u8 = 1;
/// Ticket kind 2: mailbox creation
pub const TICKET_KIND_BOX: u8 = 2;
/// Ticket kind 3: posting
pub const TICKET_KIND_POST: u8 = 3;
/// Ticket kind 4: photo upload (obtained at upload time)
pub const TICKET_KIND_MEDIA: u8 = 4;
/// Ticket kind 5: yearly subscription (web payment; the ticket unlinks the payer from the account)
pub const TICKET_KIND_PLUS_YEARLY: u8 = 5;
/// Ticket kind 6: lifetime subscription
pub const TICKET_KIND_PLUS_LIFETIME: u8 = 6;
/// Ticket kind 7: bot creation
pub const TICKET_KIND_BOT: u8 = 7;
/// Maximum number of indices handled in one call
pub const TICKET_BATCH_MAX: usize = oprf::MAX_BATCH;
/// Ticket input length
pub const TICKET_INPUT_LEN: usize = 32;

/// One ticket, `(input, output)`. On redemption the server checks `Evaluate(sk, input) == output`. Zeroized on drop.
/// Comparison (`==`) is constant time (a derived PartialEq would stop at the first differing byte)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Ticket {
    pub input: [u8; TICKET_INPUT_LEN],
    pub output: [u8; OUTPUT_LEN],
}

impl ConstantTimeEq for Ticket {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.input.ct_eq(&other.input) & self.output.ct_eq(&other.output)
    }
}

impl PartialEq for Ticket {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for Ticket {}

impl std::fmt::Debug for Ticket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Ticket(..)") // bearer token: never written to logs
    }
}

/// Byte formulas for deriving tickets. The issuing service and the JavaScript reference implementation implement the same
/// formulas
pub mod formula {
    use curve25519_dalek::scalar::Scalar;
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256, Sha512};
    use zeroize::Zeroizing;

    use crate::crypto::{self, Secret32};
    use crate::error::Error;

    /// `seed_t = HKDF-SHA256(ikm = account Ed25519 secret seed 32B, salt = period salt 32B, info = SEED_INFO)`
    pub const SEED_INFO: &[u8] = b"gori-core/ticket-seed-v1";
    /// `input_i = HMAC-SHA256(seed_t, INPUT_LABEL ‖ 0x00 ‖ ctx(i))`
    pub const INPUT_LABEL: &[u8] = b"gori-ticket-input-v1";
    /// `blind_i = LE512(HMAC-SHA512(seed_t, BLIND_LABEL ‖ 0x00 ‖ ctx(i))) mod ℓ`; zero gives `Internal`
    pub const BLIND_LABEL: &[u8] = b"gori-ticket-blind-v1";
    /// `nullifier = SHA-256(SPENT_LABEL ‖ 0x00 ‖ kind(1) ‖ period(4, BE) ‖ input)`, the value the server uses to reject an already redeemed ticket
    pub const SPENT_LABEL: &[u8] = b"gori-ticket-spent-v1";
    /// Server key `DeriveKeyPair(server_seed, utf8(KEY_INFO_PREFIX + kind + "|" + period))`, kind and period in decimal
    pub const KEY_INFO_PREFIX: &str = "gori-ticket-key-v1|";

    /// `ctx(i) = kind(1) ‖ period(4, BE) ‖ index(4, BE)`
    pub fn ctx(kind: u8, period: u32, index: u32) -> [u8; 9] {
        let mut c = [0u8; 9];
        c[0] = kind;
        c[1..5].copy_from_slice(&period.to_be_bytes());
        c[5..].copy_from_slice(&index.to_be_bytes());
        c
    }

    fn labeled(label: &[u8], ctx: &[u8; 9]) -> Vec<u8> {
        let mut m = Vec::with_capacity(label.len() + 1 + ctx.len());
        m.extend_from_slice(label);
        m.push(0);
        m.extend_from_slice(ctx);
        m
    }

    /// Ticket seed. HMAC is not keyed with the account secret directly: an intermediate seed is derived first, to separate this use from the account key's other use (signing) and to mix in the period salt.
    /// **If the byte formulas change, only this function and the three below change**
    pub fn seed_t(account_secret: &[u8; 32], period_salt: &[u8; 32]) -> Secret32 {
        crypto::hkdf32(account_secret, Some(period_salt), SEED_INFO)
    }

    pub fn input(seed_t: &[u8; 32], ctx: &[u8; 9]) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(seed_t).expect("HMAC accepts keys of any length");
        mac.update(&labeled(INPUT_LABEL, ctx));
        mac.finalize().into_bytes().into()
    }

    pub fn blind(seed_t: &[u8; 32], ctx: &[u8; 9]) -> Result<Zeroizing<Scalar>, Error> {
        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(seed_t).expect("HMAC accepts keys of any length");
        mac.update(&labeled(BLIND_LABEL, ctx));
        let wide: Zeroizing<[u8; 64]> = Zeroizing::new(mac.finalize().into_bytes().into());
        let s = Zeroizing::new(Scalar::from_bytes_mod_order_wide(&wide));
        if *s == Scalar::ZERO {
            return Err(Error::Internal); // probability 2^-252; if it happens, that index is not used
        }
        Ok(s)
    }

    pub fn nullifier(kind: u8, period: u32, input: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(SPENT_LABEL);
        h.update([0u8]);
        h.update([kind]);
        h.update(period.to_be_bytes());
        h.update(input);
        h.finalize().into()
    }

    pub fn server_key_info(kind: u8, period: u32) -> String {
        format!("{KEY_INFO_PREFIX}{kind}|{period}")
    }
}

/// Requires kind 1 to 7, 1 to 64 indices without duplicates, and a salt that is not all zero (an all-zero salt means the caller forgot it); otherwise `TicketInput`
pub fn check_request(kind: u8, indices: &[u32], period_salt: &[u8; 32]) -> Result<(), Error> {
    if period_salt.iter().all(|&b| b == 0) {
        return Err(Error::TicketInput);
    }
    if !(TICKET_KIND_INVITE..=TICKET_KIND_BOT).contains(&kind) {
        return Err(Error::TicketInput);
    }
    if indices.is_empty() || indices.len() > TICKET_BATCH_MAX {
        return Err(Error::TicketInput);
    }
    let mut sorted = indices.to_vec();
    sorted.sort_unstable();
    if sorted.windows(2).any(|w| w[0] == w[1]) {
        return Err(Error::TicketInput);
    }
    Ok(())
}

/// (input, blinding) for one index. The blinding scalar lives only inside `client` (zeroized on drop)
fn derive(seed_t: &[u8; 32], kind: u8, period: u32, index: u32) -> Result<([u8; 32], oprf::Blinded), Error> {
    let ctx = formula::ctx(kind, period, index);
    let input = formula::input(seed_t, &ctx);
    let blind = formula::blind(seed_t, &ctx)?;
    let b = oprf::blind_scalar(&input, &blind)?;
    Ok((input, b))
}

impl Core {
    /// One blinded element (32 B) per index, to be sent to the server for issuance. Does not change state (same arguments, same result).
    /// `NoAccountKey` if there is no account key, `TicketInput` for an invalid kind, index list or salt
    pub fn ticket_blind(
        &self,
        kind: u8,
        period: u32,
        period_salt: &[u8; 32],
        indices: &[u32],
    ) -> Result<Vec<[u8; ELEMENT_LEN]>, Error> {
        check_request(kind, indices, period_salt)?;
        let seed_t = formula::seed_t(self.account_secret()?, period_salt);
        indices.iter().map(|&i| derive(&seed_t, kind, period, i).map(|(_, b)| b.element)).collect()
    }

    /// Verifies the server response (evaluated elements and one batch proof) against the server public key **pinned by the app** and returns the tickets (in index order).
    /// If anything is wrong, no ticket is returned: `TicketInput` for a count mismatch, `TicketPoint` for a non-canonical or identity element or public key,
    /// `TicketProof` for a proof that does not verify
    #[allow(clippy::too_many_arguments)]
    pub fn ticket_finalize(
        &self,
        kind: u8,
        period: u32,
        period_salt: &[u8; 32],
        indices: &[u32],
        server_pub: &[u8; ELEMENT_LEN],
        evaluated: &[[u8; ELEMENT_LEN]],
        proof: &[u8; PROOF_LEN],
    ) -> Result<Vec<Ticket>, Error> {
        check_request(kind, indices, period_salt)?;
        if evaluated.len() != indices.len() {
            return Err(Error::TicketInput);
        }
        // Check the public key and elements (public values) before touching the seed, so the account secret is never used on a malformed response
        oprf::element(server_pub)?;
        for e in evaluated {
            oprf::element(e)?;
        }
        let seed_t = formula::seed_t(self.account_secret()?, period_salt);
        let n = indices.len();
        let mut inputs = Zeroizing::new(Vec::with_capacity(n)); // ticket inputs: half of a bearer token, so zeroized
        let mut clients = Vec::with_capacity(n);
        for &i in indices {
            let (input, b) = derive(&seed_t, kind, period, i)?;
            inputs.push(input);
            clients.push(b.client);
        }
        let refs: Vec<&[u8]> = inputs.iter().map(|x| x.as_slice()).collect();
        let outputs = oprf::finalize_clients(&refs, &clients, evaluated, server_pub, proof)?;
        Ok(inputs.iter().zip(outputs.iter()).map(|(input, output)| Ticket { input: *input, output: *output }).collect())
    }
}
