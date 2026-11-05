//! **Bot keys.** A subscriber's phone generates a bot key set and writes it **directly to a key file**; the seeds never
//! reach the JavaScript layer. The owner passes that file, through the share sheet, to the bot runner on their own
//! server.
//!
//! A bot key set has the same structure as a human account: identity seed isd → Ed25519 ‖ ML-DSA-65 ([`IdSeeds`]),
//! device key Ed25519 (the seed used as is), encryption seed → ML-KEM-768 ‖ X25519 = HEK ([`EncKeys`]). It lives in a
//! handle table **separate** from the core's four slots (the owner's own keys). It is never put in the secure store and
//! disappears after the file is written, through [`crate::Core::bot_forget`] (or when the app exits).
//!
//! Contract with the bot runner (byte-exact):
//! - **Key file** (one line of JSON + `\n`) = the app-supplied `meta` (`{`…`}`, the fields without seeds) with
//!   `,"seeds":{"id":"<isd base64>","device":"<device seed base64>","enc":"<encryption seed base64>"}` inserted before its final `}`. Standard base64 (with padding)
//! - **Bot mailbox** (where invitations arrive, same shape as the request-link mailbox): read key R = HKDF-SHA256(isd, no salt, `gori-bot-box-v1/read`), box id = SHA-256(R),
//!   write key W = HKDF-SHA256(bot identity public key ik, no salt, `gori-bot-box-v1/write`). Anyone who knows ik (the owner) can write; only the runner, which holds the seed, can fetch
//! - **Bot certificate**: signed with the owner's identity key over `gori-core/bot-cert-v1` 0 ‖ bot account(16) ‖ bot ik(32) ‖ name hash(32), where name hash = SHA-256(`gori-bot-name-v1` 0 ‖ UTF-8 name)
//! - **Admin key**: Ed25519 seed = HKDF-SHA256(owner isd, salt = 16 B per bot, `gori-core/bot-admin-key-v1`). Signed message `gori-core/bot-admin-v1` 0 ‖ op ‖ payload
//!   (op 1 delete: payload = bot account 16 ‖ time 8; op 2 rekey: payload = bot account 16 ‖ time 8 ‖ new ik 32). The server uses the same formulas
use std::fs::File;
use std::io::Write;

use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::{self, Secret32};
use crate::error::Error;
use crate::pq::{EncKeys, IdSeeds, DSA_SIG_LEN, HEK_LEN, PK_D_LEN};

pub const BOT_CERT_TAG: &[u8] = b"gori-core/bot-cert-v1\0";
pub const BOT_ADMIN_TAG: &[u8] = b"gori-core/bot-admin-v1\0";
pub const BOT_ADMIN_KEY_INFO: &[u8] = b"gori-core/bot-admin-key-v1";
pub const BOT_BOX_READ_INFO: &[u8] = b"gori-bot-box-v1/read";
pub const BOT_BOX_WRITE_INFO: &[u8] = b"gori-bot-box-v1/write";
pub const BOT_NAME_TAG: &[u8] = b"gori-bot-name-v1\0";

/// Admin key salt length
pub const BOT_SALT_LEN: usize = 16;
/// Bot certificate payload = bot account(16) ‖ bot ik(32) ‖ name hash(32)
pub const BOT_CERT_PAYLOAD_LEN: usize = 16 + 32 + 32;
/// Admin signature payloads: delete (account 16 ‖ time 8) and rekey (… ‖ new ik 32)
pub const BOT_DELETE_PAYLOAD_LEN: usize = 16 + 8;
pub const BOT_REKEY_PAYLOAD_LEN: usize = 16 + 8 + 32;
/// Maximum size of the app-supplied key file header (meta)
pub const BOT_META_MAX: usize = 8192;

/// Operations for [`crate::Core::bot_sign`]
pub const BOT_SIGN_CERT: u32 = 0;
pub const BOT_SIGN_ADMIN_KEY: u32 = 1;
pub const BOT_SIGN_DELETE: u32 = 2;
pub const BOT_SIGN_REKEY: u32 = 3;

/// Length of the public bundle (fixed layout, in the order of [`BotKeys::public_blob`] below)
pub const BOT_PUBLIC_LEN: usize = 32 + 32 + 64 + 32 + 64 + HEK_LEN + 64 + PK_D_LEN + 32 + 64 + DSA_SIG_LEN + 32; // 6893

/// A bot key set: three seeds, wiped on drop
pub struct BotKeys {
    id_seed: Secret32,
    device: Secret32,
    enc_seed: Secret32,
}

impl BotKeys {
    pub fn generate(rng: &mut dyn CryptoRngCore) -> BotKeys {
        BotKeys { id_seed: crypto::random_secret(rng), device: crypto::random_secret(rng), enc_seed: crypto::random_secret(rng) }
    }

    /// For tests and the bot runner: builds the set from the three seeds
    pub fn from_seeds(id_seed: &[u8; 32], device: &[u8; 32], enc_seed: &[u8; 32]) -> BotKeys {
        BotKeys { id_seed: Zeroizing::new(*id_seed), device: Zeroizing::new(*device), enc_seed: Zeroizing::new(*enc_seed) }
    }

    pub fn ik(&self) -> [u8; 32] {
        IdSeeds::from_seed(&self.id_seed).ik()
    }

    /// Bot mailbox read key R, known only to the runner (never exported from the crate; the app only sees the box id)
    fn box_read(&self) -> Secret32 {
        crypto::hkdf32(&*self.id_seed, None, BOT_BOX_READ_INFO)
    }

    /// Bot mailbox id = SHA-256(R)
    pub fn box_id(&self) -> [u8; 32] {
        Sha256::digest(&*self.box_read()).into()
    }

    /// Public bundle (fixed layout, [`BOT_PUBLIC_LEN`]):
    /// ik 32 ‖ device public key 32 ‖ device certificate v2 64 ‖ ek (X25519) 32 ‖ encryption key signature v2 64 ‖ HEK 1216 ‖ es3 64 ‖ pk_D 1952 ‖ dh 32 ‖ ds 64 ‖ dq 3309 ‖ mailbox id 32.
    /// All signatures are made with the bot identity key (same signed messages as a human account's [`crate::Core::sign_device_certificate`], `sign_encryption_key`, `_v3` and `pq_sig_binding`)
    pub fn public_blob(&self, rng: &mut dyn CryptoRngCore) -> Vec<u8> {
        let id = IdSeeds::from_seed(&self.id_seed);
        let enc = EncKeys::from_seed(&self.enc_seed);
        let ik = id.ik();
        let dev = crypto::ed25519_public(&self.device);
        let cert = crypto::ed25519_sign(&id.ed_secret, &crypto::device_cert_message(&dev));
        let ek = enc.pk_x();
        let es = crypto::ed25519_sign(&id.ed_secret, &crypto::enc_key_message(&ek));
        let hek = enc.hek();
        let es3 = crypto::ed25519_sign(&id.ed_secret, &crypto::enc_key_v3_message(&hek));
        let b = id.binding(rng);
        let mut out = Vec::with_capacity(BOT_PUBLIC_LEN);
        out.extend_from_slice(&ik);
        out.extend_from_slice(&dev);
        out.extend_from_slice(&cert);
        out.extend_from_slice(&ek);
        out.extend_from_slice(&es);
        out.extend_from_slice(&hek);
        out.extend_from_slice(&es3);
        out.extend_from_slice(&b.pk_d);
        out.extend_from_slice(&b.dh);
        out.extend_from_slice(&b.ds);
        out.extend_from_slice(&b.dq);
        out.extend_from_slice(&self.box_id());
        debug_assert_eq!(out.len(), BOT_PUBLIC_LEN);
        out
    }

    /// Key file bytes (one line of JSON + `\n`) in the format given in the module docs. meta must start with `{`, end with `}`, be non-empty and not contain `"seeds"`
    pub fn key_file(&self, meta: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        if meta.len() < 3 || meta.len() > BOT_META_MAX || meta[0] != b'{' || meta[meta.len() - 1] != b'}' {
            return Err(Error::InvalidArgument);
        }
        if std::str::from_utf8(meta).is_err() || meta.contains(&b'\n') || meta.windows(7).any(|w| w == b"\"seeds\"") {
            return Err(Error::InvalidArgument);
        }
        let mut out = Zeroizing::new(Vec::with_capacity(meta.len() + 200));
        out.extend_from_slice(&meta[..meta.len() - 1]);
        out.extend_from_slice(b",\"seeds\":{\"id\":\"");
        b64_into(&self.id_seed[..], &mut out);
        out.extend_from_slice(b"\",\"device\":\"");
        b64_into(&self.device[..], &mut out);
        out.extend_from_slice(b"\",\"enc\":\"");
        b64_into(&self.enc_seed[..], &mut out);
        out.extend_from_slice(b"\"}}\n");
        Ok(out)
    }

    /// Writes the key file: writes to `.part`, syncs it to disk, then renames it (so no half-written file is left behind)
    pub fn write_key_file(&self, meta: &[u8], path: &std::path::Path) -> Result<(), Error> {
        let bytes = self.key_file(meta)?;
        let mut name = path.file_name().map(|n| n.to_os_string()).ok_or(Error::InvalidArgument)?;
        name.push(".part");
        let part = path.with_file_name(name);
        let r = (|| -> Result<(), Error> {
            let mut f = File::create(&part)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
            std::fs::rename(&part, path)?;
            Ok(())
        })();
        if r.is_err() {
            let _ = std::fs::remove_file(&part);
        }
        r
    }
}

/// Bot mailbox write key W (derived from a public value; both owner and runner compute it)
pub fn box_write(ik: &[u8; 32]) -> [u8; 32] {
    *crypto::hkdf32(ik, None, BOT_BOX_WRITE_INFO)
}

/// Name hash = SHA-256('gori-bot-name-v1' 0 ‖ UTF-8 name)
pub fn name_hash(name: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(BOT_NAME_TAG);
    h.update(name.as_bytes());
    h.finalize().into()
}

/// Bot certificate message: 'gori-core/bot-cert-v1' 0 ‖ payload (bot account 16 ‖ bot ik 32 ‖ name hash 32)
pub fn cert_message(payload: &[u8]) -> Result<Vec<u8>, Error> {
    if payload.len() != BOT_CERT_PAYLOAD_LEN {
        return Err(Error::InvalidArgument);
    }
    let mut m = Vec::with_capacity(BOT_CERT_TAG.len() + payload.len());
    m.extend_from_slice(BOT_CERT_TAG);
    m.extend_from_slice(payload);
    Ok(m)
}

/// Admin message: 'gori-core/bot-admin-v1' 0 ‖ op (1 delete, 2 rekey) ‖ payload
pub fn admin_message(op: u8, payload: &[u8]) -> Result<Vec<u8>, Error> {
    let want = match op {
        1 => BOT_DELETE_PAYLOAD_LEN,
        2 => BOT_REKEY_PAYLOAD_LEN,
        _ => return Err(Error::InvalidArgument),
    };
    if payload.len() != want {
        return Err(Error::InvalidArgument);
    }
    let mut m = Vec::with_capacity(BOT_ADMIN_TAG.len() + 1 + payload.len());
    m.extend_from_slice(BOT_ADMIN_TAG);
    m.push(op);
    m.extend_from_slice(payload);
    Ok(m)
}

/// Ed25519 seed of the admin key, derived from the owner's identity seed isd and a per-bot salt
pub fn admin_secret(owner_isd: &[u8; 32], salt: &[u8]) -> Result<Secret32, Error> {
    if salt.len() != BOT_SALT_LEN {
        return Err(Error::InvalidArgument);
    }
    Ok(crypto::hkdf32(owner_isd, Some(salt), BOT_ADMIN_KEY_INFO))
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 (with padding), writing the seeds straight into a zeroizing buffer (no intermediate string)
fn b64_into(data: &[u8], out: &mut Vec<u8>) {
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(B64[(n >> 18) as usize & 63]);
        out.push(B64[(n >> 12) as usize & 63]);
        out.push(if chunk.len() > 1 { B64[(n >> 6) as usize & 63] } else { b'=' });
        out.push(if chunk.len() > 2 { B64[n as usize & 63] } else { b'=' });
    }
}
