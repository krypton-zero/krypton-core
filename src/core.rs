//! Core state: four private-key slots plus a table of content-key handles.
//!
//! The methods map one to one onto the key interface the app uses (the JavaScript reference implementation exposes the
//! same interface). This crate does not persist keys
//! (Keychain): the wrapper puts them in with [`Core::load`] and takes them out with [`Core::slot_secret`].

use std::collections::HashMap;
use std::fs::{self, File};
use std::path::{Path, PathBuf};

use rand_core::{CryptoRngCore, OsRng};
use zeroize::Zeroizing;

use crate::bot::{self, BotKeys};
use crate::crypto::{self, Secret32, NONCE_LEN, TAG_LEN};
use crate::error::Error;
use crate::pq::{self, EncKeys, IdSeeds, PqSigBinding, RecipientKey};
use crate::{phrase, shamir, stream};

/// Private-key slot. The numbers are C ABI values; do not change them.
///
/// **Since the post-quantum format, the 32 bytes in Account and Enc are seeds**, not Ed25519 or X25519 secrets themselves.
/// Silently reading an old-format value (a raw secret) as a seed would produce public keys different from the ones the
/// server and peers know, so the vault item names ([`Slot::vault_name`]) were changed and [`Core::load_vault`] rejects
/// the old names with `StaleKey` (there is no path that reads the old format)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Slot {
    /// Account identity seed isd → `SHAKE256("gori-core/id-seed-v1\0" ‖ isd, 64)` = Ed25519 secret ‖ ML-DSA-65 seed ξ (see `pq.rs`)
    Account = 0,
    /// Device key (Ed25519 seed, no seed expansion)
    Device = 1,
    /// Encryption seed → `SHAKE256(seed, 96)` = ML-KEM-768 seed d‖z ‖ X25519 secret (X-Wing key generation, see `pq.rs`)
    Enc = 2,
    /// Temporary receiving key on the new device for the legacy guardian recovery path (a raw X25519 secret)
    Recovery = 3,
}

/// Vault item names (iOS Keychain, Android keystore) in the **old format**. Secrets stored under these names are not seeds
pub const STALE_VAULT_NAMES: [&str; 2] = ["account", "enc"];

impl Slot {
    pub const ALL: [Slot; 4] = [Slot::Account, Slot::Device, Slot::Enc, Slot::Recovery];

    pub fn from_u32(v: u32) -> Result<Slot, Error> {
        Slot::ALL.get(v as usize).copied().ok_or(Error::InvalidArgument)
    }

    /// Vault item name, which doubles as a format marker. The wrapper stores the key under this name and passes the same
    /// name to [`Core::load_vault`] to load it. Account and Enc use the seed format, so their names differ from the old
    /// ones ("account", "enc")
    pub fn vault_name(self) -> &'static str {
        match self {
            Slot::Account => "account-seed-v2",
            Slot::Device => "device",
            Slot::Enc => "enc-seed-v2",
            Slot::Recovery => "recovery",
        }
    }

    /// Vault item name → slot. Old-format names give `StaleKey`, unknown names give `InvalidArgument`
    pub fn from_vault_name(name: &str) -> Result<Slot, Error> {
        if STALE_VAULT_NAMES.contains(&name) {
            return Err(Error::StaleKey);
        }
        Slot::ALL.into_iter().find(|s| s.vault_name() == name).ok_or(Error::InvalidArgument)
    }

    fn is_signing(self) -> bool {
        matches!(self, Slot::Account | Slot::Device)
    }

    fn missing(self) -> Error {
        match self {
            Slot::Account => Error::NoAccountKey,
            Slot::Device => Error::NoDeviceKey,
            Slot::Enc => Error::NoEncryptionKey,
            Slot::Recovery => Error::RecoveryNotStarted,
        }
    }

    /// The slot's 32-byte public key. For Account: the identity public key ik (Ed25519 derived from the seed). For Enc: the
    /// X25519 public key pk_X (the last 32 bytes of the HEK)
    pub fn public_from(self, secret: &[u8; 32]) -> [u8; 32] {
        match self {
            Slot::Account => IdSeeds::from_seed(secret).ik(),
            Slot::Device => crypto::ed25519_public(secret),
            Slot::Enc => crypto::x25519_public(&pq::x_secret_from_seed(secret)),
            Slot::Recovery => crypto::x25519_public(secret),
        }
    }
}

/// Purpose of an outer envelope v2; selects the HKDF context. The numbers are C ABI values. The context bytes are fixed
/// by the core (the caller cannot choose them)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum OuterPurpose {
    /// Key envelopes at the outer layer (reports, self copies of member keys, member keys delivered to members who lack them,
    /// call signaling, etc.): `gori-pq/envelope-v2`
    Envelope = 0,
    /// Body sealing for request-mailbox notes, contact card keys, invite bundles, etc.: `gori-pq/note-v2`
    Note = 1,
    /// Sealed inbox copies and the sealed pair-list bundle that a user keeps for their own devices: `gori-pq/keep-v2`
    Keep = 2,
}

impl OuterPurpose {
    pub const ALL: [OuterPurpose; 3] = [OuterPurpose::Envelope, OuterPurpose::Note, OuterPurpose::Keep];

    pub fn from_u32(v: u32) -> Result<OuterPurpose, Error> {
        OuterPurpose::ALL.get(v as usize).copied().ok_or(Error::InvalidArgument)
    }

    pub fn info(self) -> &'static [u8] {
        match self {
            OuterPurpose::Envelope => b"gori-pq/envelope-v2",
            OuterPurpose::Note => b"gori-pq/note-v2",
            OuterPurpose::Keep => b"gori-pq/keep-v2",
        }
    }
}

/// Inner envelope (X25519, context `circle-envelope-v1`) = ephPub(32) ‖ nonce(24) ‖ AEAD(key 32): the key envelope inside a
/// pair note. Canonical form
pub const INNER_ENVELOPE_LEN: usize = 32 + NONCE_LEN + 32 + TAG_LEN; // 104
/// Former name of [`INNER_ENVELOPE_LEN`]
pub const ENVELOPE_LEN: usize = INNER_ENVELOPE_LEN;
/// Outer envelope v2 (hybrid) = 0x02 ‖ ct(1120) ‖ nonce(24) ‖ AEAD(kid 8 ‖ key 32)
pub const OUTER_ENVELOPE_LEN: usize = crypto::OUTER_OVERHEAD + 32; // 1201
pub const WRAPPED_LEN: usize = NONCE_LEN + 32 + TAG_LEN; // 72
pub const BACKUP_V1: u8 = 1;
/// **Old** version byte of the recovery v3 (paper phrase) backup, from before the post-quantum format, when the two
/// secrets were not seeds. No longer accepted (`StaleKey`)
pub const BACKUP_V3: u8 = 3;
/// Version byte of the recovery v3 (paper phrase) backup in the post-quantum format. The length and layout (64 B = account
/// seed 32 ‖ encryption seed 32) are the same as v3, but **the meaning differs**: both 32-byte values are seeds, so after
/// recovery Ed25519, ML-DSA, X25519 and ML-KEM keys are all re-derived. Reading an old v3 backup (raw secrets) as seeds
/// would produce different keys, so the version byte was bumped to reject it explicitly.
/// v4 binds the version byte as AEAD associated data (so the version cannot be swapped on an existing ciphertext)
pub const BACKUP_V4: u8 = 4;
pub const BACKUP_LEN: usize = 1 + NONCE_LEN + 64 + TAG_LEN; // 105
/// Length of the recovery v3 locator L
pub const LOCATOR_LEN: usize = 32;
/// Shamir share `[x] ‖ y(32)`: the secret T is 32 bytes, so a share is always 33 bytes
pub const SHARE_LEN: usize = 1 + 32;
/// Sealed recovery share = eph(32) ‖ nonce(24) ‖ XChaCha20-Poly1305(share 33) = 105 bytes
pub const SHARE_ENVELOPE_LEN: usize = 32 + NONCE_LEN + SHARE_LEN + TAG_LEN;
/// Server share U
pub const SERVER_SHARE_LEN: usize = 32;
/// Upper bound on the number of guardians (shares); the app offers up to 7. Bounds how long a single batch can hold
/// the core lock
pub const MAX_GUARDIANS: usize = 16;

pub struct RecoveryKit {
    /// Backup (ciphertext)
    pub backup: Vec<u8>,
    /// Server share U. The app uploads it to the server, but it is secret (combined with T it gives S). Zeroized on drop
    pub server_share: Secret32,
    /// Share sealed to each guardian (ciphertext)
    pub guardian_shares: Vec<Vec<u8>>,
}

/// Result of preparing recovery v3 (paper phrase)
pub struct SelfRecoveryKit {
    /// The 18-word recovery phrase (R). Shown on screen **once** so the user can write it on paper; the app does not
    /// store it. Zeroized on drop
    pub words: Zeroizing<Vec<String>>,
    /// Backup = [BACKUP_V4] ‖ nonce(24) ‖ seal(S, nonce, aad = [BACKUP_V4], account seed 32 ‖ encryption seed 32)
    pub backup: Vec<u8>,
    /// Server half U. Only combined with R does it give S. Zeroized on drop
    pub server_share: Secret32,
    /// Locator L = HKDF(R, "gori-recovery-locator"). The server stores only SHA-256(L), used solely to find the account
    /// from the phrase
    pub locator: [u8; LOCATOR_LEN],
}

pub struct Core {
    slots: [Option<Secret32>; 4],
    /// Content keys are boxed individually. When the map grows (rehash), its values move to a new table and the old
    /// table is freed without being zeroed. With boxes the table holds only pointers; each key stays where it is until
    /// it is removed and overwritten (Zeroizing)
    content: HashMap<String, Box<Secret32>>,
    /// Bot key sets (see [`crate::bot`]). Not stored in the vault: after the key file is written they are dropped by
    /// `bot_forget` (or when the app exits)
    bots: HashMap<String, Box<BotKeys>>,
    rng: Box<dyn CryptoRngCore + Send>,
}

impl Default for Core {
    fn default() -> Self {
        Core::new()
    }
}

impl Core {
    /// A core that uses the OS CSPRNG
    pub fn new() -> Core {
        Core::with_rng(Box::new(OsRng))
    }

    /// For tests: fixes the RNG (so regenerating the vectors yields the same bytes)
    pub fn with_rng(rng: Box<dyn CryptoRngCore + Send>) -> Core {
        Core { slots: [None, None, None, None], content: HashMap::new(), bots: HashMap::new(), rng }
    }

    fn secret(&self, slot: Slot) -> Result<&[u8; 32], Error> {
        self.slots[slot as usize].as_deref().ok_or(slot.missing())
    }

    /// Account identity seed isd (the slot's 32 bytes as is). Borrowed only inside the crate (invite ticket seed, `ticket.rs`);
    /// the only path across the boundary is `slot_secret`. The ticket seed is HKDF(isd, period salt, label), so it is
    /// domain-separated from the SHAKE-expanded Ed25519 and ML-DSA keys
    pub(crate) fn account_secret(&self) -> Result<&[u8; 32], Error> {
        self.secret(Slot::Account)
    }

    /// Ed25519 secret of a signing slot: derived from the identity seed for Account, used as is for Device
    fn signing_secret(&self, slot: Slot) -> Result<Secret32, Error> {
        let s = self.secret(slot)?;
        match slot {
            Slot::Account => Ok(IdSeeds::from_seed(s).ed_secret),
            Slot::Device => Ok(Zeroizing::new(*s)),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Key set derived from the encryption seed (includes ML-KEM key generation)
    fn enc_keys(&self) -> Result<EncKeys, Error> {
        Ok(EncKeys::from_seed(self.secret(Slot::Enc)?))
    }

    /// Only the X25519 secret derived from the encryption seed (inner envelope, legacy guardian path)
    fn enc_x_secret(&self) -> Result<Secret32, Error> {
        Ok(pq::x_secret_from_seed(self.secret(Slot::Enc)?))
    }

    fn set(&mut self, slot: Slot, secret: Secret32) {
        self.slots[slot as usize] = Some(secret);
    }

    fn new_handle(&mut self, key: Secret32) -> String {
        let id: [u8; 16] = crypto::random_array(self.rng.as_mut());
        let handle = hex::encode(id);
        self.content.insert(handle.clone(), Box::new(key));
        handle
    }

    fn content_key(&self, handle: &str) -> Result<&[u8; 32], Error> {
        self.content.get(handle).map(|k| &***k).ok_or(Error::UnknownHandle)
    }

    // ── Private-key slots (wrapper only) ──

    /// Generates a new key in the slot and returns its public key. The wrapper immediately takes it with `slot_secret`
    /// and stores it
    pub fn generate(&mut self, slot: Slot) -> [u8; 32] {
        let s = crypto::random_secret(self.rng.as_mut());
        let pubkey = slot.public_from(&s);
        self.set(slot, s);
        pubkey
    }

    /// Loads a stored key by slot number (tests and crate internals). **The wrapper uses [`Core::load_vault`]** (the vault
    /// item name is the format marker)
    pub fn load(&mut self, slot: Slot, secret: &[u8]) -> Result<[u8; 32], Error> {
        let s = Zeroizing::new(crypto::to_array32(secret)?);
        let pubkey = slot.public_from(&s);
        self.set(slot, s);
        Ok(pubkey)
    }

    /// Loads a stored key by vault item name ([`Slot::vault_name`]). Old-format names ("account", "enc": raw secrets, not
    /// seeds) are rejected with `StaleKey`, so they are never silently read as seeds and turned into public keys that
    /// differ from the ones pinned by the server and peers. On this error the wrapper goes to the account re-creation
    /// flow (and deletes the old item). Unknown names give `InvalidArgument`
    pub fn load_vault(&mut self, name: &str, secret: &[u8]) -> Result<(Slot, [u8; 32]), Error> {
        let slot = Slot::from_vault_name(name)?;
        Ok((slot, self.load(slot, secret)?))
    }

    /// Taken out by the wrapper to store in the Keychain. **Not used on any path that reaches JavaScript**
    pub fn slot_secret(&self, slot: Slot) -> Option<Secret32> {
        self.slots[slot as usize].clone()
    }

    pub fn clear(&mut self, slot: Slot) {
        self.slots[slot as usize] = None;
    }

    pub fn has(&self, slot: Slot) -> bool {
        self.slots[slot as usize].is_some()
    }

    pub fn public_key(&self, slot: Slot) -> Result<[u8; 32], Error> {
        Ok(slot.public_from(self.secret(slot)?))
    }

    // ── Signing ──

    /// Signs an arbitrary message (the app's statements, each with its own prefix). It does **not** produce core-only
    /// statements (those starting with `gori-core/`, such as device certificate v2 and encryption key signature v2);
    /// only the dedicated functions below produce those
    pub fn sign(&self, slot: Slot, message: &[u8]) -> Result<[u8; 64], Error> {
        if !slot.is_signing() {
            return Err(Error::InvalidArgument);
        }
        if message.starts_with(crypto::CORE_STATEMENT_PREFIX) {
            return Err(Error::ReservedStatement);
        }
        Ok(crypto::ed25519_sign(&*self.signing_secret(slot)?, message))
    }

    /// **Legacy format (v1)** device certificate: `sign(account, device_pub)`. New code uses
    /// [`Core::sign_device_certificate`]
    pub fn certify_device(&self, device_pubkey: &[u8]) -> Result<[u8; 64], Error> {
        if crypto::ed25519_key_strict(device_pubkey).is_none() {
            return Err(Error::WeakKey);
        }
        self.sign(Slot::Account, device_pubkey)
    }

    /// Device certificate v2: the account key signs **this core's device key**:
    /// `sign(account, "gori-core/device-cert-v2\0" ‖ device_pub)`. The device key is not an argument, so there is no way
    /// to certify a foreign device key (one chosen from outside) as a device of this account
    pub fn sign_device_certificate(&self) -> Result<[u8; 64], Error> {
        let account = self.signing_secret(Slot::Account)?;
        let device_pub = self.public_key(Slot::Device)?;
        Ok(crypto::ed25519_sign(&account, &crypto::device_cert_message(&device_pub)))
    }

    /// Encryption key signature v2: the account key signs **this core's encryption key**:
    /// `sign(account, "gori-core/enc-key-v2\0" ‖ enc_pub)`. This signature is visible to first-degree contacts and members,
    /// so it never verifies as a device certificate (v2) or any other statement
    pub fn sign_encryption_key(&self) -> Result<[u8; 64], Error> {
        let account = self.signing_secret(Slot::Account)?;
        let enc_pub = self.public_key(Slot::Enc)?;
        Ok(crypto::ed25519_sign(&account, &crypto::enc_key_message(&enc_pub)))
    }

    // ── Post-quantum public keys and signatures ──

    /// This core's hybrid public key HEK (1216) = pk_M(1184) ‖ pk_X(32). pk_X equals [`Core::public_key`]`(Enc)`
    pub fn encryption_hybrid_key(&self) -> Result<[u8; pq::HEK_LEN], Error> {
        Ok(self.enc_keys()?.hek())
    }

    /// Encryption key signature v3 `es3`: the account key signs **this core's HEK**:
    /// `sign(account, "gori-core/enc-key-v3\0" ‖ pk_X ‖ pk_M)`. It also covers the ML-KEM public key (preventing
    /// substitution). It does not verify as v2, a device certificate or any other statement
    pub fn sign_encryption_key_v3(&self) -> Result<[u8; 64], Error> {
        let account = self.signing_secret(Slot::Account)?;
        let hek = self.encryption_hybrid_key()?;
        Ok(crypto::ed25519_sign(&account, &crypto::enc_key_v3_message(&hek)))
    }

    /// Identity key binding `(pk_D, dh, ds, dq)`: binds the ML-DSA-65 public key and the identity key to each other.
    /// Public values only. Each call draws fresh randomness (32 B) for dq (everything else is the same for the same seed)
    pub fn pq_sig_binding(&mut self) -> Result<PqSigBinding, Error> {
        let id = IdSeeds::from_seed(self.secret(Slot::Account)?);
        Ok(id.binding(self.rng.as_mut()))
    }

    /// Verifies an identity key binding presented by someone else (the same four steps as the server's registration
    /// check, see [`pq::verify_binding`])
    pub fn verify_pq_sig_binding(ik: &[u8], pk_d: &[u8], dh: &[u8], ds: &[u8], dq: &[u8]) -> bool {
        pq::verify_binding(ik, pk_d, dh, ds, dq)
    }

    /// Checks a received HEK (length must be 1216, otherwise `NeedHybridKey`; strict pk_X check and pk_M modulus check,
    /// otherwise `WeakKey`). Sealing ([`Core::seal_outer`]) performs the same check; this function exists so that keys
    /// can be screened when they are first received
    pub fn check_hybrid_key(hek: &[u8]) -> Result<(), Error> {
        RecipientKey::parse(hek).map(|_| ())
    }

    /// Strict verification: small-order, non-canonical or torsion-containing public keys, small-order R and non-canonical
    /// S all return false ([`crypto::ed25519_verify`])
    pub fn verify(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
        crypto::ed25519_verify(pubkey, message, signature)
    }

    // ── Content keys ──

    pub fn create_content_key(&mut self) -> String {
        let k = crypto::random_secret(self.rng.as_mut());
        self.new_handle(k)
    }

    pub fn encrypt(&mut self, handle: &str, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let key = Zeroizing::new(*self.content_key(handle)?);
        let nonce: [u8; NONCE_LEN] = crypto::random_array(self.rng.as_mut());
        let mut out = nonce.to_vec();
        out.extend_from_slice(&crypto::seal(&key, &nonce, &[], plaintext));
        Ok(out)
    }

    pub fn decrypt(&self, handle: &str, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        decrypt_with(self.content_key(handle)?, ciphertext)
    }

    /// Temporarily copies a content key. Used only when the C boundary releases the core lock to decrypt something large
    /// (photos, videos). The copy is zeroed when that call ends (Zeroizing). It never goes to JavaScript
    pub(crate) fn content_key_copy(&self, handle: &str) -> Result<Zeroizing<[u8; 32]>, Error> {
        Ok(Zeroizing::new(*self.content_key(handle)?))
    }

    // ── Envelopes: outer (hybrid v2, 1201 B) and inner (X25519, 104 B) ──
    //
    // The outermost sealing of anything that passes through or rests on the server, mailboxes or push providers is the
    // outer envelope (`seal_outer`). Only the key envelope inside a note already sealed with a pair secret uses the inner
    // one (`seal_inner`). The open functions tell them apart by length: openers of outer envelopes reject 104 B, so there
    // is no downgrade from the outer envelope to plain X25519

    /// Seals a content key in an outer envelope v2. Returns `NeedHybridKey` unless given the recipient's HEK (1216) (the
    /// core catches calls made with a 32-byte key by mistake), and `WeakKey` if the HEK fails the check. The result is
    /// exactly [`OUTER_ENVELOPE_LEN`] = 1201 bytes
    pub fn seal_outer(&mut self, handle: &str, purpose: OuterPurpose, recipient_hek: &[u8]) -> Result<Vec<u8>, Error> {
        let to = RecipientKey::parse(recipient_hek)?;
        let key = Zeroizing::new(*self.content_key(handle)?);
        crypto::seal_bytes_v2(self.rng.as_mut(), key.as_ref(), &to, purpose.info())
    }

    /// Opens an outer envelope v2. Accepts exactly 1201 bytes only (a 104 B inner envelope also gives `BadEnvelope`).
    /// An envelope sealed for a different purpose does not open (`NotForMe`)
    pub fn open_outer(&mut self, purpose: OuterPurpose, envelope: &[u8]) -> Result<String, Error> {
        let keys = self.enc_keys()?;
        if envelope.len() != OUTER_ENVELOPE_LEN {
            return Err(Error::BadEnvelope);
        }
        let key = crypto::open_bytes_v2(envelope, &keys, purpose.info())?;
        let key = Zeroizing::new(crypto::to_array32(&key).map_err(|_| Error::NotForMe)?);
        Ok(self.new_handle(key))
    }

    /// Seals with the inner envelope (X25519, 104 B, context `circle-envelope-v1`; the same bytes as the former `seal_to`).
    /// The recipient key is pk_X (32)
    pub fn seal_inner(&mut self, handle: &str, recipient_pub: &[u8]) -> Result<Vec<u8>, Error> {
        let key = Zeroizing::new(*self.content_key(handle)?);
        crypto::seal_bytes(self.rng.as_mut(), key.as_ref(), recipient_pub, crypto::ENVELOPE_INFO)
    }

    /// Opens an inner envelope. Accepts exactly 104 bytes only (a 1201 B outer envelope also gives `BadEnvelope`)
    pub fn open_inner(&mut self, envelope: &[u8]) -> Result<String, Error> {
        let x = self.enc_x_secret()?;
        if envelope.len() != INNER_ENVELOPE_LEN {
            return Err(Error::BadEnvelope);
        }
        let key = crypto::open_bytes(envelope, &x, crypto::ENVELOPE_INFO).ok_or(Error::NotForMe)?;
        let key = Zeroizing::new(crypto::to_array32(&key).map_err(|_| Error::NotForMe)?);
        Ok(self.new_handle(key))
    }

    pub fn wrap_key(&mut self, kek: &str, key: &str) -> Result<Vec<u8>, Error> {
        let kek_b = Zeroizing::new(*self.content_key(kek)?);
        let key_b = Zeroizing::new(*self.content_key(key)?);
        let nonce: [u8; NONCE_LEN] = crypto::random_array(self.rng.as_mut());
        let mut out = nonce.to_vec();
        out.extend_from_slice(&crypto::seal(&kek_b, &nonce, crypto::WRAP_AAD, key_b.as_ref()));
        Ok(out)
    }

    pub fn unwrap_key(&mut self, kek: &str, wrapped: &[u8]) -> Result<String, Error> {
        let kek_b = Zeroizing::new(*self.content_key(kek)?);
        if wrapped.len() != WRAPPED_LEN {
            return Err(Error::BadWrapped);
        }
        let key = crypto::open(&kek_b, &wrapped[..NONCE_LEN], crypto::WRAP_AAD, &wrapped[NONCE_LEN..])
            .ok_or(Error::UnwrapFailed)?;
        let key = Zeroizing::new(crypto::to_array32(&key).map_err(|_| Error::UnwrapFailed)?);
        Ok(self.new_handle(key))
    }

    // ── Chunked files ──

    /// Encrypts `input` in chunks and writes the result to `output`. A failure midway leaves no partially written file
    pub fn encrypt_file(&mut self, handle: &str, input: &Path, output: &Path) -> Result<u64, Error> {
        let key = Zeroizing::new(*self.content_key(handle)?);
        let rng = self.rng.as_mut();
        write_atomically(output, Durability::Synced, |w| {
            let mut r = File::open(input)?;
            stream::encrypt(&key, rng, stream::DEFAULT_CHUNK_EXP, &mut r, w)
        })
    }

    /// `output` appears only after the whole file has been authenticated
    pub fn decrypt_file(&self, handle: &str, input: &Path, output: &Path) -> Result<u64, Error> {
        decrypt_file_with(&*self.content_key_copy(handle)?, input, output, Durability::Synced)
    }

    /// **Decrypt while downloading**: decrypts only the plaintext range `[start, start+len)` into memory from a chunked
    /// file `input` that is still being downloaded (its current size is the prefix received so far). `total` is the full
    /// ciphertext length (from the download response). If the range has not arrived yet, returns `StreamNotYet`; the
    /// player calls again after more has arrived. Plaintext is never written to disk (`stream::decrypt_range`)
    pub fn decrypt_file_range(&self, handle: &str, input: &Path, total: u64, start: u64, len: u64) -> Result<Zeroizing<Vec<u8>>, Error> {
        decrypt_file_range_with(&*self.content_key_copy(handle)?, input, total, start, len)
    }

    // ── Account recovery ──

    fn recovery_secret(t: &[u8], u: &[u8]) -> Secret32 {
        let mut ikm = Zeroizing::new(Vec::with_capacity(t.len() + u.len()));
        ikm.extend_from_slice(t);
        ikm.extend_from_slice(u);
        crypto::hkdf32(&ikm, None, crypto::SECRET_INFO)
    }

    /// Opens a sealed share. The length must be exactly 105 (a 33-byte share inside)
    fn open_share(envelope: &[u8], secret: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>, Error> {
        if envelope.len() != SHARE_ENVELOPE_LEN {
            return Err(Error::BadShareEnvelope);
        }
        let share = crypto::open_bytes(envelope, secret, crypto::SHARE_INFO).ok_or(Error::ShareNotForMe)?;
        if share.len() != SHARE_LEN {
            return Err(Error::ShareLength);
        }
        Ok(share)
    }

    pub fn prepare_recovery<P: AsRef<[u8]>>(
        &mut self,
        guardian_pubkeys: &[P],
        threshold: usize,
    ) -> Result<RecoveryKit, Error> {
        let (Some(account), Some(enc)) = (
            self.slots[Slot::Account as usize].clone(),
            self.slots[Slot::Enc as usize].clone(),
        ) else {
            return Err(Error::NothingToRecover);
        };
        let n = guardian_pubkeys.len();
        if threshold < 2 || n < threshold {
            return Err(Error::TooFewGuardians);
        }
        if n > MAX_GUARDIANS {
            return Err(Error::BadShareCount);
        }
        // Guardian keys: canonical, on the curve and not of small order; the same person (representative u([8]P)) may not
        // appear twice; none may be our own encryption key.
        // The encryption slot holds a seed, so the own-key comparison uses the X25519 public key derived from the seed
        // (the format of this legacy path is unchanged)
        let own = crypto::x25519_key_class(&Slot::Enc.public_from(&enc))?;
        let mut classes: Vec<[u8; 32]> = Vec::with_capacity(n);
        for p in guardian_pubkeys {
            let class = crypto::x25519_key_class(p.as_ref())?;
            if class == own {
                return Err(Error::InvalidArgument);
            }
            if classes.contains(&class) {
                return Err(Error::DuplicateGuardian);
            }
            classes.push(class);
        }
        let rng = self.rng.as_mut();
        let t = crypto::random_secret(rng);
        // U is also Zeroizing from the start (the order and amount of randomness drawn are fixed, so the vectors stay the same)
        let u = crypto::random_secret(rng);
        let key = Core::recovery_secret(t.as_ref(), u.as_ref());

        let mut keys = Zeroizing::new([0u8; 64]);
        keys[..32].copy_from_slice(account.as_ref());
        keys[32..].copy_from_slice(enc.as_ref());
        let nonce: [u8; NONCE_LEN] = crypto::random_array(rng);
        let mut backup = vec![BACKUP_V1];
        backup.extend_from_slice(&nonce);
        backup.extend_from_slice(&crypto::seal(&key, &nonce, &[], keys.as_ref()));

        let mut coeffs = Zeroizing::new(vec![0u8; 32 * (threshold - 1)]);
        rng.fill_bytes(&mut coeffs);
        // Shares are Zeroizing from the start: if sealing to some guardian fails and `?` returns early, the remaining
        // shares are zeroed too
        let shares = shamir::split(t.as_ref(), n, threshold, &coeffs)?;
        let mut guardian_shares = Vec::with_capacity(n);
        for (share, pubkey) in shares.iter().zip(guardian_pubkeys) {
            guardian_shares.push(crypto::seal_bytes(rng, share, pubkey.as_ref(), crypto::SHARE_INFO)?);
        }
        Ok(RecoveryKit { backup, server_share: u, guardian_shares })
    }

    // ── Recovery v3: paper phrase R + server half U ──
    //
    //   S = HKDF(R ‖ U, "gori-self-recovery-v3")   locks the backup
    //   L = HKDF(R, "gori-recovery-locator")        lets the server find the account from the phrase (it stores only SHA-256(L))
    //
    // R is handed to JavaScript once, as 18 words (192 bits), because the user has to write it on paper (the exception to
    // the key boundary). The words alone cannot open the backup: U is required as well. Shares, guardians and the Recovery
    // slot are not used

    fn self_recovery_secret(r: &[u8], u: &[u8]) -> Secret32 {
        let mut ikm = Zeroizing::new(Vec::with_capacity(r.len() + u.len()));
        ikm.extend_from_slice(r);
        ikm.extend_from_slice(u);
        crypto::hkdf32(&ikm, None, crypto::SELF_RECOVERY_INFO)
    }

    fn locator_of(r: &[u8]) -> [u8; LOCATOR_LEN] {
        *crypto::hkdf32(r, None, crypto::RECOVERY_LOCATOR_INFO)
    }

    /// Prepares paper-phrase recovery. Each call creates a fresh R and U.
    /// Requires the account and encryption keys (the same check as `prepare_recovery`; otherwise `NothingToRecover`).
    /// Randomness is drawn in the order R(24), U(32), nonce(24) (the test vectors depend on this order)
    pub fn prepare_self_recovery(&mut self) -> Result<SelfRecoveryKit, Error> {
        let (Some(account), Some(enc)) = (
            self.slots[Slot::Account as usize].clone(),
            self.slots[Slot::Enc as usize].clone(),
        ) else {
            return Err(Error::NothingToRecover);
        };
        let rng = self.rng.as_mut();
        let mut r = Zeroizing::new([0u8; phrase::ENTROPY_LEN]);
        rng.fill_bytes(r.as_mut());
        let u = crypto::random_secret(rng);
        let key = Core::self_recovery_secret(r.as_ref(), u.as_ref());

        let mut keys = Zeroizing::new([0u8; 64]);
        keys[..32].copy_from_slice(account.as_ref());
        keys[32..].copy_from_slice(enc.as_ref());
        let nonce: [u8; NONCE_LEN] = crypto::random_array(rng);
        let mut backup = Vec::with_capacity(BACKUP_LEN);
        backup.push(BACKUP_V4);
        backup.extend_from_slice(&nonce);
        backup.extend_from_slice(&crypto::seal(&key, &nonce, &[BACKUP_V4], keys.as_ref()));
        debug_assert_eq!(backup.len(), BACKUP_LEN);

        Ok(SelfRecoveryKit {
            words: phrase::encode(&r),
            backup,
            server_share: u,
            locator: Core::locator_of(r.as_ref()),
        })
    }

    /// Phrase → locator L (32). Words are trimmed and lowercased. Returns `BadPhrase` if there are not 18 words, a word is
    /// not in the list, or the checksum is wrong. Neither reads nor changes core state (on a new phone there are no keys yet)
    pub fn recovery_locator<S: AsRef<str>>(words: &[S]) -> Result<[u8; LOCATOR_LEN], Error> {
        let r = phrase::decode(words)?;
        Ok(Core::locator_of(r.as_ref()))
    }

    /// Loads the account and encryption **seeds** into this core from phrase R, server half U and the backup. On success
    /// the wrapper stores account and enc under the new vault names ([`Slot::vault_name`]). Because the seeds are the
    /// same, Ed25519, ML-DSA, X25519 and ML-KEM keys all come out exactly as before, so the published HEK and ML-DSA
    /// public key stay valid. The Recovery slot (temporary receiving key of the guardian path) is neither read nor cleared.
    ///
    /// Checks **before loading**, with the same rules as `complete_recovery`. If any check fails, the core slots are unchanged:
    /// - `InvalidArgument` if `expected_account_pub` is not a strict Ed25519 public key
    /// - `StaleKey` if the version is [`BACKUP_V3`] (pre post-quantum; the two secrets are not seeds)
    /// - `BadBackup` if the backup is not 105 bytes or the version is not [`BACKUP_V4`] (a v1 backup is never opened on this path)
    /// - `InvalidArgument` if U is not 32 bytes; `BadPhrase` if the phrase is invalid
    /// - `RecoveryFailed` if the backup does not open (without revealing whether the phrase or U was wrong)
    /// - `AccountMismatch` if the recovered account public key differs from the expected one
    /// - `KeyConflict` if it would overwrite a different account or encryption key already loaded. Identical keys are left
    ///   as is (for when the wrapper stored only one of them before being interrupted and retries)
    pub fn complete_self_recovery<S: AsRef<str>>(
        &mut self,
        words: &[S],
        backup: &[u8],
        server_share: &[u8],
        expected_account_pub: &[u8],
    ) -> Result<([u8; 32], [u8; 32]), Error> {
        let expected = crypto::to_array32(expected_account_pub)?;
        if crypto::ed25519_key_strict(&expected).is_none() {
            return Err(Error::InvalidArgument);
        }
        if backup.len() == BACKUP_LEN && backup[0] == BACKUP_V3 {
            return Err(Error::StaleKey);
        }
        if backup.len() != BACKUP_LEN || backup[0] != BACKUP_V4 {
            return Err(Error::BadBackup);
        }
        if server_share.len() != SERVER_SHARE_LEN {
            return Err(Error::InvalidArgument);
        }
        let r = phrase::decode(words)?;
        let key = Core::self_recovery_secret(r.as_ref(), server_share);
        let keys = crypto::open(&key, &backup[1..25], &[BACKUP_V4], &backup[25..]).ok_or(Error::RecoveryFailed)?;
        if keys.len() != 64 {
            return Err(Error::RecoveryFailed);
        }
        let account = Zeroizing::new(crypto::to_array32(&keys[..32])?);
        let enc = Zeroizing::new(crypto::to_array32(&keys[32..])?);
        let pubs = (Slot::Account.public_from(&account), Slot::Enc.public_from(&enc));
        if pubs.0 != expected {
            return Err(Error::AccountMismatch);
        }
        for (slot, recovered) in [(Slot::Account, &account), (Slot::Enc, &enc)] {
            if let Some(current) = self.slots[slot as usize].as_deref() {
                if !crypto::same32(current, recovered) {
                    return Err(Error::KeyConflict);
                }
            }
        }
        self.set(Slot::Account, account);
        self.set(Slot::Enc, enc);
        Ok(pubs)
    }

    /// Creates the temporary receiving key (or returns the existing one). Returns `(public key, newly created)`; if it was
    /// newly created, the wrapper stores it
    pub fn begin_recovery(&mut self) -> ([u8; 32], bool) {
        if let Some(s) = &self.slots[Slot::Recovery as usize] {
            return (crypto::x25519_public(s), false);
        }
        (self.generate(Slot::Recovery), true)
    }

    pub fn reseal_share(&mut self, sealed_share: &[u8], to_pubkey: &[u8]) -> Result<Vec<u8>, Error> {
        let enc = self.enc_x_secret()?;
        let share = Core::open_share(sealed_share, &enc)?;
        crypto::seal_bytes(self.rng.as_mut(), &share, to_pubkey, crypto::SHARE_INFO)
    }

    /// Decrypts the backup and loads the account and encryption keys into this core. Clears the temporary receiving key.
    /// On success the wrapper stores account and enc and deletes recovery.
    ///
    /// Checks **before loading**; if any check fails, the core slots are unchanged:
    /// - the recovered account public key must equal `expected_account_pub` (the identity public key of the account being
    ///   recovered), otherwise `AccountMismatch`
    /// - any account or encryption key already in this core must equal the recovered one, otherwise `KeyConflict` (no
    ///   overwrite). Identical keys are left as is, for when the wrapper wrote only one of the two to the Keychain before
    ///   being interrupted and retries
    /// - 1 to [`MAX_GUARDIANS`] shares, each exactly 105 bytes (33 once opened); server share U exactly 32 bytes
    pub fn complete_recovery<S: AsRef<[u8]>>(
        &mut self,
        backup: &[u8],
        sealed_shares: &[S],
        server_share: &[u8],
        expected_account_pub: &[u8],
    ) -> Result<([u8; 32], [u8; 32]), Error> {
        let recovery = Zeroizing::new(*self.secret(Slot::Recovery)?);
        let expected = crypto::to_array32(expected_account_pub)?;
        if crypto::ed25519_key_strict(&expected).is_none() {
            return Err(Error::InvalidArgument);
        }
        if backup.len() != BACKUP_LEN || backup[0] != BACKUP_V1 {
            return Err(Error::BadBackup);
        }
        if server_share.len() != SERVER_SHARE_LEN {
            return Err(Error::InvalidArgument);
        }
        if sealed_shares.is_empty() {
            return Err(Error::NoShares);
        }
        if sealed_shares.len() > MAX_GUARDIANS {
            return Err(Error::BadShareCount);
        }
        // Check every length first, before starting any opening (X25519)
        if sealed_shares.iter().any(|s| s.as_ref().len() != SHARE_ENVELOPE_LEN) {
            return Err(Error::BadShareEnvelope);
        }
        let opened = sealed_shares
            .iter()
            .map(|s| Core::open_share(s.as_ref(), &recovery))
            .collect::<Result<Vec<_>, _>>()?;
        let t = shamir::combine(&opened)?;
        let key = Core::recovery_secret(&t, server_share);
        let keys = crypto::open(&key, &backup[1..25], &[], &backup[25..]).ok_or(Error::RecoveryFailed)?;
        if keys.len() != 64 {
            return Err(Error::RecoveryFailed);
        }
        let account = Zeroizing::new(crypto::to_array32(&keys[..32])?);
        let enc = Zeroizing::new(crypto::to_array32(&keys[32..])?);
        let pubs = (Slot::Account.public_from(&account), Slot::Enc.public_from(&enc));
        if pubs.0 != expected {
            return Err(Error::AccountMismatch);
        }
        for (slot, recovered) in [(Slot::Account, &account), (Slot::Enc, &enc)] {
            if let Some(current) = self.slots[slot as usize].as_deref() {
                if !crypto::same32(current, recovered) {
                    return Err(Error::KeyConflict);
                }
            }
        }
        self.set(Slot::Account, account);
        self.set(Slot::Enc, enc);
        self.clear(Slot::Recovery);
        Ok(pubs)
    }

    pub fn forget_all(&mut self) {
        self.slots = [None, None, None, None];
        self.content.clear();
        self.bots.clear();
    }

    // ── Bot keys (see `bot.rs`) ──

    /// Creates a new bot key set (identity, device and encryption seeds) and keeps it in the handle table. Returns the
    /// handle and the public bundle ([`bot::BOT_PUBLIC_LEN`], public values only).
    /// The seeds are not put in the vault: they are written to a file with [`Core::bot_key_file`] and erased with
    /// [`Core::bot_forget`]
    pub fn bot_create(&mut self) -> (String, Vec<u8>) {
        let keys = BotKeys::generate(self.rng.as_mut());
        let blob = keys.public_blob(self.rng.as_mut());
        let id: [u8; 16] = crypto::random_array(self.rng.as_mut());
        let handle = hex::encode(id);
        self.bots.insert(handle.clone(), Box::new(keys));
        (handle, blob)
    }

    /// Writes the bot key file to `path` (one line of JSON; see the header of `bot.rs`). This is the only way the seeds
    /// leave the crate (into a file); they never go to JavaScript
    pub fn bot_key_file(&self, handle: &str, meta: &[u8], path: &Path) -> Result<(), Error> {
        self.bots.get(handle).ok_or(Error::UnknownHandle)?.write_key_file(meta, path)
    }

    /// Erases the bot key set (zeroized). Does nothing for an unknown handle
    pub fn bot_forget(&mut self, handle: &str) {
        self.bots.remove(handle);
    }

    /// Owner signatures. op 0: bot certificate (owner identity key; payload 80 = bot account ‖ bot ik ‖ name hash →
    /// signature 64). op 1: management key public key (salt 16 → 32). op 2: delete (salt 16, payload 24 → public key 32 ‖
    /// signature 64). op 3: rekey (salt 16, payload 56 → public key 32 ‖ signature 64).
    /// The statement prefixes (`gori-core/bot-cert-v1`, `gori-core/bot-admin-v1`) are added by the core, so bytes chosen
    /// by JavaScript cannot form a different core statement
    pub fn bot_sign(&self, op: u32, salt: &[u8], payload: &[u8]) -> Result<Vec<u8>, Error> {
        match op {
            bot::BOT_SIGN_CERT => {
                if !salt.is_empty() {
                    return Err(Error::InvalidArgument);
                }
                let msg = bot::cert_message(payload)?;
                let owner = self.signing_secret(Slot::Account)?;
                Ok(crypto::ed25519_sign(&owner, &msg).to_vec())
            }
            bot::BOT_SIGN_ADMIN_KEY => {
                if !payload.is_empty() {
                    return Err(Error::InvalidArgument);
                }
                let sk = bot::admin_secret(self.account_secret()?, salt)?;
                Ok(crypto::ed25519_public(&sk).to_vec())
            }
            bot::BOT_SIGN_DELETE | bot::BOT_SIGN_REKEY => {
                let msg = bot::admin_message(if op == bot::BOT_SIGN_DELETE { 1 } else { 2 }, payload)?;
                let sk = bot::admin_secret(self.account_secret()?, salt)?;
                let mut out = crypto::ed25519_public(&sk).to_vec();
                out.extend_from_slice(&crypto::ed25519_sign(&sk, &msg));
                Ok(out)
            }
            _ => Err(Error::InvalidArgument),
        }
    }
}

fn part_path(output: &Path) -> PathBuf {
    let mut name = output.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(".part");
    output.with_file_name(name)
}

/// Opens a single `nonce ‖ ciphertext` blob (post, photo); the body of [`Core::decrypt`]
pub(crate) fn decrypt_with(key: &[u8; 32], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    if ciphertext.len() < NONCE_LEN {
        return Err(Error::BadCiphertext);
    }
    crypto::open(key, &ciphertext[..NONCE_LEN], &[], &ciphertext[NONCE_LEN..]).ok_or(Error::DecryptFailed)
}

/// Whether a finished file is flushed to disk (fsync) before it is renamed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Durability {
    /// Flushed: encrypted videos (to be uploaded) and regular decryption
    Synced,
    /// Not flushed: **cache files that can simply be downloaded again** (feed videos). As with `Synced`, the rename
    /// happens only after authentication completes. On Apple platforms `sync_all` is F_FULLFSYNC, which also flushes
    /// the drive cache, so it is skipped for these files
    Cache,
}

/// Plaintext range of a chunked file that is still being downloaded; the body of [`Core::decrypt_file_range`] (the FFI
/// copies only the key, releases the lock, then calls this)
pub(crate) fn decrypt_file_range_with(key: &[u8; 32], input: &Path, total: u64, start: u64, len: u64) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut f = File::open(input)?;
    let available = f.metadata()?.len();
    stream::decrypt_range(key, &mut f, available, total, start, len)
}

/// Decrypts a chunked file (GORS); the body of [`Core::decrypt_file`]. `output` appears only after the whole file has been
/// authenticated
pub(crate) fn decrypt_file_with(key: &[u8; 32], input: &Path, output: &Path, durability: Durability) -> Result<u64, Error> {
    write_atomically(output, durability, |w| {
        let mut r = File::open(input)?;
        stream::decrypt(key, &mut r, w)
    })
}

#[cfg(test)]
thread_local! {
    /// Number of fsyncs on this thread; lets tests observe Durability
    static SYNCS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

fn sync(file: &File) -> std::io::Result<()> {
    #[cfg(test)]
    SYNCS.with(|n| n.set(n.get() + 1));
    file.sync_all()
}

/// Writes to `.part` and renames it when done. If anything fails midway, `.part` is removed.
/// If `.part` already exists it is **truncated and written in place** (File::create), so the protection class that the iOS
/// wrapper set on a pre-created empty `.part` is preserved.
///
/// Files are read and written directly, without `BufReader`/`BufWriter`: the standard library's 8 KiB buffers are not
/// zeroed when dropped and would leave plaintext (for example a short final chunk) in freed heap memory. The stream already
/// reads and writes in 64 KiB chunks, so buffering would save no system calls (reads and writes larger than 8 KiB bypass
/// the buffer anyway)
fn write_atomically<F>(output: &Path, durability: Durability, f: F) -> Result<u64, Error>
where
    F: FnOnce(&mut File) -> Result<u64, Error>,
{
    let part = part_path(output);
    let result = (|| {
        let mut file = File::create(&part)?;
        let n = f(&mut file)?;
        if durability == Durability::Synced {
            sync(&file)?;
        }
        fs::rename(&part, output)?;
        Ok(n)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&part);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn core(seed: u64) -> Core {
        Core::with_rng(Box::new(ChaCha20Rng::seed_from_u64(seed)))
    }

    #[test]
    fn handles_are_16_byte_hex_and_not_key_material() {
        let mut c = core(1);
        let h = c.create_content_key();
        assert_eq!(h.len(), 32);
        assert!(h.chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn encrypt_decrypt_and_wrong_handle() {
        let mut c = core(2);
        let a = c.create_content_key();
        let b = c.create_content_key();
        // Multi-byte UTF-8 sample text
        let ct = c.encrypt(&a, "multi-byte: d\u{e9}j\u{e0} vu \u{2713}".as_bytes()).unwrap();
        assert_eq!(&c.decrypt(&a, &ct).unwrap()[..], "multi-byte: d\u{e9}j\u{e0} vu \u{2713}".as_bytes());
        assert_eq!(c.decrypt(&b, &ct).unwrap_err(), Error::DecryptFailed);
        assert_eq!(c.decrypt("nope", &ct).unwrap_err(), Error::UnknownHandle);
        assert_eq!(c.decrypt(&a, &[0; 10]).unwrap_err(), Error::BadCiphertext);
    }

    #[test]
    fn envelope_round_trip_and_foreign_envelope() {
        let mut sender = core(3);
        let mut recv = core(4);
        let mut other = core(5);
        let rp = recv.generate(Slot::Enc);
        other.generate(Slot::Enc);
        let h = sender.create_content_key();
        let ct = sender.encrypt(&h, b"hi").unwrap();
        let env = sender.seal_inner(&h, &rp).unwrap();
        assert_eq!(env.len(), ENVELOPE_LEN);
        let opened = recv.open_inner(&env).unwrap();
        assert_eq!(&recv.decrypt(&opened, &ct).unwrap()[..], b"hi");
        assert_eq!(other.open_inner(&env).unwrap_err(), Error::NotForMe);
        assert_eq!(recv.open_inner(&env[..100]).unwrap_err(), Error::BadEnvelope);
        assert_eq!(core(6).open_inner(&env).unwrap_err(), Error::NoEncryptionKey);
        // Sealing to a small-order public key (0) is rejected
        assert_eq!(sender.seal_inner(&h, &[0u8; 32]).unwrap_err(), Error::WeakKey);
    }

    #[test]
    fn wrap_unwrap() {
        let mut c = core(7);
        let kek = c.create_content_key();
        let key = c.create_content_key();
        let ct = c.encrypt(&key, b"profile").unwrap();
        let w = c.wrap_key(&kek, &key).unwrap();
        assert_eq!(w.len(), WRAPPED_LEN);
        let k2 = c.unwrap_key(&kek, &w).unwrap();
        assert_eq!(&c.decrypt(&k2, &ct).unwrap()[..], b"profile");
        assert_eq!(c.unwrap_key(&key, &w).unwrap_err(), Error::UnwrapFailed);
        assert_eq!(c.unwrap_key(&kek, &w[..71]).unwrap_err(), Error::BadWrapped);
        // A plain ciphertext (no AAD) does not unwrap as a wrapped key
        let plain_ct = c.encrypt(&kek, &[5u8; 32]).unwrap();
        assert_eq!(c.unwrap_key(&kek, &plain_ct).unwrap_err(), Error::UnwrapFailed);
    }

    #[test]
    fn sign_verify_and_missing_keys() {
        let mut c = core(8);
        assert_eq!(c.sign(Slot::Account, b"m").unwrap_err(), Error::NoAccountKey);
        assert_eq!(c.sign(Slot::Device, b"m").unwrap_err(), Error::NoDeviceKey);
        let acc = c.generate(Slot::Account);
        let dev = c.generate(Slot::Device);
        let cert = c.certify_device(&dev).unwrap();
        assert!(Core::verify(&acc, &dev, &cert));
        assert!(!Core::verify(&dev, &dev, &cert));
        assert!(!Core::verify(&acc[..31], &dev, &cert));
        assert_eq!(c.sign(Slot::Enc, b"m").unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn recovery_full_cycle() {
        let mut old = core(10);
        let acc = old.generate(Slot::Account);
        let enc = old.generate(Slot::Enc);
        let mut guardians: Vec<Core> = (0..3).map(|i| core(20 + i)).collect();
        let gp: Vec<[u8; 32]> = guardians.iter_mut().map(|g| g.generate(Slot::Enc)).collect();
        assert_eq!(old.prepare_recovery(&gp, 1).err(), Some(Error::TooFewGuardians));
        assert_eq!(old.prepare_recovery(&gp[..1], 2).err(), Some(Error::TooFewGuardians));
        let kit = old.prepare_recovery(&gp, 2).unwrap();
        assert_eq!(kit.backup.len(), BACKUP_LEN);

        let mut fresh = core(30);
        let (tmp, created) = fresh.begin_recovery();
        assert!(created);
        assert_eq!(fresh.begin_recovery(), (tmp, false));
        let resealed: Vec<Vec<u8>> = (0..3)
            .map(|i| guardians[i].reseal_share(&kit.guardian_shares[i], &tmp).unwrap())
            .collect();
        // A single share is not enough
        assert_eq!(
            fresh.complete_recovery(&kit.backup, &resealed[..1], &kit.server_share[..], &acc).unwrap_err(),
            Error::RecoveryFailed
        );
        // A wrong server share fails
        assert_eq!(
            fresh.complete_recovery(&kit.backup, &resealed[..2], &[0u8; 32], &acc).unwrap_err(),
            Error::RecoveryFailed
        );
        let (a, e) = fresh.complete_recovery(&kit.backup, &resealed[1..], &kit.server_share[..], &acc).unwrap();
        assert_eq!((a, e), (acc, enc));
        assert!(!fresh.has(Slot::Recovery));
        assert_eq!(fresh.slot_secret(Slot::Account), old.slot_secret(Slot::Account));
        // A guardian cannot open another guardian's share
        assert_eq!(
            guardians[0].reseal_share(&kit.guardian_shares[1], &tmp).unwrap_err(),
            Error::ShareNotForMe
        );
    }

    #[test]
    fn forget_all_clears_everything() {
        let mut c = core(40);
        c.generate(Slot::Account);
        c.generate(Slot::Enc);
        let h = c.create_content_key();
        c.forget_all();
        assert!(Slot::ALL.iter().all(|s| !c.has(*s)));
        assert_eq!(c.encrypt(&h, b"x").unwrap_err(), Error::UnknownHandle);
    }

    #[test]
    fn file_range_reads_while_receiving() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("video.mov");
        let enc_path = dir.path().join("video.gors");
        let part = dir.path().join("video.recv");
        let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        fs::write(&input, &data).unwrap();
        let mut c = core(51);
        let h = c.create_content_key();
        let total = c.encrypt_file(&h, &input, &enc_path).unwrap();
        let ct = fs::read(&enc_path).unwrap();
        // Only the first chunk (64 KiB) and a little more have arrived: the start decrypts, the rest is not there yet
        fs::write(&part, &ct[..70_000]).unwrap();
        assert_eq!(c.decrypt_file_range(&h, &part, total, 0, 1000).unwrap().to_vec(), data[..1000].to_vec());
        assert_eq!(c.decrypt_file_range(&h, &part, total, 200_000, 10).unwrap_err(), Error::StreamNotYet);
        // Fully downloaded: the last chunk decrypts, and a request past the end is clamped to the end
        fs::write(&part, &ct).unwrap();
        assert_eq!(c.decrypt_file_range(&h, &part, total, 299_990, 100).unwrap().to_vec(), data[299_990..].to_vec());
        // Wrong key, unknown handle
        let other = c.create_content_key();
        assert_eq!(c.decrypt_file_range(&other, &part, total, 0, 10).unwrap_err(), Error::StreamAuth);
        assert_eq!(c.decrypt_file_range("nope", &part, total, 0, 10).unwrap_err(), Error::UnknownHandle);
        // Missing file
        assert_eq!(c.decrypt_file_range(&h, &dir.path().join("none"), total, 0, 10).unwrap_err(), Error::Io);
    }

    #[test]
    fn file_round_trip_and_no_partial_output() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("video.mov");
        let enc_path = dir.path().join("video.gors");
        let out = dir.path().join("video.out");
        let data: Vec<u8> = (0..300_000u32).map(|i| (i % 253) as u8).collect();
        fs::write(&input, &data).unwrap();
        let mut c = core(50);
        let h = c.create_content_key();
        let n = c.encrypt_file(&h, &input, &enc_path).unwrap();
        assert_eq!(n, stream::ciphertext_len(data.len() as u64, stream::DEFAULT_CHUNK_EXP));
        c.decrypt_file(&h, &enc_path, &out).unwrap();
        assert_eq!(fs::read(&out).unwrap(), data);

        // Truncated file: neither the output nor .part remains
        let bad = dir.path().join("bad.gors");
        let ct = fs::read(&enc_path).unwrap();
        fs::write(&bad, &ct[..ct.len() - 40]).unwrap();
        let out2 = dir.path().join("bad.out");
        assert_eq!(c.decrypt_file(&h, &bad, &out2).unwrap_err(), Error::StreamAuth);
        assert!(!out2.exists());
        assert!(!part_path(&out2).exists());
        assert_eq!(c.decrypt_file(&h, &dir.path().join("none"), &out2).unwrap_err(), Error::Io);
    }

    /// Decrypting to a cache file (Durability::Cache): same result, but no fsync. A truncated file leaves neither the output
    /// nor .part. A pre-created `.part` (iOS protection class) is truncated and written in place: the same file (inode) is
    /// only renamed
    #[test]
    fn cache_decrypt_skips_sync_but_stays_atomic() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("v.mov");
        let enc_path = dir.path().join("v.gors");
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 249) as u8).collect();
        fs::write(&input, &data).unwrap();
        let mut c = core(52);
        let h = c.create_content_key();
        let syncs = || SYNCS.with(|n| n.get());

        let before = syncs();
        c.encrypt_file(&h, &input, &enc_path).unwrap();
        assert_eq!(syncs(), before + 1, "an encrypted file (to be uploaded) is fsynced");
        let key = c.content_key_copy(&h).unwrap();

        let durable = dir.path().join("durable.mp4");
        decrypt_file_with(&key, &enc_path, &durable, Durability::Synced).unwrap();
        assert_eq!(syncs(), before + 2, "regular decryption is fsynced");
        c.decrypt_file(&h, &enc_path, &dir.path().join("handle.mp4")).unwrap();
        assert_eq!(syncs(), before + 3);

        // Pre-created .part (even with junk in it): truncated and written, and that file becomes the output
        let out = dir.path().join("cache.mp4");
        fs::write(part_path(&out), b"stale bytes from before").unwrap();
        #[cfg(unix)]
        let inode = {
            use std::os::unix::fs::MetadataExt;
            fs::metadata(part_path(&out)).unwrap().ino()
        };
        decrypt_file_with(&key, &enc_path, &out, Durability::Cache).unwrap();
        assert_eq!(syncs(), before + 3, "cache files are not fsynced");
        assert_eq!(fs::read(&out).unwrap(), data);
        assert_eq!(fs::read(&durable).unwrap(), data);
        assert!(!part_path(&out).exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(fs::metadata(&out).unwrap().ino(), inode, "the pre-created .part becomes the output (its protection class is kept)");
        }

        // Truncated file: cache decryption also leaves neither the output nor .part (the pre-created .part is removed too)
        let ct = fs::read(&enc_path).unwrap();
        let bad = dir.path().join("bad.gors");
        fs::write(&bad, &ct[..ct.len() - 40]).unwrap();
        let out2 = dir.path().join("bad.mp4");
        fs::write(part_path(&out2), b"").unwrap();
        assert_eq!(decrypt_file_with(&key, &bad, &out2, Durability::Cache).unwrap_err(), Error::StreamAuth);
        assert!(!out2.exists());
        assert!(!part_path(&out2).exists());
    }

    /// Decrypting outside the lock (ffi): decrypting with the copied key gives the same result as decrypting by handle. An
    /// unknown handle yields no copy
    #[test]
    fn key_copy_decrypts_like_handle() {
        let mut c = core(51);
        let h = c.create_content_key();
        let photo: Vec<u8> = (0..120_000u32).map(|i| (i % 251) as u8).collect();
        let sealed = c.encrypt(&h, &photo).unwrap();
        let key = c.content_key_copy(&h).unwrap();
        assert_eq!(&decrypt_with(&key, &sealed).unwrap()[..], &photo[..]);
        assert_eq!(&c.decrypt(&h, &sealed).unwrap()[..], &photo[..]);
        assert_eq!(decrypt_with(&key, &sealed[..10]).unwrap_err(), Error::BadCiphertext);
        assert_eq!(c.content_key_copy("no-such-handle").unwrap_err(), Error::UnknownHandle);
    }
}
