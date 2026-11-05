use std::ffi::CStr;

/// Core error. The value is the C ABI return code (0 = success). **Never renumber these**: the native wrappers (Swift on
/// iOS, Kotlin on Android through `src/jni.rs`) rely on them.
///
/// The messages are short English descriptions for logs. Callers act on the numeric code, not on the message text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Error {
    NoAccountKey = 1,
    NoDeviceKey = 2,
    NoEncryptionKey = 3,
    UnknownHandle = 4,
    BadCiphertext = 5,
    DecryptFailed = 6,
    BadEnvelope = 7,
    NotForMe = 8,
    BadWrapped = 9,
    UnwrapFailed = 10,
    BadShareEnvelope = 11,
    ShareNotForMe = 12,
    NothingToRecover = 13,
    TooFewGuardians = 14,
    RecoveryNotStarted = 15,
    BadBackup = 16,
    RecoveryFailed = 17,
    InvalidArgument = 18,
    Io = 19,
    BadStream = 20,
    StreamAuth = 21,
    KeyConflict = 22,
    NoShares = 23,
    ShareLength = 24,
    ShareIndex = 25,
    BadShareCount = 26,
    WeakKey = 27,
    /// Two guardian public keys are the same (the identical key, or another encoding of the same key)
    DuplicateGuardian = 28,
    /// Core-only statements (messages starting with `gori-core/`) cannot be produced through the general signing call
    ReservedStatement = 29,
    /// The recovered account public key differs from the expected one; nothing was imported
    AccountMismatch = 30,
    /// Invalid invite ticket request: kind, index count (1 to 64), duplicate indices, element count or input length
    TicketInput = 31,
    /// An invite ticket element (blinded or evaluated element, server public key) is not canonically encoded or is the identity (RFC 9497 DeserializeError, InputValidationError)
    TicketPoint = 32,
    /// The invite ticket issuance proof (DLEQ) does not verify; no tickets were produced (RFC 9497 VerifyError)
    TicketProof = 33,
    /// Invalid recovery phrase: not 18 words, a word not in the BIP39 English word list, or a checksum mismatch (self-recovery v3)
    BadPhrase = 34,
    /// A vault key or backup is in the pre-post-quantum format (legacy 32-byte X25519 or Ed25519 secret, self-recovery v3
    /// backup). It is rejected instead of being silently read as a seed, which would yield a different public key. The account must be re-created
    StaleKey = 35,
    /// Outer-layer sealing was given something other than the recipient's hybrid public key (HEK, 1,216 bytes). The core itself,
    /// not a type check, refuses to seal the outer layer to a 32-byte X25519 key
    NeedHybridKey = 36,
    /// Decrypt while downloading: the requested range has not been received yet (the file is still short). The caller retries after receiving more. This is not a forgery
    StreamNotYet = 37,
    Internal = 99,
}

impl Error {
    pub fn code(self) -> i32 {
        self as i32
    }

    /// Human-readable message (a static NUL-terminated string)
    pub fn message(self) -> &'static CStr {
        match self {
            Error::NoAccountKey => c"No account key",
            Error::NoDeviceKey => c"No device key",
            Error::NoEncryptionKey => c"No encryption key",
            Error::UnknownHandle => c"Content key handle not found",
            Error::BadCiphertext => c"Malformed ciphertext",
            Error::DecryptFailed => c"Decryption failed",
            Error::BadEnvelope => c"Malformed envelope",
            Error::NotForMe => c"Cannot open the envelope: it is not addressed to me",
            Error::BadWrapped => c"Malformed wrapped key",
            Error::UnwrapFailed => c"Cannot unwrap the wrapped key",
            Error::BadShareEnvelope => c"Malformed share envelope",
            Error::ShareNotForMe => c"Cannot open the share: it is not addressed to me",
            Error::NothingToRecover => c"No key to recover",
            Error::TooFewGuardians => c"Not enough guardians",
            Error::RecoveryNotStarted => c"Recovery has not been started",
            Error::BadBackup => c"Malformed backup",
            Error::RecoveryFailed => c"Could not recover the account",
            Error::InvalidArgument => c"Invalid argument",
            Error::Io => c"Could not read or write the file",
            Error::BadStream => c"Malformed encrypted file",
            Error::StreamAuth => c"The encrypted file is corrupted or the key is wrong",
            Error::KeyConflict => c"A different key already exists on this device",
            Error::NoShares => c"No shares",
            Error::ShareLength => c"Share lengths differ",
            Error::ShareIndex => c"Invalid share index",
            Error::BadShareCount => c"Invalid share count",
            Error::WeakKey => c"Invalid public key",
            Error::DuplicateGuardian => c"The same guardian appears twice",
            Error::ReservedStatement => c"Only the security core can produce this statement",
            Error::AccountMismatch => c"The recovered account differs from this account",
            Error::TicketInput => c"Invite ticket: invalid input",
            Error::TicketPoint => c"Invite ticket: invalid element",
            Error::TicketProof => c"Invite ticket: proof does not verify",
            Error::BadPhrase => c"Invalid recovery phrase",
            Error::StaleKey => c"This device's key is in a legacy format; the account must be re-created",
            Error::NeedHybridKey => c"The recipient's post-quantum public key is required",
            Error::StreamNotYet => c"This range has not been received yet",
            Error::Internal => c"Internal security core error",
        }
    }

    pub fn from_code(code: i32) -> Option<Error> {
        ALL.iter().copied().find(|e| e.code() == code)
    }
}

pub const ALL: &[Error] = &[
    Error::NoAccountKey,
    Error::NoDeviceKey,
    Error::NoEncryptionKey,
    Error::UnknownHandle,
    Error::BadCiphertext,
    Error::DecryptFailed,
    Error::BadEnvelope,
    Error::NotForMe,
    Error::BadWrapped,
    Error::UnwrapFailed,
    Error::BadShareEnvelope,
    Error::ShareNotForMe,
    Error::NothingToRecover,
    Error::TooFewGuardians,
    Error::RecoveryNotStarted,
    Error::BadBackup,
    Error::RecoveryFailed,
    Error::InvalidArgument,
    Error::Io,
    Error::BadStream,
    Error::StreamAuth,
    Error::KeyConflict,
    Error::NoShares,
    Error::ShareLength,
    Error::ShareIndex,
    Error::BadShareCount,
    Error::WeakKey,
    Error::DuplicateGuardian,
    Error::ReservedStatement,
    Error::AccountMismatch,
    Error::TicketInput,
    Error::TicketPoint,
    Error::TicketProof,
    Error::BadPhrase,
    Error::StaleKey,
    Error::NeedHybridKey,
    Error::StreamNotYet,
    Error::Internal,
];

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message().to_str().unwrap_or("?"))
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Error::Io
    }
}
