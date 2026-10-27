//! Tasarut v1 standard / v2 paranoid / v3 Reed-Solomon: streaming encrypt-then-MAC.
//! Public comments are intentionally excluded from authentication.

use argon2::{Algorithm, Argon2, Params, Version};
use blake2::{Blake2b512, Digest};
mod chunks;
mod control;
mod crypto;
#[cfg(target_os = "linux")]
pub mod deletion;
mod deniable;
mod forced;
mod progress;
mod recovery;
pub mod revocable;
#[cfg(test)]
mod threefish_tests;
pub use control::CancellationToken;
use crypto::{Authenticator, Cascade, Keys, Suite};
pub use deniable::{
    decrypt_deniable, decrypt_deniable_with_control, decrypt_deniable_with_progress,
};
pub use forced::{
    force_decrypt, force_decrypt_with_control, force_decrypt_with_progress, DamageRange,
    ForceOptions, ForceReport, MacStatus, RecoveryDamage,
};
use progress::Tracker;
pub use progress::{ByteProgress, OperationControl, ProgressPhase};
use rand::{rngs::OsRng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use tempfile::NamedTempFile;
use thiserror::Error;
use walkdir::WalkDir;
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"TASARUT\x01";
const PARANOID_MAGIC: &[u8; 8] = b"TASARUT\x02";
const THREEFISH_MAGIC: &[u8; 8] = b"TASARUT\x05";
const FIXED_HEADER: u64 = 77;
const PARANOID_FIXED_HEADER: u64 = 94;
const TAG_LEN: u64 = 64;
const MAX_COMMENT: usize = 65536;
const BUFFER_SIZE: usize = 256 * 1024;

#[derive(Debug, Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(io::Error),
    #[error("invalid_volume")]
    InvalidVolume,
    #[error("authentication_failed")]
    Authentication,
    #[error("empty_password")]
    EmptyPassword,
    #[error("comment_too_long")]
    CommentTooLong,
    #[error("output_exists")]
    OutputExists,
    #[error("source_changed")]
    SourceChanged,
    #[error("invalid_input")]
    InvalidInput,
    #[error("key_derivation_failed")]
    Kdf,
    #[error("reed_solomon_uncorrectable")]
    ReedSolomon,
    #[error("nothing_recovered")]
    NothingRecovered,
    #[error("invalid_recovery_limit")]
    InvalidRecoveryLimit,
    #[error("invalid_chunk_size")]
    InvalidChunkSize,
    #[error("invalid_chunk_manifest")]
    InvalidChunkManifest,
    #[error("chunk_missing")]
    ChunkMissing,
    #[error("chunk_damaged")]
    ChunkDamaged,
    #[error("deniability_incompatible_options")]
    DeniabilityOptions,
    #[error("operation_cancelled")]
    Cancelled,
    #[error("revocable_provider_required")]
    RevocableProviderRequired,
    #[error("revocable_incompatible_options")]
    RevocableOptions,
    #[error("revocable_key_unavailable")]
    RevocableKeyUnavailable,
    #[error("revocable_key_mismatch")]
    RevocableKeyMismatch,
    #[error("revocable_tpm_failed")]
    RevocableTpm,
    #[error("revocable_tpm_auth")]
    RevocableTpmAuth,
    #[error("revocable_tpm_capacity")]
    RevocableTpmCapacity,
    #[error("revocable_cleanup_failed:0x{0:08x}")]
    RevocableCleanup(u32),
    #[error("cipher_incompatible_options")]
    CipherOptions,
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        if error
            .get_ref()
            .is_some_and(|e| e.is::<control::Cancelled>())
        {
            Self::Cancelled
        } else if error
            .get_ref()
            .is_some_and(|e| e.is::<recovery::Uncorrectable>())
        {
            Self::ReedSolomon
        } else {
            Self::Io(error)
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipherAlgorithm {
    #[default]
    #[serde(rename = "xchacha20")]
    XChaCha20,
    #[serde(rename = "threefish1024")]
    Threefish1024,
}

#[derive(Default)]
pub struct EncryptOptions {
    pub algorithm: CipherAlgorithm,
    pub comment: String,
    pub compress: bool,
    pub paranoid: bool,
    pub reed_solomon: bool,
    pub keyfiles: Vec<PathBuf>,
    pub chunk_size: Option<u64>,
    pub deniability: bool,
    pub revocable: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VolumeInfo {
    pub algorithm: CipherAlgorithm,
    pub comment: String,
    pub compressed: bool,
    pub original_size: u64,
    pub paranoid: bool,
    pub format_version: u8,
    pub reed_solomon: bool,
    pub chunk_count: Option<u32>,
    pub revocable: bool,
    pub revocable_id: Option<String>,
    pub revocable_index: Option<String>,
}

#[derive(Clone, Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RepairInfo {
    pub reed_solomon: bool,
    pub corrected_blocks: u64,
    pub corrected_bytes: u64,
}

struct Header {
    suite: Suite,
    flags: u8,
    salt: [u8; 32],
    nonce: [u8; 24],
    block_parameter: Option<[u8; 16]>,
    size: u64,
    comment: String,
}

impl Header {
    fn authenticated_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(90);
        match self.suite {
            Suite::Standard => bytes.extend_from_slice(MAGIC),
            Suite::Paranoid => {
                bytes.extend_from_slice(PARANOID_MAGIC);
                bytes.push(1); // v2 suite 1: XChaCha20 -> Serpent-256-CTR, HMAC-SHA3-512
            }
            Suite::Threefish => {
                bytes.extend_from_slice(THREEFISH_MAGIC);
                bytes.push(1); // v5 suite 1: Threefish-1024-CTR128BE + HMAC-SHA3-512
            }
        }
        bytes.push(self.flags);
        bytes.extend_from_slice(&self.salt);
        bytes.extend_from_slice(&self.nonce);
        if let Some(iv) = &self.block_parameter {
            bytes.extend_from_slice(iv);
        }
        bytes.extend_from_slice(&self.size.to_le_bytes());
        bytes
    }

    fn write(&self, output: &mut dyn Write) -> Result<()> {
        output.write_all(&self.authenticated_bytes())?;
        output.write_all(&(self.comment.len() as u32).to_le_bytes())?;
        output.write_all(self.comment.as_bytes())?;
        Ok(())
    }

    fn read(file: &mut (impl Read + Seek)) -> Result<Self> {
        Self::read_mode(file, false)
    }

    fn read_mode(file: &mut (impl Read + Seek), force: bool) -> Result<Self> {
        let position = file.stream_position()?;
        let total = file.seek(SeekFrom::End(0))?;
        file.seek(SeekFrom::Start(position))?;
        let tag_minimum = if force { 0 } else { TAG_LEN };
        if total < FIXED_HEADER + tag_minimum {
            return Err(Error::InvalidVolume);
        }
        let mut magic = [0u8; 8];
        file.read_exact(&mut magic)?;
        let (suite, fixed_len, flags_at) = match &magic {
            value if value == MAGIC => (Suite::Standard, FIXED_HEADER, 8),
            value if value == PARANOID_MAGIC => (Suite::Paranoid, PARANOID_FIXED_HEADER, 9),
            value if value == THREEFISH_MAGIC => (Suite::Threefish, PARANOID_FIXED_HEADER, 9),
            _ => return Err(Error::InvalidVolume),
        };
        if total < fixed_len + tag_minimum {
            return Err(Error::InvalidVolume);
        }
        let mut fixed = vec![0u8; fixed_len as usize];
        fixed[..8].copy_from_slice(&magic);
        file.read_exact(&mut fixed[8..])?;
        if (suite != Suite::Standard && fixed[8] != 1) || fixed[flags_at] & !1 != 0 {
            return Err(Error::InvalidVolume);
        }
        let comment_at = fixed.len() - 4;
        let size_at = comment_at - 8;
        let salt_at = flags_at + 1;
        let nonce_at = salt_at + 32;
        let comment_len = u32::from_le_bytes(fixed[comment_at..].try_into().unwrap()) as usize;
        if comment_len > MAX_COMMENT || total < fixed_len + comment_len as u64 + tag_minimum {
            return Err(Error::InvalidVolume);
        }
        let mut comment = vec![0; comment_len];
        file.read_exact(&mut comment)?;
        Ok(Self {
            suite,
            flags: fixed[flags_at],
            salt: fixed[salt_at..nonce_at].try_into().unwrap(),
            nonce: fixed[nonce_at..nonce_at + 24].try_into().unwrap(),
            block_parameter: if suite != Suite::Standard {
                Some(fixed[66..82].try_into().unwrap())
            } else {
                None
            },
            size: u64::from_le_bytes(fixed[size_at..comment_at].try_into().unwrap()),
            comment: if force {
                String::from_utf8_lossy(&comment).into_owned()
            } else {
                String::from_utf8(comment).map_err(|_| Error::InvalidVolume)?
            },
        })
    }
}

fn derive_keys(
    password: &str,
    keyfiles: &[PathBuf],
    salt: &[u8; 32],
    suite: Suite,
    tracker: &Tracker<'_>,
) -> Result<Keys> {
    derive_keys_profile(
        password,
        keyfiles,
        salt,
        suite,
        KdfProfile {
            domain: suite.password_domain(),
            parameters: suite.profile(),
        },
        tracker,
    )
}

struct KdfProfile<'a> {
    domain: &'a [u8],
    parameters: (u32, u32, usize),
}

fn derive_keys_profile(
    password: &str,
    keyfiles: &[PathBuf],
    salt: &[u8; 32],
    suite: Suite,
    profile: KdfProfile<'_>,
    tracker: &Tracker<'_>,
) -> Result<Keys> {
    tracker.checkpoint()?;
    if password.is_empty() {
        return Err(Error::EmptyPassword);
    }
    // Length-prefix every component; keyfile contents and order matter, names do not.
    let mut input = Blake2b512::new();
    Digest::update(&mut input, profile.domain);
    Digest::update(&mut input, (password.len() as u64).to_le_bytes());
    Digest::update(&mut input, password.as_bytes());
    Digest::update(&mut input, (keyfiles.len() as u64).to_le_bytes());
    let mut buffer = Zeroizing::new(vec![0; BUFFER_SIZE]);
    for path in keyfiles {
        tracker.checkpoint()?;
        let mut file = open_regular(path)?;
        let size = file.metadata()?.len();
        Digest::update(&mut input, size.to_le_bytes());
        let mut read_size = 0u64;
        loop {
            tracker.checkpoint()?;
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            read_size += n as u64;
            Digest::update(&mut input, &buffer[..n]);
        }
        if read_size != size {
            return Err(Error::SourceChanged);
        }
    }
    let mut digest = input.finalize();
    let mut material = Zeroizing::new([0u8; 64]);
    material.copy_from_slice(&digest);
    digest.as_mut_slice().zeroize();
    tracker.checkpoint()?;
    let (memory, iterations, output_len) = profile.parameters;
    let params = Params::new(memory, iterations, 4, Some(output_len)).map_err(|_| Error::Kdf)?;
    let mut keys = Zeroizing::new(vec![0u8; output_len]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(material.as_ref(), salt, keys.as_mut())
        .map_err(|_| Error::Kdf)?;
    tracker.checkpoint()?;
    Ok(Keys { suite, bytes: keys })
}

fn open_regular(path: &Path) -> Result<File> {
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(Error::InvalidInput);
    }
    Ok(File::open(path)?)
}

fn temporary_output(destination: &Path) -> Result<NamedTempFile> {
    if destination.try_exists()? {
        return Err(Error::OutputExists);
    }
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    Ok(NamedTempFile::new_in(parent)?)
}

fn publish(mut output: NamedTempFile, destination: &Path, tracker: &Tracker<'_>) -> Result<()> {
    tracker.checkpoint()?;
    output.flush()?;
    output.as_file().sync_all()?;
    tracker.checkpoint()?;
    output.persist_noclobber(destination).map_err(|e| {
        if e.error.kind() == io::ErrorKind::AlreadyExists {
            Error::OutputExists
        } else {
            Error::Io(e.error)
        }
    })?;
    Ok(())
}

/// Encrypt a single file, without loading its contents into memory or overwriting files.
pub fn encrypt(
    source: &Path,
    destination: &Path,
    password: &str,
    options: &EncryptOptions,
) -> Result<()> {
    encrypt_impl(
        source,
        destination,
        password,
        options,
        &mut Tracker::default(),
    )
}

pub fn encrypt_with_progress(
    source: &Path,
    destination: &Path,
    password: &str,
    options: &EncryptOptions,
    on_progress: &mut dyn FnMut(ByteProgress),
) -> Result<()> {
    progress::observe(on_progress, |tracker| {
        encrypt_impl(source, destination, password, options, tracker)
    })
}

pub fn encrypt_with_control(
    source: &Path,
    destination: &Path,
    password: &str,
    options: &EncryptOptions,
    control: &mut OperationControl<'_>,
) -> Result<()> {
    progress::observe_control(control, |tracker| {
        encrypt_impl(source, destination, password, options, tracker)
    })
}

fn encrypt_impl(
    source: &Path,
    destination: &Path,
    password: &str,
    options: &EncryptOptions,
    tracker: &mut Tracker<'_>,
) -> Result<()> {
    Suite::from_options(options)?;
    if options.revocable {
        return Err(Error::RevocableProviderRequired);
    }
    if options.deniability {
        return deniable::encrypt(source, destination, password, options, tracker);
    }
    if let Some(chunk_size) = options.chunk_size {
        return chunks::encrypt(source, destination, password, options, chunk_size, tracker);
    }
    encrypt_volume(source, destination, password, options, tracker)
}

fn encrypt_volume(
    source: &Path,
    destination: &Path,
    password: &str,
    options: &EncryptOptions,
    tracker: &mut Tracker<'_>,
) -> Result<()> {
    if options.comment.len() > MAX_COMMENT {
        return Err(Error::CommentTooLong);
    }
    let mut source_file = open_regular(source)?;
    let suite = Suite::from_options(options)?;
    let mut header = Header {
        suite,
        flags: u8::from(options.compress),
        salt: [0; 32],
        nonce: [0; 24],
        block_parameter: (suite != Suite::Standard).then_some([0; 16]),
        size: source_file.metadata()?.len(),
        comment: options.comment.clone(),
    };
    OsRng.fill_bytes(&mut header.salt);
    OsRng.fill_bytes(&mut header.nonce);
    if let Some(iv) = &mut header.block_parameter {
        // Start at a random 64-bit prefix and a zero low counter, leaving ample counter space.
        if suite == Suite::Threefish {
            OsRng.fill_bytes(iv); // Independent public 128-bit Threefish tweak.
        } else {
            OsRng.fill_bytes(&mut iv[..8]);
        }
    }
    let mut output = temporary_output(destination)?;
    tracker.begin(ProgressPhase::KeyDerivation, None)?;
    let keys = derive_keys(
        password,
        &options.keyfiles,
        &header.salt,
        header.suite,
        tracker,
    )?;
    if options.reed_solomon {
        let mut protected = recovery::ProtectedWriter::new(output.as_file_mut())?;
        encrypt_content(
            &mut source_file,
            &mut protected,
            &header,
            &keys,
            options.compress,
            tracker,
        )?;
        protected.finish()?;
    } else {
        encrypt_content(
            &mut source_file,
            &mut output,
            &header,
            &keys,
            options.compress,
            tracker,
        )?;
    }
    tracker.begin(ProgressPhase::Publishing, None)?;
    publish(output, destination, tracker)
}

fn encrypt_content(
    source_file: &mut File,
    output: &mut dyn Write,
    header: &Header,
    keys: &Keys,
    compress: bool,
    tracker: &mut Tracker<'_>,
) -> Result<()> {
    tracker.begin(ProgressPhase::Encrypting, Some(header.size))?;
    let mut cipher = keys.cipher(&header.nonce, header.block_parameter.as_ref())?;
    let mut mac = keys.mac(&header.authenticated_bytes())?;
    header.write(output)?;
    // Compress as a stream. The zstd encoder finishes before the authentication tag is written.
    let mut encrypted = EncryptWriter {
        output,
        cipher: &mut cipher,
        mac: &mut mac,
    };
    let copied = if compress {
        let mut encoder = zstd::stream::write::Encoder::new(&mut encrypted, 3)?;
        let copied = copy_private(source_file, &mut encoder, Some(tracker), None)?;
        encoder.finish()?;
        copied
    } else {
        copy_private(source_file, &mut encrypted, Some(tracker), None)?
    };
    if copied != header.size {
        return Err(Error::SourceChanged);
    }
    output.write_all(&mac.finalize())?;
    Ok(())
}

struct EncryptWriter<'a> {
    output: &'a mut dyn Write,
    cipher: &'a mut Cascade,
    mac: &'a mut Authenticator,
}

impl Write for EncryptWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        for chunk in bytes.chunks(BUFFER_SIZE) {
            let mut encrypted = Zeroizing::new(chunk.to_vec());
            self.cipher
                .encrypt(&mut encrypted)
                .map_err(|_| io::Error::other("cipher limit reached"))?;
            self.mac.update(&encrypted);
            self.output.write_all(&encrypted)?;
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

fn copy_private(
    input: &mut impl Read,
    output: &mut impl Write,
    mut tracker: Option<&mut Tracker<'_>>,
    cancellation: Option<&CancellationToken>,
) -> io::Result<u64> {
    let mut buffer = Zeroizing::new(vec![0; BUFFER_SIZE]);
    let mut total = 0;
    loop {
        if let Some(token) = cancellation {
            token.check_io()?;
        }
        if let Some(tracker) = &tracker {
            tracker.checkpoint_io()?;
        }
        let n = input.read(&mut buffer)?;
        if n == 0 {
            return Ok(total);
        }
        output.write_all(&buffer[..n])?;
        total += n as u64;
        if let Some(tracker) = &mut tracker {
            tracker
                .advance(n as u64)
                .map_err(|_| control::cancelled_io())?;
        }
    }
}

/// Authenticate the complete volume before decrypting; re-authenticate on the second pass
/// to detect changes between passes. Only publish the output after successful verification.
pub fn decrypt(
    source: &Path,
    destination: &Path,
    password: &str,
    keyfiles: &[PathBuf],
) -> Result<()> {
    decrypt_with_report(source, destination, password, keyfiles).map(|_| ())
}

pub fn decrypt_with_report(
    source: &Path,
    destination: &Path,
    password: &str,
    keyfiles: &[PathBuf],
) -> Result<RepairInfo> {
    decrypt_impl(
        source,
        destination,
        password,
        keyfiles,
        &mut Tracker::default(),
    )
}

pub fn decrypt_with_progress(
    source: &Path,
    destination: &Path,
    password: &str,
    keyfiles: &[PathBuf],
    on_progress: &mut dyn FnMut(ByteProgress),
) -> Result<RepairInfo> {
    progress::observe(on_progress, |tracker| {
        decrypt_impl(source, destination, password, keyfiles, tracker)
    })
}

pub fn decrypt_with_control(
    source: &Path,
    destination: &Path,
    password: &str,
    keyfiles: &[PathBuf],
    control: &mut OperationControl<'_>,
) -> Result<RepairInfo> {
    progress::observe_control(control, |tracker| {
        decrypt_impl(source, destination, password, keyfiles, tracker)
    })
}

fn decrypt_impl(
    source: &Path,
    destination: &Path,
    password: &str,
    keyfiles: &[PathBuf],
    tracker: &mut Tracker<'_>,
) -> Result<RepairInfo> {
    if let Some(root) = chunks::root(source)? {
        let assembled = chunks::assemble(
            &root,
            destination.parent(),
            Some((password, keyfiles)),
            tracker,
        )?;
        return decrypt_impl(
            assembled.volume.path(),
            destination,
            password,
            keyfiles,
            tracker,
        );
    }
    let mut file = recovery::VolumeReader::new(open_regular(source)?)?;
    if revocable::reader_is_revocable(&mut file)? {
        return Err(Error::RevocableProviderRequired);
    }
    let header = Header::read(&mut file)?;
    let start = file.stream_position()?;
    let length = file
        .length()
        .checked_sub(start + TAG_LEN)
        .ok_or(Error::InvalidVolume)?;
    if header.flags == 0 && length != header.size {
        return Err(Error::InvalidVolume);
    }
    tracker.begin(ProgressPhase::KeyDerivation, None)?;
    let keys = derive_keys(password, keyfiles, &header.salt, header.suite, tracker)?;
    tracker.begin(ProgressPhase::Authenticating, Some(length))?;
    let mut mac = keys.mac(&header.authenticated_bytes())?;
    let mut buffer = Zeroizing::new(vec![0; BUFFER_SIZE]);
    let mut remaining = length;
    while remaining > 0 {
        tracker.checkpoint()?;
        let n = remaining.min(BUFFER_SIZE as u64) as usize;
        file.read_exact(&mut buffer[..n])?;
        mac.update(&buffer[..n]);
        remaining -= n as u64;
        tracker.advance(n as u64)?;
    }
    let mut tag = [0u8; TAG_LEN as usize];
    file.read_exact(&mut tag)?;
    mac.verify(&tag)?;
    let report = file.report();
    // Seek back on the same handle, then verify again before committing the plaintext.
    file.seek(SeekFrom::Start(start))?;
    let mut output = temporary_output(destination)?;
    let cipher = keys.cipher(&header.nonce, header.block_parameter.as_ref())?;
    tracker.begin(ProgressPhase::Decrypting, Some(length))?;
    let cancellation = tracker.cancellation_token();
    let mut reader = DecryptReader {
        file: &mut file,
        remaining: length,
        cipher,
        mac: keys.mac(&header.authenticated_bytes())?,
        tracker,
    };
    let maximum = header.size.checked_add(1).ok_or(Error::InvalidVolume)?;
    let copied = if header.flags == 1 {
        // The first pass authenticated the stream. Bound decompression by authenticated size.
        let decoder = zstd::stream::read::Decoder::new(&mut reader)?;
        copy_private(
            &mut decoder.take(maximum),
            &mut output,
            None,
            cancellation.as_ref(),
        )?
    } else {
        copy_private(&mut reader, &mut output, None, cancellation.as_ref())?
    };
    if copied != header.size || reader.remaining != 0 {
        return Err(Error::InvalidVolume);
    }
    let DecryptReader { mac, .. } = reader;
    mac.verify(&tag)?;
    // Ensure the tag and end of file have not changed either.
    let mut second_tag = [0; TAG_LEN as usize];
    file.read_exact(&mut second_tag)?;
    if second_tag != tag || file.read(&mut [0u8; 1])? != 0 {
        return Err(Error::Authentication);
    }
    file.validate_source_length()?;
    tracker.begin(ProgressPhase::Publishing, None)?;
    publish(output, destination, tracker)?;
    Ok(report)
}

struct DecryptReader<'a, 'p> {
    file: &'a mut recovery::VolumeReader,
    remaining: u64,
    cipher: Cascade,
    mac: Authenticator,
    tracker: &'a mut Tracker<'p>,
}

impl Read for DecryptReader<'_, '_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.tracker.checkpoint_io()?;
        let n = self
            .remaining
            .min(output.len() as u64)
            .min(BUFFER_SIZE as u64) as usize;
        if n == 0 {
            return Ok(0);
        }
        self.file.read_exact(&mut output[..n])?;
        self.mac.update(&output[..n]);
        self.cipher
            .decrypt(&mut output[..n])
            .map_err(|_| io::Error::other("cipher limit reached"))?;
        self.remaining -= n as u64;
        self.tracker
            .advance(n as u64)
            .map_err(|_| control::cancelled_io())?;
        Ok(n)
    }
}

/// Comments are public, untrusted metadata; no password is required to view them.
pub fn inspect(path: &Path) -> Result<VolumeInfo> {
    inspect_mode(path, false)
}

pub fn inspect_mode(path: &Path, force: bool) -> Result<VolumeInfo> {
    if let Some(root) = chunks::root(path)? {
        let assembled = chunks::assemble(&root, None, None, &mut Tracker::default())?;
        let mut info = inspect_mode(assembled.volume.path(), force)?;
        info.chunk_count = Some(assembled.count);
        return Ok(info);
    }
    let mut reader = recovery::VolumeReader::open(open_regular(path)?, force)?;
    if revocable::reader_is_revocable(&mut reader)? {
        return revocable::inspect_reader(&mut reader);
    }
    let header = Header::read_mode(&mut reader, force)?;
    let reed_solomon = reader.report().reed_solomon;
    Ok(VolumeInfo {
        algorithm: header.suite.algorithm(),
        comment: header.comment,
        compressed: header.flags == 1,
        original_size: header.size,
        paranoid: header.suite == Suite::Paranoid,
        format_version: if reed_solomon {
            3
        } else {
            header.suite.version()
        },
        reed_solomon,
        chunk_count: None,
        revocable: false,
        revocable_id: None,
        revocable_index: None,
    })
}

pub fn generate_password(length: usize, symbols: bool) -> Result<String> {
    if !(16..=128).contains(&length) {
        return Err(Error::InvalidInput);
    }
    let alphabet = if symbols {
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&()*+,-./:;<=>?@[]^_{|}~".as_slice()
    } else {
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".as_slice()
    };
    let mut rng = OsRng;
    // gen_range uses rejection sampling; no modulo bias.
    Ok((0..length)
        .map(|_| alphabet[rng.gen_range(0..alphabet.len())] as char)
        .collect())
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InputFile {
    pub path: PathBuf,
    pub relative_path: PathBuf,
    pub size: u64,
    pub volume: bool,
    pub revocable: bool,
}

/// Keep each file separate and preserve directory layout. Never follow symlinks.
pub fn collect_inputs(paths: &[PathBuf], recursive: bool) -> Result<Vec<InputFile>> {
    collect_inputs_impl(paths, recursive, None)
}

pub fn collect_inputs_with_cancellation(
    paths: &[PathBuf],
    recursive: bool,
    cancellation: &CancellationToken,
) -> Result<Vec<InputFile>> {
    collect_inputs_impl(paths, recursive, Some(cancellation))
}

fn collect_inputs_impl(
    paths: &[PathBuf],
    recursive: bool,
    cancellation: Option<&CancellationToken>,
) -> Result<Vec<InputFile>> {
    if let Some(token) = cancellation {
        token.check()?;
    }
    let mut files = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for path in paths {
        if let Some(token) = cancellation {
            token.check()?;
        }
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            return Err(Error::InvalidInput);
        }
        let selected_set = chunks::root(path)?;
        let candidates = if let Some(root) = &selected_set {
            vec![root.clone()]
        } else if metadata.is_dir() {
            if !recursive {
                return Err(Error::InvalidInput);
            }
            let mut entries = Vec::new();
            let mut walker = WalkDir::new(path)
                .follow_links(false)
                .sort_by_file_name()
                .into_iter();
            while let Some(entry) = walker.next() {
                if let Some(token) = cancellation {
                    token.check()?;
                }
                let entry = entry.map_err(|e| Error::Io(io::Error::other(e)))?;
                if entry.file_type().is_file() {
                    entries.push(entry.into_path());
                } else if entry.file_type().is_dir() && chunks::root(entry.path())?.is_some() {
                    walker.skip_current_dir();
                    entries.push(entry.into_path());
                }
            }
            entries
        } else if metadata.is_file() {
            vec![path.clone()]
        } else {
            return Err(Error::InvalidInput);
        };
        for candidate in candidates {
            if let Some(token) = cancellation {
                token.check()?;
            }
            let set = chunks::root(&candidate)?;
            let candidate = set.clone().unwrap_or(candidate);
            let canonical = fs::canonicalize(&candidate)?;
            if !seen.insert(canonical.clone()) {
                continue;
            }
            let relative = if metadata.is_dir() && selected_set.is_none() {
                let base = path.parent().unwrap_or(Path::new("."));
                candidate
                    .strip_prefix(base)
                    .map_err(|_| Error::InvalidInput)?
                    .to_path_buf()
            } else {
                PathBuf::from(candidate.file_name().ok_or(Error::InvalidInput)?)
            };
            if set.is_some() {
                let mut size = 0u64;
                for entry in fs::read_dir(&canonical)? {
                    if let Some(token) = cancellation {
                        token.check()?;
                    }
                    let metadata = fs::symlink_metadata(entry?.path())?;
                    if metadata.is_file() {
                        size = size
                            .checked_add(metadata.len())
                            .ok_or(Error::InvalidInput)?;
                    }
                }
                files.push(InputFile {
                    path: canonical,
                    relative_path: relative,
                    size,
                    volume: true,
                    revocable: false,
                });
                continue;
            }
            let mut file = File::open(&canonical)?;
            let mut magic = [0; 8];
            let recognizable = file.read_exact(&mut magic).is_ok()
                && (&magic == MAGIC
                    || &magic == PARANOID_MAGIC
                    || &magic == THREEFISH_MAGIC
                    || &magic == recovery::MAGIC_RS
                    || &magic == revocable::MAGIC);
            file.seek(SeekFrom::Start(0))?;
            let mut reader = recovery::VolumeReader::new(file);
            let revocable = reader
                .as_mut()
                .ok()
                .is_some_and(|reader| revocable::reader_is_revocable(reader).unwrap_or(false));
            let volume = recognizable || reader.is_ok();
            files.push(InputFile {
                size: fs::metadata(&canonical)?.len(),
                path: canonical,
                relative_path: relative,
                volume,
                revocable,
            });
        }
    }
    Ok(files)
}

#[cfg(test)]
mod tests;
