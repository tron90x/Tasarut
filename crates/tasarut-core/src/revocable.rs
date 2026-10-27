//! v4: a streaming volume requiring an independent, destructible hardware secret.
//! No password-only inner volume or recoverable wrapped key is written to disk.
use crate::{
    crypto::{Keys, Suite},
    derive_keys_profile, open_regular, publish, temporary_output, CancellationToken,
    EncryptOptions, EncryptWriter, Error, KdfProfile, OperationControl, ProgressPhase, RepairInfo,
    Result, Tracker, VolumeInfo, BUFFER_SIZE, TAG_LEN,
};
use blake2::{Blake2b512, Digest};
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

pub const MAGIC: &[u8; 8] = b"TASARUT\x04";
const HEADER_LEN: u64 = 126;
pub const SLOT_BASE: u32 = 0x015a0000;
pub const SLOT_MASK: u32 = 0xffff0000;

/// Production stores must keep records outside recoverable filesystem state.
/// Records are 32 public identifier bytes followed by 32 secret random bytes.
pub trait RevocationStore {
    fn create(
        &mut self,
        record: &[u8; 64],
        authorization: &[u8; 32],
        cancellation: &CancellationToken,
    ) -> Result<u32>;
    fn read(
        &mut self,
        index: u32,
        authorization: &[u8; 32],
        cancellation: &CancellationToken,
    ) -> Result<Zeroizing<[u8; 64]>>;
    /// Verify identifier/authorization, destroy ONLY this index, and confirm absence.
    fn destroy(
        &mut self,
        index: u32,
        identifier: &[u8; 32],
        authorization: &[u8; 32],
        cancellation: &CancellationToken,
    ) -> Result<()>;
}

#[derive(Clone)]
struct Header {
    suite: Suite,
    compressed: bool,
    identifier: [u8; 32],
    index: u32,
    salt: [u8; 32],
    nonce: [u8; 24],
    iv: [u8; 16],
    size: u64,
}
impl Header {
    fn bytes(&self) -> [u8; 126] {
        let mut bytes = [0; 126];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8] = self.suite.id();
        bytes[9] = u8::from(self.compressed);
        bytes[10..42].copy_from_slice(&self.identifier);
        bytes[42..46].copy_from_slice(&self.index.to_le_bytes());
        bytes[46..78].copy_from_slice(&self.salt);
        bytes[78..102].copy_from_slice(&self.nonce);
        bytes[102..118].copy_from_slice(&self.iv);
        bytes[118..].copy_from_slice(&self.size.to_le_bytes());
        bytes
    }
    fn read(file: &mut crate::recovery::VolumeReader) -> Result<Self> {
        if file.length() < HEADER_LEN + TAG_LEN {
            return Err(Error::InvalidVolume);
        }
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = [0; 126];
        file.read_exact(&mut bytes)?;
        if &bytes[..8] != MAGIC || bytes[9] > 1 {
            return Err(Error::InvalidVolume);
        }
        let suite = match bytes[8] {
            1 => Suite::Standard,
            2 => Suite::Paranoid,
            3 => Suite::Threefish,
            _ => return Err(Error::InvalidVolume),
        };
        let index = u32::from_le_bytes(bytes[42..46].try_into().unwrap());
        if index & SLOT_MASK != SLOT_BASE {
            return Err(Error::InvalidVolume);
        }
        let header = Self {
            suite,
            compressed: bytes[9] == 1,
            identifier: bytes[10..42].try_into().unwrap(),
            index,
            salt: bytes[46..78].try_into().unwrap(),
            nonce: bytes[78..102].try_into().unwrap(),
            iv: bytes[102..118].try_into().unwrap(),
            size: u64::from_le_bytes(bytes[118..].try_into().unwrap()),
        };
        if !header.compressed && file.length() - HEADER_LEN - TAG_LEN != header.size {
            return Err(Error::InvalidVolume);
        }
        Ok(header)
    }
    fn auth_keys(
        &self,
        password: &str,
        keyfiles: &[PathBuf],
        tracker: &Tracker<'_>,
    ) -> Result<Keys> {
        derive_keys_profile(
            password,
            keyfiles,
            &self.salt,
            Suite::Standard,
            KdfProfile {
                domain: b"Tasarut/v4/TPM-auth/password+keyfiles",
                parameters: (262_144, 6, 64),
            },
            tracker,
        )
    }
    fn payload_keys(&self, auth: &Keys, record: &[u8; 64]) -> Result<Keys> {
        if record[..32] != self.identifier {
            return Err(Error::RevocableKeyMismatch);
        }
        let length = self.suite.profile().2;
        let mut material = Zeroizing::new(Vec::with_capacity(length));
        for counter in 0..(length / 64) as u8 {
            let mut hash = Blake2b512::new();
            hash.update(b"Tasarut/v4/payload-keys\0");
            hash.update([self.bytes()[8], counter]);
            hash.update(auth.bytes.as_slice());
            hash.update(&record[32..]);
            hash.update(self.identifier);
            hash.update(self.index.to_le_bytes());
            let mut digest = hash.finalize();
            material.extend_from_slice(&digest);
            use zeroize::Zeroize;
            digest.as_mut_slice().zeroize();
        }
        Ok(Keys {
            suite: self.suite,
            bytes: material,
        })
    }
}

pub(crate) fn reader_is_revocable(file: &mut crate::recovery::VolumeReader) -> Result<bool> {
    file.seek(SeekFrom::Start(0))?;
    let mut magic = [0; 8];
    file.read_exact(&mut magic)?;
    file.seek(SeekFrom::Start(0))?;
    Ok(&magic == MAGIC)
}
pub fn is_revocable(path: &Path) -> bool {
    crate::recovery::VolumeReader::new(match open_regular(path) {
        Ok(file) => file,
        Err(_) => return false,
    })
    .is_ok_and(|mut file| reader_is_revocable(&mut file).unwrap_or(false))
}
pub(crate) fn inspect_reader(file: &mut crate::recovery::VolumeReader) -> Result<VolumeInfo> {
    let header = Header::read(file)?;
    Ok(VolumeInfo {
        algorithm: header.suite.algorithm(),
        comment: String::new(),
        compressed: header.compressed,
        original_size: header.size,
        paranoid: header.suite == Suite::Paranoid,
        format_version: 4,
        reed_solomon: file.report().reed_solomon,
        chunk_count: None,
        revocable: true,
        revocable_id: Some(hex(&header.identifier)),
        revocable_index: Some(format!("0x{:08x}", header.index)),
    })
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn token(tracker: &Tracker<'_>) -> CancellationToken {
    tracker.cancellation_token().unwrap_or_default()
}

pub fn encrypt_with_control(
    source: &Path,
    destination: &Path,
    password: &str,
    options: &EncryptOptions,
    store: &mut dyn RevocationStore,
    control: &mut OperationControl<'_>,
) -> Result<()> {
    crate::progress::observe_control(control, |tracker| {
        if options.deniability || options.chunk_size.is_some() || !options.comment.is_empty() {
            return Err(Error::RevocableOptions);
        }
        let mut source = open_regular(source)?;
        let mut output = temporary_output(destination)?;
        let mut header = Header {
            suite: Suite::from_options(options)?,
            compressed: options.compress,
            identifier: [0; 32],
            index: SLOT_BASE,
            salt: [0; 32],
            nonce: [0; 24],
            iv: [0; 16],
            size: source.metadata()?.len(),
        };
        OsRng.fill_bytes(&mut header.identifier);
        OsRng.fill_bytes(&mut header.salt);
        OsRng.fill_bytes(&mut header.nonce);
        if header.suite == Suite::Threefish {
            OsRng.fill_bytes(&mut header.iv);
        } else {
            OsRng.fill_bytes(&mut header.iv[..8]);
        }
        tracker.begin(ProgressPhase::KeyDerivation, None)?;
        let auth = header.auth_keys(password, &options.keyfiles, tracker)?;
        let authorization: &[u8; 32] = auth.bytes[..32].try_into().unwrap();
        let mut record = Zeroizing::new([0; 64]);
        record[..32].copy_from_slice(&header.identifier);
        OsRng.fill_bytes(&mut record[32..]);
        tracker.begin(ProgressPhase::KeyStorage, None)?;
        header.index = store.create(&record, authorization, &token(tracker))?;
        let result = (|| {
            if header.index & SLOT_MASK != SLOT_BASE {
                return Err(Error::RevocableKeyMismatch);
            }
            tracker.checkpoint()?;
            let keys = header.payload_keys(&auth, &record)?;
            if options.reed_solomon {
                let mut writer = crate::recovery::ProtectedWriter::new(output.as_file_mut())?;
                encrypt_payload(&mut source, &mut writer, &header, &keys, tracker)?;
                writer.finish()?;
            } else {
                encrypt_payload(&mut source, &mut output, &header, &keys, tracker)?;
            }
            tracker.begin(ProgressPhase::Publishing, None)?;
            publish(output, destination, tracker)
        })();
        if result.is_err()
            && store
                .destroy(
                    header.index,
                    &header.identifier,
                    authorization,
                    &CancellationToken::default(),
                )
                .is_err()
        {
            return Err(Error::RevocableCleanup(header.index));
        }
        result
    })
}
fn encrypt_payload(
    source: &mut File,
    output: &mut dyn Write,
    header: &Header,
    keys: &Keys,
    tracker: &mut Tracker<'_>,
) -> Result<()> {
    tracker.begin(ProgressPhase::Encrypting, Some(header.size))?;
    let bytes = header.bytes();
    output.write_all(&bytes)?;
    let mut cipher = keys.cipher(
        &header.nonce,
        (header.suite != Suite::Standard).then_some(&header.iv),
    )?;
    let mut mac = keys.mac(&bytes)?;
    let mut encrypted = EncryptWriter {
        output,
        cipher: &mut cipher,
        mac: &mut mac,
    };
    let copied = if header.compressed {
        let mut encoder = zstd::stream::write::Encoder::new(&mut encrypted, 3)?;
        let copied = crate::copy_private(source, &mut encoder, Some(tracker), None)?;
        encoder.finish()?;
        copied
    } else {
        crate::copy_private(source, &mut encrypted, Some(tracker), None)?
    };
    if copied != header.size {
        return Err(Error::SourceChanged);
    }
    output.write_all(&mac.finalize())?;
    Ok(())
}

struct Verified {
    header: Header,
    keys: Keys,
    auth: Keys,
    length: u64,
    tag: [u8; 64],
    repair: RepairInfo,
}
fn authenticate(
    file: &mut crate::recovery::VolumeReader,
    password: &str,
    keyfiles: &[PathBuf],
    store: &mut dyn RevocationStore,
    tracker: &mut Tracker<'_>,
) -> Result<Verified> {
    let header = Header::read(file)?;
    tracker.begin(ProgressPhase::KeyDerivation, None)?;
    let auth = header.auth_keys(password, keyfiles, tracker)?;
    tracker.begin(ProgressPhase::KeyStorage, None)?;
    let record = store.read(
        header.index,
        auth.bytes[..32].try_into().unwrap(),
        &token(tracker),
    )?;
    let keys = header.payload_keys(&auth, &record)?;
    let length = file.length() - HEADER_LEN - TAG_LEN;
    tracker.begin(ProgressPhase::Authenticating, Some(length))?;
    let mut mac = keys.mac(&header.bytes())?;
    let mut buffer = Zeroizing::new(vec![0; BUFFER_SIZE]);
    let mut remaining = length;
    while remaining > 0 {
        tracker.checkpoint()?;
        let n = remaining.min(buffer.len() as u64) as usize;
        file.read_exact(&mut buffer[..n])?;
        mac.update(&buffer[..n]);
        remaining -= n as u64;
        tracker.advance(n as u64)?;
    }
    let mut tag = [0; 64];
    file.read_exact(&mut tag)?;
    mac.verify(&tag)?;
    file.validate_source_length()?;
    Ok(Verified {
        header,
        keys,
        auth,
        length,
        tag,
        repair: file.report(),
    })
}

pub fn decrypt_with_control(
    source: &Path,
    destination: &Path,
    password: &str,
    keyfiles: &[PathBuf],
    store: &mut dyn RevocationStore,
    control: &mut OperationControl<'_>,
) -> Result<RepairInfo> {
    crate::progress::observe_control(control, |tracker| {
        let mut output = temporary_output(destination)?;
        let mut file = crate::recovery::VolumeReader::new(open_regular(source)?)?;
        let verified = authenticate(&mut file, password, keyfiles, store, tracker)?;
        file.seek(SeekFrom::Start(0))?;
        let second_header = Header::read(&mut file)?;
        if second_header.bytes() != verified.header.bytes() {
            return Err(Error::SourceChanged);
        }
        let header = &verified.header;
        tracker.begin(ProgressPhase::Decrypting, Some(verified.length))?;
        let cancellation = tracker.cancellation_token();
        let mut reader = Reader {
            file: &mut file,
            remaining: verified.length,
            cipher: verified.keys.cipher(
                &header.nonce,
                (header.suite != Suite::Standard).then_some(&header.iv),
            )?,
            mac: verified.keys.mac(&header.bytes())?,
            tracker,
        };
        let copied = if header.compressed {
            let decoder = zstd::stream::read::Decoder::new(&mut reader)?;
            crate::copy_private(
                &mut decoder.take(header.size.checked_add(1).ok_or(Error::InvalidVolume)?),
                &mut output,
                None,
                cancellation.as_ref(),
            )?
        } else {
            crate::copy_private(&mut reader, &mut output, None, cancellation.as_ref())?
        };
        if copied != header.size || reader.remaining != 0 {
            return Err(Error::InvalidVolume);
        }
        let Reader { mac, .. } = reader;
        mac.verify(&verified.tag)?;
        let mut tag = [0; 64];
        file.read_exact(&mut tag)?;
        if tag != verified.tag || file.read(&mut [0; 1])? != 0 {
            return Err(Error::Authentication);
        }
        file.validate_source_length()?;
        tracker.begin(ProgressPhase::Publishing, None)?;
        publish(output, destination, tracker)?;
        Ok(verified.repair)
    })
}
struct Reader<'a, 'p> {
    file: &'a mut crate::recovery::VolumeReader,
    remaining: u64,
    cipher: crate::crypto::Cascade,
    mac: crate::crypto::Authenticator,
    tracker: &'a mut Tracker<'p>,
}
impl Read for Reader<'_, '_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.tracker.checkpoint_io()?;
        let n = self
            .remaining
            .min(bytes.len() as u64)
            .min(BUFFER_SIZE as u64) as usize;
        if n == 0 {
            return Ok(0);
        }
        self.file.read_exact(&mut bytes[..n])?;
        self.mac.update(&bytes[..n]);
        self.cipher
            .decrypt(&mut bytes[..n])
            .map_err(|_| io::Error::other("cipher limit"))?;
        self.remaining -= n as u64;
        self.tracker
            .advance(n as u64)
            .map_err(|_| crate::control::cancelled_io())?;
        Ok(n)
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationReport {
    pub identifier: String,
    pub index: String,
    pub hardware_absence_confirmed: bool,
    pub ciphertext_removed: bool,
}
pub fn revoke_with_control(
    source: &Path,
    password: &str,
    keyfiles: &[PathBuf],
    store: &mut dyn RevocationStore,
    control: &mut OperationControl<'_>,
) -> Result<RevocationReport> {
    crate::progress::observe_control(control, |tracker| {
        let mut file = crate::recovery::VolumeReader::new(open_regular(source)?)?;
        let verified = authenticate(&mut file, password, keyfiles, store, tracker)?;
        tracker.begin(ProgressPhase::Revoking, None)?;
        store.destroy(
            verified.header.index,
            &verified.header.identifier,
            verified.auth.bytes[..32].try_into().unwrap(),
            &token(tracker),
        )?;
        Ok(RevocationReport {
            identifier: hex(&verified.header.identifier),
            index: format!("0x{:08x}", verified.header.index),
            hardware_absence_confirmed: true,
            ciphertext_removed: false,
        })
    })
}

#[cfg(test)]
mod tests;
