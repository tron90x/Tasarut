//! Opaque envelope v1: random salt + nonce, encrypted inner volume, keyed tag.
//! Version, suite, KDF parameters and all inner metadata are absent in public.
use crate::{
    crypto::{Authenticator, Keys, Suite},
    decrypt_impl, derive_keys_profile, encrypt_volume, open_regular, publish, temporary_output,
    ByteProgress, EncryptOptions, EncryptWriter, Error, KdfProfile, OperationControl,
    ProgressPhase, RepairInfo, Result, Tracker, BUFFER_SIZE, FIXED_HEADER, TAG_LEN,
};
use rand::{rngs::OsRng, RngCore};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const PREFIX_LEN: u64 = 56;
const PASSWORD_DOMAIN: &[u8] = b"Tasarut/deniable/v1/password+keyfiles";
const MAC_DOMAIN: &[u8] = b"Tasarut/deniable/v1/envelope\0";
// One fixed, strengthened outer profile. No attacker-controlled parameters or
// suite guessing; the inner standard/paranoid/RS profile is encrypted.
const PROFILE: (u32, u32, usize) = (262_144, 6, 64);

fn keys(
    password: &str,
    keyfiles: &[PathBuf],
    prefix: &[u8; 56],
    tracker: &Tracker<'_>,
) -> Result<Keys> {
    derive_keys_profile(
        password,
        keyfiles,
        prefix[..32].try_into().unwrap(),
        Suite::Standard,
        KdfProfile {
            domain: PASSWORD_DOMAIN,
            parameters: PROFILE,
        },
        tracker,
    )
}

fn mac(keys: &Keys, prefix: &[u8; 56], length: u64) -> Result<Authenticator> {
    let mut mac = keys.mac(MAC_DOMAIN)?;
    mac.update(prefix);
    mac.update(&length.to_le_bytes());
    Ok(mac)
}

pub(crate) fn encrypt(
    source: &Path,
    destination: &Path,
    password: &str,
    options: &EncryptOptions,
    tracker: &mut Tracker<'_>,
) -> Result<()> {
    if !options.comment.is_empty() || options.chunk_size.is_some() {
        return Err(Error::DeniabilityOptions);
    }
    let mut output = temporary_output(destination)?;
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let staging = tempfile::tempdir_in(parent)?;
    let inner = staging.path().join("volume.tmp");
    encrypt_volume(source, &inner, password, options, tracker)?;
    let mut file = open_regular(&inner)?;
    let mut prefix = [0; PREFIX_LEN as usize];
    OsRng.fill_bytes(&mut prefix);
    wrap(
        &mut file,
        &mut output,
        password,
        &options.keyfiles,
        &prefix,
        tracker,
    )?;
    tracker.begin(ProgressPhase::Publishing, None)?;
    publish(output, destination, tracker)
}

fn wrap(
    file: &mut File,
    output: &mut dyn Write,
    password: &str,
    keyfiles: &[PathBuf],
    prefix: &[u8; 56],
    tracker: &mut Tracker<'_>,
) -> Result<()> {
    let length = file.metadata()?.len();
    tracker.begin(ProgressPhase::KeyDerivation, None)?;
    let keys = keys(password, keyfiles, prefix, tracker)?;
    let mut cipher = keys.cipher(prefix[32..].try_into().unwrap(), None)?;
    let mut mac = mac(&keys, prefix, length)?;
    tracker.begin(ProgressPhase::Wrapping, Some(length))?;
    output.write_all(prefix)?;
    let mut writer = EncryptWriter {
        output,
        cipher: &mut cipher,
        mac: &mut mac,
    };
    if crate::copy_private(file, &mut writer, Some(tracker), None)? != length {
        return Err(Error::SourceChanged);
    }
    output.write_all(&mac.finalize())?;
    Ok(())
}

/// Explicit secret-based recognition. No unauthenticated recovery of the outer
/// envelope; authenticate before opening or decompressing the inner volume.
pub fn decrypt_deniable(
    source: &Path,
    destination: &Path,
    password: &str,
    keyfiles: &[PathBuf],
) -> Result<RepairInfo> {
    decrypt_impl_deniable(
        source,
        destination,
        password,
        keyfiles,
        &mut Tracker::default(),
    )
}

pub fn decrypt_deniable_with_progress(
    source: &Path,
    destination: &Path,
    password: &str,
    keyfiles: &[PathBuf],
    on_progress: &mut dyn FnMut(ByteProgress),
) -> Result<RepairInfo> {
    crate::progress::observe(on_progress, |tracker| {
        decrypt_impl_deniable(source, destination, password, keyfiles, tracker)
    })
}

pub fn decrypt_deniable_with_control(
    source: &Path,
    destination: &Path,
    password: &str,
    keyfiles: &[PathBuf],
    control: &mut OperationControl<'_>,
) -> Result<RepairInfo> {
    crate::progress::observe_control(control, |tracker| {
        decrypt_impl_deniable(source, destination, password, keyfiles, tracker)
    })
}

fn decrypt_impl_deniable(
    source: &Path,
    destination: &Path,
    password: &str,
    keyfiles: &[PathBuf],
    tracker: &mut Tracker<'_>,
) -> Result<RepairInfo> {
    let mut source = open_regular(source)?;
    let mut inner = temporary_output(destination)?;
    unwrap(
        &mut source,
        inner.as_file_mut(),
        password,
        keyfiles,
        tracker,
    )?;
    decrypt_impl(inner.path(), destination, password, keyfiles, tracker)
}

fn unwrap(
    source: &mut File,
    inner: &mut File,
    password: &str,
    keyfiles: &[PathBuf],
    tracker: &mut Tracker<'_>,
) -> Result<()> {
    let verified = authenticate(source, password, keyfiles, tracker)?;
    let VerifiedEnvelope {
        physical_length,
        length,
        prefix,
        keys,
        tag,
    } = verified;
    // Use the same source handle, and verify the complete outer stream again.
    source.seek(SeekFrom::Start(0))?;
    let mut second_prefix = [0; PREFIX_LEN as usize];
    source.read_exact(&mut second_prefix)?;
    if second_prefix != prefix {
        return Err(Error::SourceChanged);
    }
    let mut cipher = keys.cipher(prefix[32..].try_into().unwrap(), None)?;
    let mut second_mac = mac(&keys, &prefix, length)?;
    tracker.begin(ProgressPhase::Unwrapping, Some(length))?;
    let mut remaining = length;
    let mut buffer = Zeroizing::new(vec![0; BUFFER_SIZE]);
    while remaining > 0 {
        tracker.checkpoint()?;
        let n = remaining.min(buffer.len() as u64) as usize;
        source.read_exact(&mut buffer[..n])?;
        second_mac.update(&buffer[..n]);
        cipher
            .decrypt(&mut buffer[..n])
            .map_err(|_| Error::InvalidVolume)?;
        inner.write_all(&buffer[..n])?;
        remaining -= n as u64;
        tracker.advance(n as u64)?;
    }
    second_mac.verify(&tag)?;
    let mut second_tag = [0; TAG_LEN as usize];
    source.read_exact(&mut second_tag)?;
    if second_tag != tag
        || source.read(&mut [0; 1])? != 0
        || source.metadata()?.len() != physical_length
    {
        return Err(Error::SourceChanged);
    }
    inner.flush()?;
    Ok(())
}

struct VerifiedEnvelope {
    physical_length: u64,
    length: u64,
    prefix: [u8; 56],
    keys: Keys,
    tag: [u8; 64],
}

#[cfg(target_os = "linux")]
pub(crate) fn verify_for_deletion(
    source: &mut File,
    password: &str,
    keyfiles: &[PathBuf],
    tracker: &mut Tracker<'_>,
) -> Result<()> {
    authenticate(source, password, keyfiles, tracker).map(|_| ())
}

fn authenticate(
    source: &mut File,
    password: &str,
    keyfiles: &[PathBuf],
    tracker: &mut Tracker<'_>,
) -> Result<VerifiedEnvelope> {
    source.seek(SeekFrom::Start(0))?;
    let physical_length = source.metadata()?.len();
    let length = physical_length
        .checked_sub(PREFIX_LEN + TAG_LEN)
        .filter(|&n| n >= FIXED_HEADER + TAG_LEN)
        .ok_or(Error::Authentication)?;
    let mut prefix = [0; PREFIX_LEN as usize];
    source.read_exact(&mut prefix)?;
    tracker.begin(ProgressPhase::KeyDerivation, None)?;
    let keys = keys(password, keyfiles, &prefix, tracker)?;
    tracker.begin(ProgressPhase::Authenticating, Some(length))?;
    let mut first_mac = mac(&keys, &prefix, length)?;
    let mut buffer = Zeroizing::new(vec![0; BUFFER_SIZE]);
    let mut remaining = length;
    while remaining > 0 {
        tracker.checkpoint()?;
        let n = remaining.min(buffer.len() as u64) as usize;
        source.read_exact(&mut buffer[..n])?;
        first_mac.update(&buffer[..n]);
        remaining -= n as u64;
        tracker.advance(n as u64)?;
    }
    let mut tag = [0; TAG_LEN as usize];
    source.read_exact(&mut tag)?;
    first_mac.verify(&tag)?;
    if source.read(&mut [0; 1])? != 0 {
        return Err(Error::SourceChanged);
    }
    if source.metadata()?.len() != physical_length {
        return Err(Error::SourceChanged);
    }
    Ok(VerifiedEnvelope {
        physical_length,
        length,
        prefix,
        keys,
        tag,
    })
}

#[cfg(test)]
mod tests;
