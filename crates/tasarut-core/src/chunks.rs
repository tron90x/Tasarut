//! A chunk set is an atomically published directory, with raw volume slices and
//! a bounded, keyed manifest. No pathname supplied by the manifest is trusted.
use crate::{
    derive_keys, encrypt_volume, open_regular, publish, recovery::VolumeReader, temporary_output,
    EncryptOptions, Error, Header, ProgressPhase, Result, Tracker, BUFFER_SIZE,
};
use blake2::{Blake2b512, Digest};
use std::{
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use tempfile::NamedTempFile;

const MAGIC: &[u8; 8] = b"TASPART\x01";
const DOMAIN: &[u8] = b"Tasarut/chunks/v1/manifest\0";
const MANIFEST: &str = "manifest.tasarut";
const FIXED: usize = 28;
const MAX_PARTS: u64 = 65536;
const MIN_SIZE: u64 = 1024;
const MAX_SIZE: u64 = 1 << 40;

fn part_name(index: u32) -> String {
    format!("{:06}.part", index + 1)
}

/// Resolve a set directory, its manifest, or any of its numbered parts.
/// Recognize incomplete sets too, so they cannot be encrypted as ordinary input.
pub(crate) fn root(path: &Path) -> Result<Option<PathBuf>> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Err(Error::InvalidInput);
    }
    let named_set = |p: &Path| {
        p.file_name()
            .is_some_and(|n| n.to_string_lossy().ends_with(".tasarut.parts"))
    };
    let has_manifest = |p: &Path| {
        open_regular(&p.join(MANIFEST))
            .ok()
            .is_some_and(|mut file| {
                let mut magic = [0; 8];
                file.read_exact(&mut magic).is_ok() && &magic == MAGIC
            })
    };
    if meta.is_dir() && (named_set(path) || has_manifest(path)) {
        return Ok(Some(path.to_path_buf()));
    }
    if meta.is_file() {
        let name = path.file_name().unwrap().to_string_lossy();
        if name == MANIFEST
            || (name.len() == 11
                && name.ends_with(".part")
                && name.as_bytes()[..6].iter().all(|b| b.is_ascii_digit()))
        {
            if let Some(parent) = path.parent() {
                if named_set(parent) || has_manifest(parent) {
                    if fs::symlink_metadata(parent)?.file_type().is_symlink() {
                        return Err(Error::InvalidInput);
                    }
                    return Ok(Some(parent.to_path_buf()));
                }
            }
        }
    }
    Ok(None)
}

fn count(total: u64, size: u64) -> Result<u32> {
    if !(MIN_SIZE..=MAX_SIZE).contains(&size) {
        return Err(Error::InvalidChunkSize);
    }
    let count = total.div_ceil(size);
    if total == 0 || count > MAX_PARTS {
        return Err(Error::InvalidChunkSize);
    }
    Ok(count as u32)
}

pub(crate) fn encrypt(
    source: &Path,
    destination: &Path,
    password: &str,
    options: &EncryptOptions,
    size: u64,
    tracker: &mut Tracker<'_>,
) -> Result<()> {
    count(1, size)?;
    match fs::symlink_metadata(destination) {
        Ok(_) => return Err(Error::OutputExists),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let staging = tempfile::tempdir_in(parent)?;
    let volume_path = staging.path().join("volume.tmp");
    encrypt_volume(source, &volume_path, password, options, tracker)?;
    let mut volume = open_regular(&volume_path)?;
    let total = volume.metadata()?.len();
    let parts = count(total, size)?;
    tracker.begin(ProgressPhase::Splitting, Some(total))?;
    let mut manifest = Vec::with_capacity(FIXED + parts as usize * 64);
    manifest.extend_from_slice(MAGIC);
    manifest.extend_from_slice(&total.to_le_bytes());
    manifest.extend_from_slice(&size.to_le_bytes());
    manifest.extend_from_slice(&parts.to_le_bytes());
    let mut buffer = vec![0; BUFFER_SIZE];
    for index in 0..parts {
        tracker.checkpoint()?;
        let target = staging.path().join(part_name(index));
        let mut output = temporary_output(&target)?;
        let mut hash = Blake2b512::new();
        let mut remaining = (total - u64::from(index) * size).min(size);
        while remaining > 0 {
            tracker.checkpoint()?;
            let n = remaining.min(buffer.len() as u64) as usize;
            volume.read_exact(&mut buffer[..n])?;
            hash.update(&buffer[..n]);
            output.write_all(&buffer[..n])?;
            remaining -= n as u64;
            tracker.advance(n as u64)?;
        }
        manifest.extend_from_slice(&hash.finalize());
        publish(output, &target, tracker)?;
    }
    volume.seek(SeekFrom::Start(0))?;
    let mut reader = VolumeReader::new(volume)?;
    let header = Header::read(&mut reader)?;
    tracker.begin(ProgressPhase::KeyDerivation, None)?;
    let keys = derive_keys(
        password,
        &options.keyfiles,
        &header.salt,
        header.suite,
        tracker,
    )?;
    let mut mac = keys.mac(DOMAIN)?;
    mac.update(&manifest);
    manifest.extend_from_slice(&mac.finalize());
    let target = staging.path().join(MANIFEST);
    tracker.begin(ProgressPhase::Publishing, None)?;
    let mut output = temporary_output(&target)?;
    output.write_all(&manifest)?;
    publish(output, &target, tracker)?;
    drop(reader);
    fs::remove_file(volume_path)?;
    tracker.checkpoint()?;
    // NOREPLACE also refuses existing empty directories and symlinks, atomically.
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        staging.path(),
        rustix::fs::CWD,
        destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|e| {
        if e == rustix::io::Errno::EXIST {
            Error::OutputExists
        } else {
            Error::Io(e.into())
        }
    })?;
    Ok(())
}

pub(crate) struct Assembled {
    pub volume: NamedTempFile,
    pub count: u32,
}

pub(crate) fn assemble(
    root: &Path,
    temporary_directory: Option<&Path>,
    secret: Option<(&str, &[PathBuf])>,
    tracker: &mut Tracker<'_>,
) -> Result<Assembled> {
    let mut file = open_regular(&root.join(MANIFEST)).map_err(|e| match e {
        Error::Io(ref io) if io.kind() == std::io::ErrorKind::NotFound => {
            Error::InvalidChunkManifest
        }
        other => other,
    })?;
    let length = file.metadata()?.len();
    if !(FIXED as u64 + 128..=FIXED as u64 + MAX_PARTS * 64 + 64).contains(&length) {
        return Err(Error::InvalidChunkManifest);
    }
    let mut manifest = Vec::with_capacity(length as usize);
    Read::by_ref(&mut file)
        .take(length + 1)
        .read_to_end(&mut manifest)?;
    if manifest.len() as u64 != length || &manifest[..8] != MAGIC {
        return Err(Error::InvalidChunkManifest);
    }
    let total = u64::from_le_bytes(manifest[8..16].try_into().unwrap());
    let size = u64::from_le_bytes(manifest[16..24].try_into().unwrap());
    let parts = u32::from_le_bytes(manifest[24..28].try_into().unwrap());
    if count(total, size).map_err(|_| Error::InvalidChunkManifest)? != parts
        || length != FIXED as u64 + u64::from(parts) * 64 + 64
    {
        return Err(Error::InvalidChunkManifest);
    }
    let mut volume = match temporary_directory.filter(|p| !p.as_os_str().is_empty()) {
        Some(parent) => NamedTempFile::new_in(parent)?,
        None => NamedTempFile::new()?,
    };
    let mut buffer = vec![0; BUFFER_SIZE];
    tracker.begin(ProgressPhase::Reassembling, Some(total))?;
    for index in 0..parts {
        tracker.checkpoint()?;
        let mut part = open_regular(&root.join(part_name(index))).map_err(|e| match e {
            Error::Io(ref io) if io.kind() == std::io::ErrorKind::NotFound => Error::ChunkMissing,
            other => other,
        })?;
        let expected = (total - u64::from(index) * size).min(size);
        if part.metadata()?.len() != expected {
            return Err(Error::ChunkDamaged);
        }
        let mut hash = Blake2b512::new();
        let mut remaining = expected;
        while remaining > 0 {
            tracker.checkpoint()?;
            let n = remaining.min(buffer.len() as u64) as usize;
            part.read_exact(&mut buffer[..n]).map_err(|e| {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    Error::ChunkDamaged
                } else {
                    e.into()
                }
            })?;
            hash.update(&buffer[..n]);
            volume.write_all(&buffer[..n])?;
            remaining -= n as u64;
            tracker.advance(n as u64)?;
        }
        let hash_at = FIXED + index as usize * 64;
        if hash.finalize().as_slice() != &manifest[hash_at..hash_at + 64]
            || part.read(&mut [0; 1])? != 0
        {
            return Err(Error::ChunkDamaged);
        }
    }
    volume.flush()?;
    if let Some((password, keyfiles)) = secret {
        let mut reader = VolumeReader::new(volume.reopen()?)?;
        let header = Header::read(&mut reader)?;
        tracker.begin(ProgressPhase::KeyDerivation, None)?;
        let keys = derive_keys(password, keyfiles, &header.salt, header.suite, tracker)?;
        let tag_at = manifest.len() - 64;
        let mut mac = keys.mac(DOMAIN)?;
        mac.update(&manifest[..tag_at]);
        mac.verify(&manifest[tag_at..])?;
    }
    Ok(Assembled {
        volume,
        count: parts,
    })
}

#[cfg(test)]
mod tests;
