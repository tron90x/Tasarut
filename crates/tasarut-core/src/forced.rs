//! Explicit best-effort recovery. This API never certifies its output as authenticated.

use crate::{
    crypto::{Authenticator, Cascade},
    derive_keys, open_regular, publish,
    recovery::VolumeReader,
    temporary_output, ByteProgress, Error, Header, OperationControl, ProgressPhase, RepairInfo,
    Result, Tracker, BUFFER_SIZE, TAG_LEN,
};
use serde::Serialize;
use std::{
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use tempfile::NamedTempFile;
use zeroize::Zeroizing;
use zstd::stream::raw::{DParameter, Decoder, Operation};

#[derive(Clone, Debug)]
pub struct ForceOptions {
    pub max_output_bytes: u64,
}
impl Default for ForceOptions {
    fn default() -> Self {
        Self {
            max_output_bytes: 4 * 1024 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum MacStatus {
    Valid,
    Invalid,
    Missing,
    NotChecked,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DamageRange {
    /// Logical byte offset in the inner encrypted volume, not in the plaintext.
    pub offset: u64,
    pub length: u64,
}

#[derive(Clone, Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryDamage {
    pub uncorrectable_blocks: u64,
    pub missing_bytes: u64,
    pub truncated: bool,
    pub trailing_data: bool,
    pub descriptor_damaged: bool,
    pub noncanonical_padding: bool,
    pub ranges: Vec<DamageRange>,
    pub ranges_omitted: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ForceReport {
    pub authenticated: bool,
    pub mac_status: MacStatus,
    pub partial: bool,
    pub declared_size: u64,
    pub recovered_bytes: u64,
    pub output_limit: u64,
    pub limit_reached: bool,
    pub decompression_failed: bool,
    pub trailing_data: bool,
    pub repair: RepairInfo,
    pub damage: RecoveryDamage,
}

/// Recover only present data. A matching MAC is reported, but does not convert this
/// single-pass, possibly partial recovery into the normal authenticated output path.
pub fn force_decrypt(
    source: &Path,
    destination: &Path,
    password: &str,
    keyfiles: &[PathBuf],
    options: &ForceOptions,
) -> Result<ForceReport> {
    force_decrypt_impl(
        source,
        destination,
        password,
        keyfiles,
        options,
        &mut Tracker::default(),
    )
}

pub fn force_decrypt_with_progress(
    source: &Path,
    destination: &Path,
    password: &str,
    keyfiles: &[PathBuf],
    options: &ForceOptions,
    on_progress: &mut dyn FnMut(ByteProgress),
) -> Result<ForceReport> {
    crate::progress::observe(on_progress, |tracker| {
        force_decrypt_impl(source, destination, password, keyfiles, options, tracker)
    })
}

pub fn force_decrypt_with_control(
    source: &Path,
    destination: &Path,
    password: &str,
    keyfiles: &[PathBuf],
    options: &ForceOptions,
    control: &mut OperationControl<'_>,
) -> Result<ForceReport> {
    crate::progress::observe_control(control, |tracker| {
        force_decrypt_impl(source, destination, password, keyfiles, options, tracker)
    })
}

fn force_decrypt_impl(
    source: &Path,
    destination: &Path,
    password: &str,
    keyfiles: &[PathBuf],
    options: &ForceOptions,
    tracker: &mut Tracker<'_>,
) -> Result<ForceReport> {
    if options.max_output_bytes == 0 || options.max_output_bytes > 1 << 40 {
        return Err(Error::InvalidRecoveryLimit);
    }
    // An incomplete or altered chunk set has no safe, unambiguous byte layout.
    // Forced recovery still requires a complete, authenticated outer manifest.
    if let Some(root) = crate::chunks::root(source)? {
        let assembled = crate::chunks::assemble(
            &root,
            destination.parent(),
            Some((password, keyfiles)),
            tracker,
        )?;
        return force_decrypt_impl(
            assembled.volume.path(),
            destination,
            password,
            keyfiles,
            options,
            tracker,
        );
    }
    let mut file = VolumeReader::open(open_regular(source)?, true)?;
    if crate::revocable::reader_is_revocable(&mut file)? {
        return Err(Error::RevocableOptions);
    }
    let header = Header::read_mode(&mut file, true)?;
    let start = file.stream_position()?;
    tracker.begin(ProgressPhase::KeyDerivation, None)?;
    let keys = derive_keys(password, keyfiles, &header.salt, header.suite, tracker)?;
    let mut cipher = keys.cipher(&header.nonce, header.block_parameter.as_ref())?;
    let mut mac = keys.mac(&header.authenticated_bytes())?;
    let mut output = temporary_output(destination)?;
    let recovered = if header.flags == 0 {
        recover_plain(
            &mut file,
            &mut output,
            &mut cipher,
            &mut mac,
            start,
            (header.size, options.max_output_bytes),
            tracker,
        )?
    } else {
        recover_compressed(
            &mut file,
            &mut output,
            &mut cipher,
            &mut mac,
            start,
            options.max_output_bytes,
            tracker,
        )?
    };
    let mut damage = file.damage();
    let mac_status = if let Some(payload_length) = recovered.complete_payload {
        file.seek(SeekFrom::Start(start + payload_length))?;
        if file.length().saturating_sub(start + payload_length) < TAG_LEN {
            MacStatus::Missing
        } else {
            let mut tag = [0; TAG_LEN as usize];
            file.read_exact(&mut tag)?;
            if mac.verify(&tag).is_ok() {
                MacStatus::Valid
            } else {
                MacStatus::Invalid
            }
        }
    } else if recovered.limit_reached || header.flags == 1 {
        MacStatus::NotChecked
    } else {
        MacStatus::Missing
    };
    let trailing_data = recovered
        .complete_payload
        .is_some_and(|length| file.length().saturating_sub(start + length) > TAG_LEN);
    // Include faults discovered while retrieving the tag, but never double-count rescanned blocks.
    let after_tag = file.damage();
    damage.uncorrectable_blocks = after_tag.uncorrectable_blocks;
    damage.ranges = after_tag.ranges;
    damage.ranges_omitted = after_tag.ranges_omitted;
    damage.noncanonical_padding |= after_tag.noncanonical_padding;
    if recovered.bytes == 0 && (header.size > 0 || recovered.decompression_failed) {
        return Err(Error::NothingRecovered);
    }
    file.validate_source_length()?;
    let report = ForceReport {
        authenticated: false,
        mac_status,
        partial: recovered.bytes != header.size
            || recovered.limit_reached
            || recovered.decompression_failed,
        declared_size: header.size,
        recovered_bytes: recovered.bytes,
        output_limit: options.max_output_bytes,
        limit_reached: recovered.limit_reached,
        decompression_failed: recovered.decompression_failed,
        trailing_data: trailing_data || damage.trailing_data,
        repair: file.report(),
        damage,
    };
    tracker.begin(ProgressPhase::Publishing, None)?;
    publish(output, destination, tracker)?;
    Ok(report)
}

struct Recovered {
    bytes: u64,
    complete_payload: Option<u64>,
    limit_reached: bool,
    decompression_failed: bool,
}

fn recover_plain(
    file: &mut VolumeReader,
    output: &mut NamedTempFile,
    cipher: &mut Cascade,
    mac: &mut Authenticator,
    start: u64,
    bounds: (u64, u64),
    tracker: &mut Tracker<'_>,
) -> Result<Recovered> {
    let (expected, limit) = bounds;
    let available = file.length().saturating_sub(start);
    let length = expected.min(available).min(limit);
    tracker.begin(ProgressPhase::Recovering, Some(length))?;
    let mut remaining = length;
    let mut buffer = Zeroizing::new(vec![0; BUFFER_SIZE]);
    while remaining > 0 {
        tracker.checkpoint()?;
        let n = remaining.min(BUFFER_SIZE as u64) as usize;
        file.read_exact(&mut buffer[..n])?;
        mac.update(&buffer[..n]);
        cipher
            .decrypt(&mut buffer[..n])
            .map_err(|_| io::Error::other("cipher limit reached"))?;
        output.write_all(&buffer[..n])?;
        remaining -= n as u64;
        tracker.advance(n as u64)?;
    }
    Ok(Recovered {
        bytes: length,
        complete_payload: (length == expected).then_some(length),
        limit_reached: length == limit && length < expected.min(available),
        decompression_failed: false,
    })
}

fn recover_compressed(
    file: &mut VolumeReader,
    output: &mut NamedTempFile,
    cipher: &mut Cascade,
    mac: &mut Authenticator,
    start: u64,
    limit: u64,
    tracker: &mut Tracker<'_>,
) -> Result<Recovered> {
    // A damaged frame's endpoint is unknown until the decoder reaches it.
    tracker.begin(ProgressPhase::Recovering, None)?;
    let mut decoder = Decoder::new()?;
    decoder.set_parameter(DParameter::WindowLogMax(27))?;
    let mut raw = Zeroizing::new(vec![0; BUFFER_SIZE]);
    let mut decoded_input = Zeroizing::new(vec![0; BUFFER_SIZE]);
    let mut plaintext = Zeroizing::new(vec![0; BUFFER_SIZE]);
    let (mut position, mut length, mut consumed, mut produced) = (0usize, 0usize, 0u64, 0u64);
    let mut eof = false;
    let mut result = Recovered {
        bytes: 0,
        complete_payload: None,
        limit_reached: false,
        decompression_failed: false,
    };
    loop {
        tracker.checkpoint()?;
        if produced == limit {
            result.limit_reached = true;
            break;
        }
        if position == length && !eof {
            let available = file.length().saturating_sub(file.stream_position()?);
            length = available.min(BUFFER_SIZE as u64) as usize;
            position = 0;
            eof = length == 0;
            if !eof {
                file.read_exact(&mut raw[..length])?;
                decoded_input[..length].copy_from_slice(&raw[..length]);
                cipher
                    .decrypt(&mut decoded_input[..length])
                    .map_err(|_| io::Error::other("cipher limit reached"))?;
            }
        }
        let capacity = (limit - produced).min(BUFFER_SIZE as u64) as usize;
        let status = match decoder
            .run_on_buffers(&decoded_input[position..length], &mut plaintext[..capacity])
        {
            Ok(status) => status,
            Err(_) => {
                result.decompression_failed = true;
                break;
            }
        };
        mac.update(&raw[position..position + status.bytes_read]);
        position += status.bytes_read;
        consumed += status.bytes_read as u64;
        output.write_all(&plaintext[..status.bytes_written])?;
        produced += status.bytes_written as u64;
        tracker.advance(status.bytes_read as u64)?;
        if status.remaining == 0 {
            result.complete_payload = Some(consumed);
            break;
        }
        if status.bytes_read == 0 && status.bytes_written == 0 {
            result.decompression_failed = true;
            break;
        }
    }
    result.bytes = produced;
    // Raw decoding tracks the frame boundary exactly, even if a read included the tag.
    debug_assert!(result
        .complete_payload
        .is_none_or(|n| start + n <= file.length()));
    Ok(result)
}

#[cfg(test)]
mod tests;
