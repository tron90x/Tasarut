//! v3 envelope: one protected descriptor, followed by systematic RS(136,128) blocks.
//! The inner v1/v2 volume still supplies the cryptographic authentication.

use crate::forced::{DamageRange, RecoveryDamage};
use crate::{Error, RepairInfo, Result, BUFFER_SIZE, MAGIC, PARANOID_MAGIC, THREEFISH_MAGIC};
use reed_solomon::{Decoder, Encoder};
use std::{
    fs::File,
    io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
};

pub(crate) const MAGIC_RS: &[u8; 8] = b"TASARUT\x03";
pub(crate) const DATA: usize = 128;
pub(crate) const PARITY: usize = 8;
pub(crate) const BLOCK: usize = DATA + PARITY;

#[derive(Debug)]
pub(crate) struct Uncorrectable;
impl std::fmt::Display for Uncorrectable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("reed_solomon_uncorrectable")
    }
}
impl std::error::Error for Uncorrectable {}
fn corruption() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, Uncorrectable)
}

fn correct(block: &[u8; BLOCK]) -> io::Result<([u8; DATA], usize)> {
    let (decoded, errors) = Decoder::new(PARITY)
        .correct_err_count(block, None)
        .map_err(|_| corruption())?;
    if errors > PARITY / 2 {
        return Err(corruption());
    }
    let mut data = [0; DATA];
    data.copy_from_slice(decoded.data());
    Ok((data, errors))
}

pub(crate) struct ProtectedWriter<'a> {
    output: BufWriter<&'a mut File>,
    encoder: Encoder,
    data: [u8; DATA],
    used: usize,
    length: u64,
}

impl<'a> ProtectedWriter<'a> {
    pub fn new(output: &'a mut File) -> io::Result<Self> {
        let mut output = BufWriter::with_capacity(BUFFER_SIZE, output);
        output.write_all(&[0; BLOCK])?; // Descriptor is patched once the inner length is known.
        Ok(Self {
            output,
            encoder: Encoder::new(PARITY),
            data: [0; DATA],
            used: 0,
            length: 0,
        })
    }

    pub fn finish(mut self) -> io::Result<()> {
        if self.used != 0 {
            self.data[self.used..].fill(0);
            self.output.write_all(&self.encoder.encode(&self.data))?;
        }
        let mut descriptor = [0; DATA];
        descriptor[..8].copy_from_slice(MAGIC_RS);
        descriptor[8..16].copy_from_slice(&self.length.to_le_bytes());
        self.output.seek(SeekFrom::Start(0))?;
        self.output.write_all(&self.encoder.encode(&descriptor))?;
        self.output.seek(SeekFrom::End(0))?;
        self.output.flush()
    }
}

impl Write for ProtectedWriter<'_> {
    fn write(&mut self, mut bytes: &[u8]) -> io::Result<usize> {
        let length = bytes.len();
        self.length = self
            .length
            .checked_add(length as u64)
            .ok_or_else(corruption)?;
        while !bytes.is_empty() {
            let n = bytes.len().min(DATA - self.used);
            self.data[self.used..self.used + n].copy_from_slice(&bytes[..n]);
            self.used += n;
            bytes = &bytes[n..];
            if self.used == DATA {
                self.output.write_all(&self.encoder.encode(&self.data))?;
                self.used = 0;
            }
        }
        Ok(length)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

pub(crate) struct ProtectedReader {
    source: BufReader<File>,
    length: u64,
    physical_length: u64,
    position: u64,
    cached_block: Option<u64>,
    next_block: Option<u64>,
    data: [u8; DATA],
    report: RepairInfo,
    force: bool,
    damage: RecoveryDamage,
    counted_through: u64,
}

impl ProtectedReader {
    fn load(&mut self, index: u64) -> io::Result<()> {
        if self.cached_block == Some(index) {
            return Ok(());
        }
        if self.next_block != Some(index) {
            self.source
                .seek(SeekFrom::Start((index + 1) * BLOCK as u64))?;
        }
        let mut block = [0; BLOCK];
        let offset = (index + 1) * BLOCK as u64;
        let present = self
            .physical_length
            .saturating_sub(offset)
            .min(BLOCK as u64) as usize;
        self.source.read_exact(&mut block[..present])?;
        self.next_block = Some(index + 1);
        let decoded = if self.force && present < BLOCK && BLOCK - present <= PARITY {
            let erasures: Vec<u8> = (present..BLOCK).map(|i| i as u8).collect();
            Decoder::new(PARITY)
                .correct_err_count(&block, Some(&erasures))
                .map(|(b, errors)| {
                    let mut data = [0; DATA];
                    data.copy_from_slice(b.data());
                    (data, errors)
                })
                .map_err(|_| corruption())
        } else if present == BLOCK {
            correct(&block)
        } else {
            Err(corruption())
        };
        let count = index >= self.counted_through;
        let (data, errors) = match decoded {
            Ok(result) => result,
            Err(error) if self.force => {
                let _ = error;
                if count {
                    self.damage.uncorrectable_blocks += 1;
                    if self.damage.ranges.len() < 128 {
                        self.damage.ranges.push(DamageRange {
                            offset: index * DATA as u64,
                            length: (self.length - index * DATA as u64).min(DATA as u64),
                        });
                    } else {
                        self.damage.ranges_omitted = true;
                    }
                }
                (block[..DATA].try_into().unwrap(), 0)
            }
            Err(error) => return Err(error),
        };
        let useful = (self.length - index * DATA as u64).min(DATA as u64) as usize;
        if data[useful..].iter().any(|&byte| byte != 0) {
            if !self.force {
                return Err(corruption());
            }
            self.damage.noncanonical_padding = true;
        }
        if count && errors > 0 {
            self.report.corrected_blocks += 1;
            self.report.corrected_bytes += errors as u64;
        }
        if count {
            self.counted_through = index + 1;
        }
        self.data = data;
        self.cached_block = Some(index);
        Ok(())
    }
}

impl Read for ProtectedReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let wanted = (self.length - self.position).min(output.len() as u64) as usize;
        let mut copied = 0;
        while copied < wanted {
            let index = self.position / DATA as u64;
            let offset = (self.position % DATA as u64) as usize;
            self.load(index)?;
            let n = (wanted - copied).min(DATA - offset);
            output[copied..copied + n].copy_from_slice(&self.data[offset..offset + n]);
            copied += n;
            self.position += n as u64;
        }
        Ok(copied)
    }
}

impl Seek for ProtectedReader {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let target = match from {
            SeekFrom::Start(n) => i128::from(n),
            SeekFrom::Current(n) => i128::from(self.position) + i128::from(n),
            SeekFrom::End(n) => i128::from(self.length) + i128::from(n),
        };
        if target < 0 || target > i128::from(self.length) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid seek"));
        }
        self.position = target as u64;
        Ok(self.position)
    }
}

pub(crate) enum VolumeReader {
    Plain { file: File, length: u64 },
    Protected(Box<ProtectedReader>),
}

impl VolumeReader {
    pub fn new(file: File) -> Result<Self> {
        Self::open(file, false)
    }

    pub fn open(mut file: File, force: bool) -> Result<Self> {
        let physical_length = file.metadata()?.len();
        let mut first = [0; BLOCK];
        let n = physical_length.min(BLOCK as u64) as usize;
        file.read_exact(&mut first[..n])?;
        file.seek(SeekFrom::Start(0))?;
        // Try the protected descriptor first, even if a damaged v3 version byte looks like v1/v2.
        if n == BLOCK && (force || physical_length.is_multiple_of(BLOCK as u64)) {
            let corrected = correct(&first);
            let raw_descriptor = &first[..8] == MAGIC_RS;
            let descriptor_result = match corrected {
                Ok((bytes, errors)) => Some((bytes, errors, false)),
                Err(_) if force && raw_descriptor => {
                    Some((first[..DATA].try_into().unwrap(), 0, true))
                }
                _ => None,
            };
            if let Some((descriptor, errors, damaged_descriptor)) = descriptor_result {
                let reserved_invalid = descriptor[16..].iter().any(|&b| b != 0);
                if &descriptor[..8] == MAGIC_RS && (!reserved_invalid || force) {
                    let length = u64::from_le_bytes(descriptor[8..16].try_into().unwrap());
                    let blocks = length
                        .div_ceil(DATA as u64)
                        .checked_add(1)
                        .ok_or(Error::InvalidVolume)?;
                    let expected_length = blocks
                        .checked_mul(BLOCK as u64)
                        .ok_or(Error::InvalidVolume)?;
                    if length < crate::FIXED_HEADER + if force { 0 } else { crate::TAG_LEN }
                        || (!force && expected_length != physical_length)
                    {
                        return Err(Error::InvalidVolume);
                    }
                    let data_physical = physical_length.saturating_sub(BLOCK as u64);
                    let available = (data_physical / BLOCK as u64) * DATA as u64
                        + (data_physical % BLOCK as u64).min(DATA as u64);
                    let logical_length = if force { length.min(available) } else { length };
                    return Ok(Self::Protected(Box::new(ProtectedReader {
                        source: BufReader::with_capacity(BUFFER_SIZE, file),
                        length: logical_length,
                        physical_length,
                        position: 0,
                        cached_block: None,
                        next_block: None,
                        data: [0; DATA],
                        force,
                        counted_through: 0,
                        damage: RecoveryDamage {
                            descriptor_damaged: damaged_descriptor || reserved_invalid,
                            truncated: physical_length < expected_length,
                            trailing_data: physical_length > expected_length,
                            missing_bytes: length.saturating_sub(logical_length),
                            ..Default::default()
                        },
                        report: RepairInfo {
                            reed_solomon: true,
                            corrected_blocks: u64::from(errors > 0),
                            corrected_bytes: errors as u64,
                        },
                    })));
                }
            }
        }
        if n >= 8
            && (&first[..8] == MAGIC
                || &first[..8] == PARANOID_MAGIC
                || &first[..8] == THREEFISH_MAGIC
                || &first[..8] == crate::revocable::MAGIC)
        {
            Ok(Self::Plain {
                file,
                length: physical_length,
            })
        } else if n >= 8 && &first[..8] == MAGIC_RS {
            Err(Error::ReedSolomon)
        } else {
            Err(Error::InvalidVolume)
        }
    }

    pub fn length(&self) -> u64 {
        match self {
            Self::Plain { length, .. } => *length,
            Self::Protected(reader) => reader.length,
        }
    }

    /// Snapshot after the first complete authentication pass, before any block is revisited.
    pub fn report(&self) -> RepairInfo {
        match self {
            Self::Plain { .. } => RepairInfo::default(),
            Self::Protected(reader) => reader.report.clone(),
        }
    }

    pub fn damage(&self) -> RecoveryDamage {
        match self {
            Self::Plain { .. } => RecoveryDamage::default(),
            Self::Protected(reader) => reader.damage.clone(),
        }
    }

    pub fn validate_source_length(&self) -> Result<()> {
        let (file, expected) = match self {
            Self::Plain { file, length } => (file, *length),
            Self::Protected(reader) => (reader.source.get_ref(), reader.physical_length),
        };
        if file.metadata()?.len() != expected {
            return Err(Error::SourceChanged);
        }
        Ok(())
    }
}

impl Read for VolumeReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain { file, .. } => file.read(out),
            Self::Protected(reader) => reader.read(out),
        }
    }
}
impl Seek for VolumeReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match self {
            Self::Plain { file, .. } => file.seek(pos),
            Self::Protected(reader) => reader.seek(pos),
        }
    }
}

#[cfg(test)]
mod tests;
