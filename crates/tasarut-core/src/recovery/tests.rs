use super::*;
use std::fs;

fn wrapped(bytes: &[u8]) -> Vec<u8> {
    let mut file = tempfile::tempfile().unwrap();
    let mut writer = ProtectedWriter::new(&mut file).unwrap();
    for chunk in bytes.chunks(11) {
        writer.write_all(chunk).unwrap();
        writer.flush().unwrap();
    }
    writer.finish().unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut output = Vec::new();
    file.read_to_end(&mut output).unwrap();
    output
}

#[test]
fn systematic_codeword_matches_independent_gf256_vector_and_corrects_all_positions() {
    // Independent Python polynomial implementation, GF(256) 0x11d, roots alpha^0..alpha^7.
    let data: [u8; DATA] = std::array::from_fn(|i| i as u8);
    let codeword = Encoder::new(PARITY).encode(&data);
    let expected = crate::tests::unhex(include_str!("../../test-vectors/rs-128.hex"));
    assert_eq!(&codeword[..], &expected);
    for position in 0..BLOCK {
        let mut damaged: [u8; BLOCK] = expected.as_slice().try_into().unwrap();
        damaged[position] ^= 0x6b;
        let (restored, errors) = correct(&damaged).unwrap();
        assert_eq!(restored, data);
        assert_eq!(errors, 1);
    }
    let mut damaged: [u8; BLOCK] = expected.as_slice().try_into().unwrap();
    for (index, position) in [0, 17, 127, 135].into_iter().enumerate() {
        damaged[position] ^= 1 + index as u8;
    }
    let (restored, errors) = correct(&damaged).unwrap();
    assert_eq!(restored, data);
    assert_eq!(errors, 4);
}

#[test]
fn reader_seeks_at_block_boundaries_and_trims_only_zero_padding() {
    let bytes: Vec<_> = (0..513).map(|i| (i % 251) as u8).collect();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wrapped");
    fs::write(&path, wrapped(&bytes)).unwrap();
    let mut reader = VolumeReader::new(File::open(&path).unwrap()).unwrap();
    assert_eq!(reader.length(), bytes.len() as u64);
    for offset in [0, 127, 128, 255, 256, 512, 513, 17] {
        reader.seek(SeekFrom::Start(offset)).unwrap();
        let mut actual = Vec::new();
        reader.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, bytes[offset as usize..]);
    }
    assert!(reader.seek(SeekFrom::End(1)).is_err());
    // Canonical padding is required even when a modified block has valid parity.
    let mut encoded = wrapped(&bytes);
    let last = encoded.len() - BLOCK;
    let mut block = [0; DATA];
    block[0] = bytes[512];
    block[1] = 1;
    encoded[last..].copy_from_slice(&Encoder::new(PARITY).encode(&block));
    fs::write(&path, encoded).unwrap();
    let mut reader = VolumeReader::new(File::open(&path).unwrap()).unwrap();
    assert!(reader.read_to_end(&mut Vec::new()).is_err());
}

#[test]
fn descriptor_is_corrected_even_when_its_version_looks_legacy_and_geometry_is_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wrapped");
    let original = wrapped(&vec![42; 300]);
    for positions in [vec![7], vec![0, 7, 8, 135]] {
        let mut bytes = original.clone();
        for position in &positions {
            bytes[*position] ^= 2;
        }
        fs::write(&path, bytes).unwrap();
        let mut reader = VolumeReader::new(File::open(&path).unwrap()).unwrap();
        assert_eq!(reader.report().corrected_bytes, positions.len() as u64);
        let mut restored = Vec::new();
        reader.read_to_end(&mut restored).unwrap();
        assert_eq!(restored, vec![42; 300]);
    }
    for length in [0, 8, 135, 136, original.len() - 1, original.len() - BLOCK] {
        fs::write(&path, &original[..length]).unwrap();
        assert!(VolumeReader::new(File::open(&path).unwrap()).is_err());
    }
    let mut descriptor = [0; DATA];
    descriptor[..8].copy_from_slice(MAGIC_RS);
    descriptor[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
    let mut changed = original;
    changed[..BLOCK].copy_from_slice(&Encoder::new(PARITY).encode(&descriptor));
    fs::write(&path, changed).unwrap();
    assert!(VolumeReader::new(File::open(&path).unwrap()).is_err());
}

#[test]
fn forced_damage_ranges_are_bounded_and_known_missing_parity_is_repaired() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wrapped");
    let data = vec![42; 150 * DATA];
    let mut bytes = wrapped(&data);
    for block in bytes[BLOCK..].chunks_exact_mut(BLOCK) {
        for (index, byte) in block[..5].iter_mut().enumerate() {
            *byte ^= index as u8 + 1;
        }
    }
    fs::write(&path, &bytes).unwrap();
    let mut reader = VolumeReader::open(File::open(&path).unwrap(), true).unwrap();
    reader.read_to_end(&mut Vec::new()).unwrap();
    assert_eq!(reader.damage().uncorrectable_blocks, 150);
    assert_eq!(reader.damage().ranges.len(), 128);
    assert!(reader.damage().ranges_omitted);
    // Re-reading cannot inflate counters, including compressed-frame tag lookups.
    reader.seek(SeekFrom::Start(0)).unwrap();
    reader.read_to_end(&mut Vec::new()).unwrap();
    assert_eq!(reader.damage().uncorrectable_blocks, 150);
    for missing in 1..=PARITY {
        let original = wrapped(&data);
        fs::write(&path, &original[..original.len() - missing]).unwrap();
        let mut reader = VolumeReader::open(File::open(&path).unwrap(), true).unwrap();
        let mut recovered = Vec::new();
        reader.read_to_end(&mut recovered).unwrap();
        assert_eq!(recovered, data);
        assert!(reader.damage().truncated);
    }
}
