use super::*;
use crate::{decrypt, encrypt, EncryptOptions};
use std::fs;

fn options(limit: u64) -> ForceOptions {
    ForceOptions {
        max_output_bytes: limit,
    }
}
fn random_bytes(size: usize) -> Vec<u8> {
    let mut value = 0xabc123u32;
    (0..size)
        .map(|_| {
            value ^= value << 13;
            value ^= value >> 17;
            value ^= value << 5;
            value as u8
        })
        .collect()
}

#[test]
fn forced_path_reports_mac_without_certifying_plain_compressed_and_paranoid_outputs() {
    let dir = tempfile::tempdir().unwrap();
    for (index, (paranoid, compress, rs, data)) in [
        (false, false, false, Vec::new()),
        (false, true, false, Vec::new()),
        (false, true, true, random_bytes(300_000)),
        (true, false, true, random_bytes(1024)),
        (true, true, false, vec![42; 900_000]),
    ]
    .into_iter()
    .enumerate()
    {
        let source = dir.path().join(format!("source{index}"));
        let volume = dir.path().join(format!("volume{index}"));
        let output = dir.path().join(format!("output{index}"));
        fs::write(&source, &data).unwrap();
        encrypt(
            &source,
            &volume,
            "password",
            &EncryptOptions {
                paranoid,
                compress,
                reed_solomon: rs,
                ..Default::default()
            },
        )
        .unwrap();
        let report =
            force_decrypt(&volume, &output, "password", &[], &ForceOptions::default()).unwrap();
        assert!(!report.authenticated);
        assert_eq!(report.mac_status, MacStatus::Valid);
        assert!(!report.partial);
        assert!(!report.decompression_failed);
        assert_eq!(report.repair.reed_solomon, rs);
        assert_eq!(report.recovered_bytes, data.len() as u64);
        assert_eq!(fs::read(output).unwrap(), data);
    }
}

#[test]
fn force_keeps_uncompressed_data_with_invalid_mac_and_does_not_accept_it_normally() {
    let dir = tempfile::tempdir().unwrap();
    for paranoid in [false, true] {
        let source = dir.path().join(format!("source{paranoid}"));
        let volume = dir.path().join(format!("volume{paranoid}"));
        let output = dir.path().join(format!("output{paranoid}"));
        let key = dir.path().join(format!("key{paranoid}"));
        let data = random_bytes(1000);
        fs::write(&source, &data).unwrap();
        fs::write(&key, b"recovery keyfile").unwrap();
        encrypt(
            &source,
            &volume,
            "password",
            &EncryptOptions {
                paranoid,
                keyfiles: vec![key.clone()],
                ..Default::default()
            },
        )
        .unwrap();
        let mut original = fs::read(&volume).unwrap();
        let start = if paranoid { 94 } else { 77 };
        original[start + 130] ^= 1;
        fs::write(&volume, &original).unwrap();
        assert!(decrypt(&volume, &output, "password", std::slice::from_ref(&key)).is_err());
        assert!(!output.exists());
        let report = force_decrypt(
            &volume,
            &output,
            "password",
            std::slice::from_ref(&key),
            &ForceOptions::default(),
        )
        .unwrap();
        assert_eq!(report.mac_status, MacStatus::Invalid);
        assert!(!report.authenticated);
        let mut expected = data.clone();
        expected[130] ^= 1;
        assert_eq!(fs::read(&output).unwrap(), expected);
        let wrong_output = dir.path().join(format!("wrong{paranoid}"));
        let wrong = force_decrypt(
            &volume,
            &wrong_output,
            "wrong",
            &[],
            &ForceOptions::default(),
        )
        .unwrap();
        assert_eq!(wrong.mac_status, MacStatus::Invalid);
        assert_ne!(fs::read(wrong_output).unwrap(), expected);
        assert_eq!(fs::read(&volume).unwrap(), original);
    }
}

#[test]
fn plain_recovery_handles_missing_tags_truncated_data_and_output_caps() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    let volume = dir.path().join("volume");
    let data = random_bytes(500);
    fs::write(&source, &data).unwrap();
    encrypt(&source, &volume, "password", &EncryptOptions::default()).unwrap();
    let original = fs::read(&volume).unwrap();
    for (index, length) in [original.len() - 17, original.len() - 64, 77 + 237]
        .into_iter()
        .enumerate()
    {
        fs::write(&volume, &original[..length]).unwrap();
        let output = dir.path().join(format!("output{index}"));
        assert!(decrypt(&volume, &output, "password", &[]).is_err());
        let report =
            force_decrypt(&volume, &output, "password", &[], &ForceOptions::default()).unwrap();
        let expected = (length - 77).min(data.len());
        assert_eq!(report.mac_status, MacStatus::Missing);
        assert_eq!(report.partial, expected < data.len());
        assert_eq!(fs::read(output).unwrap(), data[..expected]);
    }
    fs::write(&volume, &original).unwrap();
    let output = dir.path().join("limited");
    let report = force_decrypt(&volume, &output, "password", &[], &options(123)).unwrap();
    assert!(report.limit_reached && report.partial);
    assert_eq!(report.mac_status, MacStatus::NotChecked);
    assert_eq!(fs::read(output).unwrap(), data[..123]);
    assert!(matches!(
        force_decrypt(&volume, &source, "password", &[], &ForceOptions::default()),
        Err(Error::OutputExists)
    ));
    assert!(matches!(
        force_decrypt(
            &volume,
            &dir.path().join("bad"),
            "password",
            &[],
            &options(0)
        ),
        Err(Error::InvalidRecoveryLimit)
    ));
    assert_eq!(fs::read(source).unwrap(), data);
}

#[test]
fn rs_recovery_preserves_offsets_of_raw_blocks_and_handles_missing_tail_bytes() {
    use crate::recovery::{BLOCK, DATA};
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    let volume = dir.path().join("volume");
    let data = random_bytes(1200);
    fs::write(&source, &data).unwrap();
    encrypt(
        &source,
        &volume,
        "password",
        &EncryptOptions {
            reed_solomon: true,
            ..Default::default()
        },
    )
    .unwrap();
    let original = fs::read(&volume).unwrap();
    let mut damaged = original.clone();
    for offset in 0..5 {
        damaged[3 * BLOCK + offset] ^= offset as u8 + 1;
    }
    let output = dir.path().join("damaged");
    fs::write(&volume, &damaged).unwrap();
    assert!(decrypt(&volume, &output, "password", &[]).is_err());
    let report =
        force_decrypt(&volume, &output, "password", &[], &ForceOptions::default()).unwrap();
    assert_eq!(report.damage.uncorrectable_blocks, 1);
    assert_eq!(report.damage.ranges[0].offset, 2 * DATA as u64);
    assert_eq!(report.mac_status, MacStatus::Invalid);
    let mut expected = data.clone();
    for offset in 0..5 {
        expected[2 * DATA - 77 + offset] ^= offset as u8 + 1;
    }
    assert_eq!(fs::read(output).unwrap(), expected);
    // Recover a complete payload even if the final parity bytes are absent.
    fs::write(&volume, &original[..original.len() - 4]).unwrap();
    let output = dir.path().join("parity-missing");
    let report =
        force_decrypt(&volume, &output, "password", &[], &ForceOptions::default()).unwrap();
    assert!(report.damage.truncated);
    assert_eq!(report.mac_status, MacStatus::Valid);
    assert!(!report.authenticated);
    assert_eq!(fs::read(output).unwrap(), data);
    // Truncate inside ciphertext rather than manufacturing zero ciphertext for the missing tail.
    let physical_length = 5 * BLOCK + 41;
    fs::write(&volume, &original[..physical_length]).unwrap();
    let output = dir.path().join("tail-missing");
    let report =
        force_decrypt(&volume, &output, "password", &[], &ForceOptions::default()).unwrap();
    let available_plaintext = 4 * DATA + 41 - 77;
    assert!(report.partial && report.damage.truncated);
    assert!(report.damage.missing_bytes > 0);
    assert_eq!(fs::read(output).unwrap(), data[..available_plaintext]);
}

#[test]
fn compressed_recovery_keeps_a_prefix_and_stops_at_a_limit_without_guessing_frame_boundaries() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    let volume = dir.path().join("volume");
    let data = random_bytes(800_000);
    fs::write(&source, &data).unwrap();
    encrypt(
        &source,
        &volume,
        "password",
        &EncryptOptions {
            compress: true,
            ..Default::default()
        },
    )
    .unwrap();
    let original = fs::read(&volume).unwrap();
    // The entire compressed frame is present; its authentication tag is not.
    fs::write(&volume, &original[..original.len() - 64]).unwrap();
    let output = dir.path().join("tag-missing");
    let report =
        force_decrypt(&volume, &output, "password", &[], &ForceOptions::default()).unwrap();
    assert_eq!(report.mac_status, MacStatus::Missing);
    assert!(!report.decompression_failed);
    assert_eq!(fs::read(output).unwrap(), data);
    // A truncated compressed frame can still yield an earlier, complete decompressed prefix.
    fs::write(&volume, &original[..original.len() / 2]).unwrap();
    let output = dir.path().join("prefix");
    let report =
        force_decrypt(&volume, &output, "password", &[], &ForceOptions::default()).unwrap();
    let prefix = fs::read(output).unwrap();
    assert!(report.partial && report.decompression_failed);
    assert!(!prefix.is_empty() && prefix.len() < data.len());
    assert_eq!(prefix, data[..prefix.len()]);
    fs::write(&volume, &original).unwrap();
    let output = dir.path().join("limited");
    let report = force_decrypt(&volume, &output, "password", &[], &options(8192)).unwrap();
    assert!(report.partial && report.limit_reached);
    assert_eq!(fs::read(output).unwrap(), data[..8192]);
    let no_output = dir.path().join("wrong-password");
    assert!(matches!(
        force_decrypt(&volume, &no_output, "wrong", &[], &ForceOptions::default()),
        Err(Error::NothingRecovered)
    ));
    assert!(!no_output.exists());
    let truncated = dir.path().join("header-only");
    fs::write(&truncated, &original[..30]).unwrap();
    assert!(force_decrypt(
        &truncated,
        &no_output,
        "password",
        &[],
        &ForceOptions::default()
    )
    .is_err());
    assert!(!no_output.exists());
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 6);
}

#[test]
fn paranoid_compressed_rs_tail_recovery_preserves_the_decodable_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    let volume = dir.path().join("volume");
    let output = dir.path().join("prefix.recovered");
    let data = random_bytes(700_000);
    fs::write(&source, &data).unwrap();
    encrypt(
        &source,
        &volume,
        "password",
        &EncryptOptions {
            paranoid: true,
            compress: true,
            reed_solomon: true,
            ..Default::default()
        },
    )
    .unwrap();
    let original = fs::read(&volume).unwrap();
    fs::write(&volume, &original[..original.len() / 2 + 17]).unwrap();
    assert!(decrypt(&volume, &output, "password", &[]).is_err());
    let report =
        force_decrypt(&volume, &output, "password", &[], &ForceOptions::default()).unwrap();
    assert!(report.partial && report.decompression_failed && report.damage.truncated);
    assert!(!report.authenticated);
    let prefix = fs::read(&output).unwrap();
    assert!(!prefix.is_empty() && prefix.len() < data.len());
    assert_eq!(prefix, data[..prefix.len()]);
}
