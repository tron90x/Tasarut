use super::*;

#[test]
fn round_trip_streams_empty_binary_and_compressed_files() {
    let dir = tempfile::tempdir().unwrap();
    for (i, (data, compress)) in [
        (Vec::new(), false),
        ((0..700_000).map(|i| (i % 251) as u8).collect(), false),
        (vec![42; 800_000], true),
        (Vec::new(), true),
    ]
    .into_iter()
    .enumerate()
    {
        let source = dir.path().join(format!("input{i}"));
        let volume = dir.path().join(format!("volume{i}"));
        let output = dir.path().join(format!("output{i}"));
        fs::write(&source, &data).unwrap();
        encrypt(
            &source,
            &volume,
            "a strong test passphrase",
            &EncryptOptions {
                algorithm: CipherAlgorithm::XChaCha20,
                comment: "Azul — description publique 🔑".into(),
                compress,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            inspect(&volume).unwrap().comment,
            "Azul — description publique 🔑"
        );
        decrypt(&volume, &output, "a strong test passphrase", &[]).unwrap();
        assert_eq!(fs::read(output).unwrap(), data);
    }
}

#[test]
fn rejects_wrong_password_tampering_and_truncation_without_output() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("source");
    let volume = dir.path().join("volume");
    let output = dir.path().join("output");
    fs::write(&input, b"private content").unwrap();
    encrypt(
        &input,
        &volume,
        "correct password",
        &EncryptOptions::default(),
    )
    .unwrap();
    assert!(matches!(
        decrypt(&volume, &output, "wrong password", &[]),
        Err(Error::Authentication)
    ));
    assert!(!output.exists());
    let original = fs::read(&volume).unwrap();
    for index in [8, 10, 45, 65, 77, original.len() - 1] {
        let mut altered = original.clone();
        altered[index] ^= 1;
        fs::write(&volume, &altered).unwrap();
        assert!(decrypt(&volume, &output, "correct password", &[]).is_err());
        assert!(!output.exists());
    }
    fs::write(&volume, &original[..original.len() - 4]).unwrap();
    assert!(decrypt(&volume, &output, "correct password", &[]).is_err());
    assert!(!output.exists());
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
}

#[test]
fn public_comments_can_be_changed_without_affecting_authentication() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input");
    let volume = dir.path().join("volume");
    let output = dir.path().join("output");
    fs::write(&input, b"secret").unwrap();
    encrypt(
        &input,
        &volume,
        "password",
        &EncryptOptions {
            comment: "old".into(),
            ..Default::default()
        },
    )
    .unwrap();
    let original = fs::read(&volume).unwrap();
    let mut changed = original[..73].to_vec();
    changed.extend_from_slice(&11u32.to_le_bytes());
    changed.extend_from_slice(b"new comment");
    changed.extend_from_slice(&original[80..]);
    fs::write(&volume, changed).unwrap();
    assert_eq!(inspect(&volume).unwrap().comment, "new comment");
    decrypt(&volume, &output, "password", &[]).unwrap();
    assert_eq!(fs::read(output).unwrap(), b"secret");
}

#[test]
fn keyfiles_are_required_by_contents_and_order_not_name() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    let volume = dir.path().join("volume");
    let key = dir.path().join("key");
    let renamed = dir.path().join("renamed");
    let output = dir.path().join("output");
    fs::write(&source, b"payload").unwrap();
    fs::write(&key, b"keyfile bytes").unwrap();
    encrypt(
        &source,
        &volume,
        "password",
        &EncryptOptions {
            keyfiles: vec![key.clone()],
            ..Default::default()
        },
    )
    .unwrap();
    assert!(matches!(
        decrypt(&volume, &output, "password", &[]),
        Err(Error::Authentication)
    ));
    fs::rename(&key, &renamed).unwrap();
    decrypt(&volume, &output, "password", &[renamed]).unwrap();
}

#[test]
fn never_overwrites_files_and_randomizes_volumes() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    let a = dir.path().join("a");
    let b = dir.path().join("b");
    fs::write(&source, b"original").unwrap();
    encrypt(&source, &a, "password", &EncryptOptions::default()).unwrap();
    encrypt(&source, &b, "password", &EncryptOptions::default()).unwrap();
    assert_ne!(fs::read(&a).unwrap(), fs::read(&b).unwrap());
    assert!(matches!(
        decrypt(&a, &source, "password", &[]),
        Err(Error::OutputExists)
    ));
    assert!(matches!(
        encrypt(&source, &a, "password", &EncryptOptions::default()),
        Err(Error::OutputExists)
    ));
    assert_eq!(fs::read(source).unwrap(), b"original");
}

#[test]
fn recursive_collection_preserves_layout_and_deduplicates() {
    let dir = tempfile::tempdir().unwrap();
    let nested = dir.path().join("documents/nested");
    fs::create_dir_all(&nested).unwrap();
    fs::write(nested.join("report"), "report").unwrap();
    fs::write(dir.path().join("documents/other"), "other").unwrap();
    let root = dir.path().join("documents");
    assert!(collect_inputs(std::slice::from_ref(&root), false).is_err());
    let inputs = collect_inputs(&[root, nested.join("report")], true).unwrap();
    assert_eq!(inputs.len(), 2);
    assert!(inputs
        .iter()
        .any(|f| f.relative_path == Path::new("documents/nested/report")));
}

#[test]
fn malformed_comments_are_bounded_and_password_generator_validates_length() {
    let dir = tempfile::tempdir().unwrap();
    let volume = dir.path().join("volume");
    let mut bytes = vec![0; 150];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[73..77].copy_from_slice(&u32::MAX.to_le_bytes());
    fs::write(&volume, bytes).unwrap();
    assert!(matches!(inspect(&volume), Err(Error::InvalidVolume)));
    assert!(generate_password(15, true).is_err());
    for symbols in [false, true] {
        let password = generate_password(32, symbols).unwrap();
        assert_eq!(password.len(), 32);
        if !symbols {
            assert!(password.chars().all(|c| c.is_ascii_alphanumeric()));
        }
    }
}

pub(super) fn unhex(text: &str) -> Vec<u8> {
    text.trim()
        .as_bytes()
        .chunks_exact(2)
        .map(|bytes| u8::from_str_radix(std::str::from_utf8(bytes).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn reed_solomon_recovers_header_ciphertext_and_tag_for_both_suites() {
    use recovery::{BLOCK, DATA};
    let dir = tempfile::tempdir().unwrap();
    for (index, (paranoid, compress, data)) in [
        (false, false, Vec::new()),
        (
            false,
            false,
            (0..BUFFER_SIZE + 7).map(|i| (i % 251) as u8).collect(),
        ),
        (false, true, vec![42; 800_000]),
        (true, false, (0..1000).map(|i| (i % 251) as u8).collect()),
        (true, true, Vec::new()),
    ]
    .into_iter()
    .enumerate()
    {
        let source = dir.path().join(format!("source-{index}"));
        let volume = dir.path().join(format!("volume-{index}"));
        let output = dir.path().join(format!("output-{index}"));
        let key = dir.path().join(format!("key-{index}"));
        fs::write(&key, b"RS keyfile").unwrap();
        fs::write(&source, &data).unwrap();
        encrypt(
            &source,
            &volume,
            "RS password",
            &EncryptOptions {
                algorithm: CipherAlgorithm::XChaCha20,
                paranoid,
                compress,
                reed_solomon: true,
                comment: "Azul — public".into(),
                keyfiles: vec![key.clone()],
                chunk_size: None,
                deniability: false,
                revocable: false,
            },
        )
        .unwrap();
        let original = fs::read(&volume).unwrap();
        let info = inspect(&volume).unwrap();
        assert!(info.reed_solomon);
        assert_eq!(info.format_version, 3);
        assert_eq!(info.paranoid, paranoid);
        assert_eq!(info.compressed, compress);
        let mut damaged = original.clone();
        // Four damaged bytes in every block, including descriptor, crypto header and tag.
        for block in damaged.chunks_exact_mut(BLOCK) {
            for (offset, position) in [0, 7, DATA - 1, BLOCK - 1].into_iter().enumerate() {
                block[position] ^= (offset + 1) as u8;
            }
        }
        fs::write(&volume, &damaged).unwrap();
        assert_eq!(inspect(&volume).unwrap().comment, "Azul — public");
        assert!(collect_inputs(std::slice::from_ref(&volume), false).unwrap()[0].volume);
        let report = decrypt_with_report(&volume, &output, "RS password", &[key]).unwrap();
        assert!(report.reed_solomon);
        assert_eq!(report.corrected_blocks, (original.len() / BLOCK) as u64);
        assert_eq!(report.corrected_bytes, report.corrected_blocks * 4);
        assert_eq!(fs::read(&output).unwrap(), data);
        assert_eq!(fs::read(&volume).unwrap(), damaged); // Never silently alter the archived source.
    }
}

#[test]
fn reed_solomon_still_requires_authentication_and_preserves_public_comments() {
    use recovery::{BLOCK, DATA};
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    let volume = dir.path().join("volume");
    let output = dir.path().join("output");
    fs::write(&source, vec![42; 500]).unwrap();
    encrypt(
        &source,
        &volume,
        "password",
        &EncryptOptions {
            reed_solomon: true,
            comment: "old".into(),
            ..Default::default()
        },
    )
    .unwrap();
    let original = fs::read(&volume).unwrap();
    assert!(matches!(
        decrypt(&volume, &output, "wrong", &[]),
        Err(Error::Authentication)
    ));
    assert!(!output.exists());
    for length in [original.len() - 1, original.len() - BLOCK] {
        fs::write(&volume, &original[..length]).unwrap();
        assert!(collect_inputs(std::slice::from_ref(&volume), false).unwrap()[0].volume);
        assert!(decrypt(&volume, &output, "password", &[]).is_err());
        assert!(!output.exists());
    }
    let mut damaged = original.clone();
    for index in 0..5 {
        damaged[2 * BLOCK + index] ^= (index + 1) as u8;
    }
    fs::write(&volume, damaged).unwrap();
    assert!(decrypt(&volume, &output, "password", &[]).is_err());
    assert!(!output.exists());
    // An attacker can recompute public parity; valid RS is never authentication.
    let mut tampered = original.clone();
    let encoder = reed_solomon::Encoder::new(8);
    let mut block: [u8; DATA] = tampered[2 * BLOCK..2 * BLOCK + DATA].try_into().unwrap();
    block[0] ^= 1; // Ciphertext, not public comment.
    tampered[2 * BLOCK..3 * BLOCK].copy_from_slice(&encoder.encode(&block));
    fs::write(&volume, tampered).unwrap();
    assert!(matches!(
        decrypt(&volume, &output, "password", &[]),
        Err(Error::Authentication)
    ));
    assert!(!output.exists());
    // Decode and re-encode after a public comment modification, without using any secret.
    fs::write(&volume, &original).unwrap();
    let mut inner = Vec::new();
    recovery::VolumeReader::new(File::open(&volume).unwrap())
        .unwrap()
        .read_to_end(&mut inner)
        .unwrap();
    inner[77..80].copy_from_slice(b"new");
    let mut encoded = File::create(&volume).unwrap();
    let mut writer = recovery::ProtectedWriter::new(&mut encoded).unwrap();
    writer.write_all(&inner).unwrap();
    writer.finish().unwrap();
    assert_eq!(inspect(&volume).unwrap().comment, "new");
    let report = decrypt_with_report(&volume, &output, "password", &[]).unwrap();
    assert_eq!(report.corrected_bytes, 0);
    assert_eq!(fs::read(&output).unwrap(), vec![42; 500]);
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 3);
}

#[test]
fn independent_vectors_match_encryption_and_decryption_for_both_formats() {
    // Generated outside Rust with libargon2, libsodium, libgcrypt, Python hashlib/hmac.
    let dir = tempfile::tempdir().unwrap();
    let plaintext = b"Individual file encryption\0\x01\x02\xff\nAzul!";
    let password = "Tasarut reference password";
    let key1 = dir.path().join("key1");
    let key2 = dir.path().join("key2");
    fs::write(&key1, b"first keyfile").unwrap();
    fs::write(&key2, b"second keyfile").unwrap();
    for (paranoid, text) in [
        (false, include_str!("../test-vectors/v1-standard.hex")),
        (true, include_str!("../test-vectors/v2-paranoid.hex")),
    ] {
        let expected = unhex(text);
        let volume = dir.path().join(format!("reference-{paranoid}"));
        let output = dir.path().join(format!("decrypted-{paranoid}"));
        fs::write(&volume, &expected).unwrap();
        let header = Header::read(&mut File::open(&volume).unwrap()).unwrap();
        let keyfiles = if paranoid {
            vec![key1.clone(), key2.clone()]
        } else {
            vec![]
        };
        let keys = derive_keys(
            password,
            &keyfiles,
            &header.salt,
            header.suite,
            &Tracker::default(),
        )
        .unwrap();
        let mut cipher = keys
            .cipher(&header.nonce, header.block_parameter.as_ref())
            .unwrap();
        let mut mac = keys.mac(&header.authenticated_bytes()).unwrap();
        let mut encrypted = NamedTempFile::new_in(dir.path()).unwrap();
        header.write(&mut encrypted).unwrap();
        let mut writer = EncryptWriter {
            output: &mut encrypted,
            cipher: &mut cipher,
            mac: &mut mac,
        };
        // Deliberately split across non-block-aligned writes; stream state must be continuous.
        for piece in plaintext.chunks(7) {
            writer.write_all(piece).unwrap();
        }
        encrypted.write_all(&mac.finalize()).unwrap();
        assert_eq!(fs::read(encrypted.path()).unwrap(), expected);
        let info = inspect(&volume).unwrap();
        assert_eq!(info.paranoid, paranoid);
        assert_eq!(info.format_version, if paranoid { 2 } else { 1 });
        decrypt(&volume, &output, password, &keyfiles).unwrap();
        assert_eq!(fs::read(&output).unwrap(), plaintext);
        assert!(collect_inputs(&[volume], false).unwrap()[0].volume);
    }
}

#[test]
fn paranoid_round_trip_covers_empty_compressed_and_multi_buffer_inputs() {
    let dir = tempfile::tempdir().unwrap();
    for (index, (data, compress)) in [
        (Vec::new(), false),
        (Vec::new(), true),
        (
            (0..BUFFER_SIZE + 17).map(|i| (i % 251) as u8).collect(),
            false,
        ),
        (vec![42; BUFFER_SIZE * 3 + 1], true),
    ]
    .into_iter()
    .enumerate()
    {
        let source = dir.path().join(format!("source-{index}"));
        let volume = dir.path().join(format!("volume-{index}"));
        let output = dir.path().join(format!("output-{index}"));
        fs::write(&source, &data).unwrap();
        encrypt(
            &source,
            &volume,
            "paranoid password",
            &EncryptOptions {
                paranoid: true,
                compress,
                comment: "Azul".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let info = inspect(&volume).unwrap();
        assert!(info.paranoid);
        assert_eq!(info.compressed, compress);
        assert_eq!(info.original_size, data.len() as u64);
        assert_eq!(&fs::read(&volume).unwrap()[..8], PARANOID_MAGIC);
        decrypt(&volume, &output, "paranoid password", &[]).unwrap();
        assert_eq!(fs::read(&output).unwrap(), data);
    }
}

#[test]
fn paranoid_rejects_tampering_wrong_secrets_and_downgrades_but_allows_public_comments() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    let volume = dir.path().join("volume");
    let output = dir.path().join("output");
    let key1 = dir.path().join("key1");
    let key2 = dir.path().join("key2");
    fs::write(&source, b"private payload").unwrap();
    fs::write(&key1, b"first").unwrap();
    fs::write(&key2, b"second").unwrap();
    let keyfiles = [key1.clone(), key2.clone()];
    encrypt(
        &source,
        &volume,
        "password",
        &EncryptOptions {
            paranoid: true,
            comment: "old".into(),
            keyfiles: keyfiles.to_vec(),
            ..Default::default()
        },
    )
    .unwrap();
    let original = fs::read(&volume).unwrap();
    for (password, keys) in [("wrong", keyfiles.to_vec()), ("password", vec![key2, key1])] {
        assert!(matches!(
            decrypt(&volume, &output, password, &keys),
            Err(Error::Authentication)
        ));
        assert!(!output.exists());
    }
    // Version, suite, flags, salt, nonce, Serpent IV, size, ciphertext, tag.
    for index in [7, 8, 9, 11, 43, 66, 82, 97, original.len() - 1] {
        let mut changed = original.clone();
        changed[index] ^= 1;
        fs::write(&volume, changed).unwrap();
        assert!(
            decrypt(&volume, &output, "password", &keyfiles).is_err(),
            "index {index}"
        );
        assert!(!output.exists());
    }
    fs::write(&volume, &original[..original.len() - 1]).unwrap();
    assert!(decrypt(&volume, &output, "password", &keyfiles).is_err());
    assert!(!output.exists());
    // Public comment and its length remain outside the HMAC in paranoid mode too.
    let mut changed = original[..90].to_vec();
    changed.extend_from_slice(&11u32.to_le_bytes());
    changed.extend_from_slice(b"new comment");
    changed.extend_from_slice(&original[97..]);
    fs::write(&volume, changed).unwrap();
    assert_eq!(inspect(&volume).unwrap().comment, "new comment");
    decrypt(&volume, &output, "password", &keyfiles).unwrap();
    assert_eq!(fs::read(&output).unwrap(), b"private payload");
    assert!(matches!(
        decrypt(&volume, &output, "password", &keyfiles),
        Err(Error::OutputExists)
    ));
    // Failed decryptions did not leave hidden temporary plaintext files behind.
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 5);
}
