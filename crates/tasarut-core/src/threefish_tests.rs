use super::*;
use threefish::{cipher::BlockCipherEncrypt, Threefish1024};

fn unhex(text: &str) -> Vec<u8> {
    let text: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
fn plaintext() -> Vec<u8> {
    (0..=255).cycle().take(512).chain(*b"Azul!").collect()
}
fn keyfiles(dir: &Path) -> Vec<PathBuf> {
    let keys = vec![dir.join("key1"), dir.join("key2")];
    fs::write(&keys[0], b"first Threefish keyfile").unwrap();
    fs::write(&keys[1], b"second Threefish keyfile").unwrap();
    keys
}

#[test]
fn published_threefish1024_kat_and_stream_boundaries() {
    let cipher = Threefish1024::new_with_tweak(&[0; 128], &[0; 16]);
    let mut block = [0u8; 128].into();
    cipher.encrypt_block(&mut block);
    let expected = unhex(
        "F05C3D0A3D05B304F785DDC7D1E036015C8AA76E2F217B06C6E1544C0BC1A90D
        F0ACCB9473C24E0FD54FEA68057F43329CB454761D6DF5CF7B2E9B3614FBD5A2
        0B2E4760B40603540D82EABC5482C171C832AFBE68406BC39500367A592943FA
        9A5B4A43286CA3C4CF46104B443143D560A4B230488311DF4FEEF7E1DFE8391E",
    );
    assert_eq!(block.as_slice(), expected);
    let keys = Keys {
        suite: Suite::Threefish,
        bytes: Zeroizing::new(vec![0; 192]),
    };
    let mut stream = keys.cipher(&[0; 24], Some(&[0; 16])).unwrap();
    let mut bytes = vec![0; 513];
    for chunk in bytes.chunks_mut(7) {
        stream.encrypt(chunk).unwrap();
    }
    assert_eq!(&bytes[..128], &expected);
    let mut next = [0u8; 128];
    next[127] = 1;
    let mut next = next.into();
    cipher.encrypt_block(&mut next);
    assert_eq!(&bytes[128..256], next.as_slice());
    let mut decryptor = keys.cipher(&[0; 24], Some(&[0; 16])).unwrap();
    for chunk in bytes.chunks_mut(129) {
        decryptor.decrypt(chunk).unwrap();
    }
    assert_eq!(bytes, vec![0; 513]);
}

#[test]
fn independent_v5_vector_matches_full_encryption_and_decryption() {
    let dir = tempfile::tempdir().unwrap();
    let volume = dir.path().join("reference");
    let output = dir.path().join("output");
    let expected = unhex(include_str!("../test-vectors/v5-threefish.hex"));
    fs::write(&volume, &expected).unwrap();
    let files = keyfiles(dir.path());
    let header = Header::read(&mut File::open(&volume).unwrap()).unwrap();
    assert_eq!(header.suite, Suite::Threefish);
    let keys = derive_keys(
        "Tasarut Threefish reference password",
        &files,
        &header.salt,
        header.suite,
        &Tracker::default(),
    )
    .unwrap();
    let mut bytes = Vec::new();
    let mut cipher = keys
        .cipher(&header.nonce, header.block_parameter.as_ref())
        .unwrap();
    let mut mac = keys.mac(&header.authenticated_bytes()).unwrap();
    header.write(&mut bytes).unwrap();
    let mut writer = EncryptWriter {
        output: &mut bytes,
        cipher: &mut cipher,
        mac: &mut mac,
    };
    for piece in plaintext().chunks(7) {
        writer.write_all(piece).unwrap();
    }
    bytes.extend_from_slice(&mac.finalize());
    assert_eq!(bytes, expected);
    let info = inspect(&volume).unwrap();
    assert_eq!(info.algorithm, CipherAlgorithm::Threefish1024);
    assert_eq!(info.format_version, 5);
    assert!(!info.paranoid);
    assert!(collect_inputs(std::slice::from_ref(&volume), false).unwrap()[0].volume);
    decrypt(
        &volume,
        &output,
        "Tasarut Threefish reference password",
        &files,
    )
    .unwrap();
    assert_eq!(fs::read(output).unwrap(), plaintext());
}

#[test]
fn threefish_round_trips_empty_unaligned_and_all_transport_wrappers() {
    let dir = tempfile::tempdir().unwrap();
    for (i, (length, compress, rs, chunks, opaque)) in [
        (0, false, false, false, false),
        (1, false, false, false, false),
        (127, false, false, false, false),
        (128, false, false, false, false),
        (129, false, false, false, false),
        (0, true, true, false, false),
        (BUFFER_SIZE * 2 + 17, true, true, false, false),
        (4099, false, true, true, false),
        (3001, true, true, false, true),
    ]
    .into_iter()
    .enumerate()
    {
        let source = dir.path().join(format!("source{i}"));
        let volume = dir.path().join(format!("volume{i}"));
        let output = dir.path().join(format!("out{i}"));
        let data: Vec<u8> = (0..=255).cycle().take(length).collect();
        fs::write(&source, &data).unwrap();
        let options = EncryptOptions {
            algorithm: CipherAlgorithm::Threefish1024,
            compress,
            reed_solomon: rs,
            chunk_size: chunks.then_some(1024),
            deniability: opaque,
            ..Default::default()
        };
        encrypt(&source, &volume, "password", &options).unwrap();
        if opaque {
            decrypt_deniable(&volume, &output, "password", &[]).unwrap();
        } else {
            let info = inspect(&volume).unwrap();
            assert_eq!(info.algorithm, CipherAlgorithm::Threefish1024);
            assert_eq!(info.reed_solomon, rs);
            assert_eq!(info.format_version, if rs { 3 } else { 5 });
            decrypt(&volume, &output, "password", &[]).unwrap();
        }
        assert_eq!(fs::read(&output).unwrap(), data);
        assert_eq!(fs::read(&source).unwrap(), data);
        assert!(encrypt(&source, &volume, "password", &options).is_err());
    }
}

#[test]
fn threefish_refuses_corruption_wrong_secrets_and_invalid_suites_without_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let original = unhex(include_str!("../test-vectors/v5-threefish.hex"));
    let files = keyfiles(dir.path());
    let volume = dir.path().join("volume");
    let output = dir.path().join("output");
    let password = "Tasarut Threefish reference password";
    for at in [0, 8, 9, 10, 42, 66, 82, 140, original.len() - 1] {
        let mut bytes = original.clone();
        bytes[at] ^= if at == 9 { 0x80 } else { 1 };
        fs::write(&volume, bytes).unwrap();
        assert!(
            decrypt(&volume, &output, password, &files).is_err(),
            "offset {at}"
        );
        assert!(!output.exists());
    }
    fs::write(&volume, &original).unwrap();
    assert!(decrypt(&volume, &output, "wrong password", &files).is_err());
    assert!(decrypt(
        &volume,
        &output,
        password,
        &[files[1].clone(), files[0].clone()]
    )
    .is_err());
    assert!(!output.exists());
    fs::write(&volume, &original[..original.len() - 1]).unwrap();
    assert!(decrypt(&volume, &output, password, &files).is_err());
    assert!(!output.exists());
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 3);
}

#[test]
fn threefish_cancellation_and_incompatible_cascade_do_not_publish() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    let output = dir.path().join("output");
    fs::write(&source, vec![42; BUFFER_SIZE * 2 + 1]).unwrap();
    let options = EncryptOptions {
        algorithm: CipherAlgorithm::Threefish1024,
        ..Default::default()
    };
    let token = CancellationToken::default();
    let mut progress = |update: ByteProgress| {
        if update.phase == ProgressPhase::Encrypting && update.processed_bytes > 0 {
            token.cancel();
        }
    };
    let result = encrypt_with_control(
        &source,
        &output,
        "password",
        &options,
        &mut OperationControl::new(&token, &mut progress),
    );
    assert!(matches!(result, Err(Error::Cancelled)));
    assert!(!output.exists());
    assert!(matches!(
        encrypt(
            &source,
            &output,
            "password",
            &EncryptOptions {
                paranoid: true,
                ..options
            }
        ),
        Err(Error::CipherOptions)
    ));
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn threefish_forced_recovery_is_still_explicitly_unauthenticated() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    let volume = dir.path().join("volume");
    let output = dir.path().join("recovered");
    fs::write(&source, plaintext()).unwrap();
    encrypt(
        &source,
        &volume,
        "password",
        &EncryptOptions {
            algorithm: CipherAlgorithm::Threefish1024,
            ..Default::default()
        },
    )
    .unwrap();
    let mut bytes = fs::read(&volume).unwrap();
    bytes.pop();
    fs::write(&volume, bytes).unwrap();
    let report =
        force_decrypt(&volume, &output, "password", &[], &ForceOptions::default()).unwrap();
    assert!(!report.authenticated);
    assert_eq!(report.mac_status, MacStatus::Missing);
    assert_eq!(fs::read(output).unwrap(), plaintext());
}
