use super::*;
use crate::{collect_inputs, decrypt, force_decrypt, inspect, ForceOptions};

#[test]
fn round_trips_all_profiles_and_collects_a_set_only_once() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    let key = dir.path().join("key");
    fs::write(&key, b"extra secret").unwrap();
    for (index, (paranoid, reed_solomon, compress, empty)) in [
        (false, false, false, false),
        (false, true, true, false),
        (true, false, true, true),
        (true, true, false, false),
    ]
    .into_iter()
    .enumerate()
    {
        let data: Vec<u8> = if empty {
            vec![]
        } else {
            (0..330_000).map(|n| (n % 251) as u8).collect()
        };
        fs::write(&source, &data).unwrap();
        let set = dir.path().join(format!("file{index}.tasarut.parts"));
        let output = dir.path().join(format!("output{index}"));
        let options = EncryptOptions {
            algorithm: crate::CipherAlgorithm::XChaCha20,
            paranoid,
            reed_solomon,
            compress,
            comment: "Public — Azul".into(),
            chunk_size: Some(1024),
            deniability: false,
            revocable: false,
            keyfiles: vec![key.clone()],
        };
        crate::encrypt(&source, &set, "password", &options).unwrap();
        let info = inspect(&set.join(MANIFEST)).unwrap();
        assert_eq!(info.comment, "Public — Azul");
        assert_eq!(info.paranoid, paranoid);
        assert_eq!(info.reed_solomon, reed_solomon);
        let count = info.chunk_count.unwrap();
        assert!(count > 0);
        assert_eq!(fs::read_dir(&set).unwrap().count(), count as usize + 1);
        for i in 0..count {
            assert!(fs::metadata(set.join(part_name(i))).unwrap().len() <= 1024);
        }
        let collected = collect_inputs(
            &[set.clone(), set.join(MANIFEST), set.join(part_name(0))],
            false,
        )
        .unwrap();
        assert_eq!(collected.len(), 1);
        assert_eq!(collected[0].path, set);
        assert!(collected[0].volume);
        decrypt(
            &set.join(part_name(count - 1)),
            &output,
            "password",
            std::slice::from_ref(&key),
        )
        .unwrap();
        assert_eq!(fs::read(&output).unwrap(), data);
        let recovered = dir.path().join(format!("recovered{index}"));
        let report = force_decrypt(
            &set,
            &recovered,
            "password",
            std::slice::from_ref(&key),
            &ForceOptions::default(),
        )
        .unwrap();
        assert!(!report.authenticated);
        assert_eq!(fs::read(recovered).unwrap(), data);
    }
    let collected = collect_inputs(&[dir.path().to_path_buf()], true).unwrap();
    assert_eq!(collected.iter().filter(|f| f.path.is_dir()).count(), 4);
    assert!(!collected
        .iter()
        .any(|f| f.relative_path.to_string_lossy().ends_with(".part")));
}

#[test]
fn rejects_missing_mixed_truncated_and_rehashed_parts_without_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    let set = dir.path().join("source.tasarut.parts");
    let other = dir.path().join("other.tasarut.parts");
    let output = dir.path().join("output");
    fs::write(&source, vec![47; 4096]).unwrap();
    let options = EncryptOptions {
        chunk_size: Some(1024),
        ..Default::default()
    };
    crate::encrypt(&source, &set, "password", &options).unwrap();
    crate::encrypt(&source, &other, "password", &options).unwrap();
    let part = set.join(part_name(1));
    let bytes = fs::read(&part).unwrap();
    let manifest_path = set.join(MANIFEST);
    let manifest = fs::read(&manifest_path).unwrap();
    assert!(matches!(
        decrypt(&set, &output, "wrong", &[]),
        Err(Error::Authentication)
    ));
    fs::remove_file(&part).unwrap();
    assert!(matches!(
        decrypt(&set, &output, "password", &[]),
        Err(Error::ChunkMissing)
    ));
    for altered in [
        bytes[..bytes.len() - 1].to_vec(),
        fs::read(other.join(part_name(1))).unwrap(),
    ] {
        fs::write(&part, altered).unwrap();
        assert!(matches!(
            decrypt(&set, &output, "password", &[]),
            Err(Error::ChunkDamaged)
        ));
        assert!(!output.exists());
    }
    // An attacker can replace the unkeyed digest, but cannot forge the manifest MAC.
    let mut altered = bytes.clone();
    altered[13] ^= 1;
    fs::write(&part, &altered).unwrap();
    let mut forged = manifest.clone();
    forged[FIXED + 64..FIXED + 128].copy_from_slice(&Blake2b512::digest(&altered));
    fs::write(&manifest_path, forged).unwrap();
    assert!(matches!(
        decrypt(&set, &output, "password", &[]),
        Err(Error::Authentication)
    ));
    assert!(!output.exists());
    fs::write(&part, bytes).unwrap();
    fs::write(&manifest_path, &manifest).unwrap();
    let mut forged = manifest.clone();
    forged[16..24].copy_from_slice(&0u64.to_le_bytes());
    fs::write(&manifest_path, forged).unwrap();
    assert!(matches!(
        decrypt(&set, &output, "password", &[]),
        Err(Error::InvalidChunkManifest)
    ));
    fs::write(&manifest_path, &manifest[..manifest.len() - 1]).unwrap();
    assert!(matches!(inspect(&set), Err(Error::InvalidChunkManifest)));
    fs::remove_file(&manifest_path).unwrap();
    assert!(matches!(
        decrypt(&set, &output, "password", &[]),
        Err(Error::InvalidChunkManifest)
    ));
    assert!(!output.exists());
}

#[test]
fn refuses_collisions_symlinks_and_cleans_up_failed_encryption() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    let set = dir.path().join("source.tasarut.parts");
    fs::write(&source, b"secret").unwrap();
    let options = EncryptOptions {
        chunk_size: Some(1024),
        ..Default::default()
    };
    assert!(matches!(
        crate::encrypt(&source, &set, "", &options),
        Err(Error::EmptyPassword)
    ));
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    fs::create_dir(&set).unwrap();
    assert!(matches!(
        crate::encrypt(&source, &set, "password", &options),
        Err(Error::OutputExists)
    ));
    assert_eq!(fs::read_dir(&set).unwrap().count(), 0);
    fs::remove_dir(&set).unwrap();
    crate::encrypt(&source, &set, "password", &options).unwrap();
    let output = dir.path().join("output");
    fs::write(&output, b"do not overwrite").unwrap();
    assert!(matches!(
        decrypt(&set, &output, "password", &[]),
        Err(Error::OutputExists)
    ));
    assert_eq!(fs::read(&output).unwrap(), b"do not overwrite");
    #[cfg(unix)]
    {
        let part = set.join(part_name(0));
        fs::remove_file(&part).unwrap();
        std::os::unix::fs::symlink(&source, &part).unwrap();
        assert!(matches!(inspect(&set), Err(Error::InvalidInput)));
    }
    assert!(matches!(count(1, 0), Err(Error::InvalidChunkSize)));
    assert!(matches!(
        count(1024 * (MAX_PARTS + 1), 1024),
        Err(Error::InvalidChunkSize)
    ));
}
