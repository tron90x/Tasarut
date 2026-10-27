use super::*;
use crate::{collect_inputs, decrypt, encrypt, force_decrypt, inspect, ForceOptions};
use std::fs;

#[test]
fn matches_independent_libargon2_libsodium_blake2b_vector() {
    let hex = include_str!("../../test-vectors/deniable-v1.hex").trim();
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    let dir = tempfile::tempdir().unwrap();
    let opaque = dir.path().join("opaque");
    let inner = dir.path().join("inner");
    let key = dir.path().join("key");
    let output = dir.path().join("output");
    fs::write(&opaque, &bytes).unwrap();
    fs::write(&key, b"opaque reference keyfile").unwrap();
    let password = "Tasarut opaque reference password";
    let mut file = File::create(&inner).unwrap();
    unwrap(
        &mut open_regular(&opaque).unwrap(),
        &mut file,
        password,
        std::slice::from_ref(&key),
        &mut Tracker::default(),
    )
    .unwrap();
    let mut encoded = Vec::new();
    wrap(
        &mut open_regular(&inner).unwrap(),
        &mut encoded,
        password,
        std::slice::from_ref(&key),
        bytes[..56].try_into().unwrap(),
        &mut Tracker::default(),
    )
    .unwrap();
    assert_eq!(encoded, bytes);
    decrypt(&inner, &output, password, &[key]).unwrap();
    assert_eq!(
        fs::read(output).unwrap(),
        b"Opaque file encryption\x00\x01\x02\xff\nAzul!"
    );
}

#[test]
fn opaque_round_trips_standard_paranoid_rs_compression_empty_and_keyfiles() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    let key = dir.path().join("key");
    fs::write(&key, b"extra secret").unwrap();
    for (index, (paranoid, reed_solomon, compress, empty)) in [
        (false, false, false, false),
        (true, true, true, false),
        (false, false, true, true),
    ]
    .into_iter()
    .enumerate()
    {
        let data: Vec<u8> = if empty {
            vec![]
        } else {
            (0..530_000).map(|n| (n % 251) as u8).collect()
        };
        fs::write(&source, &data).unwrap();
        let volume = dir.path().join(format!("opaque{index}.bin"));
        let output = dir.path().join(format!("output{index}"));
        encrypt(
            &source,
            &volume,
            "password",
            &EncryptOptions {
                deniability: true,
                paranoid,
                reed_solomon,
                compress,
                keyfiles: vec![key.clone()],
                ..Default::default()
            },
        )
        .unwrap();
        let bytes = fs::read(&volume).unwrap();
        assert!(!bytes.windows(7).any(|window| window == b"TASARUT"));
        assert!(inspect(&volume).is_err());
        assert!(!collect_inputs(std::slice::from_ref(&volume), false).unwrap()[0].volume);
        assert!(decrypt(&volume, &output, "password", std::slice::from_ref(&key)).is_err());
        assert!(force_decrypt(
            &volume,
            &output,
            "password",
            std::slice::from_ref(&key),
            &ForceOptions::default()
        )
        .is_err());
        assert!(!output.exists());
        let report =
            decrypt_deniable(&volume, &output, "password", std::slice::from_ref(&key)).unwrap();
        assert_eq!(report.reed_solomon, reed_solomon);
        assert_eq!(fs::read(&output).unwrap(), data);
        assert_eq!(fs::read(&volume).unwrap(), bytes);
    }
}

#[test]
fn rejects_wrong_secrets_tampering_truncation_and_random_input_without_output() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    let volume = dir.path().join("opaque");
    let output = dir.path().join("output");
    let key = dir.path().join("key");
    fs::write(&source, b"private file").unwrap();
    fs::write(&key, b"keyfile bytes").unwrap();
    encrypt(
        &source,
        &volume,
        "password",
        &EncryptOptions {
            deniability: true,
            keyfiles: vec![key.clone()],
            ..Default::default()
        },
    )
    .unwrap();
    let original = fs::read(&volume).unwrap();
    assert!(matches!(
        decrypt_deniable(&volume, &output, "wrong", std::slice::from_ref(&key)),
        Err(Error::Authentication)
    ));
    assert!(matches!(
        decrypt_deniable(&volume, &output, "password", &[]),
        Err(Error::Authentication)
    ));
    for index in [0, 32, 56, original.len() - 1] {
        let mut altered = original.clone();
        altered[index] ^= 1;
        fs::write(&volume, altered).unwrap();
        assert!(matches!(
            decrypt_deniable(&volume, &output, "password", std::slice::from_ref(&key)),
            Err(Error::Authentication)
        ));
        assert!(!output.exists());
    }
    fs::write(&volume, &original[..original.len() - 1]).unwrap();
    assert!(matches!(
        decrypt_deniable(&volume, &output, "password", std::slice::from_ref(&key)),
        Err(Error::Authentication)
    ));
    fs::write(&volume, vec![19; original.len()]).unwrap();
    assert!(matches!(
        decrypt_deniable(&volume, &output, "password", std::slice::from_ref(&key)),
        Err(Error::Authentication)
    ));
    fs::write(&volume, b"short").unwrap();
    assert!(matches!(
        decrypt_deniable(&volume, &output, "password", &[]),
        Err(Error::Authentication)
    ));
    assert!(!output.exists());
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 3);
}

#[test]
fn rejects_incompatible_options_and_collisions_and_randomizes_envelopes() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    let a = dir.path().join("a");
    let b = dir.path().join("b");
    fs::write(&source, b"original").unwrap();
    for (comment, chunk_size) in [("public".into(), None), (String::new(), Some(1024))] {
        assert!(matches!(
            encrypt(
                &source,
                &a,
                "password",
                &EncryptOptions {
                    deniability: true,
                    comment,
                    chunk_size,
                    ..Default::default()
                }
            ),
            Err(Error::DeniabilityOptions)
        ));
        assert!(!a.exists());
    }
    let options = EncryptOptions {
        deniability: true,
        ..Default::default()
    };
    assert!(matches!(
        encrypt(&source, &a, "", &options),
        Err(Error::EmptyPassword)
    ));
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    encrypt(&source, &a, "password", &options).unwrap();
    encrypt(&source, &b, "password", &options).unwrap();
    assert_ne!(fs::read(&a).unwrap(), fs::read(&b).unwrap());
    assert!(matches!(
        encrypt(&source, &a, "password", &options),
        Err(Error::OutputExists)
    ));
    assert!(matches!(
        decrypt_deniable(&a, &source, "password", &[]),
        Err(Error::OutputExists)
    ));
    assert_eq!(fs::read(&source).unwrap(), b"original");
    #[cfg(unix)]
    {
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&a, &link).unwrap();
        assert!(matches!(
            decrypt_deniable(&link, &b, "password", &[]),
            Err(Error::InvalidInput)
        ));
    }
}
