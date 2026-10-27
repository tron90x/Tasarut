use super::*;
use crate::ByteProgress;
use std::{collections::BTreeMap, fs};

#[derive(Default)]
struct MemoryStore {
    slots: BTreeMap<u32, ([u8; 64], [u8; 32])>,
    next: u32,
    fail_cleanup: bool,
}
impl RevocationStore for MemoryStore {
    fn create(
        &mut self,
        record: &[u8; 64],
        auth: &[u8; 32],
        cancellation: &CancellationToken,
    ) -> Result<u32> {
        cancellation.check()?;
        self.next += 1;
        let index = SLOT_BASE + self.next;
        self.slots.insert(index, (*record, *auth));
        Ok(index)
    }
    fn read(
        &mut self,
        index: u32,
        auth: &[u8; 32],
        cancellation: &CancellationToken,
    ) -> Result<Zeroizing<[u8; 64]>> {
        cancellation.check()?;
        let (record, expected) = self
            .slots
            .get(&index)
            .ok_or(Error::RevocableKeyUnavailable)?;
        if auth != expected {
            return Err(Error::Authentication);
        }
        Ok(Zeroizing::new(*record))
    }
    fn destroy(
        &mut self,
        index: u32,
        id: &[u8; 32],
        auth: &[u8; 32],
        cancellation: &CancellationToken,
    ) -> Result<()> {
        let record = self.read(index, auth, cancellation)?;
        if record[..32] != *id {
            return Err(Error::RevocableKeyMismatch);
        }
        if self.fail_cleanup {
            return Err(Error::RevocableTpm);
        }
        self.slots.remove(&index);
        Ok(())
    }
}

#[test]
fn exact_v4_bytes_match_independent_argon2_sodium_blake2b_vector() {
    let text = include_str!("../../test-vectors/v4-revocable.hex").trim();
    let expected: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect();
    let dir = tempfile::tempdir().unwrap();
    let volume = dir.path().join("reference");
    let key = dir.path().join("key");
    let source = dir.path().join("source");
    let output = dir.path().join("output");
    fs::write(&volume, &expected).unwrap();
    fs::write(&key, b"revocable reference keyfile").unwrap();
    let plaintext = b"Revocable file encryption\x00\x01\x02\xff\nAzul!";
    fs::write(&source, plaintext).unwrap();
    let header = Header::read(
        &mut crate::recovery::VolumeReader::new(File::open(&volume).unwrap()).unwrap(),
    )
    .unwrap();
    let auth = header
        .auth_keys(
            "Tasarut revocable reference password",
            std::slice::from_ref(&key),
            &Tracker::default(),
        )
        .unwrap();
    let mut record = [0; 64];
    record[..32].copy_from_slice(&header.identifier);
    for (i, byte) in record[32..].iter_mut().enumerate() {
        *byte = 128 + i as u8;
    }
    let keys = header.payload_keys(&auth, &record).unwrap();
    let mut bytes = Vec::new();
    encrypt_payload(
        &mut File::open(&source).unwrap(),
        &mut bytes,
        &header,
        &keys,
        &mut Tracker::default(),
    )
    .unwrap();
    assert_eq!(bytes, expected);
    let mut store = MemoryStore::default();
    store
        .slots
        .insert(header.index, (record, auth.bytes[..32].try_into().unwrap()));
    decrypt_with_control(
        &volume,
        &output,
        "Tasarut revocable reference password",
        std::slice::from_ref(&key),
        &mut store,
        &mut OperationControl::new(&CancellationToken::default(), &mut |_| {}),
    )
    .unwrap();
    assert_eq!(fs::read(output).unwrap(), plaintext);
}

#[test]
fn standalone_volumes_round_trip_and_revocation_invalidates_restored_ciphertext_copies() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = MemoryStore::default();
    let key = dir.path().join("key");
    fs::write(&key, b"additional keyfile").unwrap();
    for (i, paranoid, compress, rs, empty) in [
        (0, false, false, false, false),
        (1, true, true, true, false),
        (2, false, false, true, true),
        (3, false, true, true, false),
    ] {
        let source = dir.path().join(format!("source{i}"));
        let volume = dir.path().join(format!("volume{i}.rev"));
        let output = dir.path().join(format!("output{i}"));
        let restored = dir.path().join(format!("restored{i}.rev"));
        let bytes = if empty {
            vec![]
        } else {
            vec![42; BUFFER_SIZE * 2 + 19]
        };
        fs::write(&source, &bytes).unwrap();
        let token = CancellationToken::default();
        encrypt_with_control(
            &source,
            &volume,
            "password",
            &EncryptOptions {
                algorithm: if i == 3 {
                    crate::CipherAlgorithm::Threefish1024
                } else {
                    crate::CipherAlgorithm::XChaCha20
                },
                paranoid,
                compress,
                reed_solomon: rs,
                keyfiles: vec![key.clone()],
                revocable: true,
                ..Default::default()
            },
            &mut store,
            &mut OperationControl::new(&token, &mut |_| {}),
        )
        .unwrap();
        let info = crate::inspect(&volume).unwrap();
        assert!(info.revocable);
        assert_eq!(info.format_version, 4);
        assert_eq!(info.paranoid, paranoid);
        assert_eq!(info.reed_solomon, rs);
        let inputs = crate::collect_inputs(std::slice::from_ref(&volume), false).unwrap();
        assert!(inputs[0].volume && inputs[0].revocable);
        assert!(matches!(
            crate::decrypt(&volume, &output, "password", std::slice::from_ref(&key)),
            Err(Error::RevocableProviderRequired)
        ));
        let report = decrypt_with_control(
            &volume,
            &output,
            "password",
            std::slice::from_ref(&key),
            &mut store,
            &mut OperationControl::new(&token, &mut |_| {}),
        )
        .unwrap();
        assert_eq!(report.reed_solomon, rs);
        assert_eq!(fs::read(&output).unwrap(), bytes);
        fs::copy(&volume, &restored).unwrap();
        let report = revoke_with_control(
            &volume,
            "password",
            std::slice::from_ref(&key),
            &mut store,
            &mut OperationControl::new(&token, &mut |_| {}),
        )
        .unwrap();
        assert!(report.hardware_absence_confirmed && !report.ciphertext_removed);
        assert!(volume.exists() && restored.exists());
        let rejected = dir.path().join(format!("rejected{i}"));
        assert!(matches!(
            decrypt_with_control(
                &restored,
                &rejected,
                "password",
                std::slice::from_ref(&key),
                &mut store,
                &mut OperationControl::new(&token, &mut |_| {})
            ),
            Err(Error::RevocableKeyUnavailable)
        ));
        assert!(!rejected.exists());
    }
    assert!(store.slots.is_empty());
}

#[test]
fn independent_threefish_v4_vector_matches_and_revocation_removes_its_secret() {
    let text: String = include_str!("../../test-vectors/v4-threefish.hex")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let expected: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect();
    let dir = tempfile::tempdir().unwrap();
    let volume = dir.path().join("reference");
    let output = dir.path().join("output");
    let source = dir.path().join("source");
    let files = vec![dir.path().join("key1"), dir.path().join("key2")];
    fs::write(&files[0], b"first Threefish keyfile").unwrap();
    fs::write(&files[1], b"second Threefish keyfile").unwrap();
    let plaintext: Vec<u8> = (0..=255).cycle().take(512).chain(*b"Azul!").collect();
    fs::write(&source, &plaintext).unwrap();
    fs::write(&volume, &expected).unwrap();
    let header = Header::read(
        &mut crate::recovery::VolumeReader::new(File::open(&volume).unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(header.suite, Suite::Threefish);
    let password = "Tasarut Threefish reference password";
    let auth = header
        .auth_keys(password, &files, &Tracker::default())
        .unwrap();
    let mut record = [0; 64];
    record[..32].copy_from_slice(&header.identifier);
    for (i, byte) in record[32..].iter_mut().enumerate() {
        *byte = 128 + i as u8;
    }
    let keys = header.payload_keys(&auth, &record).unwrap();
    assert_eq!(keys.bytes.len(), 192);
    let mut encrypted = Vec::new();
    encrypt_payload(
        &mut File::open(&source).unwrap(),
        &mut encrypted,
        &header,
        &keys,
        &mut Tracker::default(),
    )
    .unwrap();
    assert_eq!(encrypted, expected);
    let mut store = MemoryStore::default();
    store
        .slots
        .insert(header.index, (record, auth.bytes[..32].try_into().unwrap()));
    let mut progress = |_| {};
    let token = CancellationToken::default();
    decrypt_with_control(
        &volume,
        &output,
        password,
        &files,
        &mut store,
        &mut OperationControl::new(&token, &mut progress),
    )
    .unwrap();
    assert_eq!(fs::read(&output).unwrap(), plaintext);
    assert_eq!(
        crate::inspect(&volume).unwrap().algorithm,
        crate::CipherAlgorithm::Threefish1024
    );
    revoke_with_control(
        &volume,
        password,
        &files,
        &mut store,
        &mut OperationControl::new(&token, &mut progress),
    )
    .unwrap();
    let refused = dir.path().join("refused");
    assert!(matches!(
        decrypt_with_control(
            &volume,
            &refused,
            password,
            &files,
            &mut store,
            &mut OperationControl::new(&token, &mut progress)
        ),
        Err(Error::RevocableKeyUnavailable)
    ));
    assert!(!refused.exists());
}

#[test]
fn modified_volumes_wrong_secrets_and_substituted_records_do_not_revoke_keys() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    let volume = dir.path().join("volume");
    let output = dir.path().join("output");
    fs::write(&source, vec![43; 1000]).unwrap();
    let mut store = MemoryStore::default();
    let token = CancellationToken::default();
    encrypt_with_control(
        &source,
        &volume,
        "password",
        &EncryptOptions::default(),
        &mut store,
        &mut OperationControl::new(&token, &mut |_| {}),
    )
    .unwrap();
    assert!(revoke_with_control(
        &volume,
        "wrong",
        &[],
        &mut store,
        &mut OperationControl::new(&token, &mut |_| {})
    )
    .is_err());
    let original = fs::read(&volume).unwrap();
    let mut changed = original.clone();
    changed[HEADER_LEN as usize + 9] ^= 1;
    fs::write(&volume, changed).unwrap();
    assert!(matches!(
        revoke_with_control(
            &volume,
            "password",
            &[],
            &mut store,
            &mut OperationControl::new(&token, &mut |_| {})
        ),
        Err(Error::Authentication)
    ));
    assert_eq!(store.slots.len(), 1);
    fs::write(&volume, &original).unwrap();
    store.slots.values_mut().next().unwrap().0[0] ^= 1;
    assert!(matches!(
        decrypt_with_control(
            &volume,
            &output,
            "password",
            &[],
            &mut store,
            &mut OperationControl::new(&token, &mut |_| {})
        ),
        Err(Error::RevocableKeyMismatch)
    ));
    assert!(revoke_with_control(
        &volume,
        "password",
        &[],
        &mut store,
        &mut OperationControl::new(&token, &mut |_| {})
    )
    .is_err());
    assert_eq!(store.slots.len(), 1);
    assert!(!output.exists());
}

#[test]
fn cancellation_cleans_hardware_keys_and_never_leaves_a_password_only_temporary() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    let output = dir.path().join("output");
    fs::write(&source, vec![44; BUFFER_SIZE * 2 + 7]).unwrap();
    let mut store = MemoryStore::default();
    for phase in [ProgressPhase::Encrypting, ProgressPhase::Publishing] {
        let token = CancellationToken::default();
        let mut callback = |progress: ByteProgress| {
            if progress.phase == phase
                && (phase == ProgressPhase::Publishing || progress.processed_bytes > 0)
            {
                token.cancel();
            }
        };
        assert!(matches!(
            encrypt_with_control(
                &source,
                &output,
                "password",
                &EncryptOptions::default(),
                &mut store,
                &mut OperationControl::new(&token, &mut callback)
            ),
            Err(Error::Cancelled)
        ));
        assert!(store.slots.is_empty());
        assert!(!output.exists());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }
    store.fail_cleanup = true;
    let token = CancellationToken::default();
    let mut callback = |progress: ByteProgress| {
        if progress.phase == ProgressPhase::Publishing {
            token.cancel();
        }
    };
    assert!(matches!(
        encrypt_with_control(
            &source,
            &output,
            "password",
            &EncryptOptions::default(),
            &mut store,
            &mut OperationControl::new(&token, &mut callback)
        ),
        Err(Error::RevocableCleanup(_))
    ));
    assert_eq!(store.slots.len(), 1);
    assert!(!output.exists());
}

#[test]
fn incompatible_options_and_collisions_do_not_allocate_hardware_slots() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    let output = dir.path().join("output");
    fs::write(&source, b"data").unwrap();
    let mut store = MemoryStore::default();
    let token = CancellationToken::default();
    for options in [
        EncryptOptions {
            comment: "public".into(),
            ..Default::default()
        },
        EncryptOptions {
            deniability: true,
            ..Default::default()
        },
        EncryptOptions {
            chunk_size: Some(1024),
            ..Default::default()
        },
    ] {
        assert!(matches!(
            encrypt_with_control(
                &source,
                &output,
                "password",
                &options,
                &mut store,
                &mut OperationControl::new(&token, &mut |_| {})
            ),
            Err(Error::RevocableOptions)
        ));
    }
    fs::write(&output, b"existing").unwrap();
    assert!(matches!(
        encrypt_with_control(
            &source,
            &output,
            "password",
            &EncryptOptions::default(),
            &mut store,
            &mut OperationControl::new(&token, &mut |_| {})
        ),
        Err(Error::OutputExists)
    ));
    assert!(store.slots.is_empty());
    assert_eq!(fs::read(&output).unwrap(), b"existing");
}
