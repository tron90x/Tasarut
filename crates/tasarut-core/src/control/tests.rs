use crate::*;

fn cancel_at<T>(
    phase: ProgressPhase,
    after: u64,
    operation: impl FnOnce(&mut OperationControl<'_>) -> Result<T>,
) {
    let token = CancellationToken::default();
    let mut events = Vec::new();
    let mut observer = |event: ByteProgress| {
        events.push(event);
        if event.phase == phase && event.processed_bytes >= after {
            token.cancel();
        }
    };
    let result = operation(&mut OperationControl::new(&token, &mut observer));
    assert!(matches!(result, Err(Error::Cancelled)));
    assert_eq!(events.last().unwrap().phase, ProgressPhase::Cancelled);
    assert!(!events.iter().any(|e| e.phase == ProgressPhase::Complete));
}

#[test]
fn pre_cancelled_operations_do_no_io_and_tokens_are_independent() {
    let dir = tempfile::tempdir().unwrap();
    let token = CancellationToken::default();
    token.clone().cancel();
    let output = dir.path().join("output");
    let source = dir.path().join("absent");
    let mut observer = |_| {};
    assert!(matches!(
        encrypt_with_control(
            &source,
            &output,
            "password",
            &EncryptOptions::default(),
            &mut OperationControl::new(&token, &mut observer)
        ),
        Err(Error::Cancelled)
    ));
    assert!(matches!(
        collect_inputs_with_cancellation(&[source], true, &token),
        Err(Error::Cancelled)
    ));
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    assert!(!CancellationToken::default().is_cancelled());
}

#[test]
fn cancelled_encryption_and_pre_commit_publication_leave_no_partial_files() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    let finished = dir.path().join("finished");
    let output = dir.path().join("output");
    let data = vec![47; BUFFER_SIZE * 3 + 17];
    fs::write(&source, &data).unwrap();
    fs::write(&finished, b"keep completed result").unwrap();
    for (compress, paranoid, reed_solomon) in [
        (false, false, false),
        (true, false, true),
        (false, true, false),
    ] {
        cancel_at(ProgressPhase::Encrypting, BUFFER_SIZE as u64, |control| {
            encrypt_with_control(
                &source,
                &output,
                "password",
                &EncryptOptions {
                    compress,
                    paranoid,
                    reed_solomon,
                    ..Default::default()
                },
                control,
            )
        });
        assert!(!output.exists());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
        assert_eq!(fs::read(&source).unwrap(), data);
        assert_eq!(fs::read(&finished).unwrap(), b"keep completed result");
    }
    for phase in [ProgressPhase::KeyDerivation, ProgressPhase::Publishing] {
        cancel_at(phase, 0, |control| {
            encrypt_with_control(
                &source,
                &output,
                "password",
                &EncryptOptions::default(),
                control,
            )
        });
        assert!(!output.exists());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
    }
}

#[test]
fn cancelled_authentication_and_decompression_never_publish_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    let output = dir.path().join("output");
    fs::write(&source, vec![42; BUFFER_SIZE * 3 + 17]).unwrap();
    for compress in [false, true] {
        let volume = dir.path().join(format!("volume-{compress}"));
        encrypt(
            &source,
            &volume,
            "password",
            &EncryptOptions {
                compress,
                reed_solomon: true,
                ..Default::default()
            },
        )
        .unwrap();
        let original = fs::read(&volume).unwrap();
        for phase in [ProgressPhase::Authenticating, ProgressPhase::Decrypting] {
            let before = fs::read_dir(dir.path()).unwrap().count();
            cancel_at(phase, 1, |control| {
                decrypt_with_control(&volume, &output, "password", &[], control)
            });
            assert!(!output.exists());
            assert_eq!(fs::read_dir(dir.path()).unwrap().count(), before);
            assert_eq!(fs::read(&volume).unwrap(), original);
        }
    }
}

#[test]
fn chunk_and_opaque_temporaries_are_removed_even_after_inner_files_are_complete() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    fs::write(&source, vec![43; BUFFER_SIZE * 3 + 17]).unwrap();
    for deniability in [false, true] {
        let volume = dir
            .path()
            .join(format!("volume-{deniability}.tasarut.parts"));
        let output = dir.path().join(format!("output-{deniability}"));
        let options = EncryptOptions {
            deniability,
            chunk_size: (!deniability).then_some(BUFFER_SIZE as u64),
            reed_solomon: true,
            ..Default::default()
        };
        let phase = if deniability {
            ProgressPhase::Wrapping
        } else {
            ProgressPhase::Splitting
        };
        let before = fs::read_dir(dir.path()).unwrap().count();
        // On the split path, one complete part has already been staged.
        cancel_at(phase, (BUFFER_SIZE * 2) as u64, |control| {
            encrypt_with_control(&source, &volume, "password", &options, control)
        });
        assert!(!volume.exists());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), before);
        encrypt(&source, &volume, "password", &options).unwrap();
        let before = fs::read_dir(dir.path()).unwrap().count();
        let phase = if deniability {
            ProgressPhase::Unwrapping
        } else {
            ProgressPhase::Reassembling
        };
        cancel_at(phase, 1, |control| {
            if deniability {
                decrypt_deniable_with_control(&volume, &output, "password", &[], control)
            } else {
                decrypt_with_control(&volume, &output, "password", &[], control)
            }
        });
        assert!(!output.exists());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), before);
        if deniability {
            decrypt_deniable(&volume, &output, "password", &[]).unwrap();
        } else {
            decrypt(&volume, &output, "password", &[]).unwrap();
        }
        assert_eq!(fs::read(&output).unwrap(), fs::read(&source).unwrap());
    }
}

#[test]
fn cancelled_forced_recovery_does_not_keep_a_recovered_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    let output = dir.path().join("output.recovered");
    fs::write(&source, vec![44; BUFFER_SIZE * 3]).unwrap();
    for compress in [false, true] {
        let volume = dir.path().join(format!("volume-{compress}"));
        encrypt(
            &source,
            &volume,
            "password",
            &EncryptOptions {
                compress,
                ..Default::default()
            },
        )
        .unwrap();
        let mut damaged = fs::read(&volume).unwrap();
        *damaged.last_mut().unwrap() ^= 1;
        fs::write(&volume, &damaged).unwrap();
        let before = fs::read_dir(dir.path()).unwrap().count();
        cancel_at(ProgressPhase::Recovering, 1, |control| {
            force_decrypt_with_control(
                &volume,
                &output,
                "password",
                &[],
                &ForceOptions::default(),
                control,
            )
        });
        assert!(!output.exists());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), before);
        assert_eq!(fs::read(&volume).unwrap(), damaged);
    }
}

#[test]
fn buffered_plaintext_copy_checks_cancellation_without_another_cipher_read() {
    struct Sink {
        token: CancellationToken,
        written: usize,
    }
    impl Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.written += bytes.len();
            self.token.cancel();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let token = CancellationToken::default();
    let mut sink = Sink {
        token: token.clone(),
        written: 0,
    };
    let mut decoded = io::Cursor::new(vec![42; BUFFER_SIZE * 4]);
    let error = copy_private(&mut decoded, &mut sink, None, Some(&token)).unwrap_err();
    assert!(matches!(Error::from(error), Error::Cancelled));
    assert_eq!(sink.written, BUFFER_SIZE);
}

#[test]
fn cancellation_after_commit_preserves_a_successful_output() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    let output = dir.path().join("output");
    let next = dir.path().join("next");
    fs::write(&source, b"finished data").unwrap();
    let token = CancellationToken::default();
    let mut observer = |event: ByteProgress| {
        if event.phase == ProgressPhase::Complete {
            token.cancel();
        }
    };
    encrypt_with_control(
        &source,
        &output,
        "password",
        &EncryptOptions::default(),
        &mut OperationControl::new(&token, &mut observer),
    )
    .unwrap();
    assert!(output.exists());
    assert!(matches!(
        encrypt_with_control(
            &source,
            &next,
            "password",
            &EncryptOptions::default(),
            &mut OperationControl::new(&token, &mut observer)
        ),
        Err(Error::Cancelled)
    ));
    assert!(!next.exists());
    let plaintext = dir.path().join("plaintext");
    decrypt(&output, &plaintext, "password", &[]).unwrap();
    assert_eq!(fs::read(plaintext).unwrap(), b"finished data");
}
