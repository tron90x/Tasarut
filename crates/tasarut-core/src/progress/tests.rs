use crate::*;

fn stage(events: &[ByteProgress], phase: ProgressPhase) -> Vec<ByteProgress> {
    events
        .iter()
        .copied()
        .filter(|e| e.phase == phase)
        .collect()
}

fn assert_stage(events: &[ByteProgress], phase: ProgressPhase, total: u64) {
    let events = stage(events, phase);
    assert!(!events.is_empty(), "missing {phase:?}");
    assert_eq!(events[0].processed_bytes, 0);
    assert_eq!(events.last().unwrap().processed_bytes, total);
    assert!(events.iter().all(|e| e.total_bytes == Some(total)));
    assert!(events
        .windows(2)
        .all(|pair| pair[0].processed_bytes <= pair[1].processed_bytes));
}

#[test]
fn streaming_reports_real_bytes_for_compressed_uncompressed_and_empty_inputs() {
    let dir = tempfile::tempdir().unwrap();
    for (i, compress, empty) in [(0, false, false), (1, true, false), (2, false, true)] {
        let data = if empty {
            vec![]
        } else {
            vec![42; BUFFER_SIZE * 3 + 17]
        };
        let source = dir.path().join(format!("source{i}"));
        let volume = dir.path().join(format!("volume{i}"));
        let output = dir.path().join(format!("output{i}"));
        fs::write(&source, &data).unwrap();
        let mut events = Vec::new();
        encrypt_with_progress(
            &source,
            &volume,
            "password",
            &EncryptOptions {
                compress,
                ..Default::default()
            },
            &mut |event| events.push(event),
        )
        .unwrap();
        assert_stage(&events, ProgressPhase::Encrypting, data.len() as u64);
        if !empty {
            assert!(stage(&events, ProgressPhase::Encrypting)
                .iter()
                .any(|e| e.processed_bytes > 0 && e.processed_bytes < data.len() as u64));
        }
        assert_eq!(events.last().unwrap().phase, ProgressPhase::Complete);
        assert!(events
            .iter()
            .filter(
                |e| e.phase == ProgressPhase::KeyDerivation || e.phase == ProgressPhase::Publishing
            )
            .all(|e| e.total_bytes.is_none()));
        let logical_payload = fs::metadata(&volume).unwrap().len() - FIXED_HEADER - TAG_LEN;
        events.clear();
        decrypt_with_progress(&volume, &output, "password", &[], &mut |event| {
            events.push(event)
        })
        .unwrap();
        assert_stage(&events, ProgressPhase::Authenticating, logical_payload);
        assert_stage(&events, ProgressPhase::Decrypting, logical_payload);
        assert_eq!(fs::read(&output).unwrap(), data);
        assert_eq!(events.last().unwrap().phase, ProgressPhase::Complete);
    }
}

#[test]
fn extra_passes_share_one_observer_and_only_finish_after_the_final_publication() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    fs::write(&source, vec![47; BUFFER_SIZE * 2 + 19]).unwrap();
    for deniability in [false, true] {
        let volume = dir
            .path()
            .join(format!("volume-{deniability}.tasarut.parts"));
        let output = dir.path().join(format!("output-{deniability}"));
        let options = EncryptOptions {
            chunk_size: (!deniability).then_some(BUFFER_SIZE as u64),
            deniability,
            reed_solomon: true,
            paranoid: deniability,
            ..Default::default()
        };
        let mut events = Vec::new();
        encrypt_with_progress(&source, &volume, "password", &options, &mut |event| {
            events.push(event)
        })
        .unwrap();
        let phase = if deniability {
            ProgressPhase::Wrapping
        } else {
            ProgressPhase::Splitting
        };
        let total = stage(&events, phase).last().unwrap().total_bytes.unwrap();
        assert_stage(&events, phase, total);
        assert_eq!(stage(&events, ProgressPhase::Complete).len(), 1);
        assert_eq!(events[events.len() - 2].phase, ProgressPhase::Publishing);
        events.clear();
        let mut observer = |event| events.push(event);
        let report = if deniability {
            decrypt_deniable_with_progress(&volume, &output, "password", &[], &mut observer)
        } else {
            decrypt_with_progress(&volume, &output, "password", &[], &mut observer)
        }
        .unwrap();
        assert!(report.reed_solomon);
        let phase = if deniability {
            ProgressPhase::Unwrapping
        } else {
            ProgressPhase::Reassembling
        };
        assert_stage(&events, phase, total);
        assert!(stage(&events, ProgressPhase::Decrypting).len() > 2);
        assert_eq!(stage(&events, ProgressPhase::Complete).len(), 1);
        assert_eq!(events.last().unwrap().phase, ProgressPhase::Complete);
        assert_eq!(fs::read(output).unwrap(), fs::read(&source).unwrap());
    }
}

#[test]
fn authentication_failure_never_reports_decryption_or_completion() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    let volume = dir.path().join("volume");
    let output = dir.path().join("output");
    fs::write(&source, vec![42; BUFFER_SIZE + 17]).unwrap();
    encrypt(&source, &volume, "password", &EncryptOptions::default()).unwrap();
    let mut events = Vec::new();
    assert!(matches!(
        decrypt_with_progress(&volume, &output, "wrong", &[], &mut |event| events
            .push(event)),
        Err(Error::Authentication)
    ));
    assert_eq!(events.last().unwrap().phase, ProgressPhase::Failed);
    assert!(stage(&events, ProgressPhase::Decrypting).is_empty());
    assert!(stage(&events, ProgressPhase::Complete).is_empty());
    assert!(!output.exists());
}

#[test]
fn forced_recovery_counts_consumed_bytes_and_does_not_guess_a_damaged_frame_length() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    fs::write(&source, vec![42; BUFFER_SIZE * 3]).unwrap();
    for compress in [false, true] {
        let volume = dir.path().join(format!("volume-{compress}"));
        let output = dir.path().join(format!("output-{compress}"));
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
        let mut events = Vec::new();
        let report = force_decrypt_with_progress(
            &volume,
            &output,
            "password",
            &[],
            &ForceOptions {
                max_output_bytes: (BUFFER_SIZE + 7) as u64,
            },
            &mut |event| events.push(event),
        )
        .unwrap();
        assert!(report.partial && report.limit_reached);
        assert_eq!(report.recovered_bytes, (BUFFER_SIZE + 7) as u64);
        let recovered = stage(&events, ProgressPhase::Recovering);
        assert!(recovered.last().unwrap().processed_bytes > 0);
        if compress {
            assert!(recovered.iter().all(|e| e.total_bytes.is_none()));
        } else {
            assert_stage(&events, ProgressPhase::Recovering, report.recovered_bytes);
        }
        assert_eq!(events.last().unwrap().phase, ProgressPhase::Complete);
    }
}
