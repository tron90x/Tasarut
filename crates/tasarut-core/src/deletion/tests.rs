use super::*;
use crate::{encrypt, EncryptOptions};
use std::fs;

fn plan(paths: &[PathBuf]) -> PreparedDeletion {
    let token = CancellationToken::default();
    prepare(
        paths,
        false,
        "",
        &[],
        &mut OperationControl::new(&token, &mut |_| {}),
    )
    .unwrap()
}
fn volume(dir: &Path, name: &str, chunks: bool) -> PathBuf {
    let source = dir.join(format!("source-{name}"));
    let encrypted = dir.join(if chunks {
        format!("{name}.tasarut.parts")
    } else {
        format!("{name}.tasarut")
    });
    fs::write(&source, vec![42; 4096]).unwrap();
    encrypt(
        &source,
        &encrypted,
        "password",
        &EncryptOptions {
            chunk_size: chunks.then_some(1024),
            ..Default::default()
        },
    )
    .unwrap();
    encrypted
}

#[test]
fn deletes_only_reviewed_containers_without_overwriting_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let encrypted = volume(dir.path(), "one", false);
    let source = dir.path().join("source-one");
    let prepared = plan(&[encrypted.clone(), source.clone()]);
    assert_eq!(prepared.preview.total_files, 1);
    assert_eq!(
        prepared.preview.items[1].error.as_deref(),
        Some("deletion_unrecognized")
    );
    let report = execute(prepared, false, &CancellationToken::default(), &mut |_| {});
    assert_eq!(report.deleted_files, 1);
    assert!(report.results[0].disappearance_confirmed);
    assert!(!report.physical_erasure_verified);
    assert!(!encrypted.exists());
    assert_eq!(fs::read(&source).unwrap(), vec![42; 4096]);
    assert_eq!(report.trim[0].status, "notRequested");
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn changed_objects_and_symlinked_parents_are_not_deleted() {
    let dir = tempfile::tempdir().unwrap();
    let encrypted = volume(dir.path(), "one", false);
    let prepared = plan(std::slice::from_ref(&encrypted));
    let original = dir.path().join("moved");
    fs::rename(&encrypted, &original).unwrap();
    fs::write(&encrypted, b"new user data").unwrap();
    let report = execute(prepared, false, &CancellationToken::default(), &mut |_| {});
    assert_eq!(report.deleted_files, 0);
    assert_eq!(report.results[0].error.as_deref(), Some("source_changed"));
    assert_eq!(fs::read(&encrypted).unwrap(), b"new user data");
    assert!(original.exists());
    let nested = dir.path().join("nested");
    fs::create_dir(&nested).unwrap();
    let encrypted = volume(&nested, "two", false);
    let prepared = plan(std::slice::from_ref(&encrypted));
    let moved = dir.path().join("old-directory");
    fs::rename(&nested, &moved).unwrap();
    let external = tempfile::tempdir().unwrap();
    fs::write(external.path().join("two.tasarut"), b"outside").unwrap();
    std::os::unix::fs::symlink(external.path(), &nested).unwrap();
    let report = execute(prepared, false, &CancellationToken::default(), &mut |_| {});
    assert_eq!(report.deleted_files, 0);
    assert!(moved.join("two.tasarut").exists());
    assert_eq!(
        fs::read(external.path().join("two.tasarut")).unwrap(),
        b"outside"
    );
}

#[test]
fn sets_are_deduplicated_and_unexpected_entries_prevent_removal() {
    let dir = tempfile::tempdir().unwrap();
    let set = volume(dir.path(), "parts", true);
    let prepared = plan(&[set.clone(), set.join("000001.part"), set.join(MANIFEST)]);
    assert_eq!(prepared.preview.items.len(), 1);
    let original_count = fs::read_dir(&set).unwrap().count();
    fs::write(set.join("personal.txt"), b"keep").unwrap();
    let report = execute(prepared, false, &CancellationToken::default(), &mut |_| {});
    assert_eq!(report.deleted_files, 0);
    assert_eq!(fs::read_dir(&set).unwrap().count(), original_count + 1);
    fs::remove_file(set.join("personal.txt")).unwrap();
    let report = execute(
        plan(std::slice::from_ref(&set)),
        false,
        &CancellationToken::default(),
        &mut |_| {},
    );
    assert_eq!(report.deleted_files, original_count);
    assert!(report.results[0].directory_removed);
    assert!(!set.exists());
    assert!(dir.path().join("source-parts").exists());
}

#[test]
fn cancellation_leaves_the_manifest_and_pending_files_and_never_requests_trim() {
    let dir = tempfile::tempdir().unwrap();
    let set = volume(dir.path(), "parts", true);
    let second = volume(dir.path(), "later", false);
    let prepared = plan(&[set.clone(), second.clone()]);
    let token = CancellationToken::default();
    let mut trims = 0;
    let report = execute_with_trim(
        prepared,
        true,
        &token,
        &mut |progress| {
            if progress.deleted_files >= 1 {
                token.cancel();
            }
        },
        &mut |_| {
            trims += 1;
            Ok(123)
        },
    );
    assert_eq!(report.deleted_files, 1);
    assert!(report.cancelled);
    assert_eq!(trims, 0);
    assert!(set.join(MANIFEST).exists());
    assert!(second.exists());
    assert_eq!(report.results[0].status, "cancelled");
    assert_eq!(report.results[1].status, "notProcessed");
    assert_eq!(report.trim[0].status, "cancelled");
}

#[test]
fn trim_outcomes_are_separate_and_do_not_assert_physical_erasure() {
    for outcome in [
        Ok(123456),
        Err(rustix::io::Errno::PERM),
        Err(rustix::io::Errno::OPNOTSUPP),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let encrypted = volume(dir.path(), "one", false);
        let report = execute_with_trim(
            plan(std::slice::from_ref(&encrypted)),
            true,
            &CancellationToken::default(),
            &mut |_| {},
            &mut |_| outcome,
        );
        assert!(!encrypted.exists());
        assert_eq!(report.results[0].status, "deleted");
        assert!(!report.physical_erasure_verified);
        assert_eq!(
            report.trim[0].status,
            if outcome.is_ok() {
                "succeeded"
            } else if outcome == Err(rustix::io::Errno::PERM) {
                "permissionDenied"
            } else {
                "unsupported"
            }
        );
        assert_eq!(report.trim[0].reported_bytes, outcome.ok());
    }
}

#[test]
fn keyfiles_hardlinks_and_unknown_directories_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let encrypted = volume(dir.path(), "one", false);
    let token = CancellationToken::default();
    let prepared = prepare(
        std::slice::from_ref(&encrypted),
        false,
        "",
        std::slice::from_ref(&encrypted),
        &mut OperationControl::new(&token, &mut |_| {}),
    )
    .unwrap();
    assert_eq!(prepared.preview.total_files, 0);
    assert_eq!(
        prepared.preview.items[0].error.as_deref(),
        Some("deletion_protected_keyfile")
    );
    fs::hard_link(&encrypted, dir.path().join("alias")).unwrap();
    assert_eq!(
        plan(std::slice::from_ref(&encrypted)).preview.items[0]
            .error
            .as_deref(),
        Some("deletion_multiple_links")
    );
    let ordinary = dir.path().join("ordinary");
    fs::create_dir(&ordinary).unwrap();
    fs::write(ordinary.join("user.txt"), b"preserve").unwrap();
    assert_eq!(plan(std::slice::from_ref(&ordinary)).preview.total_files, 0);
    assert!(ordinary.join("user.txt").exists());
}

#[test]
fn opaque_recognition_authenticates_without_creating_plaintext_temporaries() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    let opaque = dir.path().join("opaque.bin");
    fs::write(&source, b"private data").unwrap();
    encrypt(
        &source,
        &opaque,
        "password",
        &EncryptOptions {
            deniability: true,
            ..Default::default()
        },
    )
    .unwrap();
    let token = CancellationToken::default();
    let bad = prepare(
        std::slice::from_ref(&opaque),
        true,
        "wrong",
        &[],
        &mut OperationControl::new(&token, &mut |_| {}),
    )
    .unwrap();
    assert_eq!(bad.preview.total_files, 0);
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
    let valid = prepare(
        std::slice::from_ref(&opaque),
        true,
        "password",
        &[],
        &mut OperationControl::new(&token, &mut |_| {}),
    )
    .unwrap();
    assert_eq!(valid.preview.items[0].kind, "opaque");
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
    let report = execute(valid, false, &token, &mut |_| {});
    assert_eq!(report.deleted_files, 1);
    assert_eq!(fs::read(source).unwrap(), b"private data");
}
