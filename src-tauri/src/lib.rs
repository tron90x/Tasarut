use serde::{Deserialize, Serialize};
use std::{
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};
use tasarut_core::{
    ByteProgress, CancellationToken, EncryptOptions, ForceOptions, ForceReport, InputFile,
    OperationControl, ProgressPhase, RepairInfo, VolumeInfo,
};
use tauri::{Emitter, Manager, State};
use zeroize::Zeroizing;
mod deletion;
mod profile_io;
mod revocation;
mod tpm;

#[derive(Default)]
struct JobState(Arc<Mutex<Option<ActiveJob>>>);

struct ActiveJob {
    id: String,
    cancellation: CancellationToken,
}

impl JobState {
    fn active(&self) -> MutexGuard<'_, Option<ActiveJob>> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn start(&self, id: &str) -> Result<JobGuard, String> {
        let mut active = self.active();
        if active.is_some() {
            return Err("job_running".into());
        }
        let cancellation = CancellationToken::default();
        *active = Some(ActiveJob {
            id: id.to_owned(),
            cancellation: cancellation.clone(),
        });
        Ok(JobGuard {
            state: self.0.clone(),
            id: id.to_owned(),
            cancellation,
        })
    }

    fn cancel(&self, id: &str) -> bool {
        self.active()
            .as_ref()
            .filter(|job| job.id == id)
            .is_some_and(|job| {
                job.cancellation.cancel();
                true
            })
    }

    fn is_running(&self) -> bool {
        self.active().is_some()
    }
}

struct JobGuard {
    state: Arc<Mutex<Option<ActiveJob>>>,
    id: String,
    cancellation: CancellationToken,
}
impl Drop for JobGuard {
    fn drop(&mut self) {
        let mut active = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if active.as_ref().is_some_and(|job| job.id == self.id) {
            *active = None;
        }
    }
}

#[tauri::command]
fn cancel_batch(state: State<'_, JobState>, id: String) -> bool {
    state.cancel(&id)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BatchRequest {
    id: String,
    mode: Mode,
    paths: Vec<PathBuf>,
    selected_paths: Vec<PathBuf>,
    output_directory: PathBuf,
    password: String,
    #[serde(default)]
    algorithm: tasarut_core::CipherAlgorithm,
    keyfiles: Vec<PathBuf>,
    comment: String,
    compress: bool,
    #[serde(default)]
    paranoid: bool,
    #[serde(default)]
    reed_solomon: bool,
    #[serde(default)]
    force_decrypt: bool,
    #[serde(
        default = "default_recovery_limit",
        rename = "recoveryLimitMiB",
        alias = "recoveryLimitMib"
    )]
    recovery_limit_mib: u64,
    #[serde(default, rename = "chunkSizeMiB", alias = "chunkSizeMib")]
    chunk_size_mib: Option<u64>,
    #[serde(default)]
    deniability: bool,
    #[serde(default)]
    revocable: bool,
    #[serde(default)]
    tpm_owner_auth: String,
    recursive: bool,
}
fn default_recovery_limit() -> u64 {
    4096
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Mode {
    Encrypt,
    Decrypt,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct FileResult {
    source: PathBuf,
    output: Option<PathBuf>,
    error: Option<String>,
    repair: Option<RepairInfo>,
    recovery: Option<ForceReport>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Progress {
    id: String,
    completed: usize,
    total: usize,
    current: PathBuf,
    result: Option<FileResult>,
    byte_progress: ByteProgress,
}

// Streaming loops can process thousands of buffers a second. Send stage changes
// and endpoints immediately, otherwise cap IPC updates at roughly ten per second.
struct ProgressGate {
    last: Option<ByteProgress>,
    sent_at: Instant,
}

impl ProgressGate {
    fn new(now: Instant) -> Self {
        Self {
            last: None,
            sent_at: now,
        }
    }

    fn should_emit(&mut self, progress: ByteProgress, now: Instant) -> bool {
        if self.last == Some(progress) {
            return false;
        }
        let changed_stage = self.last.is_none_or(|last| {
            last.phase != progress.phase || last.total_bytes != progress.total_bytes
        });
        let endpoint = progress
            .total_bytes
            .is_some_and(|total| progress.processed_bytes >= total);
        if changed_stage
            || endpoint
            || now.saturating_duration_since(self.sent_at) >= Duration::from_millis(100)
        {
            self.last = Some(progress);
            self.sent_at = now;
            return true;
        }
        false
    }
}

#[tauri::command]
async fn inspect_volume(path: PathBuf, force: Option<bool>) -> Result<VolumeInfo, String> {
    tauri::async_runtime::spawn_blocking(move || {
        tasarut_core::inspect_mode(&path, force.unwrap_or(false)).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn collect_files(paths: Vec<PathBuf>, recursive: bool) -> Result<Vec<InputFile>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        tasarut_core::collect_inputs(&paths, recursive).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
fn generate_password(length: usize, symbols: bool) -> Result<String, String> {
    tasarut_core::generate_password(length, symbols).map_err(|e| e.to_string())
}

// A collected relative path must never escape the user-selected output directory.
#[derive(Default)]
struct CreatedDirectories(Vec<PathBuf>);
impl Drop for CreatedDirectories {
    fn drop(&mut self) {
        for path in self.0.iter().rev() {
            // Remove only directories created by this file's preparation, and
            // only while empty. Never delete an existing or completed result.
            let _ = std::fs::remove_dir(path);
        }
    }
}

#[cfg(test)]
fn destination(
    root: &Path,
    relative: &Path,
    mode: Mode,
    deniability: bool,
) -> Result<PathBuf, String> {
    destination_impl(
        root,
        relative,
        mode,
        deniability,
        &mut CreatedDirectories::default(),
        None,
    )
}

fn destination_impl(
    root: &Path,
    relative: &Path,
    mode: Mode,
    deniability: bool,
    created: &mut CreatedDirectories,
    cancellation: Option<&CancellationToken>,
) -> Result<PathBuf, String> {
    if let Some(token) = cancellation {
        token.check().map_err(|e| e.to_string())?;
    }
    if relative
        .components()
        .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err("invalid_input".into());
    }
    let mut relative = relative.to_path_buf();
    let filename = relative.file_name().ok_or("invalid_input")?;
    let mut name = filename.to_os_string();
    match mode {
        Mode::Encrypt => name.push(if deniability { ".bin" } else { ".tasarut" }),
        Mode::Decrypt => {
            // Use OsString for encryption to preserve non-UTF8 Linux filenames too.
            let lossy = filename.to_string_lossy();
            let original = if deniability {
                lossy.strip_suffix(".bin")
            } else {
                lossy
                    .strip_suffix(".tasarut.parts")
                    .or_else(|| lossy.strip_suffix(".tasarut"))
                    .or_else(|| lossy.strip_suffix(".tasarut.rev"))
            };
            name = if let Some(original) = original {
                if original.is_empty() || original == "." || original == ".." {
                    return Err("invalid_input".into());
                }
                original.into()
            } else {
                name.push(".decrypted");
                name
            };
        }
    }
    relative.set_file_name(name);
    let output = root.join(relative);
    // Refuse symlinked subdirectories; never accidentally write outside the chosen root.
    let parent = output.parent().ok_or("invalid_input")?;
    let mut current = root.to_path_buf();
    for component in parent
        .strip_prefix(root)
        .map_err(|_| "invalid_input")?
        .components()
    {
        if let Some(token) = cancellation {
            token.check().map_err(|e| e.to_string())?;
        }
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {}
            Ok(_) => return Err("invalid_input".into()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&current).map_err(|e| e.to_string())?;
                created.0.push(current.clone());
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(output)
}

fn recovered_destination(path: PathBuf) -> PathBuf {
    let mut name = path.into_os_string();
    name.push(".recovered");
    PathBuf::from(name)
}

fn skipped_result(file: InputFile) -> FileResult {
    FileResult {
        source: file.path,
        output: None,
        error: Some("not_processed".into()),
        repair: None,
        recovery: None,
    }
}

fn process_files(
    files: Vec<InputFile>,
    cancellation: &CancellationToken,
    mut process: impl FnMut(usize, InputFile) -> FileResult,
    mut on_pending_cancel: impl FnMut(usize, &InputFile),
) -> Vec<FileResult> {
    let mut results = Vec::with_capacity(files.len());
    let mut files = files.into_iter().enumerate();
    while let Some((index, file)) = files.next() {
        if cancellation.is_cancelled() {
            on_pending_cancel(index, &file);
            results.push(skipped_result(file));
            results.extend(files.map(|(_, file)| skipped_result(file)));
            break;
        }
        let result = process(index, file);
        let cancelled = result.error.as_deref() == Some("operation_cancelled");
        results.push(result);
        if cancelled {
            results.extend(files.map(|(_, file)| skipped_result(file)));
            break;
        }
    }
    results
}

#[tauri::command]
async fn run_batch(
    app: tauri::AppHandle,
    state: State<'_, JobState>,
    mut request: BatchRequest,
) -> Result<Vec<FileResult>, String> {
    // Move the password immediately into zeroizing storage, including error paths.
    let password = Zeroizing::new(std::mem::take(&mut request.password));
    let tpm_owner_auth = Zeroizing::new(std::mem::take(&mut request.tpm_owner_auth));
    let guard = state.start(&request.id)?;
    let cancellation = guard.cancellation.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = guard;
        cancellation.check().map_err(|e| e.to_string())?;
        if password.is_empty() {
            return Err("empty_password".into());
        }
        if request.force_decrypt && matches!(request.mode, Mode::Encrypt) {
            return Err("invalid_input".into());
        }
        if request.deniability
            && (request.force_decrypt
                || request.chunk_size_mib.is_some()
                || (matches!(request.mode, Mode::Encrypt) && !request.comment.is_empty()))
        {
            return Err("deniability_incompatible_options".into());
        }
        if matches!(request.mode, Mode::Encrypt)
            && request.algorithm == tasarut_core::CipherAlgorithm::Threefish1024
            && request.paranoid
        {
            return Err("cipher_incompatible_options".into());
        }
        let chunk_size = request
            .chunk_size_mib
            .map(|size| {
                if !matches!(request.mode, Mode::Encrypt) || !(1..=1048576).contains(&size) {
                    return Err("invalid_chunk_size");
                }
                size.checked_mul(1024 * 1024).ok_or("invalid_chunk_size")
            })
            .transpose()?;
        if request.revocable
            && (request.deniability
                || chunk_size.is_some()
                || !request.comment.is_empty()
                || request.force_decrypt)
        {
            return Err("revocable_incompatible_options".into());
        }
        let recovery_limit = request
            .recovery_limit_mib
            .checked_mul(1024 * 1024)
            .ok_or("invalid_recovery_limit")?;
        if request.force_decrypt && !(1..=1 << 40).contains(&recovery_limit) {
            return Err("invalid_recovery_limit".into());
        }
        let root = std::fs::canonicalize(&request.output_directory).map_err(|e| e.to_string())?;
        if !root.is_dir() {
            return Err("invalid_input".into());
        }
        let selected: std::collections::HashSet<_> = request.selected_paths.into_iter().collect();
        let files: Vec<_> = tasarut_core::collect_inputs_with_cancellation(
            &request.paths,
            request.recursive,
            &cancellation,
        )
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|file| selected.contains(&file.path))
        .collect();
        if files.len() != selected.len() {
            return Err("source_changed".into());
        }
        if files.is_empty() {
            return Err("no_files".into());
        }
        let options = EncryptOptions {
            algorithm: request.algorithm,
            comment: request.comment,
            compress: request.compress,
            paranoid: request.paranoid,
            reed_solomon: request.reed_solomon,
            keyfiles: request.keyfiles,
            chunk_size,
            deniability: request.deniability,
            revocable: request.revocable,
        };
        let total = files.len();
        let results = process_files(
            files,
            &cancellation,
            |index, file| {
                let byte_progress = ByteProgress::default();
                let _ = app.emit(
                    "tasarut-progress",
                    Progress {
                        id: request.id.clone(),
                        completed: index,
                        total,
                        current: file.path.clone(),
                        result: None,
                        byte_progress,
                    },
                );
                let mut created_dirs = CreatedDirectories::default();
                let target = destination_impl(
                    &root,
                    &file.relative_path,
                    request.mode,
                    request.deniability,
                    &mut created_dirs,
                    Some(&cancellation),
                )
                .map(|path| {
                    if request.force_decrypt {
                        recovered_destination(path)
                    } else if request.revocable && matches!(request.mode, Mode::Encrypt) {
                        let mut name = path.into_os_string();
                        name.push(".rev");
                        PathBuf::from(name)
                    } else if chunk_size.is_some() {
                        let mut name = path.into_os_string();
                        name.push(".parts");
                        PathBuf::from(name)
                    } else {
                        path
                    }
                });
                let result = target.and_then(|target| {
                    let mut gate = ProgressGate::new(Instant::now());
                    let mut on_progress = |update: ByteProgress| {
                        if gate.should_emit(update, Instant::now()) {
                            let _ = app.emit(
                                "tasarut-progress",
                                Progress {
                                    id: request.id.clone(),
                                    completed: index,
                                    total,
                                    current: file.path.clone(),
                                    result: None,
                                    byte_progress: update,
                                },
                            );
                        }
                    };
                    let mut control = OperationControl::new(&cancellation, &mut on_progress);
                    let (repair, recovery) = match request.mode {
                        Mode::Encrypt if file.volume => return Err("already_encrypted".into()),
                        Mode::Encrypt if request.revocable => {
                            let mut store = tpm::TpmStore::new(tpm_owner_auth.clone())
                                .map_err(|e| e.to_string())?;
                            tasarut_core::revocable::encrypt_with_control(
                                &file.path,
                                &target,
                                &password,
                                &options,
                                &mut store,
                                &mut control,
                            )
                            .map(|_| (None, None))
                        }
                        Mode::Encrypt => tasarut_core::encrypt_with_control(
                            &file.path,
                            &target,
                            &password,
                            &options,
                            &mut control,
                        )
                        .map(|_| (None, None)),
                        Mode::Decrypt if file.revocable => {
                            if request.force_decrypt || request.deniability {
                                return Err("revocable_incompatible_options".into());
                            }
                            let mut store = tpm::TpmStore::new(tpm_owner_auth.clone())
                                .map_err(|e| e.to_string())?;
                            tasarut_core::revocable::decrypt_with_control(
                                &file.path,
                                &target,
                                &password,
                                &options.keyfiles,
                                &mut store,
                                &mut control,
                            )
                            .map(|repair| (Some(repair), None))
                        }
                        Mode::Decrypt if request.deniability => {
                            tasarut_core::decrypt_deniable_with_control(
                                &file.path,
                                &target,
                                &password,
                                &options.keyfiles,
                                &mut control,
                            )
                            .map(|report| (Some(report), None))
                        }
                        Mode::Decrypt if request.force_decrypt => {
                            tasarut_core::force_decrypt_with_control(
                                &file.path,
                                &target,
                                &password,
                                &options.keyfiles,
                                &ForceOptions {
                                    max_output_bytes: recovery_limit,
                                },
                                &mut control,
                            )
                            .map(|report| (Some(report.repair.clone()), Some(report)))
                        }
                        Mode::Decrypt => tasarut_core::decrypt_with_control(
                            &file.path,
                            &target,
                            &password,
                            &options.keyfiles,
                            &mut control,
                        )
                        .map(|report| (Some(report), None)),
                    }
                    .map_err(|e| e.to_string())?;
                    Ok((target, repair, recovery))
                });
                let result = match result {
                    Ok((output, repair, recovery)) => FileResult {
                        source: file.path.clone(),
                        output: Some(output),
                        error: None,
                        repair,
                        recovery,
                    },
                    Err(error) => FileResult {
                        source: file.path.clone(),
                        output: None,
                        error: Some(error),
                        repair: None,
                        recovery: None,
                    },
                };
                drop(created_dirs);
                let cancelled = result.error.as_deref() == Some("operation_cancelled");
                let byte_progress = ByteProgress {
                    phase: if cancelled {
                        ProgressPhase::Cancelled
                    } else if result.error.is_some() {
                        ProgressPhase::Failed
                    } else {
                        ProgressPhase::Complete
                    },
                    ..ByteProgress::default()
                };
                let _ = app.emit(
                    "tasarut-progress",
                    Progress {
                        id: request.id.clone(),
                        completed: index + usize::from(!cancelled),
                        total,
                        current: file.path,
                        result: Some(result.clone()),
                        byte_progress,
                    },
                );
                result
            },
            |index, file| {
                let _ = app.emit(
                    "tasarut-progress",
                    Progress {
                        id: request.id.clone(),
                        completed: index,
                        total,
                        current: file.path.clone(),
                        result: None,
                        byte_progress: ByteProgress {
                            phase: ProgressPhase::Cancelled,
                            ..ByteProgress::default()
                        },
                    },
                );
            },
        );
        Ok(results)
    })
    .await
    .map_err(|e| e.to_string())?
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(JobState::default())
        .manage(deletion::DeletionState::default())
        .manage(revocation::ReviewState::default())
        .setup(|app| {
            // Keep a running batch alive until it can clean up its temporary output.
            let window = app.get_webview_window("main").expect("main window");
            let handle = app.handle().clone();
            window.on_window_event(move |event| {
                if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                    if handle.state::<JobState>().is_running() {
                        api.prevent_close();
                    }
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            inspect_volume,
            collect_files,
            generate_password,
            run_batch,
            cancel_batch,
            profile_io::read_profile_document,
            profile_io::write_profile_document,
            deletion::prepare_deletion,
            deletion::run_deletion,
            deletion::discard_deletion,
            deletion::refresh_deletion_selection,
            tpm::revocable_status,
            revocation::prepare_revocation,
            revocation::run_revocation,
            revocation::discard_revocation
        ])
        .run(tauri::generate_context!())
        .expect("failed to run Tasarut");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frontend_mib_settings_reach_the_batch_request() {
        let request: BatchRequest = serde_json::from_value(serde_json::json!({
            "id": "profile", "mode": "encrypt", "paths": [], "selectedPaths": [],
            "outputDirectory": "/tmp", "password": "example", "keyfiles": [],
            "comment": "", "compress": false, "recursive": false,
            "chunkSizeMiB": 250, "recoveryLimitMiB": 2
        }))
        .unwrap();
        assert_eq!(request.chunk_size_mib, Some(250));
        assert_eq!(request.recovery_limit_mib, 2);
    }

    #[test]
    fn cancellation_is_scoped_to_the_active_job_and_cleanup_keeps_it_running() {
        let state = JobState::default();
        assert!(!state.cancel("absent"));
        let first = state.start("first").unwrap();
        assert!(state.is_running());
        assert!(!state.cancel("other"));
        assert!(!first.cancellation.is_cancelled());
        assert!(state.cancel("first"));
        assert!(state.cancel("first"));
        assert!(first.cancellation.is_cancelled());
        assert!(state.is_running());
        assert!(matches!(state.start("second"), Err(message) if message == "job_running"));
        drop(first);
        assert!(!state.is_running());
        let second = state.start("second").unwrap();
        assert!(!state.cancel("first"));
        assert!(!second.cancellation.is_cancelled());
        drop(second);
        assert!(!state.cancel("second"));
    }

    #[test]
    fn cancelled_batches_keep_finished_results_and_do_not_start_pending_files() {
        let dir = tempfile::tempdir().unwrap();
        for cancel_between_files in [false, true] {
            let token = CancellationToken::default();
            let files: Vec<_> = (0..3)
                .map(|i| InputFile {
                    path: PathBuf::from(format!("input{i}")),
                    relative_path: PathBuf::from(format!("input{i}")),
                    size: 3,
                    volume: false,
                    revocable: false,
                })
                .collect();
            let mut started = Vec::new();
            let results = process_files(
                files,
                &token,
                |index, file| {
                    started.push(index);
                    if index == 0 {
                        let output = dir.path().join(format!("finished-{cancel_between_files}"));
                        std::fs::write(&output, b"keep me").unwrap();
                        if cancel_between_files {
                            token.cancel();
                        }
                        FileResult {
                            source: file.path,
                            output: Some(output),
                            error: None,
                            repair: None,
                            recovery: None,
                        }
                    } else {
                        token.cancel();
                        FileResult {
                            source: file.path,
                            output: None,
                            error: Some("operation_cancelled".into()),
                            repair: None,
                            recovery: None,
                        }
                    }
                },
                |_, _| {},
            );
            assert_eq!(
                started,
                if cancel_between_files {
                    vec![0]
                } else {
                    vec![0, 1]
                }
            );
            assert_eq!(
                std::fs::read(results[0].output.as_ref().unwrap()).unwrap(),
                b"keep me"
            );
            assert_eq!(
                results[1].error.as_deref(),
                Some(if cancel_between_files {
                    "not_processed"
                } else {
                    "operation_cancelled"
                })
            );
            assert_eq!(results[2].error.as_deref(), Some("not_processed"));
            assert!(results[1..].iter().all(|result| result.output.is_none()));
        }
    }

    #[test]
    fn preparation_cleans_only_new_empty_output_directories() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir(root.join("existing")).unwrap();
        {
            let mut created = CreatedDirectories::default();
            destination_impl(
                root,
                Path::new("existing/new/nested/file"),
                Mode::Encrypt,
                false,
                &mut created,
                None,
            )
            .unwrap();
            assert!(root.join("existing/new/nested").exists());
        }
        assert!(root.join("existing").exists());
        assert!(!root.join("existing/new").exists());
        {
            let mut created = CreatedDirectories::default();
            let output = destination_impl(
                root,
                Path::new("existing/new/file"),
                Mode::Encrypt,
                false,
                &mut created,
                None,
            )
            .unwrap();
            std::fs::write(&output, b"committed").unwrap();
        }
        assert_eq!(
            std::fs::read(root.join("existing/new/file.tasarut")).unwrap(),
            b"committed"
        );
    }

    #[test]
    fn progress_gate_throttles_buffers_but_keeps_phase_changes_and_endpoints() {
        let start = Instant::now();
        let mut gate = ProgressGate::new(start);
        let mut progress = ByteProgress {
            phase: ProgressPhase::Encrypting,
            processed_bytes: 0,
            total_bytes: Some(1000),
        };
        assert!(gate.should_emit(progress, start));
        assert!(!gate.should_emit(progress, start));
        for i in 1..10 {
            progress.processed_bytes = i * 10;
            assert!(!gate.should_emit(progress, start + Duration::from_millis(i)));
        }
        progress.processed_bytes = 500;
        assert!(gate.should_emit(progress, start + Duration::from_millis(100)));
        progress.processed_bytes = 1000;
        assert!(gate.should_emit(progress, start + Duration::from_millis(101)));
        progress = ByteProgress {
            phase: ProgressPhase::KeyDerivation,
            ..ByteProgress::default()
        };
        assert!(gate.should_emit(progress, start + Duration::from_millis(102)));
        progress.phase = ProgressPhase::Decrypting;
        progress.total_bytes = Some(2000);
        assert!(gate.should_emit(progress, start + Duration::from_millis(103)));
        progress.phase = ProgressPhase::Failed;
        progress.total_bytes = None;
        assert!(gate.should_emit(progress, start + Duration::from_millis(104)));
    }

    #[test]
    fn output_names_and_traversal_are_checked() {
        let root = Path::new("/tmp");
        assert_eq!(
            destination(root, Path::new("report.pdf"), Mode::Encrypt, false).unwrap(),
            root.join("report.pdf.tasarut")
        );
        assert_eq!(
            destination(root, Path::new("report.pdf.tasarut"), Mode::Decrypt, false).unwrap(),
            root.join("report.pdf")
        );
        assert!(destination(root, Path::new("../escape"), Mode::Encrypt, false).is_err());
        assert!(destination(root, Path::new("/escape"), Mode::Encrypt, false).is_err());
        assert!(destination(root, Path::new(".tasarut"), Mode::Decrypt, false).is_err());
        assert_eq!(
            destination(
                root,
                Path::new("report.pdf.tasarut.parts"),
                Mode::Decrypt,
                false
            )
            .unwrap(),
            root.join("report.pdf")
        );
        assert!(destination(root, Path::new(".tasarut.parts"), Mode::Decrypt, false).is_err());
        assert_eq!(
            recovered_destination(
                destination(root, Path::new("report.pdf.tasarut"), Mode::Decrypt, false).unwrap()
            ),
            root.join("report.pdf.recovered")
        );
        assert_eq!(
            destination(root, Path::new("report.pdf"), Mode::Encrypt, true).unwrap(),
            root.join("report.pdf.bin")
        );
        assert_eq!(
            destination(root, Path::new("report.pdf.bin"), Mode::Decrypt, true).unwrap(),
            root.join("report.pdf")
        );
        assert_eq!(
            destination(root, Path::new("opaque"), Mode::Decrypt, true).unwrap(),
            root.join("opaque.decrypted")
        );
        assert!(destination(root, Path::new(".bin"), Mode::Decrypt, true).is_err());
    }
}
