use super::JobState;
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    sync::Mutex,
    time::{Duration, Instant},
};
use tasarut_core::{
    deletion::{self, DeletionPreview, DeletionProgress, DeletionReport, PreparedDeletion},
    OperationControl,
};
use tauri::{Emitter, State};
use zeroize::Zeroizing;

#[derive(Default)]
pub(crate) struct DeletionState(Mutex<Option<Review>>);
struct Review {
    token: String,
    created: Instant,
    plan: PreparedDeletion,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReviewView {
    token: String,
    preview: DeletionPreview,
}
#[derive(Serialize, Clone)]
struct Event {
    id: String,
    #[serde(flatten)]
    progress: DeletionProgress,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PrepareRequest {
    id: String,
    paths: Vec<PathBuf>,
    allow_opaque: bool,
    password: String,
    keyfiles: Vec<PathBuf>,
}

impl DeletionState {
    fn store(&self, plan: PreparedDeletion) -> Result<ReviewView, String> {
        let token = tasarut_core::generate_password(32, false).map_err(|e| e.to_string())?;
        let preview = plan.preview.clone();
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = Some(Review {
            token: token.clone(),
            created: Instant::now(),
            plan,
        });
        Ok(ReviewView { token, preview })
    }
    fn take(&self, token: &str) -> Result<PreparedDeletion, String> {
        let mut review = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if review.as_ref().is_none_or(|review| review.token != token) {
            return Err("deletion_review_invalid".into());
        }
        let review = review.take().unwrap();
        if review.created.elapsed() > Duration::from_secs(600) {
            return Err("deletion_review_expired".into());
        }
        if review.plan.preview.total_files == 0 {
            return Err("deletion_empty_plan".into());
        }
        Ok(review.plan)
    }
    fn discard(&self, token: Option<&str>) {
        let mut review = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if token.is_none()
            || review
                .as_ref()
                .is_some_and(|review| Some(review.token.as_str()) == token)
        {
            *review = None;
        }
    }
}

#[tauri::command]
pub(crate) async fn prepare_deletion(
    app: tauri::AppHandle,
    jobs: State<'_, JobState>,
    reviews: State<'_, DeletionState>,
    mut request: PrepareRequest,
) -> Result<ReviewView, String> {
    let password = Zeroizing::new(std::mem::take(&mut request.password));
    let guard = jobs.start(&request.id)?;
    let cancellation = guard.cancellation.clone();
    reviews.discard(None);
    let (guard, plan) = tauri::async_runtime::spawn_blocking(move || {
        let mut last_phase = None;
        let mut progress = |update: tasarut_core::ByteProgress| {
            if last_phase == Some(update.phase) {
                return;
            }
            last_phase = Some(update.phase);
            let _ = app.emit(
                "tasarut-deletion-progress",
                Event {
                    id: request.id.clone(),
                    progress: DeletionProgress {
                        phase: "preparing".into(),
                        current: PathBuf::new(),
                        deleted_files: 0,
                        total_files: 0,
                        deleted_bytes: 0,
                        total_bytes: 0,
                    },
                },
            );
        };
        let plan = deletion::prepare(
            &request.paths,
            request.allow_opaque,
            &password,
            &request.keyfiles,
            &mut OperationControl::new(&cancellation, &mut progress),
        )?;
        Ok::<_, String>((guard, plan))
    })
    .await
    .map_err(|e| e.to_string())??;
    let _guard = guard;
    reviews.store(plan)
}

#[tauri::command]
pub(crate) fn discard_deletion(reviews: State<'_, DeletionState>, token: String) {
    reviews.discard(Some(&token));
}

#[tauri::command]
pub(crate) async fn run_deletion(
    app: tauri::AppHandle,
    jobs: State<'_, JobState>,
    reviews: State<'_, DeletionState>,
    id: String,
    token: String,
    request_trim: bool,
) -> Result<DeletionReport, String> {
    let guard = jobs.start(&id)?;
    let cancellation = guard.cancellation.clone();
    let plan = reviews.take(&token)?;
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = guard;
        deletion::execute(plan, request_trim, &cancellation, &mut |progress| {
            let _ = app.emit(
                "tasarut-deletion-progress",
                Event {
                    id: id.clone(),
                    progress,
                },
            );
        })
    })
    .await
    .map_err(|e| e.to_string())
}

#[derive(Serialize)]
pub(crate) struct Selection {
    paths: Vec<PathBuf>,
    files: Vec<tasarut_core::InputFile>,
}
#[tauri::command]
pub(crate) async fn refresh_deletion_selection(
    paths: Vec<PathBuf>,
    recursive: bool,
) -> Result<Selection, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let mut retained = Vec::new();
        for path in paths {
            match std::fs::symlink_metadata(&path) {
                Ok(_) => retained.push(path),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.to_string()),
            }
        }
        let files =
            tasarut_core::collect_inputs(&retained, recursive).map_err(|e| e.to_string())?;
        Ok(Selection {
            paths: retained,
            files,
        })
    })
    .await
    .map_err(|e| e.to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;
    use tasarut_core::{CancellationToken, EncryptOptions};
    #[test]
    fn storage_observations_use_the_frontend_json_contract() {
        use tasarut_core::deletion::{
            FilesystemView, StorageDevice, StorageInfo, StorageKind, TrimResult,
        };
        let view = FilesystemView {
            directory: PathBuf::from("/test"),
            device: "123".into(),
            filesystem: "ext4".into(),
            storage: StorageInfo {
                kind: StorageKind::NonRotational,
                block_device: Some("dm-0".into()),
                backing_devices: vec![StorageDevice {
                    name: "sda".into(),
                    kind: StorageKind::NonRotational,
                }],
                discard_max_bytes: Some(0),
            },
        };
        let preview = serde_json::to_value(&view).unwrap();
        assert_eq!(preview["storage"]["kind"], "nonRotational");
        assert_eq!(preview["storage"]["blockDevice"], "dm-0");
        assert_eq!(preview["storage"]["backingDevices"][0]["name"], "sda");
        assert_eq!(preview["storage"]["discardMaxBytes"], 0);
        let result = TrimResult {
            directory: view.directory,
            device: view.device,
            filesystem: view.filesystem,
            storage: StorageInfo::default(),
            status: "notRequested".into(),
            reported_bytes: None,
            error: None,
        };
        let report = serde_json::to_value(&result).unwrap();
        assert_eq!(report["storage"]["kind"], "unknown");
        assert!(report["storage"]["discardMaxBytes"].is_null());
        assert!(report["storage"]["blockDevice"].is_null());
        assert_eq!(report["storage"]["backingDevices"], serde_json::json!([]));
    }
    #[test]
    fn reviewed_selection_is_single_use_and_old_tokens_do_not_affect_new_reviews() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let encrypted = dir.path().join("volume");
        std::fs::write(&source, b"private data").unwrap();
        tasarut_core::encrypt(&source, &encrypted, "password", &EncryptOptions::default()).unwrap();
        let make_plan = || {
            deletion::prepare(
                std::slice::from_ref(&encrypted),
                false,
                "",
                &[],
                &mut OperationControl::new(&CancellationToken::default(), &mut |_| {}),
            )
            .unwrap()
        };
        let reviews = DeletionState::default();
        let first = reviews.store(make_plan()).unwrap();
        assert!(reviews.take("wrong-token").is_err());
        let second = reviews.store(make_plan()).unwrap();
        reviews.discard(Some(&first.token));
        assert!(reviews.take(&first.token).is_err());
        let _plan = reviews.take(&second.token).unwrap();
        assert!(reviews.take(&second.token).is_err());
        assert!(encrypted.exists());
        let expired = reviews.store(make_plan()).unwrap();
        reviews.0.lock().unwrap().as_mut().unwrap().created =
            Instant::now() - Duration::from_secs(601);
        assert!(
            matches!(reviews.take(&expired.token), Err(message) if message == "deletion_review_expired")
        );
        assert!(encrypted.exists());
    }
}
