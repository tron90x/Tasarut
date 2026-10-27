use super::{tpm::TpmStore, JobState, Progress, ProgressGate};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::PathBuf,
    sync::Mutex,
    time::{Duration, Instant},
};
use tasarut_core::{ByteProgress, OperationControl};
use tauri::{Emitter, State};
use zeroize::Zeroizing;

#[derive(Default)]
pub(crate) struct ReviewState(Mutex<Option<Review>>);
#[derive(Clone, PartialEq)]
struct Identity {
    device: u64,
    inode: u64,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}
fn identity(path: &PathBuf) -> Result<Identity, String> {
    if fs::canonicalize(path).map_err(|e| e.to_string())? != *path {
        return Err("revocable_invalid_path".into());
    }
    let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !meta.file_type().is_file() {
        return Err("invalid_input".into());
    }
    Ok(Identity {
        device: meta.dev(),
        inode: meta.ino(),
        length: meta.len(),
        modified: (meta.mtime(), meta.mtime_nsec()),
        changed: (meta.ctime(), meta.ctime_nsec()),
    })
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Item {
    source: PathBuf,
    identifier: Option<String>,
    index: Option<String>,
    error: Option<String>,
}
struct Review {
    token: String,
    created: Instant,
    items: Vec<(Item, Option<Identity>)>,
}
#[derive(Serialize)]
pub(crate) struct Preview {
    token: String,
    items: Vec<Item>,
}

#[tauri::command]
pub(crate) async fn prepare_revocation(
    jobs: State<'_, JobState>,
    reviews: State<'_, ReviewState>,
    id: String,
    paths: Vec<PathBuf>,
) -> Result<Preview, String> {
    let guard = jobs.start(&id)?;
    if paths.is_empty() || paths.len() > 1000 {
        return Err("invalid_input".into());
    }
    let (guard, items) = tauri::async_runtime::spawn_blocking(move || {
        let mut items = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for source in paths {
            guard.cancellation.check().map_err(|e| e.to_string())?;
            if !seen.insert(source.clone()) {
                continue;
            }
            let result = identity(&source).and_then(|snapshot| {
                let info = tasarut_core::inspect(&source).map_err(|e| e.to_string())?;
                if !info.revocable {
                    return Err("revocable_not_volume".into());
                }
                if identity(&source)? != snapshot {
                    return Err("source_changed".into());
                }
                Ok((info, snapshot))
            });
            match result {
                Ok((info, snapshot)) => items.push((
                    Item {
                        source,
                        identifier: info.revocable_id,
                        index: info.revocable_index,
                        error: None,
                    },
                    Some(snapshot),
                )),
                Err(error) => items.push((
                    Item {
                        source,
                        identifier: None,
                        index: None,
                        error: Some(error),
                    },
                    None,
                )),
            }
        }
        Ok::<_, String>((guard, items))
    })
    .await
    .map_err(|e| e.to_string())??;
    let _guard = guard;
    let token = tasarut_core::generate_password(32, false).map_err(|e| e.to_string())?;
    let view = items.iter().map(|(item, _)| item.clone()).collect();
    *reviews.0.lock().unwrap_or_else(|e| e.into_inner()) = Some(Review {
        token: token.clone(),
        created: Instant::now(),
        items,
    });
    Ok(Preview { token, items: view })
}
#[tauri::command]
pub(crate) fn discard_revocation(reviews: State<'_, ReviewState>, token: String) {
    let mut review = reviews.0.lock().unwrap_or_else(|e| e.into_inner());
    if review.as_ref().is_some_and(|review| review.token == token) {
        *review = None;
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Request {
    id: String,
    token: String,
    password: String,
    keyfiles: Vec<PathBuf>,
    tpm_owner_auth: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ResultItem {
    source: PathBuf,
    identifier: Option<String>,
    index: Option<String>,
    revoked: bool,
    hardware_absence_confirmed: bool,
    error: Option<String>,
}

#[tauri::command]
pub(crate) async fn run_revocation(
    app: tauri::AppHandle,
    jobs: State<'_, JobState>,
    reviews: State<'_, ReviewState>,
    mut request: Request,
) -> Result<Vec<ResultItem>, String> {
    let password = Zeroizing::new(std::mem::take(&mut request.password));
    let owner = Zeroizing::new(std::mem::take(&mut request.tpm_owner_auth));
    let guard = jobs.start(&request.id)?;
    let review = {
        let mut review = reviews.0.lock().unwrap_or_else(|e| e.into_inner());
        if review
            .as_ref()
            .is_none_or(|review| review.token != request.token)
        {
            return Err("revocable_review_invalid".into());
        }
        review.take().unwrap()
    };
    if review.created.elapsed() > Duration::from_secs(600) {
        return Err("revocable_review_expired".into());
    }
    tauri::async_runtime::spawn_blocking(move || {
        let total = review.items.len();
        let mut results = Vec::with_capacity(total);
        for (position, (item, snapshot)) in review.items.into_iter().enumerate() {
            let mut result = ResultItem {
                source: item.source.clone(),
                identifier: item.identifier,
                index: item.index,
                revoked: false,
                hardware_absence_confirmed: false,
                error: item.error,
            };
            if guard.cancellation.is_cancelled() {
                result.error = Some("not_processed".into());
            } else if let Some(snapshot) = snapshot {
                let attempt = (|| {
                    if identity(&item.source)? != snapshot {
                        return Err("source_changed".into());
                    }
                    let mut store = TpmStore::new(owner.clone()).map_err(|e| e.to_string())?;
                    let mut gate = ProgressGate::new(Instant::now());
                    let mut on_progress = |update: ByteProgress| {
                        if gate.should_emit(update, Instant::now()) {
                            let _ = app.emit(
                                "tasarut-progress",
                                Progress {
                                    id: request.id.clone(),
                                    completed: position,
                                    total,
                                    current: item.source.clone(),
                                    result: None,
                                    byte_progress: update,
                                },
                            );
                        }
                    };
                    tasarut_core::revocable::revoke_with_control(
                        &item.source,
                        &password,
                        &request.keyfiles,
                        &mut store,
                        &mut OperationControl::new(&guard.cancellation, &mut on_progress),
                    )
                    .map_err(|e| e.to_string())
                })();
                match attempt {
                    Ok(report) => {
                        result.revoked = true;
                        result.hardware_absence_confirmed = report.hardware_absence_confirmed;
                        result.error = None;
                    }
                    Err(error) => result.error = Some(error),
                }
            }
            results.push(result);
        }
        results
    })
    .await
    .map_err(|e| e.to_string())
}
