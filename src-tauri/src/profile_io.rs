//! Bounded profile-document I/O. Only the preference schema can be exported;
//! passwords, keyfile contents and operation requests are not part of it.
use serde::{Deserialize, Deserializer};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};

const MAX_BYTES: u64 = 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    format: String,
    version: u32,
    profiles: Vec<Profile>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    name: String,
    settings: Settings,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Settings {
    #[serde(default)]
    algorithm: tasarut_core::CipherAlgorithm,
    compress: bool,
    paranoid: bool,
    reed_solomon: bool,
    chunks: bool,
    #[serde(rename = "chunkSizeMiB")]
    chunk_size_mib: u64,
    deniability: bool,
    #[serde(default)]
    revocable: bool,
    recursive: bool,
    generator_length: u64,
    generator_symbols: bool,
    #[serde(default, deserialize_with = "optional_path")]
    output_directory: Option<String>,
}
fn optional_path<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    String::deserialize(deserializer).map(Some)
}

fn validate(text: &str) -> Result<(), String> {
    if text.len() as u64 > MAX_BYTES {
        return Err("profile_document_too_large".into());
    }
    let document: Document = serde_json::from_str(text).map_err(|_| "invalid_profile_document")?;
    if document.format != "tasarut-profiles" {
        return Err("invalid_profile_document".into());
    }
    if document.version != 1 {
        return Err("profile_version_unsupported".into());
    }
    if document.profiles.is_empty() {
        return Err("invalid_profile_document".into());
    }
    if document.profiles.len() > 100 {
        return Err("profile_limit_reached".into());
    }
    for profile in document.profiles {
        if profile.name.trim().is_empty()
            || profile.name.trim().chars().count() > 120
            || profile.name.chars().any(|c| c <= '\u{1f}' || c == '\u{7f}')
        {
            return Err("profile_invalid_name".into());
        }
        let settings = profile.settings;
        if settings.algorithm == tasarut_core::CipherAlgorithm::Threefish1024 && settings.paranoid {
            return Err("cipher_incompatible_options".into());
        }
        if settings.deniability && settings.chunks {
            return Err("profile_incompatible_options".into());
        }
        if settings.revocable && (settings.deniability || settings.chunks) {
            return Err("revocable_incompatible_options".into());
        }
        if !(1..=1048576).contains(&settings.chunk_size_mib)
            || !(16..=128).contains(&settings.generator_length)
        {
            return Err("invalid_profile_document".into());
        }
        if let Some(path) = settings.output_directory {
            let windows_drive = path.as_bytes().get(..3).is_some_and(|p| {
                p[0].is_ascii_alphabetic() && p[1] == b':' && (p[2] == b'/' || p[2] == b'\\')
            });
            if path.trim().is_empty()
                || path.len() > 4096
                || path.chars().any(|c| c <= '\u{1f}' || c == '\u{7f}')
                || !(path.starts_with('/') || path.starts_with("\\\\") || windows_drive)
            {
                return Err("profile_invalid_folder".into());
            }
        }
        // Read these typed fields as part of schema validation; their combinations
        // are supported by the engine and introduce no configurable KDF parameters.
        let _ = (
            settings.compress,
            settings.paranoid,
            settings.reed_solomon,
            settings.recursive,
            settings.generator_symbols,
        );
    }
    Ok(())
}

fn read_document(path: &Path) -> Result<String, String> {
    if !fs::symlink_metadata(path)
        .map_err(|e| e.to_string())?
        .file_type()
        .is_file()
    {
        return Err("invalid_profile_document".into());
    }
    let file = File::open(path).map_err(|e| e.to_string())?;
    if file.metadata().map_err(|e| e.to_string())?.len() > MAX_BYTES {
        return Err("profile_document_too_large".into());
    }
    let mut text = String::new();
    file.take(MAX_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|_| "invalid_profile_document")?;
    validate(&text)?;
    Ok(text)
}

fn write_document(path: &Path, text: &str) -> Result<(), String> {
    validate(text)?;
    if !path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
    {
        return Err("invalid_profile_document".into());
    }
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_file() => {}
        Ok(_) => return Err("invalid_profile_document".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(|e| e.to_string())?;
    temporary
        .write_all(text.as_bytes())
        .map_err(|e| e.to_string())?;
    temporary.as_file().sync_all().map_err(|e| e.to_string())?;
    // The native save dialog chooses/confirms the destination. Rename publishes
    // a complete JSON document, including when replacing an existing export.
    temporary.persist(path).map_err(|e| e.error.to_string())?;
    Ok(())
}

#[tauri::command]
pub(crate) async fn read_profile_document(path: PathBuf) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || read_document(&path))
        .await
        .map_err(|e| e.to_string())?
}
#[tauri::command]
pub(crate) async fn write_profile_document(path: PathBuf, document: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || write_document(&path, &document))
        .await
        .map_err(|e| e.to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;
    fn valid() -> String {
        serde_json::json!({ "format": "tasarut-profiles", "version": 1, "profiles": [{ "name": "Azul — sauvegarde", "settings": {
            "compress": true, "paranoid": false, "reedSolomon": true, "chunks": false, "chunkSizeMiB": 100,
            "deniability": false, "recursive": true, "generatorLength": 32, "generatorSymbols": true
        }}]}).to_string()
    }
    #[test]
    fn profile_exports_are_atomic_and_reject_invalid_preferences_without_overwriting() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profiles.json");
        let original = valid();
        write_document(&path, &original).unwrap();
        assert_eq!(read_document(&path).unwrap(), original);
        for (field, value) in [
            ("password", serde_json::json!("secret")),
            ("forceDecrypt", serde_json::json!(true)),
            ("generatorLength", serde_json::json!(15)),
            ("chunkSizeMiB", serde_json::json!(0)),
            ("outputDirectory", serde_json::json!(null)),
        ] {
            let mut document: serde_json::Value = serde_json::from_str(&original).unwrap();
            document["profiles"][0]["settings"][field] = value;
            assert!(write_document(&path, &document.to_string()).is_err());
            assert_eq!(fs::read_to_string(&path).unwrap(), original);
        }
        let mut incompatible: serde_json::Value = serde_json::from_str(&original).unwrap();
        incompatible["profiles"][0]["settings"]["deniability"] = true.into();
        incompatible["profiles"][0]["settings"]["chunks"] = true.into();
        assert_eq!(
            validate(&incompatible.to_string()).unwrap_err(),
            "profile_incompatible_options"
        );
        write_document(&path, &original.replace("sauvegarde", "transfert")).unwrap();
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
        assert!(write_document(&dir.path().join("file.tasarut"), &original).is_err());
    }
    #[test]
    fn profile_imports_are_bounded_and_do_not_follow_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profiles.json");
        fs::write(&path, vec![b' '; MAX_BYTES as usize + 1]).unwrap();
        assert_eq!(
            read_document(&path).unwrap_err(),
            "profile_document_too_large"
        );
        fs::write(&path, valid()).unwrap();
        #[cfg(unix)]
        {
            let link = dir.path().join("link.json");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(read_document(&link).is_err());
            assert!(write_document(&link, &valid()).is_err());
            assert_eq!(fs::read_to_string(&path).unwrap(), valid());
        }
    }

    #[test]
    fn cipher_preference_is_backward_compatible_and_rejects_unknown_or_conflicting_suites() {
        let original = valid();
        validate(&original).unwrap();
        let mut document: serde_json::Value = serde_json::from_str(&original).unwrap();
        document["profiles"][0]["settings"]["algorithm"] = "threefish1024".into();
        validate(&document.to_string()).unwrap();
        document["profiles"][0]["settings"]["paranoid"] = true.into();
        assert_eq!(
            validate(&document.to_string()).unwrap_err(),
            "cipher_incompatible_options"
        );
        document["profiles"][0]["settings"]["paranoid"] = false.into();
        document["profiles"][0]["settings"]["algorithm"] = "unknown".into();
        assert_eq!(
            validate(&document.to_string()).unwrap_err(),
            "invalid_profile_document"
        );
    }
}
