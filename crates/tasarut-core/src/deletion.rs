//! Reviewed, no-follow deletion of Tasarut containers. No overwrite passes,
//! raw-device commands or assertion of physical erasure are performed.
use crate::{CancellationToken, Error, Header, OperationControl, Tracker};
use rand::{rngs::OsRng, Rng};
use rustix::fs::{self as rfs, AtFlags, Mode, OFlags, RenameFlags};
use serde::Serialize;
use std::{
    collections::HashSet,
    ffi::{OsStr, OsString},
    fs::{File, Metadata},
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

mod storage;
pub use storage::{StorageDevice, StorageInfo, StorageKind};

const MAX_TARGETS: usize = 1000;
const MAX_MEMBERS: usize = 65537;
const MAX_PATH_BYTES: usize = 16 * 1024 * 1024;
const MANIFEST: &str = "manifest.tasarut";

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewItem {
    pub source: PathBuf,
    pub kind: String,
    pub members: Vec<PathBuf>,
    pub bytes: u64,
    pub missing_parts: u64,
    pub error: Option<String>,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FilesystemView {
    pub directory: PathBuf,
    pub device: String,
    pub filesystem: String,
    pub storage: StorageInfo,
}
#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeletionPreview {
    pub items: Vec<PreviewItem>,
    pub total_files: usize,
    pub total_bytes: u64,
    pub filesystems: Vec<FilesystemView>,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeletionResult {
    pub source: PathBuf,
    pub kind: String,
    pub status: String,
    pub deleted_files: usize,
    pub deleted_bytes: u64,
    pub remaining: Vec<PathBuf>,
    pub planned: Vec<PathBuf>,
    pub disappearance_confirmed: bool,
    pub directory_removed: bool,
    pub synchronization_error: Option<String>,
    pub error: Option<String>,
    pub recovery_path: Option<PathBuf>,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrimResult {
    pub directory: PathBuf,
    pub device: String,
    pub filesystem: String,
    pub storage: StorageInfo,
    pub status: String,
    pub reported_bytes: Option<u64>,
    pub error: Option<String>,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeletionReport {
    pub results: Vec<DeletionResult>,
    pub trim: Vec<TrimResult>,
    pub cancelled: bool,
    pub deleted_files: usize,
    pub deleted_bytes: u64,
    pub physical_erasure_verified: bool,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeletionProgress {
    pub phase: String,
    pub current: PathBuf,
    pub deleted_files: usize,
    pub total_files: usize,
    pub deleted_bytes: u64,
    pub total_bytes: u64,
}

#[derive(Clone)]
struct Anchor {
    path: PathBuf,
    fd: Arc<File>,
    device: u64,
    inode: u64,
}
#[derive(Clone, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
    mode: u32,
    links: u64,
}
impl Identity {
    fn from(meta: &Metadata) -> Self {
        Self {
            device: meta.dev(),
            inode: meta.ino(),
            size: meta.len(),
            modified: (meta.mtime(), meta.mtime_nsec()),
            changed: (meta.ctime(), meta.ctime_nsec()),
            mode: meta.mode(),
            links: meta.nlink(),
        }
    }
    fn same_after_rename(&self, other: &Self) -> bool {
        self.device == other.device
            && self.inode == other.inode
            && self.size == other.size
            && self.modified == other.modified
            && self.mode == other.mode
            && self.links == other.links
    }
}
#[derive(Clone)]
struct Member {
    path: PathBuf,
    name: OsString,
    anchor: Anchor,
    identity: Identity,
}
struct Target {
    members: Vec<Member>,
    directory: Option<(Member, Anchor)>,
}
pub struct PreparedDeletion {
    pub preview: DeletionPreview,
    targets: Vec<Option<Target>>,
    filesystems: Vec<Anchor>,
}

fn open_directory(path: &Path) -> Result<Anchor, String> {
    if !path.is_absolute() {
        return Err("deletion_invalid_path".into());
    }
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut fd = File::from(rfs::open("/", flags, Mode::empty()).map_err(|e| e.to_string())?);
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                fd = File::from(
                    rfs::openat(&fd, name, flags, Mode::empty())
                        .map_err(|_| "deletion_invalid_path")?,
                );
            }
            _ => return Err("deletion_invalid_path".into()),
        }
    }
    let meta = fd.metadata().map_err(|e| e.to_string())?;
    Ok(Anchor {
        path: path.to_owned(),
        fd: Arc::new(fd),
        device: meta.dev(),
        inode: meta.ino(),
    })
}
fn check_anchor(anchor: &Anchor) -> Result<(), String> {
    let current = open_directory(&anchor.path)?;
    if current.device != anchor.device || current.inode != anchor.inode {
        return Err("source_changed".into());
    }
    Ok(())
}
fn open_member(anchor: &Anchor, name: &OsStr) -> Result<File, String> {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let file = File::from(
        rfs::openat(anchor.fd.as_ref(), name, flags, Mode::empty()).map_err(|e| e.to_string())?,
    );
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("deletion_unrecognized".into());
    }
    Ok(file)
}
fn member(
    anchor: &Anchor,
    name: &OsStr,
    protected: &HashSet<(u64, u64)>,
) -> Result<(Member, File), String> {
    let file = open_member(anchor, name)?;
    let identity = Identity::from(&file.metadata().map_err(|e| e.to_string())?);
    if protected.contains(&(identity.device, identity.inode)) {
        return Err("deletion_protected_keyfile".into());
    }
    if identity.links != 1 {
        return Err("deletion_multiple_links".into());
    }
    Ok((
        Member {
            path: anchor.path.join(name),
            name: name.to_owned(),
            anchor: anchor.clone(),
            identity,
        },
        file,
    ))
}
fn directory_names(anchor: &Anchor) -> Result<HashSet<OsString>, String> {
    let dir = rfs::Dir::read_from(anchor.fd.as_ref()).map_err(|e| e.to_string())?;
    let mut names = HashSet::new();
    for entry in dir {
        let entry = entry.map_err(|e| e.to_string())?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        use std::os::unix::ffi::OsStrExt;
        names.insert(OsStr::from_bytes(bytes).to_owned());
        if names.len() > MAX_MEMBERS {
            return Err("deletion_limit".into());
        }
    }
    Ok(names)
}
fn absence(anchor: &Anchor, name: &OsStr) -> bool {
    matches!(
        rfs::statat(anchor.fd.as_ref(), name, AtFlags::SYMLINK_NOFOLLOW),
        Err(rustix::io::Errno::NOENT)
    )
}
fn filesystem(anchor: &Anchor) -> FilesystemView {
    let kind: String = rfs::fstatfs(anchor.fd.as_ref())
        .map(|stat| match stat.f_type as u64 {
            0xef53 => "ext4".into(),
            0x9123683e => "btrfs".into(),
            0x58465342 => "xfs".into(),
            0xf2f52010 => "f2fs".into(),
            0x01021994 => "tmpfs".into(),
            0x794c7630 => "overlayfs".into(),
            value => format!("0x{value:x}"),
        })
        .unwrap_or_else(|_| "unknown".into());
    FilesystemView {
        directory: anchor.path.clone(),
        device: anchor.device.to_string(),
        storage: storage::detect(anchor.device, &kind),
        filesystem: kind,
    }
}

fn prepare_set(
    path: &Path,
    anchor: Anchor,
    protected: &HashSet<(u64, u64)>,
    tracker: &Tracker<'_>,
) -> Result<(PreviewItem, Target), String> {
    let parent = open_directory(path.parent().ok_or("deletion_invalid_path")?)?;
    if parent.device != anchor.device {
        return Err("deletion_mounted_set".into());
    }
    let name = path.file_name().ok_or("deletion_invalid_path")?.to_owned();
    let directory = Member {
        path: path.to_owned(),
        name,
        anchor: parent,
        identity: Identity::from(&anchor.fd.metadata().map_err(|e| e.to_string())?),
    };
    let (manifest, mut file) = member(&anchor, OsStr::new(MANIFEST), protected)?;
    let length = file.metadata().map_err(|e| e.to_string())?.len();
    if !(156..=28 + 65536 * 64 + 64).contains(&length) {
        return Err("invalid_chunk_manifest".into());
    }
    let mut header = [0; 28];
    file.read_exact(&mut header)
        .map_err(|_| "invalid_chunk_manifest")?;
    let bytes = u64::from_le_bytes(header[8..16].try_into().unwrap());
    let size = u64::from_le_bytes(header[16..24].try_into().unwrap());
    let count = u32::from_le_bytes(header[24..28].try_into().unwrap());
    if &header[..8] != b"TASPART\x01"
        || !(1024..=1 << 40).contains(&size)
        || bytes == 0
        || count == 0
        || count > 65536
        || bytes.div_ceil(size) != u64::from(count)
        || length != 28 + u64::from(count) * 64 + 64
    {
        return Err("invalid_chunk_manifest".into());
    }
    let names = directory_names(&anchor)?;
    use std::os::unix::ffi::OsStrExt;
    if (path.as_os_str().as_bytes().len() + 20).saturating_mul(names.len()) > MAX_PATH_BYTES {
        return Err("deletion_limit".into());
    }
    let expected: HashSet<_> = (1..=count)
        .map(|index| OsString::from(format!("{index:06}.part")))
        .chain([OsString::from(MANIFEST)])
        .collect();
    if names.iter().any(|name| !expected.contains(name)) {
        return Err("deletion_unexpected_entries".into());
    }
    let mut members = Vec::new();
    for index in 1..=count {
        tracker.checkpoint().map_err(|e| e.to_string())?;
        let name = OsString::from(format!("{index:06}.part"));
        if names.contains(&name) {
            members.push(member(&anchor, &name, protected)?.0);
        }
    }
    let missing_parts = u64::from(count) - members.len() as u64;
    // Keep the descriptor until the final file removal, including on cancellation.
    members.push(manifest);
    let total = members
        .iter()
        .try_fold(0u64, |sum, entry| sum.checked_add(entry.identity.size))
        .ok_or("deletion_limit")?;
    let view = PreviewItem {
        source: path.to_owned(),
        kind: "chunks".into(),
        members: members.iter().map(|member| member.path.clone()).collect(),
        bytes: total,
        missing_parts,
        error: None,
    };
    Ok((
        view,
        Target {
            members,
            directory: Some((directory, anchor)),
        },
    ))
}

fn prepare_one(
    path: &Path,
    protected: &HashSet<(u64, u64)>,
    allow_opaque: bool,
    password: &str,
    keyfiles: &[PathBuf],
    tracker: &mut Tracker<'_>,
) -> Result<(PreviewItem, Target), String> {
    let parent = open_directory(path.parent().ok_or("deletion_invalid_path")?)?;
    let name = path.file_name().ok_or("deletion_invalid_path")?;
    let stat = rfs::statat(parent.fd.as_ref(), name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|e| e.to_string())?;
    if rfs::FileType::from_raw_mode(stat.st_mode) == rfs::FileType::Directory {
        return prepare_set(path, open_directory(path)?, protected, tracker);
    }
    let (member, mut file) = member(&parent, name, protected)?;
    let recognised =
        crate::recovery::VolumeReader::open(file.try_clone().map_err(|e| e.to_string())?, true)
            .and_then(|mut reader| {
                if crate::revocable::reader_is_revocable(&mut reader)? {
                    crate::revocable::inspect_reader(&mut reader).map(|_| ())
                } else {
                    Header::read_mode(&mut reader, true).map(|_| ())
                }
            })
            .is_ok();
    let kind = if recognised {
        "volume"
    } else if allow_opaque {
        crate::deniable::verify_for_deletion(&mut file, password, keyfiles, tracker)
            .map_err(|e| e.to_string())?;
        "opaque"
    } else {
        return Err("deletion_unrecognized".into());
    };
    if Identity::from(&file.metadata().map_err(|e| e.to_string())?) != member.identity {
        return Err("source_changed".into());
    }
    Ok((
        PreviewItem {
            source: path.to_owned(),
            kind: kind.into(),
            members: vec![path.to_owned()],
            bytes: member.identity.size,
            missing_parts: 0,
            error: None,
        },
        Target {
            members: vec![member],
            directory: None,
        },
    ))
}

pub fn prepare(
    paths: &[PathBuf],
    allow_opaque: bool,
    password: &str,
    keyfiles: &[PathBuf],
    control: &mut OperationControl<'_>,
) -> Result<PreparedDeletion, String> {
    if paths.is_empty() || paths.len() > MAX_TARGETS {
        return Err("deletion_limit".into());
    }
    crate::progress::observe_control(control, |tracker| {
        let mut protected = HashSet::new();
        for path in keyfiles {
            if let (Some(parent), Some(name)) = (path.parent(), path.file_name()) {
                if let Ok(anchor) = open_directory(parent) {
                    if let Ok(file) = open_member(&anchor, name) {
                        if let Ok(meta) = file.metadata() {
                            protected.insert((meta.dev(), meta.ino()));
                        }
                    }
                }
            }
        }
        let mut plan = PreparedDeletion {
            preview: DeletionPreview::default(),
            targets: Vec::new(),
            filesystems: Vec::new(),
        };
        let mut seen = HashSet::new();
        let mut path_bytes = 0usize;
        for path in paths {
            tracker.checkpoint()?;
            let source = crate::chunks::root(path)
                .ok()
                .flatten()
                .unwrap_or_else(|| path.clone());
            if !seen.insert(source.clone()) {
                continue;
            }
            match prepare_one(
                &source,
                &protected,
                allow_opaque,
                password,
                keyfiles,
                tracker,
            ) {
                Ok((view, target))
                    if plan.preview.total_files + view.members.len() <= MAX_MEMBERS
                        && path_bytes.saturating_add(
                            view.members
                                .iter()
                                .map(|path| path.as_os_str().len())
                                .sum::<usize>(),
                        ) <= MAX_PATH_BYTES =>
                {
                    path_bytes += view
                        .members
                        .iter()
                        .map(|path| path.as_os_str().len())
                        .sum::<usize>();
                    plan.preview.total_files += view.members.len();
                    plan.preview.total_bytes = plan
                        .preview
                        .total_bytes
                        .checked_add(view.bytes)
                        .ok_or(Error::InvalidInput)?;
                    let anchor = target
                        .directory
                        .as_ref()
                        .map(|(directory, _)| &directory.anchor)
                        .unwrap_or(&target.members[0].anchor);
                    if !plan
                        .filesystems
                        .iter()
                        .any(|other| other.device == anchor.device)
                    {
                        plan.filesystems.push(anchor.clone());
                    }
                    plan.preview.items.push(view);
                    plan.targets.push(Some(target));
                }
                Err(error) if error == "operation_cancelled" => return Err(Error::Cancelled),
                result => {
                    let error = match result {
                        Err(error) => error,
                        Ok(_) => "deletion_limit".into(),
                    };
                    plan.preview.items.push(PreviewItem {
                        source,
                        kind: "unknown".into(),
                        members: vec![],
                        bytes: 0,
                        missing_parts: 0,
                        error: Some(error),
                    });
                    plan.targets.push(None);
                }
            }
        }
        for anchor in &plan.filesystems {
            tracker.checkpoint()?;
            plan.preview.filesystems.push(filesystem(anchor));
        }
        tracker.checkpoint()?;
        Ok(plan)
    })
    .map_err(|e| e.to_string())
}

fn check_member(member: &Member) -> Result<(), String> {
    check_anchor(&member.anchor)?;
    let file = open_member(&member.anchor, &member.name)?;
    if Identity::from(&file.metadata().map_err(|e| e.to_string())?) != member.identity {
        return Err("source_changed".into());
    }
    Ok(())
}
// Rename first, then check the moved object. A substituted entry is restored
// without overwriting any newcomer, never unlinked as the reviewed container.
fn remove_reviewed(member: &Member, directory: bool) -> Result<(), (String, Option<PathBuf>)> {
    check_anchor(&member.anchor).map_err(|e| (e, None))?;
    let quarantine = OsString::from(format!(".tasarut-delete-{:032x}", OsRng.gen::<u128>()));
    rfs::renameat_with(
        member.anchor.fd.as_ref(),
        &member.name,
        member.anchor.fd.as_ref(),
        &quarantine,
        RenameFlags::NOREPLACE,
    )
    .map_err(|e| (e.to_string(), None))?;
    let moved = (|| {
        let flags = OFlags::RDONLY
            | OFlags::NOFOLLOW
            | OFlags::NONBLOCK
            | OFlags::CLOEXEC
            | if directory {
                OFlags::DIRECTORY
            } else {
                OFlags::empty()
            };
        let file = File::from(
            rfs::openat(member.anchor.fd.as_ref(), &quarantine, flags, Mode::empty())
                .map_err(|e| e.to_string())?,
        );
        let identity = Identity::from(&file.metadata().map_err(|e| e.to_string())?);
        if directory {
            if identity.device != member.identity.device || identity.inode != member.identity.inode
            {
                return Err("source_changed".into());
            }
        } else if !member.identity.same_after_rename(&identity) {
            return Err("source_changed".into());
        }
        rfs::unlinkat(
            member.anchor.fd.as_ref(),
            &quarantine,
            if directory {
                AtFlags::REMOVEDIR
            } else {
                AtFlags::empty()
            },
        )
        .map_err(|e| e.to_string())
    })();
    if let Err(error) = moved {
        let recovery = if rfs::renameat_with(
            member.anchor.fd.as_ref(),
            &quarantine,
            member.anchor.fd.as_ref(),
            &member.name,
            RenameFlags::NOREPLACE,
        )
        .is_err()
        {
            Some(member.anchor.path.join(quarantine))
        } else {
            None
        };
        return Err((error, recovery));
    }
    Ok(())
}

fn trim_filesystem(file: &File) -> Result<u64, rustix::io::Errno> {
    rfs::syncfs(file)?;
    let mut range = linux_raw_sys::general::fstrim_range {
        start: 0,
        len: u64::MAX,
        minlen: 0,
    };
    // SAFETY: FITRIM expects this Linux UAPI struct, borrowed for the call, on a
    // directory fd. It discards filesystem FREE extents, never raw live blocks.
    unsafe {
        let update = rustix::ioctl::Updater::<
            { linux_raw_sys::ioctl::FITRIM as rustix::ioctl::Opcode },
            _,
        >::new(&mut range);
        rustix::ioctl::ioctl(file, update)?;
    }
    Ok(range.len)
}

pub fn execute(
    plan: PreparedDeletion,
    request_trim: bool,
    cancellation: &CancellationToken,
    on_progress: &mut dyn FnMut(DeletionProgress),
) -> DeletionReport {
    execute_with_trim(
        plan,
        request_trim,
        cancellation,
        on_progress,
        &mut trim_filesystem,
    )
}
fn execute_with_trim(
    plan: PreparedDeletion,
    request_trim: bool,
    cancellation: &CancellationToken,
    on_progress: &mut dyn FnMut(DeletionProgress),
    trimmer: &mut dyn FnMut(&File) -> Result<u64, rustix::io::Errno>,
) -> DeletionReport {
    let mut report = DeletionReport {
        results: vec![],
        trim: vec![],
        cancelled: false,
        deleted_files: 0,
        deleted_bytes: 0,
        physical_erasure_verified: false,
    };
    let mut affected = HashSet::new();
    for (view, target) in plan.preview.items.into_iter().zip(plan.targets) {
        let mut result = DeletionResult {
            source: view.source.clone(),
            kind: view.kind,
            status: "refused".into(),
            deleted_files: 0,
            deleted_bytes: 0,
            remaining: view.members.clone(),
            planned: view.members.clone(),
            disappearance_confirmed: false,
            directory_removed: false,
            synchronization_error: None,
            error: view.error,
            recovery_path: None,
        };
        let Some(target) = target else {
            report.results.push(result);
            continue;
        };
        if cancellation.is_cancelled() {
            result.status = "notProcessed".into();
            report.cancelled = true;
            report.results.push(result);
            continue;
        }
        let check = (|| {
            for member in &target.members {
                check_member(member)?;
            }
            if let Some((_, anchor)) = &target.directory {
                let expected: HashSet<_> = target
                    .members
                    .iter()
                    .map(|member| member.name.clone())
                    .collect();
                if directory_names(anchor)? != expected {
                    return Err("deletion_unexpected_entries".into());
                }
            }
            Ok::<_, String>(())
        })();
        if let Err(error) = check {
            result.error = Some(error);
            report.results.push(result);
            continue;
        }
        result.error = None;
        result.status = "deleted".into();
        for member in &target.members {
            on_progress(DeletionProgress {
                phase: "deleting".into(),
                current: member.path.clone(),
                deleted_files: report.deleted_files,
                total_files: plan.preview.total_files,
                deleted_bytes: report.deleted_bytes,
                total_bytes: plan.preview.total_bytes,
            });
            if cancellation.is_cancelled() {
                result.status = "cancelled".into();
                report.cancelled = true;
                break;
            }
            if let Err(error) = check_member(member) {
                result.error = Some(error);
                result.status = "partial".into();
                break;
            }
            match remove_reviewed(member, false) {
                Ok(()) => {
                    result.deleted_files += 1;
                    result.deleted_bytes += member.identity.size;
                    report.deleted_files += 1;
                    report.deleted_bytes += member.identity.size;
                    result.remaining.retain(|path| path != &member.path);
                    affected.insert(member.anchor.device);
                    if !absence(&member.anchor, &member.name) {
                        result.error = Some("deletion_path_reappeared".into());
                        result.status = "partial".into();
                    }
                }
                Err((error, path)) => {
                    result.error = Some(error);
                    result.recovery_path = path;
                    result.status = "partial".into();
                    break;
                }
            }
        }
        result.disappearance_confirmed = result.remaining.is_empty() && result.error.is_none();
        if result.remaining.is_empty() {
            if let Some((directory, anchor)) = &target.directory {
                if directory_names(anchor).is_ok_and(|names| names.is_empty()) {
                    match remove_reviewed(directory, true) {
                        Ok(()) => {
                            result.directory_removed = true;
                            if !absence(&directory.anchor, &directory.name) {
                                result.error = Some("deletion_path_reappeared".into());
                                result.disappearance_confirmed = false;
                                result.status = "partial".into();
                            }
                        }
                        Err((error, path)) => {
                            result.error = Some(error);
                            result.recovery_path = path;
                            result.status = "partial".into();
                        }
                    }
                } else {
                    result.error = Some("deletion_unexpected_entries".into());
                    result.status = "partial".into();
                }
            }
        }
        for anchor in target.members.iter().map(|member| &member.anchor).chain(
            target
                .directory
                .iter()
                .map(|(directory, _)| &directory.anchor),
        ) {
            if let Err(error) = anchor.fd.sync_all() {
                result.synchronization_error = Some(error.to_string());
            }
        }
        if result.status == "partial" && result.deleted_files == 0 {
            result.status = "refused".into();
        }
        report.results.push(result);
    }
    for anchor in plan.filesystems {
        let view = filesystem(&anchor);
        let mut result = TrimResult {
            directory: view.directory,
            device: view.device,
            filesystem: view.filesystem,
            storage: view.storage,
            status: "notRequested".into(),
            reported_bytes: None,
            error: None,
        };
        if request_trim {
            result.status = if !affected.contains(&anchor.device) {
                "noDeletion"
            } else if cancellation.is_cancelled() {
                "cancelled"
            } else {
                "requested"
            }
            .into();
            if result.status == "requested" {
                on_progress(DeletionProgress {
                    phase: "trimming".into(),
                    current: anchor.path.clone(),
                    deleted_files: report.deleted_files,
                    total_files: plan.preview.total_files,
                    deleted_bytes: report.deleted_bytes,
                    total_bytes: plan.preview.total_bytes,
                });
                if cancellation.is_cancelled() {
                    result.status = "cancelled".into();
                } else {
                    match trimmer(anchor.fd.as_ref()) {
                        Ok(bytes) => {
                            result.status = "succeeded".into();
                            result.reported_bytes = Some(bytes);
                        }
                        Err(error) => {
                            result.status = if error == rustix::io::Errno::PERM
                                || error == rustix::io::Errno::ACCESS
                            {
                                "permissionDenied"
                            } else if error == rustix::io::Errno::OPNOTSUPP
                                || error == rustix::io::Errno::NOTTY
                                || error == rustix::io::Errno::NOSYS
                            {
                                "unsupported"
                            } else {
                                "failed"
                            }
                            .into();
                            result.error = Some(error.to_string());
                        }
                    }
                }
            }
        }
        report.trim.push(result);
    }
    report.cancelled |= cancellation.is_cancelled();
    on_progress(DeletionProgress {
        phase: if report.cancelled {
            "cancelled"
        } else {
            "complete"
        }
        .into(),
        current: PathBuf::new(),
        deleted_files: report.deleted_files,
        total_files: plan.preview.total_files,
        deleted_bytes: report.deleted_bytes,
        total_bytes: plan.preview.total_bytes,
    });
    report
}

#[cfg(test)]
mod tests;
