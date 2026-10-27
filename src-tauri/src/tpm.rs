//! TPM2 NV record backend. No secret key files, disk vault or software fallback.
//! Tools use a pinned device TCTI, anonymous inherited memfds and bounded pipes.
use rustix::{
    fd::AsRawFd,
    fs::{memfd_create, MemfdFlags, SealFlags},
};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use tasarut_core::{
    revocable::{RevocationStore, SLOT_BASE, SLOT_MASK},
    CancellationToken, Error, Result,
};
use zeroize::Zeroizing;

const TOOLS: &[&str] = &[
    "nvdefine",
    "nvwrite",
    "nvwritelock",
    "nvread",
    "nvreadpublic",
    "nvundefine",
    "getcap",
];
const ATTRIBUTES: u32 = 0x02042004; // AUTHWRITE | WRITEDEFINE | AUTHREAD | NO_DA
const LOCKED_ATTRIBUTES: u32 = ATTRIBUTES | 0x20000000 | 0x00000800; // WRITTEN | WRITELOCKED
const MAX_OUTPUT: u64 = 16384;

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Availability {
    pub available: bool,
    pub reason: String,
    pub device: Option<String>,
}

fn tools() -> Option<BTreeMap<String, PathBuf>> {
    let mut found = BTreeMap::new();
    for tool in TOOLS {
        let path = ["/usr/bin", "/usr/sbin", "/bin", "/sbin"]
            .iter()
            .map(|directory| Path::new(directory).join(format!("tpm2_{tool}")))
            .find(|path| {
                fs::canonicalize(path)
                    .ok()
                    .and_then(|canonical| fs::metadata(canonical).ok())
                    .is_some_and(|meta| {
                        meta.is_file() && meta.uid() == 0 && meta.mode() & 0o022 == 0
                    })
            })?;
        found.insert((*tool).into(), path);
    }
    Some(found)
}
fn persistent_swap(text: &str) -> bool {
    text.lines()
        .skip(1)
        .filter_map(|line| line.split_whitespace().next())
        .any(|device| {
            if let Some(zram) = device
                .strip_prefix("/dev/")
                .filter(|name| name.starts_with("zram") && !name.contains('/'))
            {
                fs::read_to_string(format!("/sys/block/{zram}/backing_dev"))
                    .map(|backing| backing.trim() != "none")
                    .unwrap_or(true)
            } else {
                true
            }
        })
}
fn device() -> Option<String> {
    ["/dev/tpmrm0", "/dev/tpm0"]
        .into_iter()
        .find(|path| fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_char_device()))
        .map(str::to_owned)
}
fn prerequisites() -> Availability {
    let device = device();
    let reason = match device.as_deref() {
        None => "revocable_no_tpm",
        Some(_) if tools().is_none() => "revocable_tools_missing",
        Some(path)
            if OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .is_err() =>
        {
            "revocable_tpm_access"
        }
        Some(_)
            if fs::read_to_string("/proc/swaps")
                .map(|text| persistent_swap(&text))
                .unwrap_or(true) =>
        {
            "revocable_persistent_swap"
        }
        Some(_) => "",
    };
    Availability {
        available: reason.is_empty(),
        reason: reason.into(),
        device,
    }
}

#[tauri::command]
pub(crate) async fn revocable_status() -> Availability {
    tauri::async_runtime::spawn_blocking(|| {
        let mut status = prerequisites();
        if status.available {
            let mut runner = ProcessRunner {
                tools: tools().unwrap(),
                device: status.device.clone().unwrap(),
            };
            match runner.run(
                "getcap",
                &["properties-fixed".into()],
                &CancellationToken::default(),
                false,
            ) {
                Ok(output)
                    if output.success
                        && String::from_utf8_lossy(&output.stdout).contains("0x322E3000") => {}
                Ok(output)
                    if output.success
                        && String::from_utf8_lossy(&output.stdout).contains("0x322e3000") => {}
                _ => {
                    status.available = false;
                    status.reason = "revocable_tpm_failed".into();
                }
            }
        }
        status
    })
    .await
    .unwrap_or(Availability {
        available: false,
        reason: "revocable_tpm_failed".into(),
        device: None,
    })
}

struct Output {
    success: bool,
    stdout: Zeroizing<Vec<u8>>,
    stderr: Zeroizing<Vec<u8>>,
}
trait Runner {
    fn run(
        &mut self,
        tool: &str,
        args: &[String],
        cancellation: &CancellationToken,
        mutating: bool,
    ) -> Result<Output>;
}
struct ProcessRunner {
    tools: BTreeMap<String, PathBuf>,
    device: String,
}
struct ChildGuard(std::process::Child);
impl std::ops::Deref for ChildGuard {
    type Target = std::process::Child;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for ChildGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
fn no_core_dumps() -> Result<()> {
    // SAFETY: rlimit pointers refer to initialized structs; setting the soft
    // core-dump limit to zero changes no filesystem/TPM data and is inherited.
    unsafe {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_CORE, &mut limit) != 0 {
            return Err(Error::RevocableTpm);
        }
        limit.rlim_cur = 0;
        if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0 {
            return Err(Error::RevocableTpm);
        }
    }
    Ok(())
}
impl Runner for ProcessRunner {
    fn run(
        &mut self,
        tool: &str,
        args: &[String],
        cancellation: &CancellationToken,
        mutating: bool,
    ) -> Result<Output> {
        cancellation.check()?;
        if fs::read_to_string("/proc/swaps")
            .map(|text| persistent_swap(&text))
            .unwrap_or(true)
        {
            return Err(Error::RevocableProviderRequired);
        }
        no_core_dumps()?;
        let mut command = Command::new(self.tools.get(tool).ok_or(Error::RevocableTpm)?);
        command
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LC_ALL", "C")
            .current_dir("/")
            .arg("-T")
            .arg(format!("device:{}", self.device))
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // SAFETY: the pre-exec closure invokes only the async-signal-safe
        // setrlimit syscall with stack data, and performs no allocation/locking.
        unsafe {
            command.pre_exec(|| {
                let limit = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::setrlimit(libc::RLIMIT_CORE, &limit) == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
        let mut child = ChildGuard(command.spawn().map_err(|_| Error::RevocableTpm)?);
        let stdout = child.stdout.take().ok_or(Error::RevocableTpm)?;
        let stderr = child.stderr.take().ok_or(Error::RevocableTpm)?;
        let read = |stream: Box<dyn Read + Send>| {
            thread::spawn(move || {
                let mut bytes = Zeroizing::new(Vec::new());
                stream
                    .take(MAX_OUTPUT + 1)
                    .read_to_end(&mut bytes)
                    .map(|_| bytes)
            })
        };
        let out = read(Box::new(stdout));
        let err = read(Box::new(stderr));
        let start = Instant::now();
        let mut stopped = false;
        let status = loop {
            if let Some(status) = child.try_wait().map_err(|_| Error::RevocableTpm)? {
                break status;
            }
            if start.elapsed() > Duration::from_secs(30)
                || (!mutating && cancellation.is_cancelled())
            {
                let _ = child.kill();
                stopped = true;
                break child.wait().map_err(|_| Error::RevocableTpm)?;
            }
            thread::sleep(Duration::from_millis(20));
        };
        let stdout = out
            .join()
            .map_err(|_| Error::RevocableTpm)?
            .map_err(|_| Error::RevocableTpm)?;
        let stderr = err
            .join()
            .map_err(|_| Error::RevocableTpm)?
            .map_err(|_| Error::RevocableTpm)?;
        if stdout.len() as u64 > MAX_OUTPUT || stderr.len() as u64 > MAX_OUTPUT {
            return Err(Error::RevocableTpm);
        }
        if stopped {
            if cancellation.is_cancelled() && !mutating {
                return Err(Error::Cancelled);
            }
            return Err(Error::RevocableTpm);
        }
        // Once a mutating TPM command starts, report its actual outcome rather
        // than claiming cancellation of an already defined/destroyed index.
        if !mutating {
            cancellation.check()?;
        }
        Ok(Output {
            success: status.success(),
            stdout,
            stderr,
        })
    }
}

fn memory_file(name: &str, bytes: &[u8]) -> Result<File> {
    let fd = memfd_create(name, MemfdFlags::ALLOW_SEALING).map_err(|_| Error::RevocableTpm)?;
    // No CLOEXEC: the tool inherits this anonymous descriptor. No password or
    // record value appears in argv, and no filesystem key file is created.
    let mut file = File::from(fd);
    file.write_all(bytes)?;
    file.seek(SeekFrom::Start(0))?;
    if !bytes.is_empty() {
        rustix::fs::fcntl_add_seals(
            &file,
            SealFlags::WRITE | SealFlags::SHRINK | SealFlags::GROW | SealFlags::SEAL,
        )
        .map_err(|_| Error::RevocableTpm)?;
    }
    Ok(file)
}
fn fd_path(file: &File) -> String {
    format!("/proc/self/fd/{}", file.as_raw_fd())
}
fn auth_path(file: &File) -> String {
    format!("file:{}", fd_path(file))
}
fn response_error(output: &Output) -> Error {
    let text = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    if text.contains("0x000009a2")
        || text.contains("0x9a2")
        || text.contains("authorization")
        || text.contains("auth fail")
    {
        Error::RevocableTpmAuth
    } else if text.contains("0x0000014b") || text.contains("0x14b") || text.contains("nv space") {
        Error::RevocableTpmCapacity
    } else {
        Error::RevocableTpm
    }
}
fn missing(output: &Output) -> bool {
    let text = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    !output.success
        && (text.contains("0x0000018b")
            || text.contains("0x18b")
            || text.contains("0x000001cb")
            || text.contains("0x1cb"))
}
#[derive(PartialEq, Debug)]
struct Public {
    size: u64,
    hash: u32,
    attributes: u32,
}
fn parse_public(bytes: &[u8], index: u32) -> Result<Public> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error::RevocableTpm)?;
    let mut active = false;
    let mut section = "";
    let (mut size, mut hash, mut attributes) = (None, None, None);
    for line in text.lines() {
        if !line.starts_with(' ') && line.trim().starts_with("0x") {
            let handle = line
                .trim()
                .trim_end_matches(':')
                .strip_prefix("0x")
                .and_then(|number| u32::from_str_radix(number, 16).ok());
            active = handle == Some(index);
            section = "";
            continue;
        }
        if !active {
            continue;
        }
        let line = line.trim();
        if line == "hash algorithm:" {
            section = "hash";
        } else if line == "attributes:" {
            section = "attributes";
        } else if let Some(value) = line.strip_prefix("size:") {
            size = value.trim().parse::<u64>().ok();
        } else if let Some(value) = line.strip_prefix("value:") {
            let number = value
                .trim()
                .strip_prefix("0x")
                .and_then(|number| u32::from_str_radix(number, 16).ok());
            if section == "hash" {
                hash = number;
            } else if section == "attributes" {
                attributes = number;
            }
        } else if line.starts_with("authorization policy:")
            && !line
                .trim_start_matches("authorization policy:")
                .trim()
                .is_empty()
        {
            return Err(Error::RevocableKeyMismatch);
        }
    }
    Ok(Public {
        size: size.ok_or(Error::RevocableKeyUnavailable)?,
        hash: hash.ok_or(Error::RevocableTpm)?,
        attributes: attributes.ok_or(Error::RevocableTpm)?,
    })
}

pub(crate) struct TpmStore {
    runner: Box<dyn Runner>,
    owner: Zeroizing<String>,
}
impl TpmStore {
    pub(crate) fn new(owner: Zeroizing<String>) -> Result<Self> {
        let status = prerequisites();
        if !status.available {
            return Err(Error::RevocableProviderRequired);
        }
        if owner.len() > 64 {
            return Err(Error::RevocableTpmAuth);
        }
        Ok(Self {
            runner: Box::new(ProcessRunner {
                tools: tools().ok_or(Error::RevocableTpm)?,
                device: status.device.ok_or(Error::RevocableTpm)?,
            }),
            owner,
        })
    }
    fn public(&mut self, index: u32, token: &CancellationToken) -> Result<Option<Public>> {
        if index & SLOT_MASK != SLOT_BASE {
            return Err(Error::RevocableKeyMismatch);
        }
        let output = self
            .runner
            .run("nvreadpublic", &[format!("0x{index:08x}")], token, false)?;
        if missing(&output) {
            return Ok(None);
        }
        if !output.success {
            return Err(response_error(&output));
        }
        parse_public(&output.stdout, index).map(Some)
    }
    fn undefine(&mut self, index: u32) -> Result<()> {
        let owner = memory_file("tasarut-tpm-owner", self.owner.as_bytes())?;
        let args = vec![
            format!("0x{index:08x}"),
            "-C".into(),
            "o".into(),
            "-P".into(),
            auth_path(&owner),
        ];
        let command = self
            .runner
            .run("nvundefine", &args, &CancellationToken::default(), true);
        // Never assert revocation based only on a CLI exit code.
        match self.public(index, &CancellationToken::default()) {
            Ok(None) => Ok(()),
            Ok(Some(_)) => match command {
                Ok(output) if !output.success => Err(response_error(&output)),
                Err(error) => Err(error),
                _ => Err(Error::RevocableTpm),
            },
            Err(error) => Err(error),
        }
    }
}
impl RevocationStore for TpmStore {
    fn create(
        &mut self,
        record: &[u8; 64],
        authorization: &[u8; 32],
        token: &CancellationToken,
    ) -> Result<u32> {
        let auth = memory_file("tasarut-tpm-auth", authorization)?;
        let owner = memory_file("tasarut-tpm-owner", self.owner.as_bytes())?;
        let data = memory_file("tasarut-tpm-record", record)?;
        let mut selected = None;
        for _ in 0..32 {
            token.check()?;
            let random = tasarut_core::generate_password(16, false)?;
            let offset = random.bytes().fold(0u32, |value, byte| {
                value.wrapping_mul(31).wrapping_add(u32::from(byte))
            }) & 0xffff;
            let index = SLOT_BASE | offset;
            if self.public(index, token)?.is_some() {
                continue;
            }
            let output = self.runner.run(
                "nvdefine",
                &[
                    format!("0x{index:08x}"),
                    "-C".into(),
                    "o".into(),
                    "-s".into(),
                    "64".into(),
                    "-g".into(),
                    "sha256".into(),
                    "-a".into(),
                    format!("0x{ATTRIBUTES:x}"),
                    "-p".into(),
                    auth_path(&auth),
                    "-P".into(),
                    auth_path(&owner),
                ],
                token,
                true,
            )?;
            if !output.success {
                let text = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
                if text.contains("0x14c") || text.contains("0x0000014c") {
                    continue;
                }
                return Err(response_error(&output));
            }
            selected = Some(index);
            break;
        }
        let index = selected.ok_or(Error::RevocableTpmCapacity)?;
        let result = (|| {
            token.check()?;
            let output = self.runner.run(
                "nvwrite",
                &[
                    format!("0x{index:08x}"),
                    "-C".into(),
                    format!("0x{index:08x}"),
                    "-P".into(),
                    auth_path(&auth),
                    "-i".into(),
                    fd_path(&data),
                ],
                token,
                true,
            )?;
            if !output.success {
                return Err(response_error(&output));
            }
            token.check()?;
            let output = self.runner.run(
                "nvwritelock",
                &[
                    format!("0x{index:08x}"),
                    "-C".into(),
                    format!("0x{index:08x}"),
                    "-P".into(),
                    auth_path(&auth),
                ],
                token,
                true,
            )?;
            if !output.success {
                return Err(response_error(&output));
            }
            let actual = self.read(index, authorization, token)?;
            if actual.as_slice() != record {
                return Err(Error::RevocableKeyMismatch);
            }
            Ok(index)
        })();
        if result.is_err() && self.undefine(index).is_err() {
            return Err(Error::RevocableCleanup(index));
        }
        result
    }
    fn read(
        &mut self,
        index: u32,
        authorization: &[u8; 32],
        token: &CancellationToken,
    ) -> Result<Zeroizing<[u8; 64]>> {
        let public = self
            .public(index, token)?
            .ok_or(Error::RevocableKeyUnavailable)?;
        if public
            != (Public {
                size: 64,
                hash: 0xb,
                attributes: LOCKED_ATTRIBUTES,
            })
        {
            return Err(Error::RevocableKeyMismatch);
        }
        let auth = memory_file("tasarut-tpm-auth", authorization)?;
        let mut data = memory_file("tasarut-tpm-response", &[])?;
        let output = self.runner.run(
            "nvread",
            &[
                format!("0x{index:08x}"),
                "-C".into(),
                format!("0x{index:08x}"),
                "-P".into(),
                auth_path(&auth),
                "-s".into(),
                "64".into(),
                "-o".into(),
                fd_path(&data),
            ],
            token,
            false,
        )?;
        if !output.success {
            return Err(response_error(&output));
        }
        if data.metadata()?.len() != 64 {
            return Err(Error::RevocableTpm);
        }
        let mut record = Zeroizing::new([0; 64]);
        data.seek(SeekFrom::Start(0))?;
        data.read_exact(record.as_mut())?;
        Ok(record)
    }
    fn destroy(
        &mut self,
        index: u32,
        identifier: &[u8; 32],
        authorization: &[u8; 32],
        token: &CancellationToken,
    ) -> Result<()> {
        let record = self.read(index, authorization, token)?;
        if record[..32] != *identifier {
            return Err(Error::RevocableKeyMismatch);
        }
        token.check()?;
        self.undefine(index)
    }
}

#[cfg(test)]
mod tests;
