//! Read-only, best-effort Linux block topology observations. Queue properties
//! describe what the kernel exposes, not proof of physical media or FITRIM support.
use serde::Serialize;
use std::{
    collections::{BTreeMap, HashSet},
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

const MAX_NODES: usize = 64;
const MAX_DEPTH: usize = 16;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum StorageKind {
    Nvme,
    NonRotational,
    Rotational,
    Mixed,
    #[default]
    Unknown,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageDevice {
    pub name: String,
    pub kind: StorageKind,
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageInfo {
    pub kind: StorageKind,
    pub block_device: Option<String>,
    pub backing_devices: Vec<StorageDevice>,
    /// Effective queue limit on the containing device, not the physical leaves.
    /// None = unreadable/unknown; zero = no discard advertised by that queue.
    pub discard_max_bytes: Option<u64>,
}

pub(super) fn detect(device: u64, filesystem: &str) -> StorageInfo {
    detect_in(Path::new("/sys"), device, filesystem)
}

fn number(path: &Path) -> Option<u64> {
    let mut text = String::new();
    File::open(path)
        .ok()?
        .take(65)
        .read_to_string(&mut text)
        .ok()?;
    if text.len() > 64 {
        return None;
    }
    text.trim().parse().ok()
}

fn block_node(path: &Path, devices: &Path) -> Option<PathBuf> {
    let mut node = fs::canonicalize(path).ok()?;
    if !node.starts_with(devices) {
        return None;
    }
    if node.join("partition").try_exists().ok()? {
        node = node.parent()?.to_owned();
    }
    (node.starts_with(devices) && node.is_dir()).then_some(node)
}

fn leaf(node: &Path, devices: &Path) -> StorageDevice {
    let name = node
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    let virtual_device = node.strip_prefix(devices).is_ok_and(|relative| {
        relative
            .components()
            .any(|part| part.as_os_str() == "virtual")
    });
    let nvme = name
        .strip_prefix("nvme")
        .is_some_and(|suffix| suffix.as_bytes().first().is_some_and(u8::is_ascii_digit));
    let kind = if virtual_device {
        StorageKind::Unknown
    } else {
        match number(&node.join("queue/rotational")) {
            Some(0) if nvme => StorageKind::Nvme,
            Some(0) => StorageKind::NonRotational,
            Some(1) => StorageKind::Rotational,
            _ => StorageKind::Unknown,
        }
    };
    StorageDevice { name, kind }
}

struct Topology<'a> {
    devices: &'a Path,
    active: HashSet<PathBuf>,
    visited: HashSet<PathBuf>,
    leaves: BTreeMap<PathBuf, StorageDevice>,
}
impl Topology<'_> {
    fn visit(&mut self, node: PathBuf, depth: usize) -> Option<()> {
        if depth > MAX_DEPTH || self.active.contains(&node) {
            return None;
        }
        if self.visited.contains(&node) {
            return Some(());
        }
        if self.visited.len() >= MAX_NODES {
            return None;
        }
        self.visited.insert(node.clone());
        self.active.insert(node.clone());
        let mut slaves = Vec::new();
        for entry in fs::read_dir(node.join("slaves")).ok()? {
            if slaves.len() >= MAX_NODES {
                return None;
            }
            slaves.push(block_node(&entry.ok()?.path(), self.devices)?);
        }
        if slaves.is_empty() {
            self.leaves.insert(node.clone(), leaf(&node, self.devices));
        } else {
            for slave in slaves {
                self.visit(slave, depth + 1)?;
            }
        }
        self.active.remove(&node);
        Some(())
    }
}

fn combined(devices: &[StorageDevice]) -> StorageKind {
    if devices.is_empty()
        || devices
            .iter()
            .any(|device| device.kind == StorageKind::Unknown)
    {
        return StorageKind::Unknown;
    }
    let rotational = devices
        .iter()
        .any(|device| device.kind == StorageKind::Rotational);
    let flash = devices
        .iter()
        .any(|device| matches!(device.kind, StorageKind::Nvme | StorageKind::NonRotational));
    if rotational && flash {
        StorageKind::Mixed
    } else if rotational {
        StorageKind::Rotational
    } else if devices
        .iter()
        .all(|device| device.kind == StorageKind::Nvme)
    {
        StorageKind::Nvme
    } else {
        StorageKind::NonRotational
    }
}

fn detect_in(sys: &Path, device: u64, filesystem: &str) -> StorageInfo {
    // Btrfs st_dev may be anonymous, and a filesystem may span multiple devices.
    // An arbitrary single-device lookup would not describe that whole filesystem.
    if matches!(filesystem, "btrfs" | "tmpfs" | "overlayfs") {
        return StorageInfo::default();
    }
    let Ok(sys) = fs::canonicalize(sys) else {
        return StorageInfo::default();
    };
    let devices = sys.join("devices");
    let entry = sys.join(format!(
        "dev/block/{}:{}",
        rustix::fs::major(device),
        rustix::fs::minor(device)
    ));
    let Some(node) = block_node(&entry, &devices) else {
        return StorageInfo::default();
    };
    let mut info = StorageInfo {
        block_device: node
            .file_name()
            .map(|name| name.to_string_lossy().into_owned()),
        discard_max_bytes: number(&node.join("queue/discard_max_bytes")),
        ..Default::default()
    };
    let mut topology = Topology {
        devices: &devices,
        active: HashSet::new(),
        visited: HashSet::new(),
        leaves: BTreeMap::new(),
    };
    let complete = topology.visit(node, 0).is_some();
    info.backing_devices = topology.leaves.into_values().collect();
    if complete {
        info.kind = combined(&info.backing_devices);
    }
    info
}

#[cfg(test)]
mod tests;
