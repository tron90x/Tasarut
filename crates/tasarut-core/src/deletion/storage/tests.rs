use super::*;
use std::os::unix::fs::symlink;

struct Sysfs(tempfile::TempDir);
impl Sysfs {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("dev/block")).unwrap();
        fs::create_dir(root.path().join("devices")).unwrap();
        Self(root)
    }
    fn disk(&self, relative: &str, rotational: &str, discard: &str) -> PathBuf {
        let node = self.0.path().join("devices").join(relative);
        fs::create_dir_all(node.join("queue")).unwrap();
        fs::create_dir(node.join("slaves")).unwrap();
        fs::write(node.join("queue/rotational"), rotational).unwrap();
        fs::write(node.join("queue/discard_max_bytes"), discard).unwrap();
        node
    }
    fn map(&self, node: &Path) {
        symlink(node, self.0.path().join("dev/block/8:1")).unwrap();
    }
    fn detect(&self) -> StorageInfo {
        detect_in(self.0.path(), rustix::fs::makedev(8, 1), "ext4")
    }
}

#[test]
fn partitions_use_the_parent_queue_and_distinguish_nvme_flash_and_rotational() {
    for (name, rotational, kind) in [
        ("nvme0n1", "0\n", StorageKind::Nvme),
        ("sda", "0\n", StorageKind::NonRotational),
        ("sdb", "1\n", StorageKind::Rotational),
    ] {
        let sys = Sysfs::new();
        let disk = sys.disk(&format!("pci/block/{name}"), rotational, "1048576\n");
        let partition = disk.join(format!("{name}p1"));
        fs::create_dir(&partition).unwrap();
        fs::write(partition.join("partition"), "1\n").unwrap();
        sys.map(&partition);
        let info = sys.detect();
        assert_eq!(info.kind, kind);
        assert_eq!(info.block_device.as_deref(), Some(name));
        assert_eq!(info.backing_devices.len(), 1);
        assert_eq!(info.backing_devices[0].name, name);
        assert_eq!(info.discard_max_bytes, Some(1048576));
    }
}

#[test]
fn luks_lvm_topology_does_not_confuse_leaf_discard_with_effective_discard() {
    let sys = Sysfs::new();
    let disk = sys.disk("pci/block/nvme0n1", "0", "1048576");
    let crypt = sys.disk("virtual/block/dm-0", "0", "0");
    let logical = sys.disk("virtual/block/dm-1", "0", "0");
    symlink(&disk, crypt.join("slaves/nvme0n1")).unwrap();
    symlink(&crypt, logical.join("slaves/dm-0")).unwrap();
    sys.map(&logical);
    let info = sys.detect();
    assert_eq!(info.kind, StorageKind::Nvme);
    assert_eq!(info.block_device.as_deref(), Some("dm-1"));
    assert_eq!(info.backing_devices[0].name, "nvme0n1");
    assert_eq!(info.discard_max_bytes, Some(0));
}

#[test]
fn raid_mixed_media_and_shared_leaves_are_handled_without_guessing() {
    let sys = Sysfs::new();
    let flash = sys.disk("pci/block/sda", "0", "1024");
    let hdd = sys.disk("pci/block/sdb", "1", "0");
    let left = sys.disk("virtual/block/dm-0", "0", "0");
    let right = sys.disk("virtual/block/dm-1", "0", "0");
    let raid = sys.disk("virtual/block/md0", "0", "0");
    symlink(&flash, left.join("slaves/sda")).unwrap();
    symlink(&flash, right.join("slaves/sda")).unwrap();
    symlink(&hdd, right.join("slaves/sdb")).unwrap();
    symlink(&left, raid.join("slaves/dm-0")).unwrap();
    symlink(&right, raid.join("slaves/dm-1")).unwrap();
    sys.map(&raid);
    let info = sys.detect();
    assert_eq!(info.kind, StorageKind::Mixed);
    assert_eq!(info.backing_devices.len(), 2);
    fs::write(hdd.join("queue/rotational"), "unknown").unwrap();
    assert_eq!(sys.detect().kind, StorageKind::Unknown);
    fs::write(hdd.join("queue/rotational"), "0").unwrap();
    assert_eq!(sys.detect().kind, StorageKind::NonRotational);
}

#[test]
fn absent_sysfs_virtual_media_and_unsupported_filesystems_remain_unknown() {
    let sys = Sysfs::new();
    assert_eq!(sys.detect().kind, StorageKind::Unknown);
    let loop_device = sys.disk("virtual/block/loop0", "0", "1048576");
    sys.map(&loop_device);
    assert_eq!(sys.detect().kind, StorageKind::Unknown);
    for filesystem in ["btrfs", "tmpfs", "overlayfs"] {
        let info = detect_in(sys.0.path(), rustix::fs::makedev(8, 1), filesystem);
        assert_eq!(info.kind, StorageKind::Unknown);
        assert!(info.block_device.is_none());
        assert!(info.discard_max_bytes.is_none());
    }
}

#[test]
fn unreadable_invalid_or_partial_topology_is_not_reported_as_ssd() {
    let sys = Sysfs::new();
    let disk = sys.disk("pci/block/sda", "2", "invalid");
    sys.map(&disk);
    assert_eq!(sys.detect().kind, StorageKind::Unknown);
    assert!(sys.detect().discard_max_bytes.is_none());
    fs::remove_file(disk.join("queue/rotational")).unwrap();
    assert_eq!(sys.detect().kind, StorageKind::Unknown);
    fs::write(disk.join("queue/rotational"), "0").unwrap();
    symlink(sys.0.path().join("missing"), disk.join("slaves/missing")).unwrap();
    assert_eq!(sys.detect().kind, StorageKind::Unknown);
}

#[test]
fn cycles_excessive_depth_and_external_symlinks_are_bounded() {
    let sys = Sysfs::new();
    let first = sys.disk("virtual/block/dm-0", "0", "0");
    let second = sys.disk("virtual/block/dm-1", "0", "0");
    symlink(&second, first.join("slaves/dm-1")).unwrap();
    symlink(&first, second.join("slaves/dm-0")).unwrap();
    sys.map(&first);
    assert_eq!(sys.detect().kind, StorageKind::Unknown);
    fs::remove_file(second.join("slaves/dm-0")).unwrap();
    let mut last = second;
    for index in 2..=MAX_DEPTH + 2 {
        let next = sys.disk(&format!("virtual/block/dm-{index}"), "0", "0");
        symlink(&next, last.join("slaves/next")).unwrap();
        last = next;
    }
    assert_eq!(sys.detect().kind, StorageKind::Unknown);
    let outside = tempfile::tempdir().unwrap();
    assert!(block_node(outside.path(), &sys.0.path().join("devices")).is_none());
}

#[test]
fn excessive_fanout_is_incomplete_instead_of_classifying_a_partial_raid() {
    let sys = Sysfs::new();
    let raid = sys.disk("virtual/block/md0", "0", "0");
    for index in 0..=MAX_NODES {
        let disk = sys.disk(&format!("pci/block/disk{index}"), "0", "1024");
        symlink(&disk, raid.join(format!("slaves/disk{index}"))).unwrap();
    }
    sys.map(&raid);
    assert_eq!(sys.detect().kind, StorageKind::Unknown);
}
