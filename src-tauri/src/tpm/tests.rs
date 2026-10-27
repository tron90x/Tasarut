use super::*;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Device {
    slots: BTreeMap<u32, ([u8; 64], Vec<u8>, u32)>,
    commands: Vec<String>,
    fail_undefine: bool,
}
struct FakeRunner(Arc<Mutex<Device>>);
fn output(success: bool, out: Vec<u8>, error: &str) -> Output {
    Output {
        success,
        stdout: Zeroizing::new(out),
        stderr: Zeroizing::new(error.as_bytes().to_vec()),
    }
}
fn argument<'a>(args: &'a [String], name: &str) -> &'a str {
    &args[args.iter().position(|arg| arg == name).unwrap() + 1]
}
fn read_auth(value: &str) -> Vec<u8> {
    fs::read(value.strip_prefix("file:").unwrap()).unwrap()
}
impl Runner for FakeRunner {
    fn run(
        &mut self,
        tool: &str,
        args: &[String],
        _: &CancellationToken,
        _: bool,
    ) -> Result<Output> {
        let index = u32::from_str_radix(args[0].trim_start_matches("0x"), 16).unwrap();
        let mut device = self.0.lock().unwrap();
        device.commands.push(tool.into());
        assert!(args
            .iter()
            .all(|arg| !arg.starts_with("hex:") && !arg.contains("owner secret")));
        match tool {
            "nvreadpublic" => {
                let Some((_, _, attributes)) = device.slots.get(&index) else {
                    return Ok(output(false, vec![], "0x0000018b"));
                };
                Ok(output(true, format!("0x{index:x}:\n  hash algorithm:\n    friendly: sha256\n    value: 0xB\n  attributes:\n    value: 0x{attributes:X}\n  size: 64\n").into_bytes(), ""))
            }
            "nvdefine" => {
                assert_eq!(argument(args, "-a"), format!("0x{ATTRIBUTES:x}"));
                assert_eq!(read_auth(argument(args, "-P")), b"owner secret");
                let auth = read_auth(argument(args, "-p"));
                device.slots.insert(index, ([0; 64], auth, ATTRIBUTES));
                Ok(output(true, vec![], ""))
            }
            "nvwrite" => {
                let data = fs::read(argument(args, "-i")).unwrap();
                assert_eq!(data.len(), 64);
                let slot = device.slots.get_mut(&index).unwrap();
                assert_eq!(read_auth(argument(args, "-P")), slot.1);
                slot.0.copy_from_slice(&data);
                slot.2 |= 0x20000000;
                Ok(output(true, vec![], ""))
            }
            "nvwritelock" => {
                device.slots.get_mut(&index).unwrap().2 |= 0x800;
                Ok(output(true, vec![], ""))
            }
            "nvread" => {
                let slot = device.slots.get(&index).unwrap();
                if read_auth(argument(args, "-P")) != slot.1 {
                    return Ok(output(false, vec![], "authorization failed"));
                }
                fs::write(argument(args, "-o"), slot.0).unwrap();
                Ok(output(true, vec![], ""))
            }
            "nvundefine" => {
                if device.fail_undefine {
                    return Ok(output(false, vec![], "authorization failed"));
                }
                device.slots.remove(&index);
                Ok(output(true, vec![], ""))
            }
            _ => panic!("unexpected command"),
        }
    }
}

#[test]
fn nv_protocol_uses_anonymous_authentication_and_confirms_hardware_absence() {
    let device = Arc::new(Mutex::new(Device::default()));
    let mut store = TpmStore {
        runner: Box::new(FakeRunner(device.clone())),
        owner: Zeroizing::new("owner secret".into()),
    };
    let record = [42; 64];
    let auth = [17; 32];
    let token = CancellationToken::default();
    let index = store.create(&record, &auth, &token).unwrap();
    assert_eq!(index & SLOT_MASK, SLOT_BASE);
    assert_eq!(store.read(index, &auth, &token).unwrap().as_slice(), record);
    assert!(store.destroy(index, &[43; 32], &auth, &token).is_err());
    assert!(device.lock().unwrap().slots.contains_key(&index));
    device.lock().unwrap().fail_undefine = true;
    assert!(store.destroy(index, &[42; 32], &auth, &token).is_err());
    assert!(device.lock().unwrap().slots.contains_key(&index));
    device.lock().unwrap().fail_undefine = false;
    store.destroy(index, &[42; 32], &auth, &token).unwrap();
    assert!(matches!(
        store.read(index, &auth, &token),
        Err(Error::RevocableKeyUnavailable)
    ));
    let commands = &device.lock().unwrap().commands;
    assert!(commands.contains(&"nvwritelock".into()));
    assert_eq!(commands.last().unwrap(), "nvreadpublic");
}

#[test]
fn public_records_with_owner_read_or_unlocked_writes_are_not_accepted() {
    let device = Arc::new(Mutex::new(Device::default()));
    device.lock().unwrap().slots.insert(
        SLOT_BASE + 1,
        ([42; 64], vec![17; 32], LOCKED_ATTRIBUTES | 0x20000),
    );
    let mut store = TpmStore {
        runner: Box::new(FakeRunner(device.clone())),
        owner: Zeroizing::new(String::new()),
    };
    assert!(matches!(
        store.read(SLOT_BASE + 1, &[17; 32], &CancellationToken::default()),
        Err(Error::RevocableKeyMismatch)
    ));
    assert_eq!(device.lock().unwrap().commands, vec!["nvreadpublic"]);
    assert!(store
        .read(0x01000001, &[17; 32], &CancellationToken::default())
        .is_err());
}

#[test]
fn persistent_swap_and_foreign_public_records_are_detected() {
    assert!(!persistent_swap("Filename Type Size Used Priority\n"));
    assert!(persistent_swap(
        "Filename Type Size Used Priority\n/dev/dm-0 partition 100 0 -1\n"
    ));
    assert!(parse_public(b"0x1500001:\n  size: 64\n", SLOT_BASE).is_err());
    let file = memory_file("test", b"private test bytes").unwrap();
    assert_eq!(fs::read(fd_path(&file)).unwrap(), b"private test bytes");
    assert!(OpenOptions::new()
        .write(true)
        .open(fd_path(&file))
        .unwrap()
        .write_all(b"changed")
        .is_err());
}
