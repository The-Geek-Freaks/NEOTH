use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use neothd::updater::install_transaction::{AllowedTarget, InstallTransaction, PreparedMember};
use neothd::updater::release_bundle::{PORTABLE_OWNERSHIP_MARKER, PortableBundleProfile};

const CHILD_ROOT: &str = "NEOTH_REAL_ENTRY_RECOVERY_ROOT";
const SUPPORT_DIR: &str = "neoth-support";

#[test]
fn interrupted_apply_child() {
    let Some(root) = std::env::var_os(CHILD_ROOT) else {
        return;
    };
    let root = PathBuf::from(root);
    let install = root.join("install");
    let support_snapshot = install.join(SUPPORT_DIR).join("self-knowledge");
    let transaction = InstallTransaction::new_with_anchor(
        &install,
        [AllowedTarget::directory(&support_snapshot)],
        root.join("state"),
    )
    .unwrap();
    transaction
        .apply(&[PreparedMember::directory(
            root.join("source-snapshot"),
            support_snapshot,
        )])
        .unwrap();
}

#[test]
fn killed_transaction_is_recovered_by_real_neoth_and_neothd_entrypoints() {
    for entrypoint in [env!("CARGO_BIN_EXE_neoth"), env!("CARGO_BIN_EXE_neothd")] {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path();
        let install = root.join("install");
        let state = root.join("state");
        let support_snapshot = install.join(SUPPORT_DIR).join("self-knowledge");
        fs::create_dir_all(&support_snapshot).unwrap();
        fs::create_dir(&state).unwrap();
        fs::write(support_snapshot.join("old.txt"), b"old snapshot").unwrap();

        copy_binary(
            env!("CARGO_BIN_EXE_neoth"),
            &install.join(binary_name("neoth")),
        );
        copy_binary(
            env!("CARGO_BIN_EXE_neothd"),
            &install.join(binary_name("neothd")),
        );
        write_marker(&install);

        let source = root.join("source-snapshot");
        fs::create_dir(&source).unwrap();
        // Preparing hashes these files once; staging copies them after the
        // journal is public, leaving a deterministic window for a real
        // process termination without a production-only test hook.
        for index in 0..6_000_u32 {
            fs::write(
                source.join(format!("entry-{index:05}.txt")),
                format!("release snapshot member {index}\n"),
            )
            .unwrap();
        }

        let transaction = InstallTransaction::new_with_anchor(
            &install,
            [AllowedTarget::directory(&support_snapshot)],
            &state,
        )
        .unwrap();
        let journal = transaction.journal_path().to_path_buf();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["interrupted_apply_child", "--exact", "--nocapture"])
            .env(CHILD_ROOT, root)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        while !journal.exists() && Instant::now() < deadline {
            if child.try_wait().unwrap().is_some() {
                panic!("transaction child completed before its journal could be observed");
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(journal.exists(), "transaction journal was never published");
        child.kill().unwrap();
        let _ = child.wait().unwrap();

        let installed_entry = install.join(
            Path::new(entrypoint)
                .file_name()
                .expect("entrypoint filename"),
        );
        let output = Command::new(&installed_entry)
            .arg("--version")
            .env("NEOTH_INSTALL_STATE_DIR", &state)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "real {} startup failed: stdout={} stderr={}",
            installed_entry.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !journal.exists(),
            "real entrypoint left the journal pending"
        );
        assert_eq!(
            fs::read(support_snapshot.join("old.txt")).unwrap(),
            b"old snapshot"
        );
    }
}

fn binary_name(stem: &str) -> String {
    if cfg!(windows) {
        format!("{stem}.exe")
    } else {
        stem.to_string()
    }
}

fn copy_binary(source: &str, destination: &Path) {
    fs::create_dir_all(destination.parent().unwrap()).unwrap();
    fs::copy(source, destination).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(destination, fs::Permissions::from_mode(0o755)).unwrap();
    }
}

fn write_marker(install: &Path) {
    let canonical = fs::canonicalize(install).unwrap();
    let rendered = canonical.to_string_lossy().into_owned();
    #[cfg(windows)]
    let rendered = rendered
        .strip_prefix(r"\\?\")
        .unwrap_or(&rendered)
        .to_string();
    let marker = serde_json::json!({
        "schema_version": 2,
        "owner": "neoth_portable_release",
        "install_root": rendered.trim_end_matches(['/', '\\']),
        "release_version": env!("CARGO_PKG_VERSION"),
        "profile": PortableBundleProfile::current().as_str(),
        "support_dir": SUPPORT_DIR,
    });
    fs::write(
        install.join(PORTABLE_OWNERSHIP_MARKER),
        serde_json::to_vec_pretty(&marker).unwrap(),
    )
    .unwrap();
}
