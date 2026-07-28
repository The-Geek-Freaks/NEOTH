//! Request-bound containment for GUI-launched `neoth chat --stream` trees.
//!
//! The GUI must never park a plain `Child`: Linux asks the per-user systemd
//! manager to own a transient service, then the service's trusted guardian
//! roots private cgroup/PID/mount/user namespaces at that unit before provider
//! code starts. Windows starts suspended, enters a KILL_ON_JOB_CLOSE Job
//! Object, and is resumed only after assignment succeeds. Other Unix targets
//! fail closed because a process group cannot contain descendants that call
//! `setsid()`.

use std::collections::HashSet;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::chat_stream_phase::ChatStreamRequestId;

const CHAT_TREE_CLEANUP_WARNING_AFTER: Duration = Duration::from_secs(5);
const CHAT_TREE_POLL_INTERVAL: Duration = Duration::from_millis(20);

pub(crate) struct OwnedChatChild {
    request_id: ChatStreamRequestId,
    child: Child,
    containment: PlatformContainment,
    direct_status: Option<ExitStatus>,
}

impl OwnedChatChild {
    pub(crate) fn spawn(
        request_id: ChatStreamRequestId,
        command: &mut Command,
    ) -> Result<Self, String> {
        let setup = PlatformContainmentSetup::configure(request_id, command)?;
        let mut child = command.spawn().map_err(format_contained_spawn_error)?;
        let containment = match setup.activate(&mut child) {
            Ok(containment) => containment,
            Err(error) => {
                let kill_error = child.kill().err();
                let wait_error = child.wait().err();
                return Err(append_cleanup_errors(error, kill_error, wait_error));
            }
        };
        Ok(Self {
            request_id,
            child,
            containment,
            direct_status: None,
        })
    }

    pub(crate) const fn request_id(&self) -> ChatStreamRequestId {
        self.request_id
    }

    pub(crate) fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.child.stdin.take()
    }

    pub(crate) fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.child.stdout.take()
    }

    pub(crate) fn take_stderr(&mut self) -> Option<ChildStderr> {
        self.child.stderr.take()
    }

    /// Terminate the complete request-owned process tree.
    ///
    /// Termination is deliberately re-issued until the platform containment
    /// primitive proves empty. A timeout may warn but can never release the OS
    /// handle, worker lease, or request-owned secret material.
    pub(crate) fn request_tree_termination(&mut self) -> Result<(), String> {
        self.containment.terminate_tree()
    }

    pub(crate) fn poll_reaped_and_empty(&mut self) -> Result<Option<ExitStatus>, String> {
        if self.direct_status.is_none() {
            self.direct_status = self
                .child
                .try_wait()
                .map_err(|error| format!("poll direct chat subprocess exit: {error}"))?;
        }
        let Some(status) = self.direct_status else {
            return Ok(None);
        };
        Ok(self.containment.tree_is_empty()?.then_some(status))
    }

    pub(crate) fn terminate_and_reap(mut self) -> Result<ExitStatus, String> {
        let mut next_warning = Instant::now() + CHAT_TREE_CLEANUP_WARNING_AFTER;
        let mut last_error: Option<String> = None;
        loop {
            if let Err(error) = self.request_tree_termination() {
                last_error = Some(error);
            }
            match self.poll_reaped_and_empty() {
                Ok(Some(status)) => return Ok(status),
                Ok(None) => {}
                Err(error) => last_error = Some(error),
            }
            if Instant::now() >= next_warning {
                tracing::warn!(
                    request_id = self.request_id.get(),
                    last_error = last_error.as_deref().unwrap_or("none"),
                    "chat process tree cleanup remains pending; retaining ownership and retrying"
                );
                next_warning = Instant::now() + CHAT_TREE_CLEANUP_WARNING_AFTER;
            }
            std::thread::sleep(CHAT_TREE_POLL_INTERVAL);
        }
    }
}

impl Drop for OwnedChatChild {
    fn drop(&mut self) {
        let mut next_warning = Instant::now() + CHAT_TREE_CLEANUP_WARNING_AFTER;
        let mut last_error: Option<String> = None;
        loop {
            if let Err(error) = self.request_tree_termination() {
                last_error = Some(error);
            }
            if self.direct_status.is_none() {
                match self.child.try_wait() {
                    Ok(status) => self.direct_status = status,
                    Err(error) => {
                        last_error = Some(format!("reap direct chat subprocess: {error}"));
                    }
                }
            }
            match self.containment.tree_is_empty() {
                Ok(true) if self.direct_status.is_some() => return,
                Ok(_) => {}
                Err(error) => last_error = Some(error),
            }
            if Instant::now() >= next_warning {
                tracing::warn!(
                    request_id = self.request_id.get(),
                    last_error = last_error.as_deref().unwrap_or("none"),
                    "chat supervisor drop remains pending; retaining OS containment and retrying until empty proof"
                );
                next_warning = Instant::now() + CHAT_TREE_CLEANUP_WARNING_AFTER;
            }
            std::thread::sleep(CHAT_TREE_POLL_INTERVAL);
        }
    }
}

#[cfg(target_os = "linux")]
fn format_contained_spawn_error(error: std::io::Error) -> String {
    format!(
        "[NEOTH_GUI_CONTAINMENT_LAUNCH_FAILED] GUI chat did not enter its verified systemd \
         user-manager service boundary or could not execute: {error}"
    )
}

#[cfg(not(target_os = "linux"))]
fn format_contained_spawn_error(error: std::io::Error) -> String {
    format!("spawn contained chat subprocess: {error}")
}

fn append_cleanup_errors(
    primary: String,
    kill_error: Option<std::io::Error>,
    wait_error: Option<std::io::Error>,
) -> String {
    let mut message = primary;
    if let Some(error) = kill_error {
        message.push_str(&format!("; direct-child cleanup failed: {error}"));
    }
    if let Some(error) = wait_error {
        message.push_str(&format!("; direct-child reap failed: {error}"));
    }
    message
}

#[derive(Default)]
struct WorkerState {
    closing: bool,
    active: HashSet<ChatStreamRequestId>,
}

/// Tracks the dispatch-claimed interval that exists before a child is parked.
#[derive(Default)]
pub(crate) struct ChatWorkerBarrier {
    state: Mutex<WorkerState>,
    changed: Condvar,
}

impl ChatWorkerBarrier {
    pub(crate) fn claim(
        self: &Arc<Self>,
        request_id: ChatStreamRequestId,
    ) -> Result<ChatWorkerLease, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "chat worker barrier is unavailable".to_string())?;
        if state.closing {
            return Err("GUI shutdown has closed chat dispatch".to_string());
        }
        if !state.active.insert(request_id) {
            return Err("chat worker request is already registered".to_string());
        }
        Ok(ChatWorkerLease {
            barrier: Arc::clone(self),
            request_id,
        })
    }

    pub(crate) fn begin_shutdown(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.closing = true;
        self.changed.notify_all();
    }

    /// Wait until every dispatch-claimed worker has dropped its lease.
    ///
    /// Shutdown must not outlive workers that can still hold request bodies,
    /// launch envelopes, consent material, or process-tree ownership. The
    /// five-second interval is therefore diagnostic, never an ownership
    /// timeout.
    pub(crate) fn wait_empty(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while !state.active.is_empty() {
            let (next, wait) = self
                .changed
                .wait_timeout(state, CHAT_TREE_CLEANUP_WARNING_AFTER)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state = next;
            if wait.timed_out() && !state.active.is_empty() {
                let requests = state
                    .active
                    .iter()
                    .map(|request| request.get().to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                tracing::warn!(
                    requests = %requests,
                    "chat shutdown remains pending; retaining worker and secret ownership"
                );
            }
        }
    }
}

pub(crate) struct ChatWorkerLease {
    barrier: Arc<ChatWorkerBarrier>,
    request_id: ChatStreamRequestId,
}

impl Drop for ChatWorkerLease {
    fn drop(&mut self) {
        let mut state = self
            .barrier
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.active.remove(&self.request_id);
        self.barrier.changed.notify_all();
    }
}

#[cfg(target_os = "linux")]
const LINUX_SYSTEMD_MANAGER_ERROR: &str = "[NEOTH_GUI_CONTAINMENT_SYSTEMD_USER_MANAGER_UNAVAILABLE] GUI chat cannot start safely: \
     the per-user systemd manager did not create and verify the request-owned transient service";

#[cfg(target_os = "linux")]
const LINUX_SYSTEMD_TOOL_ERROR: &str = "[NEOTH_GUI_CONTAINMENT_SYSTEMD_TOOL_UNTRUSTED] GUI chat cannot start safely: \
     systemd-run/systemctl must be absolute, root-owned, executable, and not group/world writable";

#[cfg(target_os = "linux")]
const LINUX_NAMESPACE_ERROR: &str = "[NEOTH_GUI_CONTAINMENT_NAMESPACE_UNAVAILABLE] GUI chat cannot start safely: \
     the manager-owned service could not establish a private cgroup/PID/mount/user namespace \
     rooted at the request unit";

#[cfg(target_os = "linux")]
const LINUX_SERVICE_ERROR: &str = "[NEOTH_GUI_CONTAINMENT_SERVICE_FAILED] The manager-owned GUI chat service failed before \
     provider launch";

#[cfg(target_os = "linux")]
const LINUX_INTERNAL_HELPER_FLAG: &str = "--neoth-internal-chat-service-v1";

#[cfg(target_os = "linux")]
const LINUX_LAUNCH_FRAME_MAGIC: &[u8; 16] = b"NEOTHCHATUNITV1\0";

#[cfg(target_os = "linux")]
const LINUX_LAUNCH_FRAME_MAX_BYTES: usize = 32 * 1024 * 1024;

#[cfg(target_os = "linux")]
const LINUX_UNIT_START_TIMEOUT: Duration = Duration::from_secs(10);

#[cfg(target_os = "linux")]
const LINUX_SYSTEMCTL_TIMEOUT: Duration = Duration::from_secs(3);

#[cfg(any(target_os = "linux", test))]
fn parse_unified_cgroup_path(contents: &str) -> Result<String, String> {
    let mut unified = None;
    for line in contents.lines().filter(|line| !line.trim().is_empty()) {
        let mut fields = line.splitn(3, ':');
        let hierarchy = fields
            .next()
            .ok_or_else(|| "missing cgroup hierarchy id".to_string())?;
        let controllers = fields
            .next()
            .ok_or_else(|| "missing cgroup controller list".to_string())?;
        let path = fields
            .next()
            .ok_or_else(|| "missing cgroup path".to_string())?;
        if hierarchy == "0" && controllers.is_empty() {
            if unified.replace(path.to_string()).is_some() {
                return Err("multiple unified cgroup-v2 entries".to_string());
            }
        }
    }
    let path = unified.ok_or_else(|| "no unified cgroup-v2 entry".to_string())?;
    if !path.starts_with('/') || path.split('/').any(|part| part == "." || part == "..") {
        return Err("unified cgroup-v2 path is not absolute and normalized".to_string());
    }
    Ok(path)
}

#[cfg(any(target_os = "linux", test))]
fn decode_mountinfo_field(field: &str) -> Result<String, String> {
    let bytes = field.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'\\' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 3 >= bytes.len() {
            return Err("truncated mountinfo path escape".to_string());
        }
        let escape = &bytes[index + 1..index + 4];
        let value = match escape {
            b"040" => b' ',
            b"011" => b'\t',
            b"012" => b'\n',
            b"134" => b'\\',
            _ => return Err("unsupported mountinfo path escape".to_string()),
        };
        decoded.push(value);
        index += 4;
    }
    String::from_utf8(decoded).map_err(|_| "mountinfo path is not valid UTF-8".to_string())
}

#[cfg(any(target_os = "linux", test))]
fn parse_cgroup2_mounts(contents: &str) -> Result<Vec<(String, String)>, String> {
    let mut mounts = Vec::new();
    for (line_number, line) in contents.lines().enumerate() {
        let Some((identity, filesystem)) = line.split_once(" - ") else {
            return Err(format!(
                "mountinfo line {} has no filesystem separator",
                line_number + 1
            ));
        };
        let mut filesystem_fields = filesystem.split_ascii_whitespace();
        if filesystem_fields.next() != Some("cgroup2") {
            continue;
        }
        let identity_fields = identity.split_ascii_whitespace().collect::<Vec<_>>();
        if identity_fields.len() < 5 {
            return Err(format!(
                "cgroup2 mountinfo line {} is incomplete",
                line_number + 1
            ));
        }
        mounts.push((
            decode_mountinfo_field(identity_fields[3])?,
            decode_mountinfo_field(identity_fields[4])?,
        ));
    }
    if mounts.is_empty() {
        return Err("no cgroup2 filesystem is mounted".to_string());
    }
    Ok(mounts)
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_filesystem_mount_points(
    contents: &str,
    filesystem_type: &str,
) -> Result<Vec<String>, String> {
    let mut mount_points = Vec::new();
    for (line_number, line) in contents.lines().enumerate() {
        let Some((identity, filesystem)) = line.split_once(" - ") else {
            return Err(format!(
                "mountinfo line {} has no filesystem separator",
                line_number + 1
            ));
        };
        if filesystem.split_ascii_whitespace().next() != Some(filesystem_type) {
            continue;
        }
        let identity_fields = identity.split_ascii_whitespace().collect::<Vec<_>>();
        if identity_fields.len() < 5 {
            return Err(format!(
                "{filesystem_type} mountinfo line {} is incomplete",
                line_number + 1
            ));
        }
        mount_points.push(decode_mountinfo_field(identity_fields[4])?);
    }
    Ok(mount_points)
}

#[cfg(any(target_os = "linux", test))]
fn map_cgroup_path_to_mount(
    mount_root: &str,
    mount_point: &str,
    cgroup_path: &str,
) -> Option<String> {
    let relative = if mount_root == "/" {
        cgroup_path.strip_prefix('/')?
    } else if cgroup_path == mount_root {
        ""
    } else {
        cgroup_path.strip_prefix(&format!("{mount_root}/"))?
    };
    Some(if relative.is_empty() {
        mount_point.to_string()
    } else {
        format!("{}/{}", mount_point.trim_end_matches('/'), relative)
    })
}

#[cfg(any(target_os = "linux", test))]
fn parse_cgroup_populated(contents: &str) -> Result<bool, String> {
    let mut populated = None;
    for (line_number, line) in contents.lines().enumerate() {
        let mut fields = line.split_ascii_whitespace();
        let key = fields
            .next()
            .ok_or_else(|| format!("cgroup.events line {} has no event name", line_number + 1))?;
        let value = fields
            .next()
            .ok_or_else(|| format!("cgroup.events line {} has no value", line_number + 1))?;
        if fields.next().is_some() {
            return Err(format!(
                "cgroup.events line {} has extra fields",
                line_number + 1
            ));
        }
        if key == "populated" {
            let value = match value {
                "0" => false,
                "1" => true,
                _ => return Err("cgroup.events populated value is not 0 or 1".to_string()),
            };
            if populated.replace(value).is_some() {
                return Err("cgroup.events contains duplicate populated state".to_string());
            }
        }
    }
    populated.ok_or_else(|| "cgroup.events has no populated state".to_string())
}

#[cfg(any(target_os = "linux", test))]
fn parse_cgroup_populated_bytes(contents: &[u8]) -> Option<bool> {
    contents.split(|byte| *byte == b'\n').find_map(|line| {
        let line = line.strip_prefix(b"populated ")?;
        match line {
            b"0" => Some(false),
            b"1" => Some(true),
            _ => None,
        }
    })
}

#[cfg(target_os = "linux")]
struct PlatformContainmentSetup {
    unit: LinuxChatUnitSetup,
}

#[cfg(target_os = "linux")]
impl PlatformContainmentSetup {
    fn configure(request_id: ChatStreamRequestId, command: &mut Command) -> Result<Self, String> {
        Ok(Self {
            unit: LinuxChatUnitSetup::configure(request_id, command)?,
        })
    }

    fn activate(self, child: &mut Child) -> Result<PlatformContainment, String> {
        Ok(PlatformContainment {
            unit: self.unit.activate(child)?,
        })
    }
}

#[cfg(target_os = "linux")]
struct PlatformContainment {
    unit: LinuxChatUnit,
}

#[cfg(target_os = "linux")]
impl PlatformContainment {
    fn terminate_tree(&mut self) -> Result<(), String> {
        self.unit.terminate()
    }

    fn tree_is_empty(&mut self) -> Result<bool, String> {
        self.unit.is_empty_and_inactive()
    }
}

#[cfg(target_os = "linux")]
struct LinuxChatUnitSetup {
    unit_name: String,
    systemctl: std::path::PathBuf,
    launch_frame: Vec<u8>,
}

#[cfg(target_os = "linux")]
impl LinuxChatUnitSetup {
    fn configure(request_id: ChatStreamRequestId, command: &mut Command) -> Result<Self, String> {
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::process::CommandExt as _;

        let systemd_run = trusted_linux_systemd_tool("systemd-run")?;
        let systemctl = trusted_linux_systemd_tool("systemctl")?;
        let helper = validate_linux_executable(
            &std::env::current_exe().map_err(|error| {
                format!("{LINUX_SYSTEMD_TOOL_ERROR}: locate GUI binary: {error}")
            })?,
            false,
            "GUI containment helper",
        )?;
        if helper.as_os_str().as_bytes().contains(&b'$') {
            return Err(format!(
                "{LINUX_SYSTEMD_TOOL_ERROR}: GUI helper path contains '$', which the service manager expands"
            ));
        }
        let parent_pid = std::process::id();
        let parent_start_ticks = read_linux_process_start_ticks(parent_pid)?;
        let mut nonce = [0_u8; 16];
        getrandom::getrandom(&mut nonce).map_err(|error| {
            format!("{LINUX_SYSTEMD_MANAGER_ERROR}: generate unit nonce: {error}")
        })?;
        let unit_name = linux_chat_unit_name(request_id, parent_pid, nonce);
        let launch = LinuxLaunchEnvelope::capture(
            request_id,
            &unit_name,
            parent_pid,
            parent_start_ticks,
            command,
        )?;
        let launch_frame = launch.encode()?;

        let mut argv = vec![
            systemd_run.as_os_str().to_owned(),
            "--user".into(),
            "--quiet".into(),
            "--wait".into(),
            "--pipe".into(),
            "--collect".into(),
            "--service-type=notify".into(),
            format!("--unit={unit_name}").into(),
            "--property=Delegate=no".into(),
            "--property=KillMode=control-group".into(),
            "--property=SendSIGKILL=yes".into(),
            "--property=TimeoutStopSec=2s".into(),
            "--property=Restart=no".into(),
            "--property=NotifyAccess=main".into(),
            "--property=UMask=0077".into(),
            "--property=NoNewPrivileges=yes".into(),
            "--property=UnsetEnvironment=LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT DBUS_SESSION_BUS_ADDRESS".into(),
            "--".into(),
            helper.as_os_str().to_owned(),
        ];
        #[cfg(test)]
        {
            let separator = argv
                .iter()
                .position(|argument| argument == std::ffi::OsStr::new("--"))
                .expect("systemd-run argv has a command separator");
            argv.insert(separator, "--setenv=NEOTH_GUI_CHAT_TEST_HELPER=1".into());
            argv.extend([
                "--exact".into(),
                "chat_child_supervisor::tests::linux_systemd_helper_fixture_entry".into(),
                "--nocapture".into(),
            ]);
        }
        #[cfg(not(test))]
        argv.push(LINUX_INTERNAL_HELPER_FLAG.into());
        let exec_argv = LinuxExecArgv::new(argv)?;
        let expected_parent = unsafe { libc::getpid() };

        // Preserve the provider's final environment in the private launch
        // frame, but never let loader injection or inherited service-control
        // descriptors/addresses affect the trusted systemd client.
        for variable in [
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "LD_AUDIT",
            "DBUS_SESSION_BUS_ADDRESS",
            "NOTIFY_SOCKET",
            "WATCHDOG_PID",
            "WATCHDOG_USEC",
            "LISTEN_FDS",
            "LISTEN_PID",
            "LISTEN_FDNAMES",
        ] {
            command.env_remove(variable);
        }
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getppid() != expected_parent {
                    return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
                }
                libc::execv(exec_argv.program(), exec_argv.argv());
                Err(std::io::Error::last_os_error())
            });
        }

        Ok(Self {
            unit_name,
            systemctl,
            launch_frame,
        })
    }

    fn activate(self, child: &mut Child) -> Result<LinuxChatUnit, String> {
        use std::io::Write as _;

        let activation = (|| {
            let stdin = child.stdin.as_mut().ok_or_else(|| {
                format!("{LINUX_SERVICE_ERROR}: private launch stdin was not configured as a pipe")
            })?;
            stdin.write_all(&self.launch_frame).map_err(|error| {
                format!("{LINUX_SERVICE_ERROR}: send private launch frame: {error}")
            })?;
            stdin.flush().map_err(|error| {
                format!("{LINUX_SERVICE_ERROR}: flush private launch frame: {error}")
            })?;

            let deadline = Instant::now() + LINUX_UNIT_START_TIMEOUT;
            let mut last_state = "unit not observable".to_string();
            loop {
                if let Some(status) = child.try_wait().map_err(|error| {
                    format!("{LINUX_SYSTEMD_MANAGER_ERROR}: poll systemd-run: {error}")
                })? {
                    return Err(format!(
                        "{LINUX_SYSTEMD_MANAGER_ERROR}: systemd-run exited {status} before the \
                         request service reported READY; last state: {last_state}"
                    ));
                }
                match inspect_linux_unit(&self.systemctl, &self.unit_name) {
                    Ok(snapshot) => {
                        last_state = format!(
                            "load={}, active={}, sub={}",
                            snapshot.load_state, snapshot.active_state, snapshot.sub_state
                        );
                        if snapshot.active_state == "active" && snapshot.sub_state == "running" {
                            snapshot.verify_contract(&self.unit_name)?;
                            let directory =
                                resolve_linux_cgroup_directory(&snapshot.control_group)?;
                            return Ok(LinuxChatUnit {
                                unit_name: self.unit_name.clone(),
                                systemctl: self.systemctl.clone(),
                                cgroup_directory: directory,
                            });
                        }
                        if matches!(snapshot.active_state.as_str(), "failed" | "inactive")
                            && snapshot.load_state != "not-found"
                        {
                            return Err(format!(
                                "{LINUX_SERVICE_ERROR}: manager reported {last_state}"
                            ));
                        }
                    }
                    Err(error) => last_state = error,
                }
                if Instant::now() >= deadline {
                    return Err(format!(
                        "{LINUX_SYSTEMD_MANAGER_ERROR}: timed out waiting for READY; last state: \
                         {last_state}"
                    ));
                }
                std::thread::sleep(CHAT_TREE_POLL_INTERVAL);
            }
        })();

        if activation.is_err() {
            let _ = stop_linux_unit(&self.systemctl, &self.unit_name);
        }
        activation
    }
}

#[cfg(target_os = "linux")]
struct LinuxChatUnit {
    unit_name: String,
    systemctl: std::path::PathBuf,
    cgroup_directory: std::path::PathBuf,
}

#[cfg(target_os = "linux")]
impl LinuxChatUnit {
    fn terminate(&mut self) -> Result<(), String> {
        stop_linux_unit(&self.systemctl, &self.unit_name)
    }

    fn is_empty_and_inactive(&mut self) -> Result<bool, String> {
        let snapshot = inspect_linux_unit(&self.systemctl, &self.unit_name)?;
        let inactive = snapshot.load_state == "not-found"
            || (snapshot.active_state == "inactive" && snapshot.sub_state == "dead");
        if !inactive {
            return Ok(false);
        }
        let populated = match std::fs::read_to_string(self.cgroup_directory.join("cgroup.events")) {
            Ok(events) => parse_cgroup_populated(&events)
                .map_err(|error| format!("parse manager-owned cgroup empty proof: {error}"))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => {
                return Err(format!(
                    "read manager-owned cgroup empty proof {}: {error}",
                    self.cgroup_directory.display()
                ));
            }
        };
        Ok(!populated)
    }
}

#[cfg(target_os = "linux")]
struct LinuxExecArgv {
    _strings: Vec<std::ffi::CString>,
    pointers: Vec<*const libc::c_char>,
}

#[cfg(target_os = "linux")]
unsafe impl Send for LinuxExecArgv {}

#[cfg(target_os = "linux")]
unsafe impl Sync for LinuxExecArgv {}

#[cfg(target_os = "linux")]
impl LinuxExecArgv {
    fn new(arguments: Vec<std::ffi::OsString>) -> Result<Self, String> {
        use std::os::unix::ffi::OsStrExt as _;

        let strings = arguments
            .into_iter()
            .map(|argument| {
                std::ffi::CString::new(argument.as_os_str().as_bytes()).map_err(|_| {
                    format!(
                        "{LINUX_SYSTEMD_TOOL_ERROR}: systemd-run argument contains an interior NUL"
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut pointers = strings
            .iter()
            .map(|argument| argument.as_ptr())
            .collect::<Vec<_>>();
        pointers.push(std::ptr::null());
        Ok(Self {
            _strings: strings,
            pointers,
        })
    }

    fn program(&self) -> *const libc::c_char {
        self.pointers[0]
    }

    fn argv(&self) -> *const *const libc::c_char {
        self.pointers.as_ptr()
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
struct LinuxLaunchEnvelope {
    request_id: u64,
    unit_name: String,
    parent_pid: u32,
    parent_start_ticks: u64,
    program: std::ffi::OsString,
    arguments: Vec<std::ffi::OsString>,
    environment: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    current_directory: std::path::PathBuf,
}

#[cfg(target_os = "linux")]
impl LinuxLaunchEnvelope {
    fn capture(
        request_id: ChatStreamRequestId,
        unit_name: &str,
        parent_pid: u32,
        parent_start_ticks: u64,
        command: &Command,
    ) -> Result<Self, String> {
        let program = validate_linux_executable(
            std::path::Path::new(command.get_program()),
            false,
            "chat provider",
        )?
        .into_os_string();
        let current_directory = command.get_current_dir().map_or_else(
            || {
                std::env::current_dir()
                    .map_err(|error| format!("resolve chat working directory: {error}"))
            },
            |path| {
                std::fs::canonicalize(path).map_err(|error| {
                    format!("resolve chat working directory {}: {error}", path.display())
                })
            },
        )?;
        if !current_directory.is_absolute() || !current_directory.is_dir() {
            return Err("chat working directory is not an absolute directory".to_string());
        }

        let mut environment = std::env::vars_os().collect::<std::collections::BTreeMap<_, _>>();
        for (name, value) in command.get_envs() {
            match value {
                Some(value) => {
                    environment.insert(name.to_owned(), value.to_owned());
                }
                None => {
                    environment.remove(name);
                }
            }
        }
        Ok(Self {
            request_id: request_id.get(),
            unit_name: unit_name.to_string(),
            parent_pid,
            parent_start_ticks,
            program,
            arguments: command.get_args().map(ToOwned::to_owned).collect(),
            environment: environment.into_iter().collect(),
            current_directory,
        })
    }

    fn encode(&self) -> Result<Vec<u8>, String> {
        use std::os::unix::ffi::OsStrExt as _;

        let mut payload = Vec::new();
        payload.extend_from_slice(LINUX_LAUNCH_FRAME_MAGIC);
        push_linux_frame_u64(&mut payload, self.request_id);
        push_linux_frame_bytes(&mut payload, self.unit_name.as_bytes())?;
        push_linux_frame_u32(&mut payload, self.parent_pid);
        push_linux_frame_u64(&mut payload, self.parent_start_ticks);
        push_linux_frame_bytes(&mut payload, self.program.as_os_str().as_bytes())?;
        push_linux_frame_bytes(&mut payload, self.current_directory.as_os_str().as_bytes())?;
        push_linux_frame_u32(
            &mut payload,
            self.arguments
                .len()
                .try_into()
                .map_err(|_| "too many chat arguments".to_string())?,
        );
        for argument in &self.arguments {
            push_linux_frame_bytes(&mut payload, argument.as_os_str().as_bytes())?;
        }
        push_linux_frame_u32(
            &mut payload,
            self.environment
                .len()
                .try_into()
                .map_err(|_| "too many chat environment variables".to_string())?,
        );
        for (name, value) in &self.environment {
            push_linux_frame_bytes(&mut payload, name.as_os_str().as_bytes())?;
            push_linux_frame_bytes(&mut payload, value.as_os_str().as_bytes())?;
        }
        if payload.len() > LINUX_LAUNCH_FRAME_MAX_BYTES {
            return Err("private chat launch frame exceeds the bounded size".to_string());
        }
        let mut frame = Vec::with_capacity(8 + payload.len());
        frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        frame.extend_from_slice(&payload);
        Ok(frame)
    }

    fn decode(payload: &[u8]) -> Result<Self, String> {
        use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};

        let mut decoder = LinuxFrameDecoder::new(payload);
        if decoder.take(LINUX_LAUNCH_FRAME_MAGIC.len())? != LINUX_LAUNCH_FRAME_MAGIC {
            return Err("private chat launch frame magic mismatch".to_string());
        }
        let request_id = decoder.u64()?;
        let unit_name = String::from_utf8(decoder.bytes()?.to_vec())
            .map_err(|_| "chat unit name is not UTF-8".to_string())?;
        let parent_pid = decoder.u32()?;
        let parent_start_ticks = decoder.u64()?;
        let program = std::ffi::OsString::from_vec(decoder.bytes()?.to_vec());
        let current_directory =
            std::path::PathBuf::from(std::ffi::OsString::from_vec(decoder.bytes()?.to_vec()));
        let argument_count = decoder.bounded_count()?;
        let mut arguments = Vec::with_capacity(argument_count);
        for _ in 0..argument_count {
            arguments.push(std::ffi::OsString::from_vec(decoder.bytes()?.to_vec()));
        }
        let environment_count = decoder.bounded_count()?;
        let mut environment = Vec::with_capacity(environment_count);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..environment_count {
            let name = std::ffi::OsString::from_vec(decoder.bytes()?.to_vec());
            let value = std::ffi::OsString::from_vec(decoder.bytes()?.to_vec());
            if name.is_empty()
                || name
                    .as_os_str()
                    .as_bytes()
                    .iter()
                    .any(|byte| matches!(byte, 0 | b'='))
                || !seen.insert(name.clone())
            {
                return Err("private chat launch frame has an invalid environment".to_string());
            }
            environment.push((name, value));
        }
        if !decoder.is_empty() {
            return Err("private chat launch frame has trailing bytes".to_string());
        }
        let envelope = Self {
            request_id,
            unit_name,
            parent_pid,
            parent_start_ticks,
            program,
            arguments,
            environment,
            current_directory,
        };
        verify_linux_unit_binding(
            &envelope.unit_name,
            envelope.request_id,
            envelope.parent_pid,
        )?;
        Ok(envelope)
    }
}

#[cfg(target_os = "linux")]
fn push_linux_frame_u32(payload: &mut Vec<u8>, value: u32) {
    payload.extend_from_slice(&value.to_be_bytes());
}

#[cfg(target_os = "linux")]
fn push_linux_frame_u64(payload: &mut Vec<u8>, value: u64) {
    payload.extend_from_slice(&value.to_be_bytes());
}

#[cfg(target_os = "linux")]
fn push_linux_frame_bytes(payload: &mut Vec<u8>, value: &[u8]) -> Result<(), String> {
    let length = u32::try_from(value.len())
        .map_err(|_| "private chat launch field is too large".to_string())?;
    push_linux_frame_u32(payload, length);
    payload.extend_from_slice(value);
    Ok(())
}

#[cfg(target_os = "linux")]
struct LinuxFrameDecoder<'a> {
    remaining: &'a [u8],
}

#[cfg(target_os = "linux")]
impl<'a> LinuxFrameDecoder<'a> {
    const fn new(remaining: &'a [u8]) -> Self {
        Self { remaining }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], String> {
        if length > self.remaining.len() {
            return Err("private chat launch frame is truncated".to_string());
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn u32(&mut self) -> Result<u32, String> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| "invalid u32 launch field".to_string())?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, String> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| "invalid u64 launch field".to_string())?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn bytes(&mut self) -> Result<&'a [u8], String> {
        let length = self.u32()? as usize;
        self.take(length)
    }

    fn bounded_count(&mut self) -> Result<usize, String> {
        let count = self.u32()? as usize;
        if count > 65_536 {
            return Err("private chat launch collection is too large".to_string());
        }
        Ok(count)
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

#[cfg(target_os = "linux")]
fn linux_chat_unit_name(
    request_id: ChatStreamRequestId,
    parent_pid: u32,
    nonce: [u8; 16],
) -> String {
    format!(
        "neoth-gui-chat-r{}-p{parent_pid}-n{}.service",
        request_id.get(),
        hex::encode(nonce)
    )
}

#[cfg(target_os = "linux")]
fn verify_linux_unit_binding(
    unit_name: &str,
    request_id: u64,
    parent_pid: u32,
) -> Result<(), String> {
    let prefix = format!("neoth-gui-chat-r{request_id}-p{parent_pid}-n");
    let nonce = unit_name
        .strip_prefix(&prefix)
        .and_then(|value| value.strip_suffix(".service"))
        .ok_or_else(|| "chat unit is not bound to the exact request and GUI process".to_string())?;
    if nonce.len() != 32
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("chat unit nonce is not canonical lowercase hex".to_string());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_linux_executable(
    path: &std::path::Path,
    require_root_owner: bool,
    role: &str,
) -> Result<std::path::PathBuf, String> {
    use std::os::unix::fs::MetadataExt as _;

    let canonical = std::fs::canonicalize(path).map_err(|error| {
        format!(
            "{LINUX_SYSTEMD_TOOL_ERROR}: resolve {role} {}: {error}",
            path.display()
        )
    })?;
    let metadata = std::fs::metadata(&canonical).map_err(|error| {
        format!(
            "{LINUX_SYSTEMD_TOOL_ERROR}: inspect {role} {}: {error}",
            canonical.display()
        )
    })?;
    let owner_allowed = metadata.uid() == 0
        || (!require_root_owner && metadata.uid() == unsafe { libc::geteuid() });
    if !canonical.is_absolute()
        || !metadata.is_file()
        || !owner_allowed
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
    {
        return Err(format!(
            "{LINUX_SYSTEMD_TOOL_ERROR}: {role} {} failed ownership/mode validation",
            canonical.display()
        ));
    }
    Ok(canonical)
}

#[cfg(target_os = "linux")]
fn trusted_linux_systemd_tool(name: &str) -> Result<std::path::PathBuf, String> {
    for candidate in [
        std::path::PathBuf::from("/usr/bin").join(name),
        std::path::PathBuf::from("/bin").join(name),
    ] {
        if candidate.exists()
            && let Ok(validated) = validate_linux_executable(&candidate, true, name)
        {
            return Ok(validated);
        }
    }
    Err(format!(
        "{LINUX_SYSTEMD_TOOL_ERROR}: no trusted /usr/bin/{name} or /bin/{name}"
    ))
}

#[cfg(target_os = "linux")]
fn read_linux_process_start_ticks(pid: u32) -> Result<u64, String> {
    let path = format!("/proc/{pid}/stat");
    let stat = std::fs::read_to_string(&path)
        .map_err(|error| format!("{LINUX_SYSTEMD_MANAGER_ERROR}: read {path}: {error}"))?;
    parse_linux_process_start_ticks(&stat)
        .map_err(|error| format!("{LINUX_SYSTEMD_MANAGER_ERROR}: parse {path}: {error}"))
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_process_start_ticks(stat: &str) -> Result<u64, String> {
    let close = stat
        .rfind(") ")
        .ok_or_else(|| "process stat has no command terminator".to_string())?;
    stat[close + 2..]
        .split_ascii_whitespace()
        .nth(19)
        .ok_or_else(|| "process stat has no starttime field".to_string())?
        .parse()
        .map_err(|_| "process starttime is not an unsigned integer".to_string())
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct LinuxUnitSnapshot {
    load_state: String,
    active_state: String,
    sub_state: String,
    control_group: String,
    delegate: String,
    kill_mode: String,
    send_sigkill: String,
    main_pid: u32,
}

#[cfg(target_os = "linux")]
impl LinuxUnitSnapshot {
    fn verify_contract(&self, unit_name: &str) -> Result<(), String> {
        if self.load_state != "loaded"
            || self.delegate != "no"
            || self.kill_mode != "control-group"
            || self.send_sigkill != "yes"
            || self.main_pid == 0
        {
            return Err(format!(
                "{LINUX_SERVICE_ERROR}: unit contract mismatch: load={}, delegate={}, \
                 kill_mode={}, send_sigkill={}, main_pid={}",
                self.load_state, self.delegate, self.kill_mode, self.send_sigkill, self.main_pid
            ));
        }
        if self
            .control_group
            .rsplit('/')
            .next()
            .filter(|component| *component == unit_name)
            .is_none()
        {
            return Err(format!(
                "{LINUX_SERVICE_ERROR}: manager ControlGroup is not bound to {unit_name}"
            ));
        }
        let main_cgroup = std::fs::read_to_string(format!("/proc/{}/cgroup", self.main_pid))
            .map_err(|error| {
                format!(
                    "{LINUX_SERVICE_ERROR}: read manager MainPID {} cgroup: {error}",
                    self.main_pid
                )
            })
            .and_then(|contents| parse_unified_cgroup_path(&contents))?;
        if main_cgroup != self.control_group {
            return Err(format!(
                "{LINUX_SERVICE_ERROR}: manager MainPID cgroup {main_cgroup} does not match {}",
                self.control_group
            ));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn parse_linux_unit_snapshot(contents: &str) -> Result<LinuxUnitSnapshot, String> {
    let mut properties = std::collections::HashMap::new();
    for line in contents.lines().filter(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once('=')
            .ok_or_else(|| "systemctl show emitted a malformed property".to_string())?;
        if properties.insert(name, value).is_some() {
            return Err(format!("systemctl show duplicated {name}"));
        }
    }
    let required = |name: &str| {
        properties
            .get(name)
            .copied()
            .ok_or_else(|| format!("systemctl show omitted {name}"))
    };
    Ok(LinuxUnitSnapshot {
        load_state: required("LoadState")?.to_string(),
        active_state: required("ActiveState")?.to_string(),
        sub_state: required("SubState")?.to_string(),
        control_group: required("ControlGroup")?.to_string(),
        delegate: required("Delegate")?.to_string(),
        kill_mode: required("KillMode")?.to_string(),
        send_sigkill: required("SendSIGKILL")?.to_string(),
        main_pid: required("MainPID")?
            .parse()
            .map_err(|_| "systemctl show MainPID is not numeric".to_string())?,
    })
}

#[cfg(target_os = "linux")]
fn inspect_linux_unit(
    systemctl: &std::path::Path,
    unit_name: &str,
) -> Result<LinuxUnitSnapshot, String> {
    let output = run_linux_systemctl(
        systemctl,
        &[
            "--user",
            "--no-pager",
            "show",
            unit_name,
            "--property=LoadState",
            "--property=ActiveState",
            "--property=SubState",
            "--property=ControlGroup",
            "--property=Delegate",
            "--property=KillMode",
            "--property=SendSIGKILL",
            "--property=MainPID",
        ],
    )?;
    if output.stdout.len() > 64 * 1024 {
        return Err("systemctl show output exceeded the bounded size".to_string());
    }
    let stdout = std::str::from_utf8(&output.stdout)
        .map_err(|_| "systemctl show output is not UTF-8".to_string())?;
    if stdout.is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "{LINUX_SYSTEMD_MANAGER_ERROR}: systemctl show returned no state ({})",
            stderr.trim()
        ));
    }
    parse_linux_unit_snapshot(stdout)
}

#[cfg(target_os = "linux")]
fn stop_linux_unit(systemctl: &std::path::Path, unit_name: &str) -> Result<(), String> {
    let output = run_linux_systemctl(
        systemctl,
        &["--user", "--no-pager", "--quiet", "stop", unit_name],
    )?;
    if output.status.success() {
        return Ok(());
    }
    let snapshot = inspect_linux_unit(systemctl, unit_name)?;
    if snapshot.load_state == "not-found"
        || (snapshot.active_state == "inactive" && snapshot.sub_state == "dead")
    {
        return Ok(());
    }
    Err(format!(
        "{LINUX_SYSTEMD_MANAGER_ERROR}: systemctl stop failed for {unit_name}: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

#[cfg(target_os = "linux")]
fn run_linux_systemctl(
    systemctl: &std::path::Path,
    arguments: &[&str],
) -> Result<std::process::Output, String> {
    let mut command = Command::new(systemctl);
    command
        .args(arguments)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .env_remove("LD_PRELOAD")
        .env_remove("LD_LIBRARY_PATH")
        .env_remove("LD_AUDIT")
        .env_remove("DBUS_SESSION_BUS_ADDRESS")
        .env_remove("NOTIFY_SOCKET")
        .env_remove("WATCHDOG_PID")
        .env_remove("WATCHDOG_USEC")
        .env_remove("LISTEN_FDS")
        .env_remove("LISTEN_PID")
        .env_remove("LISTEN_FDNAMES");
    let mut child = command.spawn().map_err(|error| {
        format!("{LINUX_SYSTEMD_MANAGER_ERROR}: start trusted systemctl: {error}")
    })?;
    let deadline = Instant::now() + LINUX_SYSTEMCTL_TIMEOUT;
    loop {
        if child
            .try_wait()
            .map_err(|error| format!("poll trusted systemctl: {error}"))?
            .is_some()
        {
            return child
                .wait_with_output()
                .map_err(|error| format!("collect trusted systemctl output: {error}"));
        }
        if Instant::now() >= deadline {
            let kill_error = child.kill().err();
            let wait_error = child.wait().err();
            return Err(append_cleanup_errors(
                format!("{LINUX_SYSTEMD_MANAGER_ERROR}: trusted systemctl timed out"),
                kill_error,
                wait_error,
            ));
        }
        std::thread::sleep(CHAT_TREE_POLL_INTERVAL);
    }
}

#[cfg(target_os = "linux")]
fn resolve_linux_cgroup_directory(cgroup_path: &str) -> Result<std::path::PathBuf, String> {
    let mounts = std::fs::read_to_string("/proc/self/mountinfo")
        .map_err(|error| format!("read /proc/self/mountinfo: {error}"))
        .and_then(|contents| parse_cgroup2_mounts(&contents))?;
    let (_, mapped) = mounts
        .into_iter()
        .filter_map(|(root, point)| {
            map_cgroup_path_to_mount(&root, &point, cgroup_path).map(|mapped| (root.len(), mapped))
        })
        .max_by_key(|(root_length, _)| *root_length)
        .ok_or_else(|| "manager ControlGroup is outside every cgroup2 mount".to_string())?;
    let directory = std::path::PathBuf::from(mapped);
    if !directory.is_dir() {
        return Err(format!(
            "manager ControlGroup {} is not a directory",
            directory.display()
        ));
    }
    Ok(directory)
}

/// Intercept the private Linux guardian mode before tracing or GUI startup.
///
/// The flag is necessary but not sufficient: the helper also verifies its
/// exact request/unit binding and GUI PID identity from the private stdin
/// frame before it creates namespaces or starts provider code.
#[cfg(target_os = "linux")]
pub(crate) fn run_linux_manager_helper_if_requested() -> Option<i32> {
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new(LINUX_INTERNAL_HELPER_FLAG)) {
        return None;
    }
    if arguments.next().is_some() {
        eprintln!("{LINUX_SERVICE_ERROR}: unexpected internal helper argument");
        return Some(125);
    }
    Some(match linux_manager_helper_main() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{error}");
            125
        }
    })
}

#[cfg(target_os = "linux")]
fn linux_manager_helper_main() -> Result<i32, String> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _};

    let envelope = read_linux_launch_envelope()?;
    let current_cgroup = std::fs::read_to_string("/proc/self/cgroup")
        .map_err(|error| format!("{LINUX_NAMESPACE_ERROR}: read helper cgroup: {error}"))
        .and_then(|contents| parse_unified_cgroup_path(&contents))?;
    if current_cgroup.rsplit('/').next() != Some(envelope.unit_name.as_str()) {
        return Err(format!(
            "{LINUX_SERVICE_ERROR}: helper cgroup {current_cgroup} is not bound to {}",
            envelope.unit_name
        ));
    }
    verify_linux_cgroup_mount_has_nsdelegate()?;
    let parent_pidfd = open_verified_linux_pidfd(envelope.parent_pid, envelope.parent_start_ticks)?;
    let notify = connect_linux_notify_socket()?;

    enter_linux_request_namespaces(&envelope.unit_name)?;

    let mut ready_pipe = [-1; 2];
    if unsafe { libc::pipe2(ready_pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(format!(
            "{LINUX_NAMESPACE_ERROR}: create guardian readiness pipe: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: pipe2 returned two fresh descriptors; ownership moves once.
    let ready_read = unsafe { std::os::fd::OwnedFd::from_raw_fd(ready_pipe[0]) };
    let ready_write = unsafe { std::os::fd::OwnedFd::from_raw_fd(ready_pipe[1]) };
    let guardian = unsafe { libc::fork() };
    if guardian < 0 {
        return Err(format!(
            "{LINUX_NAMESPACE_ERROR}: fork PID-namespace guardian: {}",
            std::io::Error::last_os_error()
        ));
    }
    if guardian == 0 {
        drop(ready_read);
        run_linux_pid_namespace_guardian(envelope, ready_write);
    }
    drop(ready_write);

    wait_for_linux_guardian_ready(parent_pidfd.as_raw_fd(), ready_read.as_raw_fd(), guardian)?;
    notify
        .send(b"READY=1\nSTATUS=GUI chat request contained")
        .map_err(|error| format!("{LINUX_SERVICE_ERROR}: notify systemd READY: {error}"))?;
    monitor_linux_gui_and_guardian(parent_pidfd.as_raw_fd(), guardian)
}

#[cfg(target_os = "linux")]
fn read_linux_launch_envelope() -> Result<LinuxLaunchEnvelope, String> {
    let mut length = [0_u8; 8];
    read_exact_linux_fd(libc::STDIN_FILENO, &mut length)
        .map_err(|error| format!("{LINUX_SERVICE_ERROR}: read launch frame length: {error}"))?;
    let length = u64::from_be_bytes(length);
    if length == 0 || length > LINUX_LAUNCH_FRAME_MAX_BYTES as u64 {
        return Err(format!(
            "{LINUX_SERVICE_ERROR}: private launch frame length is out of bounds"
        ));
    }
    let mut payload = vec![0_u8; length as usize];
    read_exact_linux_fd(libc::STDIN_FILENO, &mut payload)
        .map_err(|error| format!("{LINUX_SERVICE_ERROR}: read launch frame: {error}"))?;
    LinuxLaunchEnvelope::decode(&payload).map_err(|error| format!("{LINUX_SERVICE_ERROR}: {error}"))
}

#[cfg(target_os = "linux")]
fn read_exact_linux_fd(fd: libc::c_int, mut bytes: &mut [u8]) -> Result<(), std::io::Error> {
    while !bytes.is_empty() {
        let read = unsafe { libc::read(fd, bytes.as_mut_ptr().cast(), bytes.len()) };
        if read > 0 {
            bytes = &mut bytes[read as usize..];
            continue;
        }
        if read < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(if read == 0 {
            std::io::Error::from_raw_os_error(libc::EPIPE)
        } else {
            std::io::Error::last_os_error()
        });
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn write_linux_ready_byte(fd: libc::c_int, value: u8) -> Result<(), std::io::Error> {
    loop {
        let written = unsafe { libc::write(fd, (&raw const value).cast(), 1) };
        if written == 1 {
            return Ok(());
        }
        if written < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(error);
        }
        return Err(std::io::Error::from_raw_os_error(libc::EIO));
    }
}

#[cfg(target_os = "linux")]
fn open_verified_linux_pidfd(
    pid: u32,
    expected_start_ticks: u64,
) -> Result<std::os::fd::OwnedFd, String> {
    use std::os::fd::FromRawFd as _;

    if read_linux_process_start_ticks(pid)? != expected_start_ticks {
        return Err(format!(
            "{LINUX_SERVICE_ERROR}: GUI PID identity changed before helper startup"
        ));
    }
    let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0_u32) as libc::c_int };
    if descriptor < 0 {
        return Err(format!(
            "{LINUX_SYSTEMD_MANAGER_ERROR}: pidfd_open for GUI PID {pid}: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: pidfd_open returned a fresh descriptor.
    let pidfd = unsafe { std::os::fd::OwnedFd::from_raw_fd(descriptor) };
    if read_linux_process_start_ticks(pid)? != expected_start_ticks {
        return Err(format!(
            "{LINUX_SERVICE_ERROR}: GUI PID identity changed during helper startup"
        ));
    }
    Ok(pidfd)
}

#[cfg(target_os = "linux")]
fn connect_linux_notify_socket() -> Result<std::os::unix::net::UnixDatagram, String> {
    use std::os::linux::net::SocketAddrExt as _;
    use std::os::unix::ffi::OsStrExt as _;

    let address = std::env::var_os("NOTIFY_SOCKET")
        .ok_or_else(|| format!("{LINUX_SERVICE_ERROR}: NOTIFY_SOCKET is missing"))?;
    let bytes = address.as_os_str().as_bytes();
    let socket = std::os::unix::net::UnixDatagram::unbound()
        .map_err(|error| format!("{LINUX_SERVICE_ERROR}: create notify socket: {error}"))?;
    if let Some(name) = bytes.strip_prefix(b"@") {
        let address = std::os::unix::net::SocketAddr::from_abstract_name(name)
            .map_err(|error| format!("{LINUX_SERVICE_ERROR}: parse notify socket: {error}"))?;
        socket
            .connect_addr(&address)
            .map_err(|error| format!("{LINUX_SERVICE_ERROR}: connect notify socket: {error}"))?;
    } else {
        socket
            .connect(std::path::Path::new(&address))
            .map_err(|error| format!("{LINUX_SERVICE_ERROR}: connect notify socket: {error}"))?;
    }
    Ok(socket)
}

#[cfg(target_os = "linux")]
fn verify_linux_cgroup_mount_has_nsdelegate() -> Result<(), String> {
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo")
        .map_err(|error| format!("{LINUX_NAMESPACE_ERROR}: read mountinfo: {error}"))?;
    let mounts = parse_cgroup2_mounts(&mountinfo)
        .map_err(|error| format!("{LINUX_NAMESPACE_ERROR}: {error}"))?;
    if mounts.as_slice() != [("/".to_string(), "/sys/fs/cgroup".to_string())] {
        return Err(format!(
            "{LINUX_NAMESPACE_ERROR}: expected only the canonical /sys/fs/cgroup cgroup2 mount; \
             found {mounts:?}"
        ));
    }
    let proc_mounts = parse_linux_filesystem_mount_points(&mountinfo, "proc")
        .map_err(|error| format!("{LINUX_NAMESPACE_ERROR}: {error}"))?;
    if proc_mounts.is_empty()
        || proc_mounts
            .iter()
            .any(|point| point != "/proc" && !point.starts_with("/proc/"))
    {
        return Err(format!(
            "{LINUX_NAMESPACE_ERROR}: procfs is exposed outside /proc: {proc_mounts:?}"
        ));
    }
    if linux_cgroup_mount_security(&mountinfo, Some("/sys/fs/cgroup"))?.nsdelegate {
        Ok(())
    } else {
        Err(format!(
            "{LINUX_NAMESPACE_ERROR}: cgroup2 is not mounted with nsdelegate"
        ))
    }
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, PartialEq, Eq)]
struct LinuxCgroupMountSecurity {
    root: String,
    read_only: bool,
    nsdelegate: bool,
}

#[cfg(any(target_os = "linux", test))]
fn linux_cgroup_mount_security(
    mountinfo: &str,
    exact_mount_point: Option<&str>,
) -> Result<LinuxCgroupMountSecurity, String> {
    let mut matches = Vec::new();
    for (line_number, line) in mountinfo.lines().enumerate() {
        let Some((identity, filesystem)) = line.split_once(" - ") else {
            return Err(format!(
                "mountinfo line {} has no filesystem separator",
                line_number + 1
            ));
        };
        let filesystem_fields = filesystem.split_ascii_whitespace().collect::<Vec<_>>();
        if filesystem_fields.first().copied() != Some("cgroup2") {
            continue;
        }
        let identity_fields = identity.split_ascii_whitespace().collect::<Vec<_>>();
        if identity_fields.len() < 6 || filesystem_fields.len() < 3 {
            return Err(format!(
                "cgroup2 mountinfo line {} is incomplete",
                line_number + 1
            ));
        }
        let mount_point = decode_mountinfo_field(identity_fields[4])?;
        if exact_mount_point.is_some_and(|expected| mount_point != expected) {
            continue;
        }
        let mount_id = identity_fields[0].parse::<u64>().map_err(|_| {
            format!(
                "cgroup2 mountinfo line {} has an invalid id",
                line_number + 1
            )
        })?;
        let mount_options = identity_fields[5].split(',').collect::<HashSet<_>>();
        let super_options = filesystem_fields[2].split(',').collect::<HashSet<_>>();
        matches.push((
            mount_id,
            LinuxCgroupMountSecurity {
                root: decode_mountinfo_field(identity_fields[3])?,
                read_only: mount_options.contains("ro"),
                nsdelegate: super_options.contains("nsdelegate"),
            },
        ));
    }
    if matches.is_empty() || (exact_mount_point.is_none() && matches.len() != 1) {
        return Err(format!(
            "expected exactly one matching cgroup2 mount, found {}",
            matches.len()
        ));
    }
    matches
        .into_iter()
        .max_by_key(|(mount_id, _)| *mount_id)
        .map(|(_, security)| security)
        .ok_or_else(|| "no matching cgroup2 mount".to_string())
}

#[cfg(target_os = "linux")]
fn enter_linux_request_namespaces(expected_unit: &str) -> Result<(), String> {
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    let flags =
        libc::CLONE_NEWUSER | libc::CLONE_NEWCGROUP | libc::CLONE_NEWNS | libc::CLONE_NEWPID;
    if unsafe { libc::unshare(flags) } != 0 {
        return Err(format!(
            "{LINUX_NAMESPACE_ERROR}: unshare user/cgroup/mount/PID namespaces: {}",
            std::io::Error::last_os_error()
        ));
    }
    if let Err(error) = std::fs::write("/proc/self/setgroups", b"deny\n")
        && error.kind() != std::io::ErrorKind::NotFound
    {
        return Err(format!(
            "{LINUX_NAMESPACE_ERROR}: deny setgroups before gid map: {error}"
        ));
    }
    std::fs::write("/proc/self/uid_map", format!("{uid} {uid} 1\n")).map_err(|error| {
        format!("{LINUX_NAMESPACE_ERROR}: install single-UID user namespace map: {error}")
    })?;
    std::fs::write("/proc/self/gid_map", format!("{gid} {gid} 1\n")).map_err(|error| {
        format!("{LINUX_NAMESPACE_ERROR}: install single-GID user namespace map: {error}")
    })?;
    make_linux_mounts_private()?;
    remount_linux_cgroup_at_namespace_root()?;
    hide_linux_user_runtime(uid)?;

    let cgroup = std::fs::read_to_string("/proc/self/cgroup")
        .map_err(|error| format!("{LINUX_NAMESPACE_ERROR}: read namespaced cgroup: {error}"))
        .and_then(|contents| parse_unified_cgroup_path(&contents))?;
    if cgroup != "/" {
        return Err(format!(
            "{LINUX_NAMESPACE_ERROR}: helper cgroup namespace root is {cgroup}, expected / for \
             {expected_unit}"
        ));
    }
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo")
        .map_err(|error| format!("{LINUX_NAMESPACE_ERROR}: read namespaced mountinfo: {error}"))?;
    let security = linux_cgroup_mount_security(&mountinfo, Some("/sys/fs/cgroup"))
        .map_err(|error| format!("{LINUX_NAMESPACE_ERROR}: {error}"))?;
    if security.root != "/" || !security.read_only || !security.nsdelegate {
        return Err(format!(
            "{LINUX_NAMESPACE_ERROR}: cgroup mount contract mismatch: root={}, ro={}, \
             nsdelegate={}",
            security.root, security.read_only, security.nsdelegate
        ));
    }
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } != 0 {
        return Err(format!(
            "{LINUX_NAMESPACE_ERROR}: make service guardian non-dumpable: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn make_linux_mounts_private() -> Result<(), String> {
    let root = std::ffi::CString::new("/").expect("static root path");
    if unsafe {
        libc::mount(
            std::ptr::null(),
            root.as_ptr(),
            std::ptr::null(),
            (libc::MS_REC | libc::MS_PRIVATE) as libc::c_ulong,
            std::ptr::null(),
        )
    } != 0
    {
        return Err(format!(
            "{LINUX_NAMESPACE_ERROR}: make mount propagation private: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn remount_linux_cgroup_at_namespace_root() -> Result<(), String> {
    let target = std::ffi::CString::new("/sys/fs/cgroup").expect("static cgroup path");
    let source = std::ffi::CString::new("none").expect("static cgroup source");
    let filesystem = std::ffi::CString::new("cgroup2").expect("static cgroup filesystem");
    let flags = libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
    if unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            filesystem.as_ptr(),
            flags as libc::c_ulong,
            std::ptr::null(),
        )
    } != 0
    {
        return Err(format!(
            "{LINUX_NAMESPACE_ERROR}: mount read-only cgroup namespace root: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn hide_linux_user_runtime(uid: libc::uid_t) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::MetadataExt as _;

    let runtime = std::path::PathBuf::from(format!("/run/user/{uid}"));
    let metadata = std::fs::symlink_metadata(&runtime).map_err(|error| {
        format!(
            "{LINUX_SYSTEMD_MANAGER_ERROR}: inspect user runtime {}: {error}",
            runtime.display()
        )
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.uid() != uid {
        return Err(format!(
            "{LINUX_SYSTEMD_MANAGER_ERROR}: user runtime {} failed ownership/type validation",
            runtime.display()
        ));
    }
    let target = std::ffi::CString::new(runtime.as_os_str().as_bytes())
        .map_err(|_| format!("{LINUX_NAMESPACE_ERROR}: user runtime path contains NUL"))?;
    let source = std::ffi::CString::new("none").expect("static tmpfs source");
    let filesystem = std::ffi::CString::new("tmpfs").expect("static tmpfs filesystem");
    let options =
        std::ffi::CString::new("mode=000,size=1048576").expect("static tmpfs mount options");
    let flags = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
    if unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            filesystem.as_ptr(),
            flags as libc::c_ulong,
            options.as_ptr().cast(),
        )
    } != 0
    {
        return Err(format!(
            "{LINUX_NAMESPACE_ERROR}: hide user manager bus/runtime: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_linux_pid_namespace_guardian(
    envelope: LinuxLaunchEnvelope,
    ready: std::os::fd::OwnedFd,
) -> ! {
    use std::os::fd::AsRawFd as _;

    let ready_fd = ready.as_raw_fd();
    let result = (|| {
        mount_private_linux_proc()?;
        let program = validate_linux_executable(
            std::path::Path::new(envelope.program.as_os_str()),
            false,
            "chat provider",
        )?;
        let current_directory =
            std::fs::canonicalize(&envelope.current_directory).map_err(|error| {
                format!(
                    "{LINUX_SERVICE_ERROR}: resolve provider working directory {}: {error}",
                    envelope.current_directory.display()
                )
            })?;
        if current_directory != envelope.current_directory {
            return Err(format!(
                "{LINUX_SERVICE_ERROR}: provider working directory changed after request capture"
            ));
        }
        let mut command = Command::new(program);
        command
            .args(envelope.arguments)
            .current_dir(current_directory)
            .env_clear()
            .stdin(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit());
        for (name, value) in envelope.environment {
            if linux_provider_environment_allowed(name.as_os_str()) {
                command.env(name, value);
            }
        }
        let mut child = command
            .spawn()
            .map_err(|error| format!("{LINUX_SERVICE_ERROR}: execute exact provider: {error}"))?;
        write_linux_ready_byte(ready_fd, 0).map_err(|error| {
            format!("{LINUX_SERVICE_ERROR}: publish provider readiness: {error}")
        })?;
        let status = child
            .wait()
            .map_err(|error| format!("{LINUX_SERVICE_ERROR}: wait exact provider: {error}"))?;
        kill_and_reap_linux_pid_namespace();
        Ok(linux_exit_status_code(status))
    })();
    match result {
        Ok(code) => unsafe { libc::_exit(code) },
        Err(error) => {
            eprintln!("{error}");
            let _ = write_linux_ready_byte(ready_fd, 1);
            unsafe { libc::_exit(125) }
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_provider_environment_allowed(name: &std::ffi::OsStr) -> bool {
    use std::os::unix::ffi::OsStrExt as _;

    !matches!(
        name.as_bytes(),
        b"DBUS_SESSION_BUS_ADDRESS"
            | b"NOTIFY_SOCKET"
            | b"WATCHDOG_PID"
            | b"WATCHDOG_USEC"
            | b"LISTEN_FDS"
            | b"LISTEN_PID"
            | b"LISTEN_FDNAMES"
            | b"SYSTEMD_EXEC_PID"
            | b"INVOCATION_ID"
            | b"JOURNAL_STREAM"
    )
}

#[cfg(target_os = "linux")]
fn mount_private_linux_proc() -> Result<(), String> {
    if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
        return Err(format!(
            "{LINUX_NAMESPACE_ERROR}: unshare guardian mount namespace: {}",
            std::io::Error::last_os_error()
        ));
    }
    make_linux_mounts_private()?;
    let target = std::ffi::CString::new("/proc").expect("static proc path");
    let source = std::ffi::CString::new("proc").expect("static proc source");
    let filesystem = std::ffi::CString::new("proc").expect("static proc filesystem");
    let options = std::ffi::CString::new("hidepid=2").expect("static proc mount options");
    let flags = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
    if unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            filesystem.as_ptr(),
            flags as libc::c_ulong,
            options.as_ptr().cast(),
        )
    } != 0
    {
        return Err(format!(
            "{LINUX_NAMESPACE_ERROR}: mount PID-namespace proc: {}",
            std::io::Error::last_os_error()
        ));
    }
    let self_pid = unsafe { libc::getpid() };
    if self_pid != 1 || !std::path::Path::new("/proc/1").is_dir() {
        return Err(format!(
            "{LINUX_NAMESPACE_ERROR}: guardian is PID {self_pid}, expected namespace PID 1"
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn kill_and_reap_linux_pid_namespace() {
    unsafe {
        libc::kill(-1, libc::SIGKILL);
    }
    loop {
        let mut status = 0;
        let waited = unsafe { libc::waitpid(-1, &raw mut status, 0) };
        if waited > 0 {
            continue;
        }
        if waited < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return;
    }
}

#[cfg(target_os = "linux")]
fn linux_exit_status_code(status: ExitStatus) -> libc::c_int {
    use std::os::unix::process::ExitStatusExt as _;

    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(libc::SIGKILL))
}

#[cfg(target_os = "linux")]
fn wait_for_linux_guardian_ready(
    parent_pidfd: libc::c_int,
    ready_fd: libc::c_int,
    guardian: libc::pid_t,
) -> Result<(), String> {
    loop {
        if let Some(status) = try_wait_linux_pid(guardian)? {
            return Err(format!(
                "{LINUX_SERVICE_ERROR}: PID-namespace guardian exited {status} before provider READY"
            ));
        }
        let mut descriptors = [
            libc::pollfd {
                fd: parent_pidfd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: ready_fd,
                events: libc::POLLIN | libc::POLLHUP,
                revents: 0,
            },
        ];
        let polled = unsafe {
            libc::poll(
                descriptors.as_mut_ptr(),
                descriptors.len() as libc::nfds_t,
                100,
            )
        };
        if polled < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(format!(
                "{LINUX_SERVICE_ERROR}: poll guardian readiness: {}",
                std::io::Error::last_os_error()
            ));
        }
        if descriptors[0].revents != 0 {
            return Err(format!(
                "{LINUX_SERVICE_ERROR}: GUI exited before provider READY"
            ));
        }
        if descriptors[1].revents != 0 {
            let mut ready = [0_u8; 1];
            read_exact_linux_fd(ready_fd, &mut ready).map_err(|error| {
                format!("{LINUX_SERVICE_ERROR}: read guardian readiness: {error}")
            })?;
            return match ready[0] {
                0 => Ok(()),
                _ => Err(format!(
                    "{LINUX_SERVICE_ERROR}: guardian rejected provider launch"
                )),
            };
        }
    }
}

#[cfg(target_os = "linux")]
fn monitor_linux_gui_and_guardian(
    parent_pidfd: libc::c_int,
    guardian: libc::pid_t,
) -> Result<i32, String> {
    loop {
        if let Some(status) = try_wait_linux_pid(guardian)? {
            return Ok(status);
        }
        let mut descriptor = libc::pollfd {
            fd: parent_pidfd,
            events: libc::POLLIN,
            revents: 0,
        };
        let polled = unsafe { libc::poll(&raw mut descriptor, 1, 100) };
        if polled < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(format!(
                "{LINUX_SERVICE_ERROR}: poll GUI pidfd: {}",
                std::io::Error::last_os_error()
            ));
        }
        if descriptor.revents != 0 {
            // Exiting the systemd MainPID makes the manager stop the complete
            // control group with KillMode=control-group.
            return Ok(125);
        }
    }
}

#[cfg(target_os = "linux")]
fn try_wait_linux_pid(pid: libc::pid_t) -> Result<Option<i32>, String> {
    let mut status = 0;
    let waited = unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG) };
    if waited == 0 {
        return Ok(None);
    }
    if waited == pid {
        return Ok(Some(if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else if libc::WIFSIGNALED(status) {
            128 + libc::WTERMSIG(status)
        } else {
            125
        }));
    }
    if waited < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
        return Ok(None);
    }
    Err(format!(
        "{LINUX_SERVICE_ERROR}: wait PID-namespace guardian: {}",
        std::io::Error::last_os_error()
    ))
}

#[cfg(all(unix, not(target_os = "linux")))]
struct PlatformContainmentSetup;

#[cfg(all(unix, not(target_os = "linux")))]
impl PlatformContainmentSetup {
    fn configure(_request_id: ChatStreamRequestId, _command: &mut Command) -> Result<Self, String> {
        Err(
            "[NEOTH_GUI_CONTAINMENT_UNAVAILABLE] GUI chat cannot start safely on this Unix \
             target: NEOTH has no native complete-tree containment primitive here and refused \
             an escapable process-group fallback"
                .to_string(),
        )
    }

    fn activate(self, _child: &Child) -> Result<PlatformContainment, String> {
        Err("unreachable Unix containment activation".to_string())
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
struct PlatformContainment;

#[cfg(all(unix, not(target_os = "linux")))]
impl PlatformContainment {
    fn terminate_tree(&mut self) -> Result<(), String> {
        Err("complete-tree containment is unavailable on this Unix target".to_string())
    }

    fn tree_is_empty(&mut self) -> Result<bool, String> {
        Err("complete-tree containment is unavailable on this Unix target".to_string())
    }
}

#[cfg(windows)]
struct PlatformContainmentSetup {
    job: WindowsChatJob,
}

#[cfg(windows)]
impl PlatformContainmentSetup {
    fn configure(_request_id: ChatStreamRequestId, command: &mut Command) -> Result<Self, String> {
        use std::os::windows::process::CommandExt as _;

        const CREATE_SUSPENDED: u32 = 0x0000_0004;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW);
        Ok(Self {
            job: WindowsChatJob::create()?,
        })
    }

    fn activate(self, child: &Child) -> Result<PlatformContainment, String> {
        self.job.assign(child)?;
        self.job.resume(child)?;
        Ok(PlatformContainment { job: self.job })
    }
}

#[cfg(windows)]
struct PlatformContainment {
    job: WindowsChatJob,
}

#[cfg(windows)]
impl PlatformContainment {
    fn terminate_tree(&mut self) -> Result<(), String> {
        self.job.terminate()
    }

    fn tree_is_empty(&mut self) -> Result<bool, String> {
        self.job.active_processes().map(|count| count == 0)
    }
}

#[cfg(windows)]
struct WindowsChatJob {
    handle: std::os::windows::io::OwnedHandle,
}

#[cfg(windows)]
impl WindowsChatJob {
    fn create() -> Result<Self, String> {
        use std::os::windows::io::FromRawHandle as _;
        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };

        let raw_handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if raw_handle.is_null() {
            return Err(format!(
                "create chat Job Object: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: CreateJobObjectW returned a fresh non-null handle and
        // ownership moves exactly once into OwnedHandle.
        let handle =
            unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(raw_handle.cast()) };
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let configured = unsafe {
            SetInformationJobObject(
                Self::raw_handle(&handle),
                JobObjectExtendedLimitInformation,
                (&raw const info).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if configured == 0 {
            let error = std::io::Error::last_os_error();
            return Err(format!("configure chat Job Object: {error}"));
        }
        Ok(Self { handle })
    }

    fn raw_handle(
        handle: &std::os::windows::io::OwnedHandle,
    ) -> windows_sys::Win32::Foundation::HANDLE {
        use std::os::windows::io::AsRawHandle as _;

        handle.as_raw_handle().cast()
    }

    fn assign(&self, child: &Child) -> Result<(), String> {
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;

        if unsafe {
            AssignProcessToJobObject(Self::raw_handle(&self.handle), child.as_raw_handle().cast())
        } == 0
        {
            return Err(format!(
                "assign suspended chat subprocess to Job Object: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    fn resume(&self, child: &Child) -> Result<(), String> {
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::Foundation::HANDLE;

        #[link(name = "ntdll")]
        unsafe extern "system" {
            #[link_name = "NtResumeProcess"]
            fn nt_resume_process(process_handle: HANDLE) -> i32;
        }

        let status = unsafe { nt_resume_process(child.as_raw_handle().cast()) };
        if status < 0 {
            return Err(format!(
                "resume contained chat subprocess failed with NTSTATUS 0x{:08x}",
                status as u32
            ));
        }
        Ok(())
    }

    fn terminate(&self) -> Result<(), String> {
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;

        if unsafe { TerminateJobObject(Self::raw_handle(&self.handle), 1) } == 0 {
            return Err(format!(
                "terminate chat Job Object: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    fn active_processes(&self) -> Result<u32, String> {
        use windows_sys::Win32::System::JobObjects::{
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JobObjectBasicAccountingInformation,
            QueryInformationJobObject,
        };

        let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
        let mut returned = 0_u32;
        if unsafe {
            QueryInformationJobObject(
                Self::raw_handle(&self.handle),
                JobObjectBasicAccountingInformation,
                (&raw mut info).cast(),
                std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                &raw mut returned,
            )
        } == 0
        {
            return Err(format!(
                "inspect chat Job Object membership: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(info.ActiveProcesses)
    }
}

#[cfg(not(any(unix, windows)))]
compile_error!("GUI chat process-tree containment is unavailable on this platform");

#[cfg(test)]
mod tests {
    use super::*;

    fn request(value: u64) -> ChatStreamRequestId {
        ChatStreamRequestId::parse_wire(&value.to_string()).unwrap()
    }

    #[test]
    fn worker_barrier_rejects_new_dispatch_after_shutdown() {
        let barrier = Arc::new(ChatWorkerBarrier::default());
        barrier.begin_shutdown();
        assert!(barrier.claim(request(1)).is_err());
    }

    #[test]
    fn worker_lease_acknowledges_exact_request() {
        let barrier = Arc::new(ChatWorkerBarrier::default());
        let first = barrier.claim(request(1)).unwrap();
        let second = barrier.claim(request(2)).unwrap();
        drop(first);
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let waiting = Arc::clone(&barrier);
        let waiter = std::thread::spawn(move || {
            waiting.wait_empty();
            finished_tx.send(()).unwrap();
        });
        assert!(
            finished_rx.recv_timeout(Duration::from_millis(20)).is_err(),
            "the barrier returned while the second request still owned a lease"
        );
        drop(second);
        finished_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("the barrier did not observe the final worker lease");
        waiter.join().unwrap();
    }

    #[test]
    fn source_keeps_platform_tree_contracts_explicit() {
        let source = include_str!("chat_child_supervisor.rs");
        for required in [
            concat!("NEOTH_GUI_CONTAINMENT_", "SYSTEMD_USER_MANAGER_UNAVAILABLE"),
            concat!("NEOTH_GUI_CONTAINMENT_", "SYSTEMD_TOOL_UNTRUSTED"),
            concat!("NEOTH_GUI_CONTAINMENT_", "NAMESPACE_UNAVAILABLE"),
            concat!("PR_SET_", "PDEATHSIG"),
            concat!("--service-type=", "notify"),
            concat!("--property=Delegate=", "no"),
            concat!("--property=KillMode=", "control-group"),
            concat!("--property=SendSIGKILL=", "yes"),
            concat!("--property=Restart=", "no"),
            concat!("--", "pipe"),
            concat!("--", "wait"),
            concat!("--", "collect"),
            concat!("CLONE_", "NEWUSER"),
            concat!("CLONE_", "NEWCGROUP"),
            concat!("CLONE_", "NEWPID"),
            concat!("MS_", "RDONLY"),
            concat!("mode=000", ",size=1048576"),
            concat!("DBUS_SESSION_", "BUS_ADDRESS"),
            concat!("pidfd_", "open"),
            concat!("systemctl", " stop"),
            concat!("cgroup.", "events"),
            concat!("populated", " 0"),
            concat!("CREATE_", "SUSPENDED"),
            concat!("JOB_OBJECT_LIMIT_", "KILL_ON_JOB_CLOSE"),
            concat!("AssignProcess", "ToJobObject"),
            concat!("nt_resume_", "process"),
            concat!("Terminate", "JobObject"),
            concat!("active_", "processes"),
        ] {
            assert!(source.contains(required), "missing contract: {required}");
        }
        assert!(
            !source.contains("Command::new(\"sh\")"),
            "containment must never route trusted control through a shell"
        );
    }

    #[test]
    fn unified_cgroup_parser_requires_one_normalized_v2_entry() {
        assert_eq!(
            parse_unified_cgroup_path("0::/user.slice/user-1000.slice/session.scope\n").unwrap(),
            "/user.slice/user-1000.slice/session.scope"
        );
        assert!(parse_unified_cgroup_path("2:cpu:/legacy\n").is_err());
        assert!(parse_unified_cgroup_path("0::/safe\n0::/duplicate\n").is_err());
        assert!(parse_unified_cgroup_path("0::/safe/../escape\n").is_err());
    }

    #[test]
    fn mountinfo_parser_decodes_only_kernel_path_escapes() {
        let mounts = parse_cgroup2_mounts(
            "31 22 0:28 /user\\040root /run/user\\040space/cgroup rw - cgroup2 cgroup rw\n",
        )
        .unwrap();
        assert_eq!(
            mounts,
            vec![(
                "/user root".to_string(),
                "/run/user space/cgroup".to_string()
            )]
        );
        assert_eq!(
            map_cgroup_path_to_mount(
                "/user root",
                "/run/user space/cgroup",
                "/user root/neoth.scope"
            ),
            Some("/run/user space/cgroup/neoth.scope".to_string())
        );
        assert_eq!(
            map_cgroup_path_to_mount("/user", "/sys/fs/cgroup", "/username/not-a-child"),
            None
        );
        assert_eq!(decode_mountinfo_field(r"/one\134two").unwrap(), r"/one\two");
        assert!(decode_mountinfo_field("/bad\\041escape").is_err());
        assert_eq!(
            parse_linux_filesystem_mount_points(
                "20 1 0:1 / /proc rw - proc proc rw\n\
                 21 20 0:1 /sys /proc/sys ro - proc proc rw\n",
                "proc"
            )
            .unwrap(),
            vec!["/proc".to_string(), "/proc/sys".to_string()]
        );
    }

    #[test]
    fn cgroup_events_parser_pins_empty_proof_contract() {
        assert!(!parse_cgroup_populated("populated 0\nfrozen 0\n").unwrap());
        assert!(parse_cgroup_populated("populated 1\nfrozen 0\n").unwrap());
        assert_eq!(
            parse_cgroup_populated_bytes(b"populated 0\nfrozen 0\n"),
            Some(false)
        );
        assert_eq!(parse_cgroup_populated_bytes(b"populated 2\n"), None);
        assert!(parse_cgroup_populated("frozen 0\n").is_err());
        assert!(parse_cgroup_populated("populated 0\npopulated 1\n").is_err());
        assert!(parse_cgroup_populated("populated 2\n").is_err());
    }

    #[test]
    fn capability_failures_are_operator_and_machine_readable() {
        let source = include_str!("chat_child_supervisor.rs");
        assert!(source.contains("[NEOTH_GUI_CONTAINMENT_SYSTEMD_USER_MANAGER_UNAVAILABLE]"));
        assert!(source.contains("[NEOTH_GUI_CONTAINMENT_SYSTEMD_TOOL_UNTRUSTED]"));
        assert!(source.contains("[NEOTH_GUI_CONTAINMENT_NAMESPACE_UNAVAILABLE]"));
        assert!(source.contains("[NEOTH_GUI_CONTAINMENT_SERVICE_FAILED]"));
        assert!(source.contains("[NEOTH_GUI_CONTAINMENT_LAUNCH_FAILED]"));
        assert!(source.contains("[NEOTH_GUI_CONTAINMENT_UNAVAILABLE]"));
        assert!(source.contains("GUI chat cannot start safely"));
        assert!(source.contains("refused an escapable process-group fallback"));
    }

    #[test]
    fn process_stat_parser_handles_parentheses_and_pins_starttime_field() {
        let stat = "123 (provider ) name) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 424242 20";
        assert_eq!(parse_linux_process_start_ticks(stat).unwrap(), 424_242);
        assert!(parse_linux_process_start_ticks("123 malformed").is_err());
    }

    #[test]
    fn cgroup_mount_security_requires_nsdelegate_and_read_only_root() {
        let mountinfo = concat!(
            "31 22 0:28 /host/user.slice/request.service /sys/fs/cgroup ro,nosuid,nodev,noexec ",
            "- cgroup2 cgroup rw,nsdelegate,memory_recursiveprot\n"
        );
        assert_eq!(
            linux_cgroup_mount_security(mountinfo, Some("/sys/fs/cgroup")).unwrap(),
            LinuxCgroupMountSecurity {
                root: "/host/user.slice/request.service".to_string(),
                read_only: true,
                nsdelegate: true,
            }
        );
        assert!(
            linux_cgroup_mount_security(
                "31 22 0:28 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n",
                Some("/sys/fs/cgroup")
            )
            .is_ok_and(|security| !security.read_only && !security.nsdelegate)
        );
    }

    #[cfg(target_os = "linux")]
    const LINUX_TEST_PROVIDER_ENV: &str = "NEOTH_GUI_CHAT_ADVERSARIAL_PROVIDER";

    #[cfg(target_os = "linux")]
    const LINUX_TEST_PARENT_DEATH_RESULT_ENV: &str = "NEOTH_GUI_PARENT_DEATH_RESULT";

    #[cfg(target_os = "linux")]
    const LINUX_TEST_REQUIRED_ENV: &str = "NEOTH_GUI_REQUIRE_SYSTEMD_CONTAINMENT_TESTS";

    #[cfg(target_os = "linux")]
    struct LinuxTestTree {
        child: OwnedChatChild,
        unit_name: String,
        cgroup_directory: std::path::PathBuf,
    }

    #[cfg(target_os = "linux")]
    fn linux_capability_is_unavailable(error: &str) -> bool {
        [
            "NEOTH_GUI_CONTAINMENT_SYSTEMD_USER_MANAGER_UNAVAILABLE",
            "NEOTH_GUI_CONTAINMENT_SYSTEMD_TOOL_UNTRUSTED",
            "NEOTH_GUI_CONTAINMENT_NAMESPACE_UNAVAILABLE",
            "NEOTH_GUI_CONTAINMENT_SERVICE_FAILED",
        ]
        .iter()
        .any(|code| error.contains(code))
    }

    #[cfg(target_os = "linux")]
    fn skip_unavailable_linux_integration(error: &str) {
        assert!(
            std::env::var_os(LINUX_TEST_REQUIRED_ENV).as_deref() != Some(std::ffi::OsStr::new("1")),
            "required systemd containment integration capability is unavailable: {error}"
        );
        eprintln!(
            "skipping unavailable systemd containment fixture: {error}; set \
             {LINUX_TEST_REQUIRED_ENV}=1 in the provisioned Linux integration job to make this fatal"
        );
    }

    /// The Rust test harness, not a shell, is the transient service MainPID.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_systemd_helper_fixture_entry() {
        if std::env::var_os("NEOTH_GUI_CHAT_TEST_HELPER").as_deref()
            != Some(std::ffi::OsStr::new("1"))
        {
            return;
        }
        let code = match linux_manager_helper_main() {
            Ok(code) => code,
            Err(error) => {
                eprintln!("{error}");
                125
            }
        };
        std::process::exit(code);
    }

    /// Malicious provider fixture: create a new session plus a double-forked
    /// descendant, then stay alive until the manager kills the entire unit.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_adversarial_provider_fixture_entry() {
        use std::io::Write as _;
        use std::os::fd::{AsRawFd as _, FromRawFd as _};

        if std::env::var_os(LINUX_TEST_PROVIDER_ENV).as_deref() != Some(std::ffi::OsStr::new("1")) {
            return;
        }

        let cgroup = std::fs::read_to_string("/proc/self/cgroup")
            .and_then(|contents| {
                parse_unified_cgroup_path(&contents).map_err(|error| std::io::Error::other(error))
            })
            .expect("read private cgroup namespace");
        assert_eq!(cgroup, "/", "provider can see a cgroup ancestor");

        let mountinfo =
            std::fs::read_to_string("/proc/self/mountinfo").expect("read private mountinfo");
        let cgroup_mounts = parse_cgroup2_mounts(&mountinfo).expect("find private cgroup2 mount");
        assert!(
            cgroup_mounts
                .iter()
                .all(|(_, mount_point)| mount_point == "/sys/fs/cgroup"),
            "provider can see an alternate cgroup2 mount"
        );
        let proc_mounts =
            parse_linux_filesystem_mount_points(&mountinfo, "proc").expect("find private procfs");
        assert!(
            !proc_mounts.is_empty()
                && proc_mounts
                    .iter()
                    .all(|point| point == "/proc" || point.starts_with("/proc/")),
            "provider can see host procfs outside the private /proc"
        );
        assert!(
            std::path::Path::new("/sys/fs/cgroup/cgroup.procs").is_file(),
            "private cgroup root has no cgroup.procs"
        );
        assert!(
            std::fs::OpenOptions::new()
                .write(true)
                .open("/sys/fs/cgroup/cgroup.procs")
                .is_err(),
            "provider can migrate within the manager-owned cgroup"
        );
        for (_, mount_point) in &cgroup_mounts {
            assert!(
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(std::path::Path::new(mount_point).join("../cgroup.procs"))
                    .is_err(),
                "provider can migrate to an ancestor cgroup"
            );
        }

        let uid = unsafe { libc::geteuid() };
        let runtime = std::path::PathBuf::from(format!("/run/user/{uid}"));
        assert!(
            std::fs::read_dir(&runtime).is_err(),
            "provider can enumerate the systemd user-manager runtime"
        );
        assert!(
            std::os::unix::net::UnixStream::connect(runtime.join("bus")).is_err(),
            "provider can reach the user D-Bus"
        );
        assert!(
            std::os::unix::net::UnixStream::connect(runtime.join("systemd/private")).is_err(),
            "provider can reach the systemd user-manager private socket"
        );

        let mut ready_pipe = [-1; 2];
        assert_eq!(
            unsafe { libc::pipe2(ready_pipe.as_mut_ptr(), libc::O_CLOEXEC) },
            0,
            "create adversarial descendant readiness pipe"
        );
        // SAFETY: pipe2 returned two fresh descriptors and each branch closes
        // or transfers exactly its own copies.
        let ready_read = unsafe { std::os::fd::OwnedFd::from_raw_fd(ready_pipe[0]) };
        let ready_write = unsafe { std::os::fd::OwnedFd::from_raw_fd(ready_pipe[1]) };
        let session_child = unsafe { libc::fork() };
        assert!(session_child >= 0, "fork setsid fixture child");
        if session_child == 0 {
            drop(ready_read);
            if unsafe { libc::setsid() } < 0 {
                unsafe { libc::_exit(121) };
            }
            let double_fork = unsafe { libc::fork() };
            if double_fork < 0 {
                unsafe { libc::_exit(122) };
            }
            if double_fork == 0 {
                drop(ready_write);
                loop {
                    unsafe { libc::pause() };
                }
            }
            if write_linux_ready_byte(ready_write.as_raw_fd(), 0).is_err() {
                unsafe { libc::_exit(123) };
            }
            drop(ready_write);
            loop {
                unsafe { libc::pause() };
            }
        }
        drop(ready_write);
        let mut ready = [1_u8; 1];
        read_exact_linux_fd(ready_read.as_raw_fd(), &mut ready)
            .expect("setsid/double-fork fixture did not become ready");
        assert_eq!(ready, [0]);

        println!(
            "CONTAINED cgroup_root=true cgroup_read_only=true \
             no_writable_ancestor=true user_bus_blocked=true setsid=true double_fork=true"
        );
        std::io::stdout()
            .flush()
            .expect("flush adversarial fixture state");
        loop {
            unsafe { libc::pause() };
        }
    }

    #[cfg(target_os = "linux")]
    fn spawn_linux_adversarial_tree(
        request_id: ChatStreamRequestId,
    ) -> Result<LinuxTestTree, String> {
        use std::io::BufRead as _;

        let mut command = Command::new(
            std::env::current_exe().map_err(|error| format!("locate test binary: {error}"))?,
        );
        command
            .arg("--exact")
            .arg("chat_child_supervisor::tests::linux_adversarial_provider_fixture_entry")
            .arg("--nocapture")
            .env(LINUX_TEST_PROVIDER_ENV, "1")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = OwnedChatChild::spawn(request_id, &mut command)?;
        let unit_name = child.containment.unit.unit_name.clone();
        let cgroup_directory = child.containment.unit.cgroup_directory.clone();
        let stdout = child
            .take_stdout()
            .ok_or_else(|| "adversarial fixture stdout is unavailable".to_string())?;
        let mut stdout = std::io::BufReader::new(stdout);
        let mut contained = false;
        for _ in 0..32 {
            let mut line = String::new();
            let read = stdout
                .read_line(&mut line)
                .map_err(|error| format!("read adversarial fixture state: {error}"))?;
            if read == 0 {
                break;
            }
            if line.starts_with("CONTAINED ") {
                assert!(line.contains("cgroup_root=true"));
                assert!(line.contains("cgroup_read_only=true"));
                assert!(line.contains("no_writable_ancestor=true"));
                assert!(line.contains("user_bus_blocked=true"));
                assert!(line.contains("setsid=true"));
                assert!(line.contains("double_fork=true"));
                contained = true;
                break;
            }
        }
        if !contained {
            return Err(
                "adversarial provider exited before publishing containment proof".to_string(),
            );
        }
        Ok(LinuxTestTree {
            child,
            unit_name,
            cgroup_directory,
        })
    }

    #[cfg(target_os = "linux")]
    fn assert_linux_unit_empty_and_inactive(
        systemctl: &std::path::Path,
        unit_name: &str,
        cgroup_directory: &std::path::Path,
    ) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let snapshot = inspect_linux_unit(systemctl, unit_name)
                .unwrap_or_else(|error| panic!("inspect stopped test unit {unit_name}: {error}"));
            let inactive = snapshot.load_state == "not-found"
                || (snapshot.active_state == "inactive" && snapshot.sub_state == "dead");
            let empty = match std::fs::read_to_string(cgroup_directory.join("cgroup.events")) {
                Ok(events) => !parse_cgroup_populated(&events).expect("parse test cgroup.events"),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
                Err(error) => panic!(
                    "read stopped test cgroup {}: {error}",
                    cgroup_directory.display()
                ),
            };
            if inactive && empty {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "manager did not prove unit {unit_name} inactive and empty"
            );
            std::thread::sleep(CHAT_TREE_POLL_INTERVAL);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_launch_frame_binds_exact_request_unit_and_private_bytes() {
        use std::os::unix::ffi::OsStringExt as _;

        let envelope = LinuxLaunchEnvelope {
            request_id: 71,
            unit_name: "neoth-gui-chat-r71-p123-n000102030405060708090a0b0c0d0e0f.service"
                .to_string(),
            parent_pid: 123,
            parent_start_ticks: 456,
            program: std::ffi::OsString::from_vec(b"/tmp/provider-\xff".to_vec()),
            arguments: vec![std::ffi::OsString::from_vec(b"arg-\xfe".to_vec())],
            environment: vec![(
                std::ffi::OsString::from("PRIVATE_TOKEN"),
                std::ffi::OsString::from_vec(b"value-\xfd".to_vec()),
            )],
            current_directory: std::path::PathBuf::from("/tmp"),
        };
        let frame = envelope.encode().unwrap();
        let decoded = LinuxLaunchEnvelope::decode(&frame[8..]).unwrap();
        assert_eq!(decoded, envelope);
        let mut wrong_unit = frame[8..].to_vec();
        let unit_offset = LINUX_LAUNCH_FRAME_MAGIC.len() + 8 + 4;
        wrong_unit[unit_offset] = b'x';
        assert!(LinuxLaunchEnvelope::decode(&wrong_unit).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_unit_snapshot_pins_manager_owned_kill_contract() {
        let snapshot = parse_linux_unit_snapshot(
            "LoadState=loaded\nActiveState=active\nSubState=running\n\
             ControlGroup=/user.slice/neoth-gui-chat-r1-p2-n00000000000000000000000000000000.service\n\
             Delegate=no\nKillMode=control-group\nSendSIGKILL=yes\nMainPID=99\n",
        )
        .unwrap();
        assert_eq!(snapshot.delegate, "no");
        assert_eq!(snapshot.kill_mode, "control-group");
        assert_eq!(snapshot.send_sigkill, "yes");
        assert_eq!(snapshot.main_pid, 99);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_manager_stop_reaps_setsid_and_double_fork_tree() {
        let mut tree = match spawn_linux_adversarial_tree(request(11)) {
            Ok(tree) => tree,
            Err(error) if linux_capability_is_unavailable(&error) => {
                skip_unavailable_linux_integration(&error);
                return;
            }
            Err(error) => panic!("spawn contained Linux fixture: {error}"),
        };
        let systemctl = tree.child.containment.unit.systemctl.clone();
        inspect_linux_unit(&systemctl, &tree.unit_name)
            .expect("inspect active manager-owned test unit")
            .verify_contract(&tree.unit_name)
            .expect("verify active manager-owned test unit");
        tree.child.request_tree_termination().unwrap();
        tree.child.request_tree_termination().unwrap();
        let unit_name = tree.unit_name.clone();
        let cgroup_directory = tree.cgroup_directory.clone();
        let (status_tx, status_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            status_tx.send(tree.child.terminate_and_reap()).unwrap();
        });
        status_rx
            .recv_timeout(Duration::from_secs(15))
            .expect("manager stop/wait exceeded its test deadline")
            .expect("manager stop/wait failed");
        assert_linux_unit_empty_and_inactive(&systemctl, &unit_name, &cgroup_directory);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_parent_death_fixture_entry() {
        let Some(result_path) = std::env::var_os(LINUX_TEST_PARENT_DEATH_RESULT_ENV) else {
            return;
        };
        let tree = match spawn_linux_adversarial_tree(request(12)) {
            Ok(tree) => tree,
            Err(error) => {
                std::fs::write(result_path, format!("SKIP\n{error}"))
                    .expect("publish unavailable manager capability");
                return;
            }
        };
        std::fs::write(
            result_path,
            format!("{}\n{}", tree.unit_name, tree.cgroup_directory.display()),
        )
        .expect("publish parent-death manager unit");
        std::mem::forget(tree);
        unsafe {
            libc::_exit(0);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_gui_crash_kills_complete_manager_unit() {
        let directory = tempfile::tempdir().unwrap();
        let result_path = directory.path().join("manager-unit.txt");
        let status = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("chat_child_supervisor::tests::linux_parent_death_fixture_entry")
            .arg("--nocapture")
            .env(LINUX_TEST_PARENT_DEATH_RESULT_ENV, &result_path)
            .status()
            .expect("run GUI-crash fixture process");
        assert!(status.success(), "GUI-crash fixture process failed");
        let result = std::fs::read_to_string(result_path).expect("read GUI-crash fixture result");
        if let Some(error) = result.strip_prefix("SKIP\n") {
            if linux_capability_is_unavailable(error) {
                skip_unavailable_linux_integration(error);
                return;
            }
            panic!("GUI-crash fixture failed before containment: {error}");
        }
        let (unit_name, cgroup_directory) = result
            .split_once('\n')
            .expect("parse GUI-crash manager-unit result");
        let systemctl = trusted_linux_systemd_tool("systemctl").unwrap();
        assert_linux_unit_empty_and_inactive(
            &systemctl,
            unit_name,
            std::path::Path::new(cgroup_directory),
        );
    }
}
