use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::AsRawHandle as _;
use std::ptr;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_BROKEN_PIPE, ERROR_INSUFFICIENT_BUFFER, ERROR_IO_PENDING, ERROR_PIPE_BUSY,
    ERROR_SUCCESS, GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
    LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
    DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation, GetLengthSid,
    GetSecurityDescriptorControl, GetTokenInformation, INHERITED_ACE, IsValidAcl, IsValidSid,
    SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR_CONTROL, TOKEN_QUERY, TOKEN_USER,
    TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ALL_ACCESS, FILE_FLAG_OVERLAPPED, OPEN_EXISTING,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcess, OpenProcessToken, OpenThreadToken,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

use super::{AuditEndpointV2, AuditStream};

const PIPE_PREFIX: &str = r"\\.\pipe\neoth-audit-v2-";
const PIPE_BUFFER_BYTES: u32 = 8 * 1024;
pub(super) const PIPE_REJECT_REMOTE_CLIENTS: bool = true;
const SECURITY_IDENTIFICATION: u32 = 0x0001_0000;
const SECURITY_SQOS_PRESENT: u32 = 0x0010_0000;
const WAIT_OBJECT_0: u32 = 0;
const WAIT_TIMEOUT: u32 = 258;
const INFINITE: u32 = u32::MAX;

pub(super) struct Listener {
    endpoint: AuditEndpointV2,
    pending: Option<NamedPipeServer>,
}

pub(super) fn pipe_name(home_sha256: &str, endpoint_nonce: &str) -> String {
    format!("{PIPE_PREFIX}{home_sha256}-{endpoint_nonce}")
}

pub(super) fn validate_endpoint_shape(
    name: &str,
    endpoint_nonce: &str,
    home_sha256: &str,
) -> Result<()> {
    super::validate_endpoint_nonce(endpoint_nonce)?;
    super::validate_home_sha256(home_sha256)?;
    ensure!(
        name == pipe_name(home_sha256, endpoint_nonce),
        "audit-RPC named-pipe name is not bound to home and endpoint nonce"
    );
    Ok(())
}

impl Listener {
    pub(super) fn bind(endpoint: &AuditEndpointV2) -> Result<Self> {
        let pending = create_server(endpoint, true)
            .context("create first, current-user-only audit-RPC named-pipe instance")?;
        Ok(Self {
            endpoint: endpoint.clone(),
            pending: Some(pending),
        })
    }

    /// Cancel-safe: the pending instance is only removed AFTER `connect`
    /// resolves.
    ///
    /// `run_accept_loop` awaits this inside a `tokio::select!`, so the future
    /// is dropped whenever the other branch wins. Taking the instance up front
    /// meant a cancellation at that point destroyed the only listening pipe
    /// instance; the next call then found `None`, reported "listener is
    /// closed", and the accept loop treats any accept error as fatal. The
    /// daemon therefore served exactly one audit connection and silently
    /// stopped accepting — silently, because `AuditSink::DaemonRpc` is
    /// best-effort by AUDIT-RPC-01, so every later one-shot CLI audit frame
    /// was dropped with nothing to show for it.
    pub(super) async fn accept(&mut self) -> Result<AuditStream> {
        loop {
            {
                let pending = self
                    .pending
                    .as_ref()
                    .context("audit-RPC named-pipe listener is closed")?;
                pending
                    .connect()
                    .await
                    .context("accept audit-RPC named-pipe connection")?;
            }
            let server = self
                .pending
                .take()
                .context("audit-RPC named-pipe listener is closed")?;

            // Keep the listener continuously available.  The first
            // instance already established the protected pipe namespace.
            self.pending = Some(
                create_server(&self.endpoint, false)
                    .context("create next audit-RPC named-pipe instance")?,
            );
            match attest_named_pipe_client(&server) {
                Ok(()) => return Ok(Box::new(server)),
                Err(_) => drop(server),
            }
        }
    }
}

pub(super) async fn connect(endpoint: &AuditEndpointV2) -> Result<AuditStream> {
    let (name, endpoint_nonce, home_sha256) = endpoint_fields(endpoint);
    validate_endpoint_shape(name, endpoint_nonce, home_sha256)?;
    let client = ClientOptions::new()
        .security_qos_flags(SECURITY_IDENTIFICATION)
        .open(name)
        .with_context(|| format!("connect audit-RPC named pipe {name}"))?;
    attest_named_pipe_server(client.as_raw_handle() as HANDLE)?;
    Ok(Box::new(client))
}

pub(super) fn exchange_blocking(
    endpoint: &AuditEndpointV2,
    request: &[u8],
    max_response: usize,
    timeout: Duration,
) -> Result<Vec<u8>> {
    let (name, endpoint_nonce, home_sha256) = endpoint_fields(endpoint);
    validate_endpoint_shape(name, endpoint_nonce, home_sha256)?;
    let deadline = Instant::now()
        .checked_add(timeout)
        .context("audit-RPC timeout overflow")?;
    let handle = open_pipe_overlapped(name, deadline)
        .with_context(|| format!("open audit-RPC named pipe {name}"))?;
    attest_named_pipe_server(handle.0)?;

    let mut written = 0;
    while written < request.len() {
        let count = overlapped_write(handle.0, &request[written..], deadline)
            .context("write audit-RPC named-pipe request")?;
        ensure!(count != 0, "audit-RPC named-pipe write made no progress");
        written += count;
    }

    let mut response = Vec::with_capacity(max_response.min(8192));
    loop {
        let remaining_capacity = max_response
            .checked_add(1)
            .context("audit-RPC response bound overflow")?
            .saturating_sub(response.len());
        ensure!(
            remaining_capacity != 0,
            "audit-RPC response exceeds {max_response} bytes"
        );
        let mut chunk = [0_u8; 8192];
        let read_capacity = chunk.len().min(remaining_capacity);
        match overlapped_read(handle.0, &mut chunk[..read_capacity], deadline) {
            Ok(0) => break,
            Ok(count) => {
                response.extend_from_slice(&chunk[..count]);
                ensure!(
                    response.len() <= max_response,
                    "audit-RPC response exceeds {max_response} bytes"
                );
            }
            Err(error) if error.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) => break,
            Err(error) => return Err(error).context("read audit-RPC named-pipe response"),
        }
    }
    Ok(response)
}

fn endpoint_fields(endpoint: &AuditEndpointV2) -> (&str, &str, &str) {
    let AuditEndpointV2::WindowsNamedPipe {
        name,
        endpoint_nonce,
        home_sha256,
    } = endpoint;
    (name, endpoint_nonce, home_sha256)
}

fn create_server(endpoint: &AuditEndpointV2, first: bool) -> Result<NamedPipeServer> {
    let (name, endpoint_nonce, home_sha256) = endpoint_fields(endpoint);
    validate_endpoint_shape(name, endpoint_nonce, home_sha256)?;
    let descriptor = CurrentUserSecurityDescriptor::new()?;
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first)
        .reject_remote_clients(PIPE_REJECT_REMOTE_CLIENTS)
        .in_buffer_size(PIPE_BUFFER_BYTES)
        .out_buffer_size(PIPE_BUFFER_BYTES);
    // SAFETY: `attributes` and its security descriptor remain alive until
    // CreateNamedPipeW returns; Win32 copies the descriptor into the pipe.
    let server = unsafe {
        options.create_with_security_attributes_raw(
            name,
            (&mut attributes as *mut SECURITY_ATTRIBUTES).cast(),
        )
    }?;
    verify_named_pipe_current_user_dacl(server.as_raw_handle() as HANDLE)
        .context("verify exact current-TokenUser audit-RPC pipe DACL")?;
    Ok(server)
}

fn verify_named_pipe_current_user_dacl(handle: HANDLE) -> Result<()> {
    let expected_sid = current_process_sid()?;
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut descriptor: *mut c_void = ptr::null_mut();
    // SAFETY: handle is a live named-pipe kernel object. All requested
    // optional owner/group/SACL outputs are null; DACL and descriptor are
    // valid out-pointers. The descriptor is released with LocalFree.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(status as i32))
            .context("GetSecurityInfo(named pipe)");
    }
    ensure!(
        !descriptor.is_null() && !dacl.is_null(),
        "audit-RPC named pipe has a null security descriptor or DACL"
    );
    let _descriptor = LocalAllocation(descriptor);
    // SAFETY: dacl belongs to the live descriptor returned above.
    ensure!(
        unsafe { IsValidAcl(dacl) } != 0,
        "audit-RPC named pipe DACL is invalid"
    );

    let mut control: SECURITY_DESCRIPTOR_CONTROL = 0;
    let mut revision = 0;
    // SAFETY: descriptor is live and both scalar out-pointers are valid.
    ensure!(
        unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } != 0,
        "cannot inspect audit-RPC named-pipe security descriptor control"
    );
    ensure!(
        control & SE_DACL_PROTECTED != 0,
        "audit-RPC named-pipe DACL inherits external ACEs"
    );

    let mut information = std::mem::MaybeUninit::<ACL_SIZE_INFORMATION>::zeroed();
    // SAFETY: information has the exact requested layout and writable size.
    ensure!(
        unsafe {
            GetAclInformation(
                dacl,
                information.as_mut_ptr().cast(),
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        } != 0,
        "cannot inspect audit-RPC named-pipe DACL"
    );
    // SAFETY: GetAclInformation succeeded for the complete structure.
    let information = unsafe { information.assume_init() };
    ensure!(
        information.AceCount == 1,
        "audit-RPC named-pipe DACL has {} ACEs; expected exactly one",
        information.AceCount
    );
    let mut ace = ptr::null_mut();
    // SAFETY: the validated ACL contains exactly one ACE at index zero.
    ensure!(
        unsafe { GetAce(dacl, 0, &mut ace) } != 0 && !ace.is_null(),
        "cannot read audit-RPC named-pipe DACL ACE"
    );
    let dacl_start = dacl as usize;
    let dacl_end = dacl_start
        .checked_add(information.AclBytesInUse as usize)
        .context("audit-RPC named-pipe ACL size overflows the address space")?;
    let ace_start = ace as usize;
    let ace_header_end = ace_start
        .checked_add(std::mem::size_of::<ACE_HEADER>())
        .context("audit-RPC named-pipe ACE header overflows the address space")?;
    ensure!(
        ace_start >= dacl_start && ace_header_end <= dacl_end,
        "audit-RPC named-pipe ACE header lies outside the validated ACL"
    );
    // SAFETY: GetAce returned the sole ACE in the live descriptor, and the
    // preceding range check proved these exact header bytes lie inside
    // AclBytesInUse. They are read as bytes because the ACE is not guaranteed
    // to have Rust's alignment for a typed dereference.
    let ace_header_bytes =
        unsafe { std::slice::from_raw_parts(ace.cast::<u8>(), std::mem::size_of::<ACE_HEADER>()) };
    let (ace_type, ace_flags, ace_size) = parse_ace_header(ace_header_bytes)?;
    ensure!(
        ace_type == 0 && u32::from(ace_flags) & INHERITED_ACE == 0,
        "audit-RPC named-pipe DACL ACE is not one explicit allow entry"
    );
    let ace_end = ace_start
        .checked_add(ace_size)
        .context("audit-RPC named-pipe ACE size overflows the address space")?;
    ensure!(
        ace_size >= std::mem::size_of::<ACCESS_ALLOWED_ACE>() && ace_end <= dacl_end,
        "audit-RPC named-pipe allow ACE is truncated"
    );
    // SAFETY: the preceding size and range checks prove the complete ACE
    // extent lies inside the live descriptor. Parsing this bounded byte slice
    // avoids a potentially unaligned typed ACE dereference.
    let ace_bytes = unsafe { std::slice::from_raw_parts(ace.cast::<u8>(), ace_size) };
    let mask = parse_access_allowed_ace_mask(ace_bytes)?;
    // The SDDL below writes `GA` (GENERIC_ALL), but the kernel applies the
    // object's generic mapping when the descriptor lands on the pipe, so what
    // `GetSecurityInfo` reads back is always the mapped FILE_ALL_ACCESS —
    // `GENERIC_ALL` never appears in a read-back ACE. Comparing against the
    // pre-mapping constant could therefore never succeed on any Windows host:
    // every bind failed, which on the audit path is silent (`AuditSink::
    // DaemonRpc` is best-effort by AUDIT-RPC-01), so one-shot CLI audit frames
    // were being dropped on Windows without a word.
    //
    // This is exactly as strict as the original intent: FILE_ALL_ACCESS is the
    // mapped form of GENERIC_ALL for a file/pipe object, so the assertion still
    // demands one explicit full-control ACE and nothing weaker.
    const MAPPED_FULL_CONTROL: u32 = FILE_ALL_ACCESS;
    ensure!(
        mask == MAPPED_FULL_CONTROL,
        "audit-RPC named-pipe allow ACE mask is {:#010x}; expected the mapped form of \
         GENERIC_ALL ({MAPPED_FULL_CONTROL:#010x})",
        mask
    );
    let sid_offset = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
    const SID_FIXED_HEADER_BYTES: usize = 8;
    ensure!(
        ace_size >= sid_offset + SID_FIXED_HEADER_BYTES,
        "audit-RPC named-pipe allow ACE has a truncated SID header"
    );
    let sid_bytes = &ace_bytes[sid_offset..];
    let sub_authority_count = usize::from(sid_bytes[1]);
    let sid_size = SID_FIXED_HEADER_BYTES
        .checked_add(
            sub_authority_count
                .checked_mul(std::mem::size_of::<u32>())
                .context("audit-RPC named-pipe SID sub-authority count overflows")?,
        )
        .context("audit-RPC named-pipe SID size overflows")?;
    ensure!(
        sid_size <= sid_bytes.len(),
        "audit-RPC named-pipe allow ACE has a truncated SID"
    );
    let sid = sid_bytes.as_ptr().cast_mut().cast();
    ensure!(
        unsafe { IsValidSid(sid) } != 0,
        "audit-RPC named-pipe DACL contains an invalid SID"
    );
    ensure!(
        unsafe { GetLengthSid(sid) } as usize == sid_size,
        "audit-RPC named-pipe DACL SID length is inconsistent"
    );
    // SAFETY: both the expected SID and ACE SID were validated.
    ensure!(
        unsafe { EqualSid(expected_sid.as_ptr().cast_mut().cast(), sid) } != 0,
        "audit-RPC named-pipe DACL is not bound to the current TokenUser"
    );
    Ok(())
}

/// Decode the fixed `ACE_HEADER` fields without assuming pointer alignment.
///
/// Windows ACLs are little-endian on every supported target, so the encoded
/// `ACE_HEADER::AceSize` is decoded explicitly rather than through a typed
/// pointer supplied by `GetAce`.
fn parse_ace_header(ace_bytes: &[u8]) -> Result<(u8, u8, usize)> {
    const ACE_HEADER_BYTES: usize = std::mem::size_of::<ACE_HEADER>();
    let header = ace_bytes
        .get(..ACE_HEADER_BYTES)
        .context("audit-RPC named-pipe ACE header is truncated")?;
    let ace_size = usize::from(u16::from_le_bytes([header[2], header[3]]));
    Ok((header[0], header[1], ace_size))
}

/// Decode the `ACCESS_ALLOWED_ACE::Mask` prefix without assuming alignment.
fn parse_access_allowed_ace_mask(ace_bytes: &[u8]) -> Result<u32> {
    const ACCESS_ALLOWED_ACE_MASK_END: usize = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
    let mask_bytes = ace_bytes
        .get(std::mem::size_of::<ACE_HEADER>()..ACCESS_ALLOWED_ACE_MASK_END)
        .context("audit-RPC named-pipe allow ACE is truncated before its mask")?;
    let mask: [u8; std::mem::size_of::<u32>()] = mask_bytes
        .try_into()
        .context("audit-RPC named-pipe allow ACE mask has an invalid width")?;
    Ok(u32::from_le_bytes(mask))
}

struct CurrentUserSecurityDescriptor(*mut c_void);

impl CurrentUserSecurityDescriptor {
    fn new() -> Result<Self> {
        let sid = current_process_sid()?;
        let mut sid_text = ptr::null_mut();
        // SAFETY: `sid` contains one validated, self-relative SID and
        // sid_text is a valid out-pointer freed with LocalFree below.
        if unsafe { ConvertSidToStringSidW(sid.as_ptr().cast_mut().cast(), &mut sid_text) } == 0 {
            return Err(std::io::Error::last_os_error()).context("ConvertSidToStringSidW");
        }
        let sid_guard = LocalAllocation(sid_text.cast());
        let sid_len = unsafe {
            (0..)
                .find(|&index| *sid_text.add(index) == 0)
                .context("current TokenUser SID string is not terminated")?
        };
        // SAFETY: the preceding scan found the terminator in the
        // LocalAlloc-owned SID string returned by Win32.
        let sid_string =
            String::from_utf16(unsafe { std::slice::from_raw_parts(sid_text, sid_len) })
                .context("current TokenUser SID is not valid UTF-16")?;
        let sddl = format!("D:P(A;;GA;;;{sid_string})");
        let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut descriptor = ptr::null_mut();
        // SAFETY: `wide` is NUL-terminated and descriptor is a valid
        // out-pointer.  LocalFree owns the returned allocation.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error()).context(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW(current TokenUser)",
            );
        }
        drop(sid_guard);
        Ok(Self(descriptor))
    }
}

impl Drop for CurrentUserSecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: the descriptor came from LocalAlloc through the SDDL API
        // and this guard owns it exactly once.
        unsafe {
            LocalFree(self.0);
        }
    }
}

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: this guard owns one LocalAlloc allocation.
        unsafe {
            LocalFree(self.0);
        }
    }
}

struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the guard owns a valid non-pseudo Win32 handle.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

pub(super) fn current_process_sid() -> Result<Vec<u8>> {
    // SAFETY: GetCurrentProcess returns a valid pseudo-handle.
    let process = unsafe { GetCurrentProcess() };
    let mut token = ptr::null_mut();
    // SAFETY: token is a valid out-pointer and TOKEN_QUERY is the only
    // access requested.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(std::io::Error::last_os_error()).context("OpenProcessToken");
    }
    token_sid(Handle(token))
}

fn process_sid(process_id: u32) -> Result<Vec<u8>> {
    // SAFETY: no inherited handle, least-privilege query access.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if process.is_null() {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("OpenProcess({process_id})"));
    }
    let process = Handle(process);
    let mut token = ptr::null_mut();
    // SAFETY: token is a valid out-pointer for the live process handle.
    if unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &mut token) } == 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("OpenProcessToken({process_id})"));
    }
    token_sid(Handle(token))
}

fn current_thread_sid() -> Result<Vec<u8>> {
    let mut token = ptr::null_mut();
    // SAFETY: GetCurrentThread is a valid pseudo-handle. OpenAsSelf=FALSE
    // queries the active impersonation token rather than our process token.
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 0, &mut token) } == 0 {
        return Err(std::io::Error::last_os_error()).context("OpenThreadToken");
    }
    token_sid(Handle(token))
}

fn token_sid(token: Handle) -> Result<Vec<u8>> {
    let mut required = 0;
    // SAFETY: the null buffer/zero length probe returns the required size.
    let probe =
        unsafe { GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut required) };
    if probe != 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
        return Err(std::io::Error::last_os_error()).context("GetTokenInformation(TokenUser size)");
    }
    ensure!(
        required as usize >= std::mem::size_of::<TOKEN_USER>(),
        "GetTokenInformation returned an undersized TokenUser buffer"
    );
    let word_count = (required as usize).div_ceil(std::mem::size_of::<usize>());
    let mut storage = vec![0_usize; word_count];
    // SAFETY: storage is aligned and contains at least `required` writable
    // bytes.  TokenUser is the requested layout.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            storage.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error()).context("GetTokenInformation(TokenUser)");
    }
    // SAFETY: GetTokenInformation initialized a complete aligned TOKEN_USER.
    let user = unsafe { &*(storage.as_ptr().cast::<TOKEN_USER>()) };
    ensure!(
        !user.User.Sid.is_null() && unsafe { IsValidSid(user.User.Sid) } != 0,
        "TokenUser returned an invalid SID"
    );
    // SAFETY: IsValidSid succeeded for this pointer.
    let length = unsafe { GetLengthSid(user.User.Sid) } as usize;
    // SAFETY: the SID is valid for exactly GetLengthSid bytes and remains
    // inside the live token-information buffer during this copy.
    Ok(unsafe { std::slice::from_raw_parts(user.User.Sid.cast::<u8>(), length) }.to_vec())
}

pub(super) fn same_sid(expected: &[u8], actual: &[u8]) -> bool {
    // SAFETY: both slices were copied from validated TokenUser SIDs.
    unsafe {
        EqualSid(
            expected.as_ptr().cast_mut().cast(),
            actual.as_ptr().cast_mut().cast(),
        ) != 0
    }
}

fn attest_named_pipe_client(server: &NamedPipeServer) -> Result<()> {
    let expected = current_process_sid()?;
    let handle = server.as_raw_handle() as HANDLE;
    // SAFETY: handle is a connected named-pipe server instance.
    if unsafe { ImpersonateNamedPipeClient(handle) } == 0 {
        return Err(std::io::Error::last_os_error()).context("ImpersonateNamedPipeClient");
    }
    let revert = RevertGuard { active: true };
    attest_client_sid_with(&expected, current_thread_sid, move || revert.finish())
}

pub(super) fn attest_client_sid_with<Query, Revert>(
    expected: &[u8],
    query_sid: Query,
    revert: Revert,
) -> Result<()>
where
    Query: FnOnce() -> Result<Vec<u8>>,
    Revert: FnOnce(),
{
    let actual = query_sid();
    revert();
    let actual = actual?;
    ensure!(
        same_sid(expected, &actual),
        "audit-RPC named-pipe client TokenUser does not match current process"
    );
    Ok(())
}

fn attest_named_pipe_server(handle: HANDLE) -> Result<()> {
    let mut process_id = 0;
    // SAFETY: handle is a connected named-pipe client handle and the PID
    // out-pointer is valid.
    if unsafe { GetNamedPipeServerProcessId(handle, &mut process_id) } == 0 {
        return Err(std::io::Error::last_os_error()).context("GetNamedPipeServerProcessId");
    }
    ensure!(process_id != 0, "named-pipe server returned PID zero");
    let expected = current_process_sid()?;
    let actual = process_sid(process_id)?;
    ensure!(
        same_sid(&expected, &actual),
        "audit-RPC named-pipe server TokenUser does not match current process"
    );
    Ok(())
}

struct RevertGuard {
    active: bool,
}

impl RevertGuard {
    fn finish(mut self) {
        // SAFETY: this thread is impersonating after a successful
        // ImpersonateNamedPipeClient call.
        if unsafe { RevertToSelf() } == 0 {
            // Continuing an async runtime worker under an attacker-selected
            // token would violate every later authorization boundary.  A
            // process abort is the only fail-closed outcome when Windows
            // cannot restore the daemon token.
            std::process::abort();
        }
        self.active = false;
    }
}

impl Drop for RevertGuard {
    fn drop(&mut self) {
        if self.active {
            // SAFETY: best-effort second attempt on the same thread.  The
            // process must not continue if the token cannot be restored.
            if unsafe { RevertToSelf() } == 0 {
                std::process::abort();
            }
        }
    }
}

fn open_pipe_overlapped(name: &str, deadline: Instant) -> std::io::Result<Handle> {
    let wide: Vec<u16> = std::ffi::OsStr::new(name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    loop {
        let wait_ms = remaining_millis(deadline)?;
        // SAFETY: wide is a live NUL-terminated pipe name.
        if unsafe { WaitNamedPipeW(wide.as_ptr(), wait_ms) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: all pointers and flags meet CreateFileW's named-pipe
        // contract.  No inheritable security attributes are supplied.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                ptr::null_mut(),
            )
        };
        if handle != INVALID_HANDLE_VALUE {
            return Ok(Handle(handle));
        }
        let error = unsafe { GetLastError() };
        if error != ERROR_PIPE_BUSY {
            return Err(std::io::Error::from_raw_os_error(error as i32));
        }
    }
}

fn overlapped_write(handle: HANDLE, bytes: &[u8], deadline: Instant) -> std::io::Result<usize> {
    let length = u32::try_from(bytes.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "write too large"))?;
    run_overlapped(handle, deadline, |overlapped, transferred| unsafe {
        WriteFile(
            handle,
            bytes.as_ptr().cast(),
            length,
            transferred,
            overlapped,
        )
    })
}

fn overlapped_read(handle: HANDLE, bytes: &mut [u8], deadline: Instant) -> std::io::Result<usize> {
    let length = u32::try_from(bytes.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "read too large"))?;
    run_overlapped(handle, deadline, |overlapped, transferred| unsafe {
        ReadFile(
            handle,
            bytes.as_mut_ptr().cast(),
            length,
            transferred,
            overlapped,
        )
    })
}

fn run_overlapped(
    handle: HANDLE,
    deadline: Instant,
    start: impl FnOnce(*mut RawOverlapped, *mut u32) -> i32,
) -> std::io::Result<usize> {
    // SAFETY: null security attributes, manual reset, initially non-signaled.
    let event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
    if event.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    let event = Handle(event);
    let mut overlapped = RawOverlapped {
        internal: 0,
        internal_high: 0,
        offset: 0,
        offset_high: 0,
        event: event.0,
    };
    let mut transferred = 0;
    if start(&mut overlapped, &mut transferred) != 0 {
        return Ok(transferred as usize);
    }
    let error = unsafe { GetLastError() };
    if error != ERROR_IO_PENDING {
        return Err(std::io::Error::from_raw_os_error(error as i32));
    }
    let wait_ms = match remaining_millis(deadline) {
        Ok(wait_ms) => wait_ms,
        Err(error) => {
            cancel_and_drain(handle, &overlapped, event.0);
            return Err(error);
        }
    };
    // SAFETY: the event belongs to this live OVERLAPPED operation.
    match unsafe { WaitForSingleObject(event.0, wait_ms) } {
        WAIT_OBJECT_0 => {}
        WAIT_TIMEOUT => {
            cancel_and_drain(handle, &overlapped, event.0);
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "audit-RPC blocking named-pipe I/O timed out",
            ));
        }
        wait_result => {
            let wait_error = std::io::Error::last_os_error();
            cancel_and_drain(handle, &overlapped, event.0);
            return Err(std::io::Error::new(
                wait_error.kind(),
                format!(
                    "WaitForSingleObject returned unexpected result {wait_result:#x}: \
                         {wait_error}"
                ),
            ));
        }
    }
    // SAFETY: the event signaled completion and both out-pointers remain
    // valid until this call returns.
    if unsafe { GetOverlappedResult(handle, &overlapped, &mut transferred, 0) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(transferred as usize)
}

/// End a pending operation before its stack-backed OVERLAPPED storage can
/// be dropped.  If Windows cannot prove terminal completion, continuing the
/// process would be memory-unsafe, so the only fail-closed outcome is abort.
fn cancel_and_drain(handle: HANDLE, overlapped: &RawOverlapped, event: HANDLE) {
    // SAFETY: cancel exactly the operation described by this live
    // OVERLAPPED. ERROR_NOT_FOUND means it completed concurrently.
    if unsafe { CancelIoEx(handle, overlapped) } == 0 {
        let error = unsafe { GetLastError() };
        const ERROR_NOT_FOUND: u32 = 1168;
        if error != ERROR_NOT_FOUND {
            std::process::abort();
        }
    }
    // SAFETY: a successful cancel or concurrent completion must eventually
    // signal this operation's private event.
    if unsafe { WaitForSingleObject(event, INFINITE) } != WAIT_OBJECT_0 {
        std::process::abort();
    }
    let mut ignored = 0;
    // SAFETY: the signaled event proves the kernel completed its access to
    // OVERLAPPED. A false result here is a terminal I/O status (normally
    // ERROR_OPERATION_ABORTED), not an outstanding operation.
    unsafe {
        GetOverlappedResult(handle, overlapped, &mut ignored, 0);
    }
}

fn remaining_millis(deadline: Instant) -> std::io::Result<u32> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "audit-RPC blocking exchange timed out",
        ));
    }
    Ok(remaining.as_millis().clamp(1, u32::MAX as u128) as u32)
}

#[cfg(test)]
mod tests {
    use super::{parse_access_allowed_ace_mask, parse_ace_header};

    #[test]
    fn ace_header_parser_decodes_little_endian_fields() {
        let (ace_type, ace_flags, ace_size) =
            parse_ace_header(&[0, 0x10, 0x34, 0x12]).expect("complete ACE header");

        assert_eq!(ace_type, 0);
        assert_eq!(ace_flags, 0x10);
        assert_eq!(ace_size, 0x1234);
    }

    #[test]
    fn ace_header_parser_rejects_truncated_header() {
        assert!(parse_ace_header(&[0, 0, 12]).is_err());
    }

    #[test]
    fn access_allowed_ace_mask_parser_decodes_little_endian_mask() {
        let mask = parse_access_allowed_ace_mask(&[
            0, 0, 16, 0, // ACE_HEADER
            0x78, 0x56, 0x34, 0x12, // ACCESS_ALLOWED_ACE::Mask
        ])
        .expect("complete fixed allow-ACE prefix");

        assert_eq!(mask, 0x1234_5678);
    }

    #[test]
    fn access_allowed_ace_mask_parser_rejects_truncated_prefix() {
        assert!(parse_access_allowed_ace_mask(&[0; 7]).is_err());
    }
}

#[repr(C)]
struct RawOverlapped {
    internal: usize,
    internal_high: usize,
    offset: u32,
    offset_high: u32,
    event: HANDLE,
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn ImpersonateNamedPipeClient(named_pipe: HANDLE) -> i32;
    fn RevertToSelf() -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateEventW(
        event_attributes: *const c_void,
        manual_reset: i32,
        initial_state: i32,
        name: *const u16,
    ) -> HANDLE;
    fn CreateFileW(
        file_name: *const u16,
        desired_access: u32,
        share_mode: u32,
        security_attributes: *const c_void,
        creation_disposition: u32,
        flags_and_attributes: u32,
        template_file: HANDLE,
    ) -> HANDLE;
    fn WaitNamedPipeW(name: *const u16, timeout: u32) -> i32;
    fn GetNamedPipeServerProcessId(pipe: HANDLE, server_process_id: *mut u32) -> i32;
    fn ReadFile(
        file: HANDLE,
        buffer: *mut c_void,
        bytes_to_read: u32,
        bytes_read: *mut u32,
        overlapped: *mut RawOverlapped,
    ) -> i32;
    fn WriteFile(
        file: HANDLE,
        buffer: *const c_void,
        bytes_to_write: u32,
        bytes_written: *mut u32,
        overlapped: *mut RawOverlapped,
    ) -> i32;
    fn GetOverlappedResult(
        file: HANDLE,
        overlapped: *const RawOverlapped,
        transferred: *mut u32,
        wait: i32,
    ) -> i32;
    fn CancelIoEx(file: HANDLE, overlapped: *const RawOverlapped) -> i32;
    fn WaitForSingleObject(handle: HANDLE, milliseconds: u32) -> u32;
}
