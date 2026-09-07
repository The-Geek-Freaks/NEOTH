//! Current-user-only Windows named-pipe primitives.
//!
//! This module owns OS-level namespace, DACL, peer-attestation, and bounded
//! overlapped-I/O mechanics. Protocol sidecars, bearer tokens, framing, and
//! service authorization stay with each caller.

use std::{
    ffi::c_void,
    os::windows::{ffi::OsStrExt as _, io::AsRawHandle as _},
    ptr,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_BROKEN_PIPE, ERROR_INSUFFICIENT_BUFFER, ERROR_IO_PENDING,
        ERROR_PIPE_BUSY, ERROR_SUCCESS, GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE,
        INVALID_HANDLE_VALUE, LocalFree,
    },
    Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        GetSecurityInfo, SDDL_REVISION_1, SE_KERNEL_OBJECT,
    },
    Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
        DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation, GetLengthSid,
        GetSecurityDescriptorControl, GetTokenInformation, INHERITED_ACE, IsValidAcl, IsValidSid,
        SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR_CONTROL, TOKEN_QUERY,
        TOKEN_USER, TokenUser,
    },
    Storage::FileSystem::{FILE_ALL_ACCESS, FILE_FLAG_OVERLAPPED, OPEN_EXISTING},
    System::Threading::{
        GetCurrentProcess, GetCurrentThread, OpenProcess, OpenProcessToken, OpenThreadToken,
        PROCESS_QUERY_LIMITED_INFORMATION,
    },
};

pub(crate) const PIPE_REJECT_REMOTE_CLIENTS: bool = true;
const SECURITY_IDENTIFICATION: u32 = 0x0001_0000;
const SECURITY_SQOS_PRESENT: u32 = 0x0010_0000;
const WAIT_OBJECT_0: u32 = 0;
const WAIT_TIMEOUT: u32 = 258;
const INFINITE: u32 = u32::MAX;

/// A name that is bound to one service namespace, one canonical-home hash,
/// and one endpoint nonce. It is transport identity only, never a bearer
/// capability or a sidecar authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PrivatePipeEndpoint {
    service: String,
    home_sha256: String,
    endpoint_nonce: String,
    name: String,
}

impl PrivatePipeEndpoint {
    pub(crate) fn derive(service: &str, home_sha256: &str, endpoint_nonce: &str) -> Result<Self> {
        validate_service(service)?;
        validate_lower_hex("canonical-home SHA-256", home_sha256, 64)?;
        validate_lower_hex("endpoint nonce", endpoint_nonce, 32)?;
        Ok(Self {
            service: service.to_owned(),
            home_sha256: home_sha256.to_owned(),
            endpoint_nonce: endpoint_nonce.to_owned(),
            name: format!(r"\\.\pipe\{service}-{home_sha256}-{endpoint_nonce}"),
        })
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    #[cfg(test)]
    pub(crate) fn validate_binding(
        &self,
        service: &str,
        home_sha256: &str,
        endpoint_nonce: &str,
    ) -> Result<()> {
        let expected = Self::derive(service, home_sha256, endpoint_nonce)?;
        ensure!(
            self == &expected,
            "private named-pipe endpoint is not bound to its service, home, and nonce"
        );
        Ok(())
    }
}

fn validate_service(service: &str) -> Result<()> {
    ensure!(
        !service.is_empty()
            && service
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && !service.starts_with('-')
            && !service.ends_with('-'),
        "private named-pipe service identifier must be lowercase ASCII alphanumeric segments"
    );
    Ok(())
}

fn validate_lower_hex(label: &str, value: &str, expected_len: usize) -> Result<()> {
    ensure!(
        value.len() == expected_len
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
        "{label} must be {expected_len} lowercase hexadecimal characters"
    );
    Ok(())
}

pub(crate) struct Listener {
    endpoint: PrivatePipeEndpoint,
    buffer_bytes: u32,
    pending: Option<NamedPipeServer>,
}

impl Listener {
    pub(crate) fn bind(endpoint: PrivatePipeEndpoint, buffer_bytes: u32) -> Result<Self> {
        ensure!(
            buffer_bytes != 0,
            "private named-pipe buffer size must be non-zero"
        );
        let pending = create_server(&endpoint, true, buffer_bytes)
            .context("create first current-user-only private named-pipe instance")?;
        Ok(Self {
            endpoint,
            buffer_bytes,
            pending: Some(pending),
        })
    }

    /// The pending instance remains borrowed until connect resolves, so a
    /// dropped select branch cannot destroy the listener's sole accept slot.
    pub(crate) async fn accept(&mut self) -> Result<NamedPipeServer> {
        loop {
            self.pending
                .as_ref()
                .context("private named-pipe listener is closed")?
                .connect()
                .await
                .context("accept private named-pipe connection")?;
            let server = self
                .pending
                .take()
                .context("private named-pipe listener is closed")?;
            self.pending = Some(
                create_server(&self.endpoint, false, self.buffer_bytes)
                    .context("create next private named-pipe instance")?,
            );
            if attest_named_pipe_client(&server).is_ok() {
                return Ok(server);
            }
            drop(server);
        }
    }
}

/// Connect through Tokio and attest the server process's TokenUser SID.
pub(crate) async fn connect(endpoint: &PrivatePipeEndpoint) -> Result<NamedPipeClient> {
    let client = ClientOptions::new()
        .security_qos_flags(SECURITY_IDENTIFICATION)
        .open(endpoint.name())
        .with_context(|| format!("connect private named pipe {}", endpoint.name()))?;
    attest_named_pipe_server(client.as_raw_handle() as HANDLE)?;
    Ok(client)
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ExchangeBounds {
    pub(crate) max_request_bytes: usize,
    pub(crate) max_response_bytes: usize,
    pub(crate) timeout: Duration,
}

pub(crate) fn exchange_blocking(
    endpoint: &PrivatePipeEndpoint,
    request: &[u8],
    bounds: ExchangeBounds,
) -> Result<Vec<u8>> {
    ensure!(
        request.len() <= bounds.max_request_bytes,
        "private named-pipe request exceeds {} bytes",
        bounds.max_request_bytes
    );
    let deadline = Instant::now()
        .checked_add(bounds.timeout)
        .context("private named-pipe timeout overflow")?;
    let handle = open_pipe_overlapped(endpoint.name(), deadline)
        .with_context(|| format!("open private named pipe {}", endpoint.name()))?;
    attest_named_pipe_server(handle.0)?;

    let mut written = 0;
    while written < request.len() {
        let count = overlapped_write(handle.0, &request[written..], deadline)?;
        ensure!(count != 0, "private named-pipe write made no progress");
        written += count;
    }
    let mut response = Vec::with_capacity(bounds.max_response_bytes.min(8192));
    loop {
        let remaining = bounds
            .max_response_bytes
            .checked_add(1)
            .context("private named-pipe response bound overflow")?
            .saturating_sub(response.len());
        ensure!(
            remaining != 0,
            "private named-pipe response exceeds {} bytes",
            bounds.max_response_bytes
        );
        let mut chunk = [0_u8; 8192];
        let chunk_len = chunk.len().min(remaining);
        match overlapped_read(handle.0, &mut chunk[..chunk_len], deadline) {
            Ok(0) => break,
            Ok(count) => {
                response.extend_from_slice(&chunk[..count]);
                ensure!(
                    response.len() <= bounds.max_response_bytes,
                    "private named-pipe response exceeds {} bytes",
                    bounds.max_response_bytes
                );
            }
            Err(error) if error.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) => break,
            Err(error) => return Err(error).context("read private named-pipe response"),
        }
    }
    Ok(response)
}

fn create_server(
    endpoint: &PrivatePipeEndpoint,
    first: bool,
    buffer_bytes: u32,
) -> Result<NamedPipeServer> {
    let descriptor = CurrentUserSecurityDescriptor::new()?;
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
            .expect("SECURITY_ATTRIBUTES fits ULONG"),
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first)
        .reject_remote_clients(PIPE_REJECT_REMOTE_CLIENTS)
        .in_buffer_size(buffer_bytes)
        .out_buffer_size(buffer_bytes);
    // SAFETY: attributes and descriptor survive until CreateNamedPipeW copies them.
    let server = unsafe {
        options.create_with_security_attributes_raw(
            endpoint.name(),
            (&mut attributes as *mut SECURITY_ATTRIBUTES).cast(),
        )
    }?;
    verify_named_pipe_current_user_dacl(server.as_raw_handle() as HANDLE)?;
    Ok(server)
}

fn verify_named_pipe_current_user_dacl(handle: HANDLE) -> Result<()> {
    let expected_sid = current_process_sid()?;
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut descriptor: *mut c_void = ptr::null_mut();
    // SAFETY: handle is live; only DACL and descriptor outputs are requested.
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
            .context("GetSecurityInfo(private named pipe)");
    }
    ensure!(
        !descriptor.is_null() && !dacl.is_null(),
        "private named pipe has a null security descriptor or DACL"
    );
    let _descriptor = LocalAllocation(descriptor);
    ensure!(
        unsafe { IsValidAcl(dacl) } != 0,
        "private named-pipe DACL is invalid"
    );
    let mut control: SECURITY_DESCRIPTOR_CONTROL = 0;
    let mut revision = 0;
    ensure!(
        unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } != 0,
        "cannot inspect private named-pipe security descriptor control"
    );
    ensure!(
        control & SE_DACL_PROTECTED != 0,
        "private named-pipe DACL inherits external ACEs"
    );
    let mut information = std::mem::MaybeUninit::<ACL_SIZE_INFORMATION>::zeroed();
    ensure!(
        unsafe {
            GetAclInformation(
                dacl,
                information.as_mut_ptr().cast(),
                u32::try_from(std::mem::size_of::<ACL_SIZE_INFORMATION>())
                    .expect("ACL_SIZE_INFORMATION fits ULONG"),
                AclSizeInformation,
            )
        } != 0,
        "cannot inspect private named-pipe DACL"
    );
    let information = unsafe { information.assume_init() };
    ensure!(
        information.AceCount == 1,
        "private named-pipe DACL has {} ACEs; expected exactly one",
        information.AceCount
    );
    let mut ace = ptr::null_mut();
    ensure!(
        unsafe { GetAce(dacl, 0, &mut ace) } != 0 && !ace.is_null(),
        "cannot read private named-pipe DACL ACE"
    );
    let dacl_start = dacl as usize;
    let dacl_end = dacl_start
        .checked_add(information.AclBytesInUse as usize)
        .context("private named-pipe ACL size overflows address space")?;
    let ace_start = ace as usize;
    let ace_header_end = ace_start
        .checked_add(std::mem::size_of::<ACE_HEADER>())
        .context("private named-pipe ACE header overflows address space")?;
    ensure!(
        ace_start >= dacl_start && ace_header_end <= dacl_end,
        "private named-pipe ACE header lies outside the validated ACL"
    );
    let ace_header_bytes =
        unsafe { std::slice::from_raw_parts(ace.cast::<u8>(), std::mem::size_of::<ACE_HEADER>()) };
    let (ace_type, ace_flags, ace_size) = parse_ace_header(ace_header_bytes)?;
    ensure!(
        ace_type == 0 && u32::from(ace_flags) & INHERITED_ACE == 0,
        "private named-pipe DACL ACE is not one explicit allow entry"
    );
    let ace_end = ace_start
        .checked_add(ace_size)
        .context("private named-pipe ACE size overflows address space")?;
    ensure!(
        ace_size >= std::mem::size_of::<ACCESS_ALLOWED_ACE>() && ace_end <= dacl_end,
        "private named-pipe allow ACE is truncated"
    );
    let ace_bytes = unsafe { std::slice::from_raw_parts(ace.cast::<u8>(), ace_size) };
    ensure!(
        parse_access_allowed_ace_mask(ace_bytes)? == FILE_ALL_ACCESS,
        "private named-pipe allow ACE is not mapped GENERIC_ALL"
    );
    let sid_offset = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
    const SID_FIXED_HEADER_BYTES: usize = 8;
    ensure!(
        ace_size >= sid_offset + SID_FIXED_HEADER_BYTES,
        "private named-pipe allow ACE has a truncated SID header"
    );
    let sid_bytes = &ace_bytes[sid_offset..];
    let sid_size = SID_FIXED_HEADER_BYTES
        .checked_add(
            usize::from(sid_bytes[1])
                .checked_mul(std::mem::size_of::<u32>())
                .context("private named-pipe SID sub-authority count overflows")?,
        )
        .context("private named-pipe SID size overflows")?;
    ensure!(
        sid_size <= sid_bytes.len(),
        "private named-pipe allow ACE has a truncated SID"
    );
    let sid = sid_bytes.as_ptr().cast_mut().cast();
    ensure!(
        unsafe { IsValidSid(sid) } != 0 && unsafe { GetLengthSid(sid) } as usize == sid_size,
        "private named-pipe DACL contains an inconsistent SID"
    );
    ensure!(
        unsafe { EqualSid(expected_sid.as_ptr().cast_mut().cast(), sid) } != 0,
        "private named-pipe DACL is not bound to the current TokenUser"
    );
    Ok(())
}

fn parse_ace_header(bytes: &[u8]) -> Result<(u8, u8, usize)> {
    let header = bytes
        .get(..std::mem::size_of::<ACE_HEADER>())
        .context("private named-pipe ACE header is truncated")?;
    Ok((
        header[0],
        header[1],
        usize::from(u16::from_le_bytes([header[2], header[3]])),
    ))
}

fn parse_access_allowed_ace_mask(bytes: &[u8]) -> Result<u32> {
    let mask = bytes
        .get(std::mem::size_of::<ACE_HEADER>()..std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart))
        .context("private named-pipe allow ACE is truncated before its mask")?;
    Ok(u32::from_le_bytes(mask.try_into().context(
        "private named-pipe allow ACE mask has an invalid width",
    )?))
}

struct CurrentUserSecurityDescriptor(*mut c_void);

impl CurrentUserSecurityDescriptor {
    fn new() -> Result<Self> {
        let sid = current_process_sid()?;
        let mut sid_text = ptr::null_mut();
        // SAFETY: sid is a validated TokenUser SID and sid_text is an output pointer.
        if unsafe { ConvertSidToStringSidW(sid.as_ptr().cast_mut().cast(), &mut sid_text) } == 0 {
            return Err(std::io::Error::last_os_error()).context("ConvertSidToStringSidW");
        }
        let sid_guard = LocalAllocation(sid_text.cast());
        let sid_len = unsafe { (0..).find(|&index| *sid_text.add(index) == 0) }
            .context("current TokenUser SID string is not terminated")?;
        let sid_string =
            String::from_utf16(unsafe { std::slice::from_raw_parts(sid_text, sid_len) })
                .context("current TokenUser SID is not valid UTF-16")?;
        let wide: Vec<u16> = format!("D:P(A;;GA;;;{sid_string})")
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut descriptor = ptr::null_mut();
        // SAFETY: wide is NUL terminated and descriptor is a valid out-pointer.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error())
                .context("build protected current-TokenUser private-pipe DACL");
        }
        drop(sid_guard);
        Ok(Self(descriptor))
    }
}

impl Drop for CurrentUserSecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: this guard owns the LocalAlloc result exactly once.
        unsafe {
            LocalFree(self.0);
        }
    }
}

struct LocalAllocation(*mut c_void);
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: this guard owns the LocalAlloc result exactly once.
        unsafe {
            LocalFree(self.0);
        }
    }
}

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: this guard owns a non-pseudo Win32 handle.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

pub(crate) fn current_process_sid() -> Result<Vec<u8>> {
    let mut token = ptr::null_mut();
    // SAFETY: current-process is a valid pseudo-handle and token is an out-pointer.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(std::io::Error::last_os_error()).context("OpenProcessToken");
    }
    token_sid(Handle(token))
}

fn process_sid(process_id: u32) -> Result<Vec<u8>> {
    // SAFETY: least-privilege process query for the PID obtained from the pipe.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if process.is_null() {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("OpenProcess({process_id})"));
    }
    let process = Handle(process);
    let mut token = ptr::null_mut();
    // SAFETY: process is live and token is an output pointer.
    if unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &mut token) } == 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("OpenProcessToken({process_id})"));
    }
    token_sid(Handle(token))
}

fn current_thread_sid() -> Result<Vec<u8>> {
    let mut token = ptr::null_mut();
    // SAFETY: OpenAsSelf FALSE queries the active impersonation token.
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 0, &mut token) } == 0 {
        return Err(std::io::Error::last_os_error()).context("OpenThreadToken");
    }
    token_sid(Handle(token))
}

fn token_sid(token: Handle) -> Result<Vec<u8>> {
    let mut required = 0;
    let probe =
        unsafe { GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut required) };
    if probe != 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
        return Err(std::io::Error::last_os_error()).context("GetTokenInformation(TokenUser size)");
    }
    ensure!(
        required as usize >= std::mem::size_of::<TOKEN_USER>(),
        "TokenUser buffer is undersized"
    );
    let mut storage = vec![0_usize; (required as usize).div_ceil(std::mem::size_of::<usize>())];
    // SAFETY: aligned storage is at least required bytes and requests TokenUser.
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
    let user = unsafe { &*(storage.as_ptr().cast::<TOKEN_USER>()) };
    ensure!(
        !user.User.Sid.is_null() && unsafe { IsValidSid(user.User.Sid) } != 0,
        "TokenUser returned an invalid SID"
    );
    let length = unsafe { GetLengthSid(user.User.Sid) } as usize;
    Ok(unsafe { std::slice::from_raw_parts(user.User.Sid.cast::<u8>(), length) }.to_vec())
}

pub(crate) fn same_sid(expected: &[u8], actual: &[u8]) -> bool {
    // SAFETY: both inputs are copies of validated TokenUser SIDs.
    unsafe {
        EqualSid(
            expected.as_ptr().cast_mut().cast(),
            actual.as_ptr().cast_mut().cast(),
        ) != 0
    }
}

fn attest_named_pipe_client(server: &NamedPipeServer) -> Result<()> {
    let expected = current_process_sid()?;
    // SAFETY: this is a connected named-pipe server endpoint.
    if unsafe { ImpersonateNamedPipeClient(server.as_raw_handle() as HANDLE) } == 0 {
        return Err(std::io::Error::last_os_error()).context("ImpersonateNamedPipeClient");
    }
    let revert = RevertGuard { active: true };
    attest_client_sid_with(&expected, current_thread_sid, move || revert.finish())
}

/// Testable core of mandatory server-side client impersonation attestation.
pub(crate) fn attest_client_sid_with<Query, Revert>(
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
        "private named-pipe client TokenUser does not match current process"
    );
    Ok(())
}

fn attest_named_pipe_server(handle: HANDLE) -> Result<()> {
    let mut process_id = 0;
    // SAFETY: handle is a connected client and process_id is a writable out-pointer.
    if unsafe { GetNamedPipeServerProcessId(handle, &mut process_id) } == 0 {
        return Err(std::io::Error::last_os_error()).context("GetNamedPipeServerProcessId");
    }
    ensure!(process_id != 0, "named-pipe server returned PID zero");
    let expected = current_process_sid()?;
    let actual = process_sid(process_id)?;
    ensure!(
        same_sid(&expected, &actual),
        "private named-pipe server TokenUser does not match current process"
    );
    Ok(())
}

struct RevertGuard {
    active: bool,
}
impl RevertGuard {
    fn finish(mut self) {
        // SAFETY: successful impersonation makes RevertToSelf mandatory.
        if unsafe { RevertToSelf() } == 0 {
            std::process::abort();
        }
        self.active = false;
    }
}
impl Drop for RevertGuard {
    fn drop(&mut self) {
        if self.active {
            // SAFETY: this thread remains impersonated until revert succeeds.
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
        // SAFETY: wide remains live and NUL terminated for the call.
        if unsafe { WaitNamedPipeW(wide.as_ptr(), remaining_millis(deadline)?) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: all CreateFileW inputs meet the named-pipe contract.
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
        if unsafe { GetLastError() } != ERROR_PIPE_BUSY {
            return Err(std::io::Error::last_os_error());
        }
    }
}

fn overlapped_write(handle: HANDLE, bytes: &[u8], deadline: Instant) -> std::io::Result<usize> {
    let length = u32::try_from(bytes.len()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "private named-pipe write is too large",
        )
    })?;
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
    let length = u32::try_from(bytes.len()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "private named-pipe read is too large",
        )
    })?;
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
    // SAFETY: unnamed manual-reset event with no inherited attributes.
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
    if unsafe { GetLastError() } != ERROR_IO_PENDING {
        return Err(std::io::Error::last_os_error());
    }
    let wait_ms = match remaining_millis(deadline) {
        Ok(value) => value,
        Err(error) => {
            cancel_and_drain(handle, &overlapped, event.0);
            return Err(error);
        }
    };
    match unsafe { WaitForSingleObject(event.0, wait_ms) } {
        WAIT_OBJECT_0 => {}
        WAIT_TIMEOUT => {
            cancel_and_drain(handle, &overlapped, event.0);
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "private named-pipe I/O timed out",
            ));
        }
        result => {
            let error = std::io::Error::last_os_error();
            cancel_and_drain(handle, &overlapped, event.0);
            return Err(std::io::Error::new(
                error.kind(),
                format!("WaitForSingleObject returned {result:#x}: {error}"),
            ));
        }
    }
    // SAFETY: the private event proved completion before querying the result.
    if unsafe { GetOverlappedResult(handle, &overlapped, &mut transferred, 0) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(transferred as usize)
}

/// Ensure the kernel has stopped accessing stack-backed OVERLAPPED memory.
/// Failure to prove completion is process-fatal rather than memory-unsafe.
fn cancel_and_drain(handle: HANDLE, overlapped: &RawOverlapped, event: HANDLE) {
    // SAFETY: cancel only the active operation described by overlapped.
    if unsafe { CancelIoEx(handle, overlapped) } == 0 {
        const ERROR_NOT_FOUND: u32 = 1168;
        if unsafe { GetLastError() } != ERROR_NOT_FOUND {
            std::process::abort();
        }
    }
    // SAFETY: successful cancel or concurrent completion must signal event.
    if unsafe { WaitForSingleObject(event, INFINITE) } != WAIT_OBJECT_0 {
        std::process::abort();
    }
    let mut ignored = 0;
    // SAFETY: signaled completion ends kernel access to overlapped.
    unsafe {
        GetOverlappedResult(handle, overlapped, &mut ignored, 0);
    }
}

fn remaining_millis(deadline: Instant) -> std::io::Result<u32> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "private named-pipe exchange timed out",
        ));
    }
    Ok(remaining.as_millis().clamp(1, u32::MAX as u128) as u32)
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    const HOME_SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const ENDPOINT_NONCE: &str = "fedcba9876543210fedcba9876543210";
    const TEST_SERVICE: &str = "neoth-private-ipc-test";
    const DEADLINE_TEST_SERVICE: &str = "neoth-private-ipc-deadline";
    const PIPE_BUFFER_BYTES: u32 = 8 * 1024;

    #[tokio::test]
    async fn exact_service_home_and_nonce_round_trip_attests_both_peers() {
        let endpoint = PrivatePipeEndpoint::derive(TEST_SERVICE, HOME_SHA256, ENDPOINT_NONCE)
            .expect("valid exact private-pipe binding");
        endpoint
            .validate_binding(TEST_SERVICE, HOME_SHA256, ENDPOINT_NONCE)
            .expect("endpoint remains exactly bound");
        assert!(
            endpoint
                .validate_binding("neoth-audit-v2", HOME_SHA256, ENDPOINT_NONCE)
                .is_err()
        );

        let mut listener = Listener::bind(endpoint.clone(), PIPE_BUFFER_BYTES)
            .expect("first private-pipe instance");
        assert!(
            Listener::bind(endpoint.clone(), PIPE_BUFFER_BYTES).is_err(),
            "a second first-instance bind must reject namespace squatting"
        );
        const { assert!(PIPE_REJECT_REMOTE_CLIENTS) };

        let client_endpoint = endpoint.clone();
        let client = tokio::spawn(async move {
            let mut stream = connect(&client_endpoint)
                .await
                .expect("client must attest the same-user server PID token");
            stream.write_all(b"ping").await.expect("write request");
            let mut reply = [0_u8; 4];
            stream.read_exact(&mut reply).await.expect("read response");
            reply
        });
        let mut server = listener
            .accept()
            .await
            .expect("server must attest client TokenUser then revert");
        let mut request = [0_u8; 4];
        server.read_exact(&mut request).await.expect("read request");
        assert_eq!(&request, b"ping");
        server.write_all(b"pong").await.expect("write response");
        drop(server);
        assert_eq!(&client.await.expect("client task"), b"pong");
    }

    #[tokio::test]
    async fn malformed_or_oversized_exchange_fails_and_deadline_cancellation_leaves_next_accept_usable()
     {
        assert!(PrivatePipeEndpoint::derive("Neoth", HOME_SHA256, ENDPOINT_NONCE).is_err());
        assert!(
            PrivatePipeEndpoint::derive(TEST_SERVICE, "not-a-home-hash", ENDPOINT_NONCE).is_err()
        );
        assert!(PrivatePipeEndpoint::derive(TEST_SERVICE, HOME_SHA256, "not-a-nonce").is_err());

        let endpoint =
            PrivatePipeEndpoint::derive(DEADLINE_TEST_SERVICE, HOME_SHA256, ENDPOINT_NONCE)
                .expect("valid endpoint");
        let oversized = ExchangeBounds {
            max_request_bytes: 1,
            max_response_bytes: 1,
            timeout: Duration::from_secs(1),
        };
        assert!(
            exchange_blocking(&endpoint, b"too-large", oversized).is_err(),
            "the generic exchange must reject an oversized frame before opening a pipe"
        );

        let mut listener = Listener::bind(endpoint.clone(), PIPE_BUFFER_BYTES)
            .expect("first private-pipe instance");
        let server = tokio::spawn(async move {
            let first = listener.accept().await.expect("first accepted client");
            // Keep the first peer open past its client deadline. The blocking
            // exchange must cancel and drain its stack-backed OVERLAPPED state.
            tokio::time::sleep(Duration::from_millis(200)).await;
            drop(first);

            let mut second = listener
                .accept()
                .await
                .expect("post-cancel client accepted");
            second
                .write_all(b"x")
                .await
                .expect("write one over-limit response byte");
            drop(second);
        });

        let timeout_endpoint = endpoint.clone();
        let timed_out = tokio::task::spawn_blocking(move || {
            exchange_blocking(
                &timeout_endpoint,
                b"q",
                ExchangeBounds {
                    max_request_bytes: 1,
                    max_response_bytes: 1,
                    timeout: Duration::from_millis(50),
                },
            )
        })
        .await
        .expect("blocking exchange task");
        assert!(
            timed_out.is_err(),
            "unresponsive peer must hit the bounded deadline"
        );

        let response_endpoint = endpoint.clone();
        let oversized_response = tokio::task::spawn_blocking(move || {
            exchange_blocking(
                &response_endpoint,
                b"q",
                ExchangeBounds {
                    max_request_bytes: 1,
                    max_response_bytes: 0,
                    timeout: Duration::from_secs(1),
                },
            )
        })
        .await
        .expect("post-cancel blocking exchange task");
        assert!(
            oversized_response.is_err(),
            "a received byte over the response cap must fail closed"
        );
        server
            .await
            .expect("server task must complete after the cancellation");
    }
}
