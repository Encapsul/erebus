//! Windows process spawning for the erebus stub.
//!
//! Windows has no `fork`/`execvp`: the launcher spawns the app as a child
//! process via `CreateProcessW` and either waits for it (exit code passthrough)
//! or detaches (self-update re-exec). This module is compiled only for
//! `target_os = "windows"`.

#![cfg(target_os = "windows")]

use std::collections::BTreeMap;
use std::ffi::{c_void, OsStr, OsString};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

const CREATE_UNICODE_ENVIRONMENT: u32 = 0x0000_0400;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const DETACHED_PROCESS: u32 = 0x0000_0008;
const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
/// `CreateProcess` reads `STARTUPINFOEXW` instead of `STARTUPINFOW`.
const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x0008_0000;
/// `ProcThreadAttributeValue(9, FALSE, TRUE, FALSE)`.
const PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES: usize = 0x2_0009;
/// `ProcThreadAttributeValue(2, FALSE, TRUE, FALSE)`.
const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 0x2_0002;
const INFINITE: u32 = 0xFFFF_FFFF;
const WAIT_OBJECT_0: u32 = 0;
const WAIT_TIMEOUT: u32 = 0x0000_0102;
const STILL_ACTIVE: u32 = 259;

#[repr(C)]
struct StartupInfoW {
    cb: u32,
    lp_reserved: *mut u16,
    lp_desktop: *mut u16,
    lp_title: *mut u16,
    dw_x: u32,
    dw_y: u32,
    dw_x_size: u32,
    dw_y_size: u32,
    dw_x_count_chars: u32,
    dw_y_count_chars: u32,
    dw_fill_attribute: u32,
    dw_flags: u32,
    w_show_window: u16,
    cb_reserved2: u16,
    lp_reserved2: *mut u8,
    h_std_input: *mut c_void,
    h_std_output: *mut c_void,
    h_std_error: *mut c_void,
}

#[repr(C)]
struct StartupInfoExW {
    startup: StartupInfoW,
    attr: *mut c_void,
}

#[repr(C)]
struct SecurityCapabilities {
    app_container_sid: *mut c_void,
    capabilities: *mut c_void,
    capability_count: u32,
    reserved: u32,
}

#[repr(C)]
struct ProcessInformation {
    h_process: *mut c_void,
    h_thread: *mut c_void,
    dw_process_id: u32,
    dw_thread_id: u32,
}

extern "system" {
    fn CreateProcessW(
        lp_application_name: *const u16,
        lp_command_line: *mut u16,
        lp_process_attributes: *mut c_void,
        lp_thread_attributes: *mut c_void,
        b_inherit_handles: i32,
        dw_creation_flags: u32,
        lp_environment: *mut c_void,
        lp_current_directory: *const u16,
        lp_startup_info: *mut StartupInfoW,
        lp_process_information: *mut ProcessInformation,
    ) -> i32;
    fn WaitForSingleObject(h_handle: *mut c_void, dw_milliseconds: u32) -> u32;
    fn GetExitCodeProcess(h_process: *mut c_void, lp_exit_code: *mut u32) -> i32;
    fn CloseHandle(h_object: *mut c_void) -> i32;
    fn GetLastError() -> u32;
    fn CreateJobObjectW(attrs: *mut c_void, name: *const u16) -> *mut c_void;
    fn SetInformationJobObject(job: *mut c_void, class: i32, info: *const c_void, len: u32) -> i32;
    fn AssignProcessToJobObject(job: *mut c_void, process: *mut c_void) -> i32;
    fn LoadLibraryW(name: *const u16) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    fn GetStdHandle(kind: u32) -> *mut c_void;
    fn InitializeProcThreadAttributeList(
        list: *mut c_void,
        count: u32,
        flags: u32,
        size: *mut usize,
    ) -> i32;
    fn UpdateProcThreadAttribute(
        list: *mut c_void,
        flags: u32,
        attribute: usize,
        value: *mut c_void,
        size: usize,
        previous: *mut c_void,
        returned: *mut usize,
    ) -> i32;
    fn DeleteProcThreadAttributeList(list: *mut c_void);
}

#[link(name = "advapi32")]
extern "system" {
    fn FreeSid(sid: *mut c_void) -> *mut c_void;
    fn ConvertSidToStringSidW(sid: *mut c_void, out: *mut *mut u16) -> i32;
    fn LocalFree(mem: *mut c_void) -> *mut c_void;
}

/// A handle to a spawned child process.
pub struct Child {
    handle: *mut c_void,
    /// Job object. Closed on drop; `KILL_ON_JOB_CLOSE` reaps a child that
    /// outlives the launcher.
    job: *mut c_void,
    pub pid: u32,
}

impl Drop for Child {
    fn drop(&mut self) {
        // SAFETY: both handles come from this module. The job is closed
        // first so JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE reaps a child that is
        // still running. A null job (detached, or a host that refused
        // assignment) skips that. Closing the process handle does not.
        unsafe {
            if !self.job.is_null() {
                CloseHandle(self.job);
            }
            CloseHandle(self.handle);
        }
    }
}

/// Resolve a bare command name against the process `PATH`, mirroring Unix
/// `execvp` semantics: `CreateProcessW` performs no PATH search and no
/// extension expansion when `lpApplicationName` is non-NULL, so the stub must
/// do both itself. Names with a directory component are returned unchanged.
fn resolve_on_path(prog: &Path) -> PathBuf {
    if prog.parent().is_some_and(|p| !p.as_os_str().is_empty()) {
        return prog.to_path_buf();
    }
    // Executable extensions tried in PATHEXT order (subset that matters for
    // interpreters and packaged apps; cmd/bat would be re-parsed by cmd.exe).
    const EXTS: [&str; 3] = ["exe", "com", "bat"];
    // Windows distributions install `python.exe` while erebus entrypoints use
    // the POSIX spelling `python3`: after exhausting the exact name, retry
    // once with any trailing version digits stripped before giving up.
    let lossy = prog.to_string_lossy();
    let mut names = vec![lossy.to_string()];
    let stripped = lossy.trim_end_matches(|c: char| c.is_ascii_digit());
    if !stripped.is_empty() && stripped != lossy {
        names.push(stripped.to_string());
    }
    let dirs = std::env::var_os("PATH").map_or(Vec::new(), |p| {
        std::env::split_paths(&p).collect::<Vec<_>>()
    });
    for name in &names {
        for dir in &dirs {
            let direct = dir.join(name);
            if direct.is_file() {
                return direct;
            }
            for ext in EXTS {
                let candidate = dir.join(format!("{name}.{ext}"));
                if candidate.is_file() {
                    return candidate;
                }
            }
        }
    }
    // Unresolved: hand back the original so CreateProcessW reports the error.
    prog.to_path_buf()
}

/// Spawn `prog` with `argv` and environment, optionally detached.
///
/// `argv[0]` is the program name. When `detached`, the child runs without a
/// console and the caller does not wait for it (used for self-update re-exec).
pub fn spawn(
    prog: &Path,
    argv: &[OsString],
    env: &BTreeMap<String, String>,
    cwd: Option<&Path>,
    detached: bool,
) -> io::Result<Child> {
    let prog = resolve_on_path(prog);
    let command_line = build_command_line(argv);
    let env_block = build_env_block(env)?;

    let mut cmd_line_wide = to_wide(&command_line);
    // CreateProcessW may modify the command line buffer.
    cmd_line_wide.push(0);

    let mut si = StartupInfoW {
        cb: std::mem::size_of::<StartupInfoW>() as u32,
        lp_reserved: std::ptr::null_mut(),
        lp_desktop: std::ptr::null_mut(),
        lp_title: std::ptr::null_mut(),
        dw_x: 0,
        dw_y: 0,
        dw_x_size: 0,
        dw_y_size: 0,
        dw_x_count_chars: 0,
        dw_y_count_chars: 0,
        dw_fill_attribute: 0,
        dw_flags: 0,
        w_show_window: 0,
        cb_reserved2: 0,
        lp_reserved2: std::ptr::null_mut(),
        h_std_input: std::ptr::null_mut(),
        h_std_output: std::ptr::null_mut(),
        h_std_error: std::ptr::null_mut(),
    };
    let mut pi = ProcessInformation {
        h_process: std::ptr::null_mut(),
        h_thread: std::ptr::null_mut(),
        dw_process_id: 0,
        dw_thread_id: 0,
    };

    let cwd_wide = cwd.map(|c| to_wide_null(c.as_os_str()));
    let prog_wide = to_wide_null(prog.as_os_str());

    let mut flags = CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_PROCESS_GROUP;
    if detached {
        flags |= CREATE_NO_WINDOW | DETACHED_PROCESS;
    }
    // Detached re-exec must outlive the launcher, so it stays out of the jail.
    let jail = if detached {
        None
    } else {
        prepare_app_container(cwd)?
    };
    let inherit = jail.as_ref().map(|j| j.inherit).unwrap_or(1);
    if jail.is_some() {
        flags |= EXTENDED_STARTUPINFO_PRESENT;
        si.cb = std::mem::size_of::<StartupInfoExW>() as u32;
    }
    let attr = jail
        .as_ref()
        .map(|j| j.list.as_ptr() as *mut c_void)
        .unwrap_or(std::ptr::null_mut());
    let mut ex = StartupInfoExW { startup: si, attr };
    let startup = if jail.is_some() {
        &mut ex as *mut StartupInfoExW as *mut StartupInfoW
    } else {
        &mut ex.startup
    };

    // SAFETY: all pointers are valid null-terminated UTF-16 buffers or
    // initialized structures. CreateProcessW copies the command line,
    // environment and security capabilities before returning. `jail` stays
    // alive until that copy is done.
    let ok = unsafe {
        CreateProcessW(
            prog_wide.as_ptr(),
            cmd_line_wide.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            // Inherit std handles: unlike a Unix console, piped/redirected
            // stdout only reaches the child through handle inheritance
            // (execvp semantics — `app.exe > log` must work). An AppContainer
            // passes those handles through the attribute list instead.
            inherit,
            flags,
            env_block.as_ptr() as *mut c_void,
            cwd_wide.as_ref().map_or(std::ptr::null(), Vec::as_ptr),
            startup,
            &mut pi,
        )
    };

    if ok == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("CreateProcessW failed: {}", last_error()),
        ));
    }

    // Detached children outlive the launcher, so they stay out of the job.
    // A host already inside a job (some CI runners, older Wine) refuses
    // assignment: the launch continues, without the kill-on-close sandbox.
    let job = if detached {
        std::ptr::null_mut()
    } else {
        confine_in_job(pi.h_process).unwrap_or(std::ptr::null_mut())
    };
    let pid = pi.dw_process_id;
    // SAFETY: pi.h_thread is a handle we own; close it (the process handle is
    // kept for waiting).
    unsafe {
        CloseHandle(pi.h_thread);
    }

    Ok(Child {
        handle: pi.h_process,
        job,
        pid,
    })
}

/// Put `process` in a job that dies with this handle.
fn confine_in_job(process: *mut c_void) -> io::Result<*mut c_void> {
    const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x2000;
    const JOB_OBJECT_BASIC_LIMIT_INFORMATION: i32 = 2;
    #[repr(C)]
    struct BasicLimit {
        per_process_user_time: i64,
        per_job_user_time: i64,
        limit_flags: u32,
        min_ws: usize,
        max_ws: usize,
        active_process_limit: u32,
        affinity: usize,
        priority_class: u32,
        scheduling_class: u32,
    }
    // SAFETY: CreateJobObjectW with null security/name returns a job we own.
    let job = unsafe { CreateJobObjectW(std::ptr::null_mut(), std::ptr::null()) };
    if job.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("CreateJobObjectW failed: {}", last_error()),
        ));
    }
    let info = BasicLimit {
        per_process_user_time: 0,
        per_job_user_time: 0,
        limit_flags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        min_ws: 0,
        max_ws: 0,
        active_process_limit: 0,
        affinity: 0,
        priority_class: 0,
        scheduling_class: 0,
    };
    // SAFETY: `info` is a valid BasicLimit and `job` is a job handle we own.
    let ok = unsafe {
        SetInformationJobObject(
            job,
            JOB_OBJECT_BASIC_LIMIT_INFORMATION,
            &info as *const BasicLimit as *const c_void,
            std::mem::size_of::<BasicLimit>() as u32,
        )
    };
    if ok == 0 {
        unsafe {
            CloseHandle(job);
        }
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("SetInformationJobObject failed: {}", last_error()),
        ));
    }
    // SAFETY: both handles are valid; the process is assigned for its lifetime.
    let assigned = unsafe { AssignProcessToJobObject(job, process) };
    if assigned == 0 {
        unsafe {
            CloseHandle(job);
        }
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("AssignProcessToJobObject failed: {}", last_error()),
        ));
    }
    Ok(job)
}

/// AppContainer bound to the payload directory, plus the std handles the
/// child is allowed to inherit. Missing `userenv` exports (Wine) yield
/// `None` so the launch still happens; a real Windows failure is an error.
struct AppJail {
    sid: *mut c_void,
    /// Pointer-aligned buffer. `Vec<u8>` is only 1-aligned; Windows rejects
    /// an attribute list that is not DWORD-aligned.
    list: Vec<u64>,
    caps: SecurityCapabilities,
    handles: Vec<*mut c_void>,
    inherit: i32,
    list_ready: bool,
}

impl Drop for AppJail {
    fn drop(&mut self) {
        // SAFETY: `list` is an initialized attribute list when `list_ready`,
        // and `sid` came from CreateAppContainerProfile / Derive…Sid.
        unsafe {
            if self.list_ready {
                DeleteProcThreadAttributeList(self.list.as_mut_ptr() as *mut c_void);
            }
            if !self.sid.is_null() {
                FreeSid(self.sid);
            }
        }
    }
}

fn prepare_app_container(cwd: Option<&Path>) -> io::Result<Option<AppJail>> {
    let Some(dir) = cwd else {
        return Ok(None);
    };
    let Some(sid) = app_container_sid()? else {
        return Ok(None);
    };
    if let Err(err) = grant_payload_dir(dir, sid) {
        // SAFETY: CreateAppContainerProfile allocated this SID.
        unsafe { FreeSid(sid) };
        return Err(err);
    }
    let mut jail = AppJail {
        sid,
        list: Vec::new(),
        caps: SecurityCapabilities {
            app_container_sid: sid,
            capabilities: std::ptr::null_mut(),
            capability_count: 0,
            reserved: 0,
        },
        handles: std_handles(),
        inherit: 0,
        list_ready: false,
    };
    jail.inherit = i32::from(!jail.handles.is_empty());
    init_attr_list(&mut jail)?;
    Ok(Some(jail))
}

fn app_container_sid() -> io::Result<Option<*mut c_void>> {
    type CreateProfile = unsafe extern "system" fn(
        *const u16,
        *const u16,
        *const u16,
        *const c_void,
        u32,
        *mut *mut c_void,
    ) -> i32;
    type DeriveSid = unsafe extern "system" fn(*const u16, *mut *mut c_void) -> i32;
    let name = to_wide_null(OsStr::new("userenv.dll"));
    // SAFETY: LoadLibraryW of a null-terminated name. A null module means
    // userenv is absent (Wine); the caller falls back to the job object.
    let module = unsafe { LoadLibraryW(name.as_ptr()) };
    if module.is_null() {
        return Ok(None);
    }
    // SAFETY: `module` is a loaded userenv. Null exports mean this host
    // cannot build an AppContainer (Wine); that is a fallback, not an error.
    let create = unsafe { GetProcAddress(module, b"CreateAppContainerProfile\0".as_ptr()) };
    let derive = unsafe {
        GetProcAddress(
            module,
            b"DeriveAppContainerSidFromAppContainerName\0".as_ptr(),
        )
    };
    if create.is_null() || derive.is_null() {
        return Ok(None);
    }
    // SAFETY: the addresses are the two userenv exports named above.
    let create = unsafe { std::mem::transmute::<*mut c_void, CreateProfile>(create) };
    let derive = unsafe { std::mem::transmute::<*mut c_void, DeriveSid>(derive) };
    let profile = to_wide_null(OsStr::new("erebus.payload"));
    let display = to_wide_null(OsStr::new("erebus"));
    let mut sid = std::ptr::null_mut();
    // SAFETY: profile and display are null-terminated. The function writes
    // one SID we own on success.
    let hr = unsafe {
        create(
            profile.as_ptr(),
            display.as_ptr(),
            display.as_ptr(),
            std::ptr::null(),
            0,
            &mut sid,
        )
    };
    if hr == 0 {
        return Ok(Some(sid));
    }
    // HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS).
    if hr as u32 != 0x8007_00B7 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("CreateAppContainerProfile failed: {hr:#x}"),
        ));
    }
    // SAFETY: same profile name; writes a SID we own on success.
    let hr = unsafe { derive(profile.as_ptr(), &mut sid) };
    if hr == 0 {
        return Ok(Some(sid));
    }
    Err(io::Error::new(
        io::ErrorKind::Other,
        format!("DeriveAppContainerSidFromAppContainerName failed: {hr:#x}"),
    ))
}

fn grant_payload_dir(dir: &Path, sid: *mut c_void) -> io::Result<()> {
    let sid_str = sid_string(sid)?;
    let status = std::process::Command::new("icacls")
        .arg(dir)
        .arg("/grant")
        .arg(format!("*{sid_str}:(OI)(CI)M"))
        .arg("/Q")
        .status()
        .map_err(|err| io::Error::new(io::ErrorKind::Other, format!("icacls: {err}")))?;
    if status.success() {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::Other,
        format!("icacls /grant failed: {status}"),
    ))
}

fn sid_string(sid: *mut c_void) -> io::Result<String> {
    let mut raw = std::ptr::null_mut();
    // SAFETY: `sid` is a valid SID. ConvertSidToStringSidW allocates `raw`.
    let ok = unsafe { ConvertSidToStringSidW(sid, &mut raw) };
    if ok == 0 || raw.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("ConvertSidToStringSidW failed: {}", last_error()),
        ));
    }
    let mut len = 0usize;
    // SAFETY: `raw` is a null-terminated UTF-16 string from advapi32.
    unsafe {
        while *raw.add(len) != 0 {
            len += 1;
        }
    }
    let text = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(raw, len) });
    // SAFETY: `raw` was allocated by ConvertSidToStringSidW. LocalFree takes
    // that allocation as an untyped pointer.
    unsafe { LocalFree(raw.cast::<c_void>()) };
    Ok(text)
}

fn std_handles() -> Vec<*mut c_void> {
    const STDS: [u32; 3] = [0xFFFF_FFF6, 0xFFFF_FFF5, 0xFFFF_FFF4];
    let invalid = -1isize as *mut c_void;
    let mut out = Vec::new();
    for kind in STDS {
        // SAFETY: GetStdHandle only reads a well-known standard-handle id.
        let handle = unsafe { GetStdHandle(kind) };
        if !handle.is_null() && handle != invalid {
            out.push(handle);
        }
    }
    out
}

fn init_attr_list(jail: &mut AppJail) -> io::Result<()> {
    let count = if jail.handles.is_empty() { 1 } else { 2 };
    let mut size = 0usize;
    // SAFETY: a null list asks for the byte size. Failure is expected.
    unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), count, 0, &mut size) };
    if size == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("InitializeProcThreadAttributeList size: {}", last_error()),
        ));
    }
    jail.list = vec![0u64; size.div_ceil(8)];
    // SAFETY: `jail.list` has the size the previous call reported.
    let ok = unsafe {
        InitializeProcThreadAttributeList(
            jail.list.as_mut_ptr() as *mut c_void,
            count,
            0,
            &mut size,
        )
    };
    if ok == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("InitializeProcThreadAttributeList failed: {}", last_error()),
        ));
    }
    jail.list_ready = true;
    let list = jail.list.as_mut_ptr() as *mut c_void;
    let caps = std::ptr::addr_of_mut!(jail.caps).cast::<c_void>();
    update_attr(
        list,
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
        caps,
        std::mem::size_of::<SecurityCapabilities>(),
    )?;
    if jail.handles.is_empty() {
        return Ok(());
    }
    let handles = jail.handles.as_mut_ptr().cast::<c_void>();
    let handle_bytes = std::mem::size_of::<*mut c_void>() * jail.handles.len();
    update_attr(
        list,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        handles,
        handle_bytes,
    )
}

fn update_attr(
    list: *mut c_void,
    attribute: usize,
    value: *mut c_void,
    size: usize,
) -> io::Result<()> {
    // SAFETY: `list` is an initialized attribute list and `value` points at
    // memory that outlives CreateProcessW (the caps or the handle vec).
    let ok = unsafe {
        UpdateProcThreadAttribute(
            list,
            0,
            attribute,
            value,
            size,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("UpdateProcThreadAttribute failed: {}", last_error()),
        ));
    }
    Ok(())
}

/// Block until the child exits and return its exit code.
pub fn wait(child: &Child) -> io::Result<i32> {
    // SAFETY: child.handle is a valid process handle from CreateProcessW.
    let rc = unsafe { WaitForSingleObject(child.handle, INFINITE) };
    if rc != WAIT_OBJECT_0 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("WaitForSingleObject failed: {rc}"),
        ));
    }
    exit_code(child)
}

/// Non-blocking poll: `Ok(None)` while running, `Ok(Some(code))` on exit.
pub fn try_wait(child: &Child) -> io::Result<Option<i32>> {
    // SAFETY: child.handle is a valid process handle; 0ms timeout polls.
    let rc = unsafe { WaitForSingleObject(child.handle, 0) };
    if rc == WAIT_OBJECT_0 {
        return exit_code(child).map(Some);
    }
    if rc == WAIT_TIMEOUT {
        return Ok(None);
    }
    Err(io::Error::new(
        io::ErrorKind::Other,
        format!("WaitForSingleObject failed: {rc}"),
    ))
}

fn exit_code(child: &Child) -> io::Result<i32> {
    let mut code: u32 = 0;
    // SAFETY: GetExitCodeProcess writes the exit code after success.
    let rc = unsafe { GetExitCodeProcess(child.handle, &mut code) };
    if rc == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("GetExitCodeProcess failed: {}", last_error()),
        ));
    }
    // STILL_ACTIVE means the process is still running (should not happen
    // after a signaled wait); treat as 0 rather than a bogus code.
    Ok(if code == STILL_ACTIVE { 0 } else { code as i32 })
}

fn last_error() -> String {
    // SAFETY: GetLastError has no preconditions.
    format!("error {}", unsafe { GetLastError() })
}

/// Join argv into a Windows command line with quoting.
fn build_command_line(argv: &[OsString]) -> String {
    argv.iter()
        .map(|a| quote_arg(&a.to_string_lossy()))
        .collect::<Vec<String>>()
        .join(" ")
}

/// Quote a single command-line argument: wrap in quotes if it contains
/// spaces, tabs, or quotes (standard Windows argv parsing rules).
fn quote_arg(arg: &str) -> String {
    if arg.contains(' ') || arg.contains('\t') || arg.contains('"') {
        format!("\"{}\"", arg.replace('"', "\\\""))
    } else {
        arg.to_string()
    }
}

/// UTF-16LE environment block: `KEY=VALUE\0` pairs terminated by `\0`.
fn build_env_block(env: &BTreeMap<String, String>) -> io::Result<Vec<u16>> {
    let mut block = Vec::new();
    for (k, v) in env {
        for unit in format!("{k}={v}").encode_utf16() {
            block.push(unit);
        }
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

fn to_wide_null(s: &OsStr) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_wide().collect();
    v.push(0);
    v
}

// ---------------------------------------------------------------------------
// Entropy shim
// ---------------------------------------------------------------------------

/// mingw-w64 satisfies std's RNG seeding by importing `ProcessPrng` from
/// `bcryptprimitives.dll`, which only ships with Windows 10+. Providing our
/// own definition keeps the launcher loadable on Windows 7/8 and Wine, which
/// lack that DLL.
#[no_mangle]
extern "system" fn ProcessPrng(pb_data: *mut u8, cb_data: usize) -> i32 {
    // RtlGenRandom (exported as SystemFunction036) has existed since Windows
    // XP and is what ProcessPrng itself wraps on legacy builds. Chunked
    // because its length parameter is 32-bit while `cb_data` is pointer-sized.
    #[link(name = "advapi32")]
    extern "system" {
        fn SystemFunction036(random_buffer: *mut u8, random_buffer_length: u32) -> i32;
    }
    const MAX_CHUNK: usize = u32::MAX as usize;
    let mut remaining = cb_data;
    let mut cursor = pb_data;
    while remaining > 0 {
        let chunk = remaining.min(MAX_CHUNK);
        // SAFETY: `[cursor, cursor+chunk)` lies within the caller-provided
        // buffer of `cb_data` bytes; SystemFunction036 only writes to it and
        // returns nonzero on success.
        let ok = unsafe { SystemFunction036(cursor, chunk as u32) };
        if ok == 0 {
            return 0;
        }
        // SAFETY: offset stays within the same allocation (chunk <= remaining).
        cursor = unsafe { cursor.add(chunk) };
        remaining -= chunk;
    }
    1
}

#[cfg(test)]
mod tests {
    use super::{spawn, CloseHandle, GetExitCodeProcess, STILL_ACTIVE};
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::path::Path;
    use std::time::Duration;

    #[test]
    fn sandbox_kills_child_and_blocks_outside_write() {
        let root = std::env::temp_dir().join(format!("erebus-sandbox-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let allowed = root.join("payload");
        let outside = root.join("outside");
        std::fs::create_dir_all(&allowed).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let script = allowed.join("run.cmd");
        std::fs::write(
            &script,
            "@echo off\r\necho in>\"%~dp0in.txt\"\r\necho out>\"%~dp0..\\outside\\out.txt\"\r\n:loop\r\ngoto loop\r\n",
        )
        .unwrap();
        let child = spawn(
            Path::new("cmd.exe"),
            &[
                OsString::from("cmd.exe"),
                OsString::from("/c"),
                script.as_os_str().to_os_string(),
            ],
            &BTreeMap::new(),
            Some(&allowed),
            false,
        )
        .expect("spawn confined child");
        let pid = child.pid;
        std::thread::sleep(Duration::from_secs(3));
        assert!(
            allowed.join("in.txt").is_file(),
            "write inside the payload directory"
        );
        assert!(
            !outside.join("out.txt").exists(),
            "write outside the payload directory"
        );
        assert!(process_alive(pid), "child still running before drop");
        drop(child);
        std::thread::sleep(Duration::from_millis(800));
        assert!(!process_alive(pid), "job kill-on-close reaped the child");
        let _ = std::fs::remove_dir_all(&root);
    }

    fn process_alive(pid: u32) -> bool {
        extern "system" {
            fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
        }
        // SAFETY: query-limited access. A null handle means the pid is gone.
        let handle = unsafe { OpenProcess(0x1000, 0, pid) };
        if handle.is_null() {
            return false;
        }
        let mut code = 0u32;
        // SAFETY: `handle` is a process we opened; GetExitCodeProcess writes `code`.
        let ok = unsafe { GetExitCodeProcess(handle, &mut code) };
        unsafe { CloseHandle(handle) };
        ok != 0 && code == STILL_ACTIVE
    }
}
