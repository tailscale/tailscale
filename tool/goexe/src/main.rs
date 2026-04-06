// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//! A thin wrapper that finds and execs the Tailscale Go toolchain without
//! going through cmd.exe, avoiding its argument mangling (cmd.exe treats ^
//! as an escape character, breaking -run "^$" and similar, and = signs
//! also cause issues in PowerShell→cmd.exe argument passing).
//! See https://github.com/tailscale/tailscale/issues/19255.
//!
//! This replaces tool/go.cmd. When PowerShell resolves `./tool/go`, it
//! prefers go.exe over go.cmd, so this binary is used automatically.
//!
//! Built as no_std with raw Win32 API calls for minimal binary size (~17KB).
//! Built as 32-bit x86 so one binary runs on x86, x64 (via WoW64), and
//! ARM64 (via Windows x86 emulation).
//!
//! The raw command line from GetCommandLineW is passed through directly to
//! CreateProcessW (after swapping out argv[0]), so arguments are never
//! parsed or re-escaped, preserving them exactly as the caller specified.

#![no_std]
#![no_main]
#![windows_subsystem = "console"]
// Every function in this program calls raw Win32 FFI; requiring unsafe
// blocks inside each unsafe fn would be pure noise.
#![allow(unsafe_op_in_unsafe_fn)]

use core::ptr;

// Win32 constants.

/// https://learn.microsoft.com/en-us/windows/win32/secauthz/generic-access-rights
const GENERIC_READ: u32 = 0x80000000;
const GENERIC_WRITE: u32 = 0x40000000;
/// https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew (dwCreationDisposition)
const OPEN_EXISTING: u32 = 3;
const CREATE_ALWAYS: u32 = 2;
/// https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew (dwShareMode)
const FILE_SHARE_READ: u32 = 1;
/// Returned by CreateFileW on failure.
const INVALID_HANDLE_VALUE: isize = -1;
/// Returned by GetFileAttributesW when the file does not exist.
/// https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileattributesw
const INVALID_FILE_ATTRIBUTES: u32 = 0xFFFFFFFF;
/// https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject
const INFINITE: u32 = 0xFFFFFFFF;

/// https://learn.microsoft.com/en-us/windows/console/getstdhandle
const STD_INPUT_HANDLE: u32 = (-10i32) as u32;
const STD_OUTPUT_HANDLE: u32 = (-11i32) as u32;
const STD_ERROR_HANDLE: u32 = (-12i32) as u32;

/// Indicates that the hStdInput/hStdOutput/hStdError fields in STARTUPINFOW
/// contain valid handles.
/// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfow
const STARTF_USESTDHANDLES: u32 = 0x00000100;

/// https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/ns-sysinfoapi-system_info
const PROCESSOR_ARCHITECTURE_INTEL: u16 = 0;
const PROCESSOR_ARCHITECTURE_AMD64: u16 = 9;
const PROCESSOR_ARCHITECTURE_ARM64: u16 = 12;

/// Exit code used when this wrapper panics, to distinguish from child
/// process failures.
const EXIT_CODE_PANIC: u32 = 0xFE;

// Win32 struct definitions.

/// STARTUPINFOW — passed to CreateProcessW to configure the child process.
/// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfow
#[repr(C)]
struct StartupInfoW {
    cb: u32,            // Size of this struct in bytes.
    reserved: usize,    // lpReserved (must be NULL).
    desktop: usize,     // lpDesktop
    title: usize,       // lpTitle
    x: u32,             // dwX
    y: u32,             // dwY
    x_size: u32,        // dwXSize
    y_size: u32,        // dwYSize
    x_count_chars: u32, // dwXCountChars
    y_count_chars: u32, // dwYCountChars
    fill_attribute: u32,// dwFillAttribute
    flags: u32,         // dwFlags (e.g. STARTF_USESTDHANDLES)
    show_window: u16,   // wShowWindow
    cb_reserved2: u16,  // cbReserved2
    reserved2: usize,   // lpReserved2
    std_input: isize,   // hStdInput (HANDLE)
    std_output: isize,  // hStdOutput (HANDLE)
    std_error: isize,   // hStdError (HANDLE)
}

/// PROCESS_INFORMATION — filled by CreateProcessW with handles to the new process/thread.
/// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information
#[repr(C)]
struct ProcessInformation {
    process: isize,    // hProcess (HANDLE)
    thread: isize,     // hThread (HANDLE)
    process_id: u32,   // dwProcessId
    thread_id: u32,    // dwThreadId
}

/// SYSTEM_INFO — returned by GetNativeSystemInfo.
/// https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/ns-sysinfoapi-system_info
#[repr(C)]
struct SystemInfo {
    processor_architecture: u16, // wProcessorArchitecture
    _reserved: u16,
    _page_size: u32,
    _min_app_addr: usize,
    _max_app_addr: usize,
    _active_processor_mask: usize,
    _number_of_processors: u32,
    _processor_type: u32,
    _allocation_granularity: u32,
    _processor_level: u16,
    _processor_revision: u16,
}

// Win32 API declarations (all from kernel32.dll unless noted).

unsafe extern "system" {
    /// Returns the fully qualified path of the running executable.
    /// https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulefilenamew
    fn GetModuleFileNameW(module: isize, filename: *mut u16, size: u32) -> u32;

    /// Opens or creates a file, returning a HANDLE.
    /// https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
    fn CreateFileW(
        name: *const u16,
        access: u32,
        share: u32,
        security: usize,
        disposition: u32,
        flags: u32,
        template: usize,
    ) -> isize;

    /// Reads bytes from a file handle.
    /// https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile
    fn ReadFile(
        file: isize,
        buffer: *mut u8,
        to_read: u32,
        read: *mut u32,
        overlapped: usize,
    ) -> i32;

    /// Closes a kernel object handle.
    /// https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
    fn CloseHandle(handle: isize) -> i32;

    /// Returns file attributes, or INVALID_FILE_ATTRIBUTES if not found.
    /// Used here as a lightweight file-existence check.
    /// https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileattributesw
    fn GetFileAttributesW(name: *const u16) -> u32;

    /// Retrieves the value of an environment variable.
    /// https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-getenvironmentvariablew
    fn GetEnvironmentVariableW(name: *const u16, buffer: *mut u16, size: u32) -> u32;

    /// Sets or deletes an environment variable (pass null value to delete).
    /// https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-setenvironmentvariablew
    fn SetEnvironmentVariableW(name: *const u16, value: *const u16) -> i32;

    /// Creates a new process and its primary thread.
    /// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw
    fn CreateProcessW(
        app: *const u16,
        cmd: *mut u16,
        proc_attr: usize,
        thread_attr: usize,
        inherit: i32,
        flags: u32,
        env: usize,
        dir: usize,
        startup: *const StartupInfoW,
        info: *mut ProcessInformation,
    ) -> i32;

    /// Waits until a handle is signaled (process exits) or timeout elapses.
    /// https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject
    fn WaitForSingleObject(handle: isize, ms: u32) -> u32;

    /// Retrieves the exit code of a process.
    /// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getexitcodeprocess
    fn GetExitCodeProcess(process: isize, code: *mut u32) -> i32;

    /// Terminates the calling process with the given exit code.
    /// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-exitprocess
    fn ExitProcess(code: u32) -> !;

    /// Returns a handle to stdin, stdout, or stderr.
    /// https://learn.microsoft.com/en-us/windows/console/getstdhandle
    fn GetStdHandle(id: u32) -> isize;

    /// Returns a pointer to the command-line string for the current process.
    /// https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-getcommandlinew
    fn GetCommandLineW() -> *const u16;

    /// Writes bytes to a file handle (used here for stderr output).
    /// https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile
    fn WriteFile(
        file: isize,
        buffer: *const u8,
        to_write: u32,
        written: *mut u32,
        overlapped: usize,
    ) -> i32;

    /// Creates a directory.
    /// https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createdirectoryw
    fn CreateDirectoryW(path: *const u16, security: usize) -> i32;

    /// Deletes a file.
    /// https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-deletefilew
    fn DeleteFileW(path: *const u16) -> i32;

    /// Returns system info including processor architecture, using the
    /// native architecture even when called from a WoW64 process.
    /// https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getnativesysteminfo
    fn GetNativeSystemInfo(info: *mut SystemInfo);
}

// A fixed-capacity UTF-16 buffer for building null-terminated wide strings
// to pass to Win32 APIs. All Win32-facing methods automatically null-terminate.
//
// Callers push ASCII (&[u8]) or wide (&WBuf) content; the buffer handles
// the ASCII-to-UTF-16 widening internally, keeping encoding concerns in
// one place.

struct WBuf<const N: usize> {
    buf: [u16; N],
    len: usize,
}

impl<const N: usize> WBuf<N> {
    fn new() -> Self {
        Self {
            buf: [0; N],
            len: 0,
        }
    }

    /// Null-terminated pointer for Win32 APIs.
    fn as_ptr(&mut self) -> *const u16 {
        self.buf[self.len] = 0;
        self.buf.as_ptr()
    }

    /// Mutable null-terminated pointer (for CreateProcessW's lpCommandLine).
    fn as_mut_ptr(&mut self) -> *mut u16 {
        self.buf[self.len] = 0;
        self.buf.as_mut_ptr()
    }

    /// Append ASCII bytes, widening each byte to UTF-16.
    fn push_ascii(&mut self, s: &[u8]) -> &mut Self {
        for &b in s {
            self.buf[self.len] = b as u16;
            self.len += 1;
        }
        self
    }

    /// Append the contents of another WBuf.
    fn push_wbuf<const M: usize>(&mut self, other: &WBuf<M>) -> &mut Self {
        self.buf[self.len..self.len + other.len].copy_from_slice(&other.buf[..other.len]);
        self.len += other.len;
        self
    }

    /// Append raw UTF-16 content from a pointer until null terminator.
    /// Used for appending the tail of GetCommandLineW.
    unsafe fn push_ptr(&mut self, mut p: *const u16) -> &mut Self {
        loop {
            let c = *p;
            if c == 0 {
                break;
            }
            self.buf[self.len] = c;
            self.len += 1;
            p = p.add(1);
        }
        self
    }

    /// Find the last path separator (\ or /) and truncate to it,
    /// effectively navigating to the parent directory.
    fn pop_path_component(&mut self) -> bool {
        let mut i = self.len;
        while i > 0 {
            i -= 1;
            if self.buf[i] == b'\\' as u16 || self.buf[i] == b'/' as u16 {
                self.len = i;
                return true;
            }
        }
        false
    }

    /// Check whether a file exists at "<self>\<suffix>".
    unsafe fn file_exists_with(&mut self, suffix: &[u8]) -> bool {
        let saved = self.len;
        self.push_ascii(suffix);
        let result = GetFileAttributesW(self.as_ptr()) != INVALID_FILE_ATTRIBUTES;
        self.len = saved;
        result
    }
}

/// Check if an environment variable equals an expected ASCII value.
/// Neither name nor val should include a null terminator.
unsafe fn env_eq(name: &[u8], val: &[u8]) -> bool {
    let mut name_w = WBuf::<64>::new();
    name_w.push_ascii(name);
    let mut buf = [0u16; 64];
    let n = GetEnvironmentVariableW(name_w.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) as usize;
    if n != val.len() {
        return false;
    }
    for (i, &b) in val.iter().enumerate() {
        if buf[i] != b as u16 {
            return false;
        }
    }
    true
}

/// Get an environment variable's value into a WBuf.
/// Returns the number of characters written (0 if not set).
unsafe fn get_env<const N: usize>(name: &[u8], dst: &mut WBuf<N>) -> usize {
    let mut name_w = WBuf::<64>::new();
    name_w.push_ascii(name);
    let n = GetEnvironmentVariableW(
        name_w.as_ptr(),
        dst.buf.as_mut_ptr(),
        dst.buf.len() as u32,
    ) as usize;
    dst.len = n;
    n
}

/// Unset an environment variable.
unsafe fn unset_env(name: &[u8]) {
    let mut name_w = WBuf::<64>::new();
    name_w.push_ascii(name);
    SetEnvironmentVariableW(name_w.as_ptr(), ptr::null());
}

/// C runtime entry point for MinGW/MSVC. Called before main() would be.
/// We use #[no_main] so we define this directly.
#[unsafe(no_mangle)]
pub extern "C" fn mainCRTStartup() -> ! {
    unsafe { main_impl() }
}

unsafe fn main_impl() -> ! {
    // Get our own exe path, e.g. "C:\Users\...\tailscale\tool\go.exe".
    let mut exe = WBuf::<4096>::new();
    exe.len = GetModuleFileNameW(0, exe.buf.as_mut_ptr(), exe.buf.len() as u32) as usize;
    if exe.len == 0 {
        die(b"GetModuleFileNameW failed\n");
    }

    // Walk up directories from our exe location to find the repo root,
    // identified by the presence of "go.toolchain.rev".
    exe.pop_path_component(); // strip filename, e.g. "...\tool"
    let repo_root = loop {
        if !exe.file_exists_with(b"\\go.toolchain.rev") {
            if !exe.pop_path_component() {
                die(b"could not find go.toolchain.rev\n");
            }
            continue;
        }
        break WBuf::<4096> {
            buf: exe.buf,
            len: exe.len,
        };
    };

    // Read the toolchain revision hash from go.toolchain.rev (or
    // go.toolchain.next.rev if TS_GO_NEXT=1).
    let mut rev_path = WBuf::<4096>::new();
    rev_path.push_wbuf(&repo_root);
    if env_eq(b"TS_GO_NEXT", b"1") {
        rev_path.push_ascii(b"\\go.toolchain.next.rev");
    } else {
        rev_path.push_ascii(b"\\go.toolchain.rev");
    }

    let mut rev_buf = [0u8; 256];
    let rev = read_file_trimmed(&mut rev_path, &mut rev_buf);

    // Build the toolchain path. The rev is normally a git hash, and
    // the toolchain lives at %USERPROFILE%\.cache\tsgo\<hash>.
    // If the rev starts with "/" or "\" it's an absolute path to a
    // local toolchain (used for testing).
    let mut toolchain = WBuf::<4096>::new();
    if rev.first() == Some(&b'/') || rev.first() == Some(&b'\\') {
        toolchain.push_ascii(rev);
    } else {
        if get_env(b"USERPROFILE", &mut toolchain) == 0 {
            die(b"USERPROFILE not set\n");
        }
        toolchain.push_ascii(b"\\.cache\\tsgo\\");
        toolchain.push_ascii(rev);
    }

    // If the toolchain hasn't been downloaded yet (no ".extracted" marker),
    // download it. For TS_USE_GOCROSS=1, fall back to PowerShell since
    // that path also needs to build gocross.
    if !toolchain.file_exists_with(b".extracted") {
        if env_eq(b"TS_USE_GOCROSS", b"1") {
            fallback_pwsh(&repo_root);
        }
        download_toolchain(&toolchain, rev);
    }

    // Build the path to the real go.exe binary inside the toolchain,
    // or to gocross.exe if TS_USE_GOCROSS=1.
    let mut go_exe = WBuf::<4096>::new();
    if env_eq(b"TS_USE_GOCROSS", b"1") {
        go_exe.push_wbuf(&repo_root).push_ascii(b"\\gocross.exe");
    } else {
        go_exe.push_wbuf(&toolchain).push_ascii(b"\\bin\\go.exe");
    }

    // Unset GOROOT to avoid breaking builds that depend on our Go
    // fork's patches (e.g. net/). The Go toolchain sets GOROOT
    // internally from its own location.
    unset_env(b"GOROOT");

    // Build the new command line by replacing argv[0] with the real
    // go.exe path. We take the raw command line from GetCommandLineW
    // and pass the args portion through untouched — no parsing or
    // re-escaping — so special characters like ^ and = survive intact.
    let raw_cmd = GetCommandLineW();
    let args_tail = skip_argv0(raw_cmd);

    let mut cmd = WBuf::<32768>::new();
    cmd.push_ascii(b"\"");
    cmd.push_wbuf(&go_exe);
    cmd.push_ascii(b"\"");
    cmd.push_ptr(args_tail);

    // Exec: create the child process, wait for it, and exit with its code.
    let code = run_and_wait(go_exe.as_ptr(), &mut cmd, ptr::null());
    ExitProcess(code);
}

/// Download the Go toolchain tarball from GitHub and extract it.
/// Uses curl.exe and tar.exe which ship with Windows 10+.
unsafe fn download_toolchain(toolchain: &WBuf<4096>, rev: &[u8]) {
    stderr(b"# Downloading Go toolchain ");
    stderr(rev);
    stderr(b"\n");

    // Create parent directories (%USERPROFILE%\.cache\tsgo).
    // CreateDirectoryW is fine if the dir already exists.
    let mut dir = WBuf::<4096>::new();
    get_env(b"USERPROFILE", &mut dir);
    dir.push_ascii(b"\\.cache");
    CreateDirectoryW(dir.as_ptr(), 0);
    dir.push_ascii(b"\\tsgo");
    CreateDirectoryW(dir.as_ptr(), 0);

    // Create the toolchain directory itself.
    let mut tc_dir = WBuf::<4096>::new();
    tc_dir.push_wbuf(toolchain);
    CreateDirectoryW(tc_dir.as_ptr(), 0);

    // Detect host architecture via GetNativeSystemInfo (gives real arch
    // even from a WoW64 32-bit process).
    let mut si: SystemInfo = core::mem::zeroed();
    GetNativeSystemInfo(&mut si);
    let arch: &[u8] = match si.processor_architecture {
        PROCESSOR_ARCHITECTURE_AMD64 => b"amd64",
        PROCESSOR_ARCHITECTURE_ARM64 => b"arm64",
        PROCESSOR_ARCHITECTURE_INTEL => b"386",
        _ => die(b"unsupported architecture\n"),
    };

    // Build tarball path: <toolchain>.tar.gz
    let mut tgz = WBuf::<4096>::new();
    tgz.push_wbuf(toolchain).push_ascii(b".tar.gz");

    // Build URL:
    //   https://github.com/tailscale/go/releases/download/build-<rev>/windows-<arch>.tar.gz
    let mut url = [0u8; 512];
    let mut u = 0;
    for part in [
        b"https://github.com/tailscale/go/releases/download/build-" as &[u8],
        rev,
        b"/windows-",
        arch,
        b".tar.gz",
    ] {
        url[u..u + part.len()].copy_from_slice(part);
        u += part.len();
    }

    // Run: curl.exe -fsSL -o <tgz> <url>
    let mut cmd = WBuf::<32768>::new();
    cmd.push_ascii(b"curl.exe -fsSL -o \"");
    cmd.push_wbuf(&tgz);
    cmd.push_ascii(b"\" ");
    cmd.push_ascii(&url[..u]);

    let code = run_and_wait(ptr::null(), &mut cmd, ptr::null());
    if code != 0 {
        die(b"curl failed to download Go toolchain\n");
    }

    // Run: tar.exe --strip-components=1 -xf <tgz>
    // with working directory set to the toolchain dir.
    let mut cmd = WBuf::<32768>::new();
    cmd.push_ascii(b"tar.exe --strip-components=1 -xf \"");
    cmd.push_wbuf(&tgz);
    cmd.push_ascii(b"\"");

    let code = run_and_wait(ptr::null(), &mut cmd, tc_dir.as_ptr());
    if code != 0 {
        die(b"tar failed to extract Go toolchain\n");
    }

    // Write the .extracted marker file.
    let mut marker = WBuf::<4096>::new();
    marker.push_wbuf(toolchain).push_ascii(b".extracted");
    let fh = CreateFileW(marker.as_ptr(), GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
    if fh != INVALID_HANDLE_VALUE {
        let mut written: u32 = 0;
        WriteFile(fh, rev.as_ptr(), rev.len() as u32, &mut written, 0);
        CloseHandle(fh);
    }

    // Clean up the tarball.
    DeleteFileW(tgz.as_ptr());
}

/// Spawn a child process, wait for it, and return its exit code.
/// If app is null, CreateProcessW searches PATH using the command line.
/// If dir is null, the child inherits the current directory.
unsafe fn run_and_wait(app: *const u16, cmd: &mut WBuf<32768>, dir: *const u16) -> u32 {
    let si = StartupInfoW {
        cb: core::mem::size_of::<StartupInfoW>() as u32,
        reserved: 0,
        desktop: 0,
        title: 0,
        x: 0,
        y: 0,
        x_size: 0,
        y_size: 0,
        x_count_chars: 0,
        y_count_chars: 0,
        fill_attribute: 0,
        flags: STARTF_USESTDHANDLES,
        show_window: 0,
        cb_reserved2: 0,
        reserved2: 0,
        std_input: GetStdHandle(STD_INPUT_HANDLE),
        std_output: GetStdHandle(STD_OUTPUT_HANDLE),
        std_error: GetStdHandle(STD_ERROR_HANDLE),
    };
    let mut pi = ProcessInformation {
        process: 0,
        thread: 0,
        process_id: 0,
        thread_id: 0,
    };

    if CreateProcessW(
        app,
        cmd.as_mut_ptr(),
        0,
        0,
        1, // bInheritHandles = TRUE
        0,
        0,
        dir as usize,
        &si,
        &mut pi,
    ) == 0
    {
        die(b"CreateProcess failed\n");
    }

    WaitForSingleObject(pi.process, INFINITE);
    let mut code: u32 = 1;
    GetExitCodeProcess(pi.process, &mut code);
    CloseHandle(pi.process);
    CloseHandle(pi.thread);
    code
}

/// Fall back to PowerShell for the full bootstrap flow (downloading the
/// toolchain, optionally building gocross, and then running go):
///   pwsh -NoProfile -ExecutionPolicy Bypass "<repo>\tool\gocross\gocross-wrapper.ps1" <args...>
unsafe fn fallback_pwsh(repo_root: &WBuf<4096>) -> ! {
    let raw_cmd = GetCommandLineW();
    let args_tail = skip_argv0(raw_cmd);

    let mut cmd = WBuf::<32768>::new();
    cmd.push_ascii(b"pwsh -NoProfile -ExecutionPolicy Bypass \"");
    cmd.push_wbuf(repo_root);
    cmd.push_ascii(b"\\tool\\gocross\\gocross-wrapper.ps1\"");
    cmd.push_ptr(args_tail);

    // Pass null for lpApplicationName so CreateProcessW searches PATH for "pwsh".
    let code = run_and_wait(ptr::null(), &mut cmd, ptr::null());
    ExitProcess(code);
}

/// Read an entire file (expected to be small ASCII, e.g. a git hash) into buf,
/// and return the trimmed content as a byte slice.
unsafe fn read_file_trimmed<'a, const N: usize>(
    path: &mut WBuf<N>,
    buf: &'a mut [u8],
) -> &'a [u8] {
    let h = CreateFileW(
        path.as_ptr(),
        GENERIC_READ,
        FILE_SHARE_READ,
        0,
        OPEN_EXISTING,
        0,
        0,
    );
    if h == INVALID_HANDLE_VALUE {
        die(b"cannot open go.toolchain.rev\n");
    }
    let mut n: u32 = 0;
    ReadFile(h, buf.as_mut_ptr(), buf.len() as u32, &mut n, 0);
    CloseHandle(h);

    let s = &buf[..n as usize];
    let start = s.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(s.len());
    let end = s.iter().rposition(|b| !b.is_ascii_whitespace()).map_or(start, |i| i + 1);
    &s[start..end]
}

/// Advance past argv[0] in a raw Windows command line string.
///
/// Windows command lines are a single string; argv[0] may be quoted
/// (if the path contains spaces) or unquoted.
/// See https://learn.microsoft.com/en-us/cpp/c-language/parsing-c-command-line-arguments
unsafe fn skip_argv0(cmd: *const u16) -> *const u16 {
    let mut p = cmd;
    if *p == b'"' as u16 {
        // Quoted argv[0]: advance past closing quote.
        p = p.add(1);
        while *p != 0 && *p != b'"' as u16 {
            p = p.add(1);
        }
        if *p == b'"' as u16 {
            p = p.add(1);
        }
    } else {
        // Unquoted argv[0]: advance to first whitespace.
        while *p != 0 && *p != b' ' as u16 && *p != b'\t' as u16 {
            p = p.add(1);
        }
    }
    // Return pointer to the rest (typically starts with a space before
    // the first real argument, or is empty if there are no arguments).
    p
}

/// Write bytes to stderr.
unsafe fn stderr(msg: &[u8]) {
    let h = GetStdHandle(STD_ERROR_HANDLE);
    let mut n: u32 = 0;
    WriteFile(h, msg.as_ptr(), msg.len() as u32, &mut n, 0);
}

/// Write an error message to stderr and terminate with exit code 1.
unsafe fn die(msg: &[u8]) -> ! {
    stderr(b"tool/go: ");
    stderr(msg);
    ExitProcess(1);
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { ExitProcess(EXIT_CODE_PANIC) }
}
