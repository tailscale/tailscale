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

use core::ptr::{null, null_mut};
use windows_sys::w;
use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{CreateDirectoryW, CreateFileW, DeleteFileW, GetFileAttributesW, ReadFile, WriteFile, CREATE_ALWAYS, FILE_SHARE_READ, INVALID_FILE_ATTRIBUTES, OPEN_EXISTING};
use windows_sys::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE};
use windows_sys::Win32::System::Environment::{GetCommandLineW, GetEnvironmentVariableW, SetEnvironmentVariableW};
use windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW;
use windows_sys::Win32::System::SystemInformation::{GetNativeSystemInfo, PROCESSOR_ARCHITECTURE_AMD64, PROCESSOR_ARCHITECTURE_ARM64, PROCESSOR_ARCHITECTURE_INTEL};
use windows_sys::Win32::System::Threading::{ExitProcess, STARTF_USESTDHANDLES, CreateProcessW, STARTUPINFOW, PROCESS_INFORMATION, WaitForSingleObject, INFINITE, GetExitCodeProcess};

/// Exit code used when this wrapper panics, to distinguish from child
/// process failures.
#[cfg(not(test))]
const EXIT_CODE_PANIC: u32 = 0xFE;

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

/// C runtime entry point for MinGW/MSVC. Called before main() would be.
/// We use #[no_main] so we define this directly.
#[unsafe(no_mangle)]
pub extern "C" fn mainCRTStartup() -> ! {
    unsafe { main_impl() }
}

unsafe fn main_impl() -> ! {
    // Get our own exe path, e.g. "C:\Users\...\tailscale\tool\go.exe".
    let mut exe = WBuf::<4096>::new();
    exe.len = GetModuleFileNameW(null_mut(), exe.buf.as_mut_ptr(), exe.buf.len() as u32) as usize;
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
    SetEnvironmentVariableW(w!("GOROOT"), null());

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
    let code = run_and_wait(go_exe.as_ptr(), &mut cmd, null());
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
    CreateDirectoryW(dir.as_ptr(), null());
    dir.push_ascii(b"\\tsgo");
    CreateDirectoryW(dir.as_ptr(), null());

    // Create the toolchain directory itself.
    let mut tc_dir = WBuf::<4096>::new();
    tc_dir.push_wbuf(toolchain);
    CreateDirectoryW(tc_dir.as_ptr(), null());

    // Detect host architecture via GetNativeSystemInfo (gives real arch
    // even from a WoW64 32-bit process).
    let mut si = core::mem::zeroed();
    GetNativeSystemInfo(&mut si);
    
    let arch: &[u8] = match si.Anonymous.Anonymous.wProcessorArchitecture as u16 {
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

    let code = run_and_wait(null(), &mut cmd, null());
    if code != 0 {
        die(b"curl failed to download Go toolchain\n");
    }

    // Run: tar.exe --strip-components=1 -xf <tgz>
    // with working directory set to the toolchain dir.
    let mut cmd = WBuf::<32768>::new();
    cmd.push_ascii(b"tar.exe --strip-components=1 -xf \"");
    cmd.push_wbuf(&tgz);
    cmd.push_ascii(b"\"");

    let code = run_and_wait(null(), &mut cmd, tc_dir.as_ptr());
    if code != 0 {
        die(b"tar failed to extract Go toolchain\n");
    }

    // Write the .extracted marker file.
    let mut marker = WBuf::<4096>::new();
    marker.push_wbuf(toolchain).push_ascii(b".extracted");
    let fh = CreateFileW(marker.as_ptr(), GENERIC_WRITE, 0, null(), CREATE_ALWAYS, 0, null_mut());
    if fh != INVALID_HANDLE_VALUE {
        let mut written: u32 = 0;
        WriteFile(fh, rev.as_ptr(), rev.len() as u32, &mut written, null_mut());
        CloseHandle(fh);
    }

    // Clean up the tarball.
    DeleteFileW(tgz.as_ptr());
}

/// Spawn a child process, wait for it, and return its exit code.
/// If app is null, CreateProcessW searches PATH using the command line.
/// If dir is null, the child inherits the current directory.
unsafe fn run_and_wait(app: *const u16, cmd: &mut WBuf<32768>, dir: *const u16) -> u32 {
    let si = STARTUPINFOW {
        cb: size_of::<STARTUPINFOW>() as u32,
        dwFlags: STARTF_USESTDHANDLES,
        hStdInput: GetStdHandle(STD_INPUT_HANDLE),
        hStdOutput: GetStdHandle(STD_OUTPUT_HANDLE), 
        hStdError: GetStdHandle(STD_ERROR_HANDLE),
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();

    if CreateProcessW(
        app,
        cmd.as_mut_ptr(),
        null(),
        null(),
        1, // bInheritHandles = TRUE
        0,
        null(),
        dir,
        &si,
        &mut pi,
    ) == 0
    {
        die(b"CreateProcess failed\n");
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    let mut code: u32 = 1;
    GetExitCodeProcess(pi.hProcess, &mut code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
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
    let code = run_and_wait(null(), &mut cmd, null());
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
        null(),
        OPEN_EXISTING,
        0,
        null_mut(),
    );
    if h == INVALID_HANDLE_VALUE {
        die(b"cannot open go.toolchain.rev\n");
    }
    let mut n: u32 = 0;
    ReadFile(h, buf.as_mut_ptr(), buf.len() as u32, &mut n, null_mut());
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
    WriteFile(h, msg.as_ptr(), msg.len() as u32, &mut n, null_mut());
}

/// Write an error message to stderr and terminate with exit code 1.
unsafe fn die(msg: &[u8]) -> ! {
    stderr(b"tool/go: ");
    stderr(msg);
    ExitProcess(1);
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { ExitProcess(EXIT_CODE_PANIC) }
}
