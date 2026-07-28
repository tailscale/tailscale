# Builds tool/go.exe, a thin wrapper that execs the Tailscale Go
# toolchain without going through cmd.exe (which mangles ^ and other
# special characters in arguments).
# See https://github.com/tailscale/tailscale/issues/19255
#
# Built as no_std Rust with raw Win32 API calls for minimal size (~17KB).
# The resulting go.exe is checked into the repo at tool/go.exe.
#
# Built as 32-bit x86 so one binary runs on x86, x64 (via WoW64),
# and ARM64 (via Windows x86 emulation).
#
# Requirements:
#   rustup target add i686-pc-windows-gnu
#   apt install gcc-mingw-w64-i686  (or equivalent)

RUST_TARGET = i686-pc-windows-gnu

.PHONY: all clean

all: go.exe

go.exe: src/main.rs Cargo.toml
	cargo build --release --target $(RUST_TARGET)
	cp target/$(RUST_TARGET)/release/go.exe $@

clean:
	rm -f go.exe
	rm -rf target
