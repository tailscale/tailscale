# systray

The systray command is a minimal Tailscale systray application for Linux.
It is designed to provide quick access to common operations like profile switching
and exit node selection.

## Supported platforms

The `fyne.io/systray` package we use supports Windows, macOS, Linux, and many BSDs,
so the systray application will likely work for the most part on those platforms.
Notifications currently only work on Linux, as that is the main target.
