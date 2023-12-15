//go:build !unix

package tailfs

func useUserServers() bool {
	// On non-UNIX platforms, we use the GUI application (e.g. Windows taskbar
	// icon) to access the filesystem as whatever unprivileged user is running
	// the GUI app.
	return false
}
