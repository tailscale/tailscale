//go:build !windows

package systray

func IsWindowsDarkMode() bool {
	return false
}
