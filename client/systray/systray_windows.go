//go:build windows

package systray

import (
	"runtime"

	"golang.org/x/sys/windows/registry"
)

func IsWindowsDarkMode() bool {
	if runtime.GOOS != "windows" {
		return false
	}

	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Themes\Personalize`, registry.QUERY_VALUE)
	if err != nil {
		return false // fallback: assume light mode if error
	}

	v, _, err := k.GetIntegerValue("SystemUsesLightTheme")
	k.Close()
	if err != nil {
		return false
	}

	return v == 0 // 0 = dark mode, 1 = light mode
}
