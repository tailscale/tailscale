//go:build !linux

package dns

// GetGlobalDnsMode exists to make the build happy on non-linux platforms.
// The actual implementation is in manager_linux.go & in there it safely returns the current resolv.conf mode
func GetGlobalDnsMode() string {
	return ""
}
