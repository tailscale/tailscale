//go:build windows

package mdm

func NewWindowsMDMHandler(settings *MDMSettings) *MDMHandler {
	return &MDMHandler{Settings: settings}
}

// readRegistryBool reads a boolean value with the given key from the Windows registry.
func readRegistryBool(key string) (bool, error) {
	// TODO(angott): Windows support
	return false, nil
}

// readRegistryBool reads a string value with the given key from the Windows registry.
func readRegistryString(key string) (string, error) {
	// TODO(angott): Windows support
	return "", nil
}
