//go:build linux

package posture

import (
	"errors"
	"fmt"
	"strings"

	"github.com/digitalocean/go-smbios"
)

// GetByte retrieves a 8-bit unsigned integer at the given offset.
func GetByte(s *smbios.Structure, offset int) uint8 {
	// the `Formatted` byte slice is missing the first 4 bytes of the structure that are stripped out as header info.
	// so we need to subtract 4 from the offset mentioned in the SMBIOS documentation to get the right value.
	index := offset - 4
	if index >= len(s.Formatted) {
		return 0
	}

	return s.Formatted[index]
}

// GetStringOrEmpty retrieves a string at the given offset.
// Returns an empty string if no string was present.
func GetStringOrEmpty(s *smbios.Structure, offset int) (string, error) {
	index := GetByte(s, offset)

	if index == 0 || int(index) > len(s.Strings) {
		return errors.New("offset does not exist in smbios structure")
	}

	str := s.Strings[index-1]
	trimmed := strings.TrimSpace(str)

	// Convert to lowercase to address multiple formats:
	//   - "To Be Filled By O.E.M."
	//   - "To be filled by O.E.M."
	if strings.ToLower(trimmed) == "to be filled by o.e.m." {
		return errors.New("data is not provided by O.E.M.")
	}

	return trimmed
}

// System Information (Type 1) structure
// https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.1.1.pdf
// Page 34
const (
	sysInfoHeaderType  = 1
	serialNumberOffset = 0x07
)

func getSerialNumber() (string, error) {
	// Find SMBIOS data in operating system-specific location.
	rc, _, err := smbios.Stream()
	if err != nil {
		return "", fmt.Errorf("failed to open dmi/smbios stream: %w", err)
	}
	defer rc.Close()

	// Decode SMBIOS structures from the stream.
	d := smbios.NewDecoder(rc)
	ss, err := d.Decode()
	if err != nil {
		return "", fmt.Errorf("failed to decode dmi/smbios structures: %w", err)
	}

	for _, s := range ss {
		if s.Header.Type == sysInfoHeaderType {
			serial, err := GetStringFromSmbiosStructure(s, serialNumberOffset)
			if err != nil {
				return "", fmt.Errorf("could not read serial from dmi/smbios structure: %w", err)
			}

			return serial, nil
		}
	}

	return "", fmt.Errorf("could not read serial from dmi/smbios structure: no data found")
}
