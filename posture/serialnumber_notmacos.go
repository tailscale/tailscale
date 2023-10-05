// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Build on Windows, Linux and *BSD

//go:build windows || (linux && !android) || freebsd || openbsd || dragonfly || netbsd

package posture

import (
	"errors"
	"fmt"
	"strings"

	"github.com/digitalocean/go-smbios/smbios"
	"tailscale.com/types/logger"
	"tailscale.com/util/multierr"
)

// getByteFromSmbiosStructure retrieves a 8-bit unsigned integer at the given specOffset.
func getByteFromSmbiosStructure(s *smbios.Structure, specOffset int) uint8 {
	// the `Formatted` byte slice is missing the first 4 bytes of the structure that are stripped out as header info.
	// so we need to subtract 4 from the offset mentioned in the SMBIOS documentation to get the right value.
	index := specOffset - 4
	if index >= len(s.Formatted) || index < 0 {
		return 0
	}

	return s.Formatted[index]
}

// getStringFromSmbiosStructure retrieves a string at the given specOffset.
// Returns an empty string if no string was present.
func getStringFromSmbiosStructure(s *smbios.Structure, specOffset int) (string, error) {
	index := getByteFromSmbiosStructure(s, specOffset)

	if index == 0 || int(index) > len(s.Strings) {
		return "", errors.New("specified offset does not exist in smbios structure")
	}

	str := s.Strings[index-1]
	trimmed := strings.TrimSpace(str)

	return trimmed, nil
}

// Product Table (Type 1) structure
// https://web.archive.org/web/20220126173219/https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.1.1.pdf
// Page 34 and onwards.
const (
	// Serial is present at the same offset in all IDs
	serialNumberOffset = 0x07

	productID   = 1
	baseboardID = 2
	chassisID   = 3
)

var (
	idToTableName = map[int]string{
		1: "product",
		2: "baseboard",
		3: "chassis",
	}
	validTables []string
	numOfTables int
)

func init() {
	for _, table := range idToTableName {
		validTables = append(validTables, table)
	}
	numOfTables = len(validTables)

}

// serialFromSmbiosStructure extracts a serial number from a product,
// baseboard or chassis SMBIOS table.
func serialFromSmbiosStructure(s *smbios.Structure) (string, error) {
	id := s.Header.Type
	if (id != productID) && (id != baseboardID) && (id != chassisID) {
		return "", fmt.Errorf(
			"cannot get serial table type %d, supported tables are %v",
			id,
			validTables,
		)
	}

	serial, err := getStringFromSmbiosStructure(s, serialNumberOffset)
	if err != nil {
		return "", fmt.Errorf(
			"failed to get serial from %s table: %w",
			idToTableName[int(s.Header.Type)],
			err,
		)
	}

	return serial, nil
}

func GetSerialNumbers(logf logger.Logf) ([]string, error) {
	// Find SMBIOS data in operating system-specific location.
	rc, _, err := smbios.Stream()
	if err != nil {
		return nil, fmt.Errorf("failed to open dmi/smbios stream: %w", err)
	}
	defer rc.Close()

	// Decode SMBIOS structures from the stream.
	d := smbios.NewDecoder(rc)
	ss, err := d.Decode()
	if err != nil {
		return nil, fmt.Errorf("failed to decode dmi/smbios structures: %w", err)
	}

	serials := make([]string, 0, numOfTables)
	errs := make([]error, 0, numOfTables)

	for _, s := range ss {
		switch s.Header.Type {
		case productID, baseboardID, chassisID:
			serial, err := serialFromSmbiosStructure(s)
			if err != nil {
				errs = append(errs, err)
				continue
			}

			serials = append(serials, serial)
		}
	}

	err = multierr.New(errs...)

	// if there were no serial numbers, check if any errors were
	// returned and combine them.
	if len(serials) == 0 && err != nil {
		return nil, err
	}

	logf("got serial numbers %v (errors: %s)", serials, err)

	return serials, nil
}
