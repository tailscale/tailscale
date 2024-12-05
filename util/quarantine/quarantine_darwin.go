// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package quarantine

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

func setQuarantineAttr(f *os.File) error {
	sc, err := f.SyscallConn()
	if err != nil {
		return err
	}

	now := time.Now()

	// We uppercase the UUID to match what other applications on macOS do
	id := strings.ToUpper(uuid.New().String())

	// kLSQuarantineTypeOtherDownload; this matches what AirDrop sets when
	// receiving a file.
	quarantineType := "0001"

	// This format is under-documented, but the following links contain a
	// reasonably comprehensive overview:
	//    https://eclecticlight.co/2020/10/29/quarantine-and-the-quarantine-flag/
	//    https://nixhacker.com/security-protection-in-macos-1/
	//    https://ilostmynotes.blogspot.com/2012/06/gatekeeper-xprotect-and-quarantine.html
	attrData := fmt.Sprintf("%s;%x;%s;%s",
		quarantineType, // quarantine value
		now.Unix(),     // time in hex
		"Tailscale",    // application
		id,             // UUID
	)

	var innerErr error
	err = sc.Control(func(fd uintptr) {
		innerErr = unix.Fsetxattr(
			int(fd),
			"com.apple.quarantine", // attr
			[]byte(attrData),
			0,
		)
	})
	if err != nil {
		return err
	}
	return innerErr
}
