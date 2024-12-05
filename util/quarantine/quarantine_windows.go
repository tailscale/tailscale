// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package quarantine

import (
	"os"
	"strings"
)

func setQuarantineAttr(f *os.File) error {
	// Documentation on this can be found here:
	//    https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8
	//
	// Additional information can be found at:
	//    https://www.digital-detective.net/forensic-analysis-of-zone-identifier-stream/
	//    https://bugzilla.mozilla.org/show_bug.cgi?id=1433179
	content := strings.Join([]string{
		"[ZoneTransfer]",

		// "URLZONE_INTERNET"
		// https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms537175(v=vs.85)
		"ZoneId=3",

		// TODO(andrew): should/could we add ReferrerUrl or HostUrl?
	}, "\r\n")

	return os.WriteFile(f.Name()+":Zone.Identifier", []byte(content), 0)
}
