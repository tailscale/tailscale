/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package cli

import (
	"tailscale.com/util/winutil/authenticode"
)

func init() {
	verifyAuthenticode = verifyTailscale
}

const certSubjectTailscale = "Tailscale Inc."

func verifyTailscale(path string) error {
	return authenticode.Verify(path, certSubjectTailscale)
}
