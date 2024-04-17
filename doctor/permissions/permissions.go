// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package permissions provides a doctor.Check that prints the process
// permissions for the running process.
package permissions

import (
	"context"
	"fmt"
	"os/user"
	"strings"

	"golang.org/x/exp/constraints"
	"tailscale.com/types/logger"
)

// Check implements the doctor.Check interface.
type Check struct{}

func (Check) Name() string {
	return "permissions"
}

func (Check) Run(_ context.Context, logf logger.Logf) error {
	return permissionsImpl(logf)
}

//lint:ignore U1000 used in non-windows implementations.
func formatUserID[T constraints.Integer](id T) string {
	idStr := fmt.Sprint(id)
	if uu, err := user.LookupId(idStr); err != nil {
		return idStr + "(<unknown>)"
	} else {
		return fmt.Sprintf("%s(%q)", idStr, uu.Username)
	}
}

//lint:ignore U1000 used in non-windows implementations.
func formatGroupID[T constraints.Integer](id T) string {
	idStr := fmt.Sprint(id)
	if g, err := user.LookupGroupId(idStr); err != nil {
		return idStr + "(<unknown>)"
	} else {
		return fmt.Sprintf("%s(%q)", idStr, g.Name)
	}
}

//lint:ignore U1000 used in non-windows implementations.
func formatGroups[T constraints.Integer](groups []T) string {
	var buf strings.Builder
	for i, group := range groups {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteString(formatGroupID(group))
	}
	return buf.String()
}
