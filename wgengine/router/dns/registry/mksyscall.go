// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// The code in this file is copied from:
// Copyright (C) 2020 WireGuard LLC. All Rights Reserved.

// TODO(peske): Check the file header ^^^ to ensure appropriate copyright info.

package registry

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output zregistry_windows.go registry_windows.go
