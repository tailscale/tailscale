// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_drive

package main

import (
	"errors"
	"fmt"

	"tailscale.com/drive/driveimpl"
	"tailscale.com/tsd"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine"
)

func init() {
	subCommands["serve-taildrive"] = &serveDriveFunc

	hookSetSysDrive.Set(func(sys *tsd.System, logf logger.Logf) {
		sys.Set(driveimpl.NewFileSystemForRemote(logf))
	})
	hookSetWgEnginConfigDrive.Set(func(conf *wgengine.Config, logf logger.Logf) {
		conf.DriveForLocal = driveimpl.NewFileSystemForLocal(logf)
	})
}

var serveDriveFunc = serveDrive

// serveDrive serves one or more Taildrives on localhost using the WebDAV
// protocol. On UNIX and MacOS tailscaled environment, Taildrive spawns child
// tailscaled processes in serve-taildrive mode in order to access the fliesystem
// as specific (usually unprivileged) users.
//
// serveDrive prints the address on which it's listening to stdout so that the
// parent process knows where to connect to.
func serveDrive(args []string) error {
	if len(args) == 0 {
		return errors.New("missing shares")
	}
	if len(args)%2 != 0 {
		return errors.New("need <sharename> <path> pairs")
	}
	s, err := driveimpl.NewFileServer()
	if err != nil {
		return fmt.Errorf("unable to start Taildrive file server: %v", err)
	}
	shares := make(map[string]string)
	for i := 0; i < len(args); i += 2 {
		shares[args[i]] = args[i+1]
	}
	s.SetShares(shares)
	fmt.Printf("%v\n", s.Addr())
	return s.Serve()
}
