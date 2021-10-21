//go:build !js
// +build !js

package cli

import "syscall"

var syscallExec = syscall.Exec
