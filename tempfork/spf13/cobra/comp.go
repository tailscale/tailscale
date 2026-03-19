package cobra

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"fmt"
	"io"
)

//go:generate go run gen.go

//go:embed comp.bash.gz
var compBash string

func ScriptBash(w io.Writer, name, compCmd, nameForVar string) error {
	return fmtgz(
		w, compBash,
		name, compCmd,
		ShellCompDirectiveError, ShellCompDirectiveNoSpace, ShellCompDirectiveNoFileComp,
		ShellCompDirectiveFilterFileExt, ShellCompDirectiveFilterDirs, ShellCompDirectiveKeepOrder,
	)
}

//go:embed comp.zsh.gz
var compZsh string

func ScriptZsh(w io.Writer, name, compCmd, nameForVar string) error {
	return fmtgz(
		w, compZsh,
		name, compCmd,
		ShellCompDirectiveError, ShellCompDirectiveNoSpace, ShellCompDirectiveNoFileComp,
		ShellCompDirectiveFilterFileExt, ShellCompDirectiveFilterDirs, ShellCompDirectiveKeepOrder,
	)
}

//go:embed comp.fish.gz
var compFish string

func ScriptFish(w io.Writer, name, compCmd, nameForVar string) error {
	return fmtgz(
		w, compFish,
		nameForVar, name, compCmd,
		ShellCompDirectiveError, ShellCompDirectiveNoSpace, ShellCompDirectiveNoFileComp,
		ShellCompDirectiveFilterFileExt, ShellCompDirectiveFilterDirs, ShellCompDirectiveKeepOrder,
	)
}

//go:embed comp.ps1.gz
var compPowershell string

func ScriptPowershell(w io.Writer, name, compCmd, nameForVar string) error {
	return fmtgz(
		w, compPowershell,
		name, nameForVar, compCmd,
		ShellCompDirectiveError, ShellCompDirectiveNoSpace, ShellCompDirectiveNoFileComp,
		ShellCompDirectiveFilterFileExt, ShellCompDirectiveFilterDirs, ShellCompDirectiveKeepOrder,
	)
}

func fmtgz(w io.Writer, formatgz string, args ...any) error {
	f, err := gzip.NewReader(bytes.NewBufferString(formatgz))
	if err != nil {
		return fmt.Errorf("decompressing script: %w", err)
	}
	format, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("decompressing script: %w", err)
	}
	_, err = fmt.Fprintf(w, string(format), args...)
	return err
}
