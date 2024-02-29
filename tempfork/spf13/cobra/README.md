# github.com/spf13/cobra

This package contains a copy of the Apache 2.0-licensed shell scripts that Cobra
uses to integrate tab-completion into bash, zsh, fish and powershell, and the
constants that interface with them. We are re-using these scripts to implement
similar tab-completion for ffcli and the standard library flag package.

The shell scripts were Go constants in the Cobra code, but we have extracted
them into separate files to facilitate gzipping them, and have removed the
activeHelp functionality from them.
