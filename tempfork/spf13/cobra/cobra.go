// Copyright 2013-2023 The Cobra Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package cobra contains shell scripts and constants copied from
// https://github.com/spf13/cobra for use in our own shell tab-completion logic.
package cobra

import (
	"fmt"
	"strings"
)

// ShellCompDirective is a bit map representing the different behaviors the shell
// can be instructed to have once completions have been provided.
type ShellCompDirective int

const (
	// ShellCompDirectiveError indicates an error occurred and completions should be ignored.
	ShellCompDirectiveError ShellCompDirective = 1 << iota

	// ShellCompDirectiveNoSpace indicates that the shell should not add a space
	// after the completion even if there is a single completion provided.
	ShellCompDirectiveNoSpace

	// ShellCompDirectiveNoFileComp indicates that the shell should not provide
	// file completion even when no completion is provided.
	ShellCompDirectiveNoFileComp

	// ShellCompDirectiveFilterFileExt indicates that the provided completions
	// should be used as file extension filters.
	ShellCompDirectiveFilterFileExt

	// ShellCompDirectiveFilterDirs indicates that only directory names should
	// be provided in file completion.  To request directory names within another
	// directory, the returned completions should specify the directory within
	// which to search.
	ShellCompDirectiveFilterDirs

	// ShellCompDirectiveKeepOrder indicates that the shell should preserve the order
	// in which the completions are provided
	ShellCompDirectiveKeepOrder

	// ===========================================================================

	// All directives using iota should be above this one.
	// For internal use.
	shellCompDirectiveMaxValue

	// ShellCompDirectiveDefault indicates to let the shell perform its default
	// behavior after completions have been provided.
	// This one must be last to avoid messing up the iota count.
	ShellCompDirectiveDefault ShellCompDirective = 0
)

// Returns a string listing the different directive enabled in the specified parameter
func (d ShellCompDirective) String() string {
	var directives []string
	if d&ShellCompDirectiveError != 0 {
		directives = append(directives, "ShellCompDirectiveError")
	}
	if d&ShellCompDirectiveNoSpace != 0 {
		directives = append(directives, "ShellCompDirectiveNoSpace")
	}
	if d&ShellCompDirectiveNoFileComp != 0 {
		directives = append(directives, "ShellCompDirectiveNoFileComp")
	}
	if d&ShellCompDirectiveFilterFileExt != 0 {
		directives = append(directives, "ShellCompDirectiveFilterFileExt")
	}
	if d&ShellCompDirectiveFilterDirs != 0 {
		directives = append(directives, "ShellCompDirectiveFilterDirs")
	}
	if d&ShellCompDirectiveKeepOrder != 0 {
		directives = append(directives, "ShellCompDirectiveKeepOrder")
	}
	if len(directives) == 0 {
		directives = append(directives, "ShellCompDirectiveDefault")
	}

	if d >= shellCompDirectiveMaxValue {
		return fmt.Sprintf("ERROR: unexpected ShellCompDirective value: %d", d)
	}
	return strings.Join(directives, " | ")
}

const UsageTemplate = `To load completions:

Bash:

	$ source <(%[1]s completion bash)

	# To load completions for each session, execute once:
	# Linux:
	$ %[1]s completion bash > /etc/bash_completion.d/%[1]s
	# macOS:
	$ %[1]s completion bash > $(brew --prefix)/etc/bash_completion.d/%[1]s

Zsh:

	# If shell completion is not already enabled in your environment,
	# you will need to enable it.  You can execute the following once:

	$ echo "autoload -U compinit; compinit" >> ~/.zshrc

	# To load completions for each session, execute once:
	$ %[1]s completion zsh > "${fpath[1]}/_%[1]s"

	# You will need to start a new shell for this setup to take effect.

fish:

	$ %[1]s completion fish | source

	# To load completions for each session, execute once:
	$ %[1]s completion fish > ~/.config/fish/completions/%[1]s.fish

PowerShell:

	PS> %[1]s completion powershell | Out-String | Invoke-Expression

	# To load completions for every new session, run:
	PS> %[1]s completion powershell > %[1]s.ps1
	# and source this file from your PowerShell profile.

The shell scripts and this help message have been adapted from the
Cobra project (https://cobra.dev, https://github.com/spf13/cobra)
under the Apache-2.0 license. Thank you for making these available.
`
