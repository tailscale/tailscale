// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

// goMod is the parts of go.mod that bumpdeps cares about.
type goMod struct {
	requires []*modfile.Require // in file order
	versions map[string]string  // module path to required version
	replaced map[string]bool    // module paths with a replace directive
}

// readGoMod reads go.mod from the current directory.
func readGoMod() (*goMod, error) {
	data, err := os.ReadFile("go.mod")
	if err != nil {
		return nil, err
	}
	return parseGoMod(data)
}

func parseGoMod(data []byte) (*goMod, error) {
	mf, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		return nil, err
	}
	gm := &goMod{
		requires: mf.Require,
		versions: make(map[string]string, len(mf.Require)),
		replaced: make(map[string]bool, len(mf.Replace)),
	}
	for _, req := range mf.Require {
		gm.versions[req.Mod.Path] = req.Mod.Version
	}
	for _, r := range mf.Replace {
		gm.replaced[r.Old.Path] = true
	}
	return gm, nil
}

// selection is what the command line asked bumpdeps to do.
type selection struct {
	toolchain bool             // run ./pull-toolchain.sh
	lookups   []module.Version // modules to resolve via the proxy, with their current versions ("" if new)
	explicit  []update         // modules to hand to go get at a given version, no lookup
	names     []string         // what was asked for, for the report when nothing changed
}

// splitArgs splits args on commas and whitespace and drops empty pieces.
// The GitHub workflow passes its comma-separated input as one argument.
func splitArgs(args []string) []string {
	var out []string
	for _, a := range args {
		for _, f := range strings.FieldsFunc(a, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
			out = append(out, f)
		}
	}
	return out
}

// parseArgs turns the command line into a selection against gm. With no
// args, every direct dependency is selected (plus indirect ones if
// indirect is set). See the package comment for the argument forms.
func parseArgs(gm *goMod, args []string, indirect bool) (*selection, error) {
	sel := &selection{}
	args = splitArgs(args)
	if len(args) == 0 {
		for _, req := range gm.requires {
			if req.Indirect && !indirect {
				continue
			}
			sel.addLookup(gm, req.Mod)
		}
		return sel, nil
	}

	seen := map[string]bool{}
	for _, arg := range args {
		if arg == "go" {
			sel.toolchain = true
			sel.names = append(sel.names, "Go toolchain")
			continue
		}
		if path, ok := aliases[arg]; ok {
			sel.names = append(sel.names, arg)
			sel.addKnown(gm, path, seen)
			continue
		}
		if path, ver, ok := strings.Cut(arg, "@"); ok {
			if err := module.CheckPath(path); err != nil {
				return nil, fmt.Errorf("bad module path in %q: %v", arg, err)
			}
			if ver == "" {
				return nil, fmt.Errorf("empty version in %q", arg)
			}
			sel.names = append(sel.names, path)
			if seen[path] {
				return nil, fmt.Errorf("%s selected more than once", path)
			}
			seen[path] = true
			if gm.replaced[path] {
				return nil, fmt.Errorf("%s has a replace directive; edit go.mod by hand", path)
			}
			if ver == "latest" {
				sel.lookups = append(sel.lookups, module.Version{Path: path, Version: gm.versions[path]})
			} else {
				sel.explicit = append(sel.explicit, update{Path: path, Current: gm.versions[path], Latest: ver})
			}
			continue
		}
		if _, ok := gm.versions[arg]; ok {
			sel.names = append(sel.names, arg)
			sel.addKnown(gm, arg, seen)
			continue
		}
		var matched bool
		for _, req := range gm.requires {
			if req.Indirect && !indirect {
				continue
			}
			if strings.Contains(strings.ToLower(req.Mod.Path), strings.ToLower(arg)) {
				matched = true
				sel.addKnown(gm, req.Mod.Path, seen)
			}
		}
		if matched {
			sel.names = append(sel.names, arg)
			continue
		}
		// Nothing in go.mod matches. If it looks like a module path,
		// add it at its latest version.
		if strings.Contains(arg, "/") && module.CheckPath(arg) == nil {
			sel.names = append(sel.names, arg)
			seen[arg] = true
			sel.lookups = append(sel.lookups, module.Version{Path: arg})
			continue
		}
		return nil, fmt.Errorf("no modules in go.mod match %q", arg)
	}
	return sel, nil
}

// addKnown selects the module at path, which is required by gm, unless
// it was already selected or has a replace directive.
func (sel *selection) addKnown(gm *goMod, path string, seen map[string]bool) {
	if seen[path] {
		return
	}
	seen[path] = true
	sel.addLookup(gm, module.Version{Path: path, Version: gm.versions[path]})
}

// addLookup queues mod for a proxy lookup, skipping replaced modules.
func (sel *selection) addLookup(gm *goMod, mod module.Version) {
	if gm.replaced[mod.Path] {
		fmt.Fprintf(os.Stderr, "skipping %s: has a replace directive\n", mod.Path)
		return
	}
	sel.lookups = append(sel.lookups, mod)
}

// checkDowngrades returns an error if any module required by both before
// and after has a lower version in after. A downgrade means something
// went wrong and needs a human's rollback commit, not an unattended bump.
func checkDowngrades(before, after *goMod) error {
	var downgraded []string
	for path, oldVer := range before.versions {
		newVer, ok := after.versions[path]
		if ok && semver.Compare(newVer, oldVer) < 0 {
			downgraded = append(downgraded, fmt.Sprintf("%s %s => %s", path, oldVer, newVer))
		}
	}
	if len(downgraded) == 0 {
		return nil
	}
	slices.Sort(downgraded)
	return fmt.Errorf("refusing to downgrade modules (go.mod and go.sum are left modified; revert them):\n\t%s", strings.Join(downgraded, "\n\t"))
}
