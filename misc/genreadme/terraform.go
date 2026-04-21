// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package main

import (
	"bytes"
	"errors"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/terraform-docs/terraform-docs/print"
	"github.com/terraform-docs/terraform-docs/terraform"
)

func hasTerraformFiles(dir string, dents []fs.DirEntry) bool {
	for _, de := range dents {
		if strings.HasSuffix(de.Name(), ".tf") {
			return true
		}
	}
	return false
}

func genTerraform(dir string) ([]byte, error) {
	config := print.DefaultConfig()
	config.ModuleRoot = dir

	module, err := terraform.LoadWithOptions(config)
	if err != nil {
		return nil, err
	}

	// For now, only generate documentation for "library" modules with
	// inputs.
	tmpl := moduleTmpl
	hasDeploy := false
	if len(module.Inputs) == 0 {
		tmpl = toplevelTmpl
		if _, err := os.Stat(filepath.Join(dir, "deploy.sh")); err == nil {
			hasDeploy = true
		}
	}

	hdr, err := findTfModuleDoc(dir)
	if err != nil {
		return nil, err
	}
	if hdr == "" {
		hdr = strings.TrimSpace(`
There is no top-level documentation for this module. If you know what
it does, please write one?

To add documentation to this module, add a comment at the top of
any .tf file in this directory (preferably main.tf or doc.tf).
Leave an empty line between the comment and the first bit of Terraform
config, so that the comment gets treated as module-wide documentation.
`)
	}
	module.Header = hdr

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, map[string]any{
		"TF":        module,
		"HasDeploy": hasDeploy,
		"CodeBlock": "```",
	}); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func findTfModuleDoc(dir string) (string, error) {
	log.Printf("Looking for Terraform module doc in %s ...", dir)
	dents, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}

	// If doc.tf exists, use the header comment from that file.
	hdr, err := getTfHeader(filepath.Join(dir, "doc.tf"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	if hdr != "" {
		return hdr, nil
	}

	// If not, merge the header comments from all .tf files.
	var mergedHdr string
	for _, ent := range dents {
		if !strings.HasSuffix(ent.Name(), ".tf") {
			continue
		}
		hdr, err := getTfHeader(filepath.Join(dir, ent.Name()))
		if err != nil {
			return "", err
		}
		if hdr != "" {
			if mergedHdr == "" {
				mergedHdr = hdr
			} else {
				mergedHdr += "\n\n" + hdr
			}
		}
	}
	return mergedHdr, nil
}

func getTfHeader(path string) (string, error) {
	bs, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	if len(bs) == 0 || bs[0] != '#' {
		// File doesn't start with a comment, not a header.
		return "", nil
	}

	var ret []string
	for _, line := range strings.Split(string(bs), "\n") {
		if !strings.HasPrefix(line, "#") {
			// The line following the header must be whitespace, to
			// disambiguate between module documentation and a
			// docstring for a particular piece of the Terraform
			// config.
			if len(strings.TrimSpace(line)) == 0 {
				break
			}
			// Not a header comment.
			return "", nil
		}
		line = line[1:]
		if len(line) > 0 {
			// Remove one space between # and text, on lines that aren't just a #.
			// TODO: dedent properly? Does godoc have a function for that somewhere we can use?
			line = line[1:]
		}
		ret = append(ret, line)
	}
	return strings.TrimRight(strings.Join(ret, "\n"), "\n "), nil
}

var moduleTmpl = template.Must(template.New("").Parse(genHeader + `
{{.TF.Header}}

## Inputs
{{ range .TF.Inputs }}
 - {{.Name}}

{{- if .Type}} ({{.Type}}){{end}}
{{- if .Description}}: {{.Description}}{{end}}
{{- if .HasDefault}} (default: {{.Default}}){{end -}}
{{ end }}

## Outputs
{{ range .TF.Outputs }}
 - {{.Name}}

{{- if .Description }}: {{.Description}}{{end -}}
{{ end }}
`))

var toplevelTmpl = template.Must(template.New("").Parse(genHeader + `
{{.TF.Header}}

{{ if .HasDeploy -}}
## Deploying

To deploy, cd to this directory and run:

{{.CodeBlock}}
aws-vault exec <aws profile> -- ./deploy.sh terraform
{{.CodeBlock}}

See the [Terrible stack documentation](/deploy/doc/terrible.md)
for more details, including initial setup instructions.

For other commands and documentation, see:

{{.CodeBlock}}
./deploy.sh --help
./deploy.sh terraform --help
{{.CodeBlock}}
{{ end -}}

{{ if .TF.Outputs }}
## Terraform Outputs
{{ range .TF.Outputs }}
 - {{.Name}}

{{- if .Description }}: {{.Description}}{{end -}}
{{ end }}
{{ end }}
`))