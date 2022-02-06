package chglog

import (
	"text/template"

	"github.com/Masterminds/sprig"
)

const (
	rpmTpl = `
{{- range .Entries }}{{$version := semver .Semver}}
* {{ date_in_zone "Mon Jan 2 2006" .Date "UTC" }} {{ .Packager }} - {{ $version.Major }}.{{ $version.Minor }}.{{ $version.Patch }}{{if $version.Prerelease}}-{{ $version.Prerelease }}{{end}}
{{- range .Changes }}{{$note := splitList "\n" .Note}}
  - {{ first $note }}{{ range $i,$n := (rest $note) }}{{if ne $n "\n"}}  {{$n}}{{end}}
  {{end}}
{{- end }}
{{ end }}
`
	debTpl = `{{- $name := .Name}}
{{- range .Entries }}
{{ $name }} ({{ .Semver }}){{if .Deb}} {{default "" (.Deb.Distributions | join " ")}}; urgency={{default "low" .Deb.Urgency}}{{end}}
  {{- range .Changes }}{{$note := splitList "\n" .Note}}
  * {{ first $note }}
   {{- range $i,$n := (rest $note) }}
   {{- if ne (trim $n) ""}}
   - {{$n}}{{end}}
{{- end}}{{end}}

 -- {{ .Packager }}  {{ date_in_zone "Mon, 02 Jan 2006 03:04:05 -0700" .Date "UTC" }}
{{ end }}
`
	releaseTpl = `
Changelog
=========
{{- with (first .Entries)}}
{{range .Changes }}{{$note := splitList "\n" .Note}}
{{substr 0 8 .Commit}} {{ first $note }}{{end}}
{{ end}}
`
	repoTpl = `
{{- range .Entries }}
{{ .Semver }}
=============
{{ date_in_zone "2006-01-02" .Date "UTC" }}
{{range .Changes }}{{$note := splitList "\n" .Note}}
* {{ first $note }} ({{substr 0 8 .Commit}}){{end}}
{{ end}}
`
)

// LoadTemplateData load a template from string with all of the sprig.TxtFuncMap loaded.
func LoadTemplateData(data string) (*template.Template, error) {
	return template.New("base").Funcs(sprig.TxtFuncMap()).Parse(data)
}

// DebTemplate load default debian template.
func DebTemplate() (*template.Template, error) {
	return LoadTemplateData(debTpl)
}

// RPMTemplate load default RPM template.
func RPMTemplate() (*template.Template, error) {
	return LoadTemplateData(rpmTpl)
}

// ReleaseTemplate load default release template.
func ReleaseTemplate() (*template.Template, error) {
	return LoadTemplateData(releaseTpl)
}

// RepoTemplate load default repo template.
func RepoTemplate() (*template.Template, error) {
	return LoadTemplateData(repoTpl)
}
