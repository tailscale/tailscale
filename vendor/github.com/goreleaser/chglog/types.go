// Package chglog contains the public API for working with a changlog.yml file
package chglog

import (
	"time"

	"github.com/Masterminds/semver/v3"
)

// ChangeLogEntries list of ChangeLog entries.
type ChangeLogEntries []*ChangeLog

// Len returns the length of a collection. The number of Version instances
// on the slice.
func (c ChangeLogEntries) Len() int {
	return len(c)
}

// Less is needed for the sort interface to compare two Version objects on the
// slice. If checks if one is less than the other.
func (c ChangeLogEntries) Less(i, j int) bool {
	v1, err := semver.NewVersion(c[i].Semver)
	if err != nil {
		return true
	}
	v2, err := semver.NewVersion(c[j].Semver)
	if err != nil {
		return false
	}

	return v1.LessThan(v2)
}

// Swap is needed for the sort interface to replace the Version objects
// at two different positions in the slice.
func (c ChangeLogEntries) Swap(i, j int) {
	c[i], c[j] = c[j], c[i]
}

// PackageChangeLog used for the formatting API.
type PackageChangeLog struct {
	Name    string           `yaml:"name"`
	Entries ChangeLogEntries `yaml:"entries"`
}

// ChangeLog a single changelog entry.
type ChangeLog struct {
	ChangeLogOverridables `yaml:",inline"`
	Semver                string           `yaml:"semver"`
	Date                  time.Time        `yaml:"date"`
	Packager              string           `yaml:"packager"`
	Notes                 *ChangeLogNotes  `yaml:"notes,omitempty"`
	Changes               ChangeLogChanges `yaml:"changes,omitempty"`
}

// ChangeLogOverridables contains potential format specific fields.
type ChangeLogOverridables struct {
	Deb *ChangelogDeb `yaml:"deb,omitempty"`
}

// ChangelogDeb contains fields specific to the debian changelog format
// https://www.debian.org/doc/debian-policy/ch-source.html#s-dpkgchangelog
type ChangelogDeb struct {
	Urgency       string   `yaml:"urgency"`
	Distributions []string `yaml:"distributions"`
}

// ChangeLogNotes contains a potential header/footer string for output formatting.
type ChangeLogNotes struct {
	Header *string `yaml:"header,omitempty"`
	Footer *string `yaml:"footer,omitempty"`
}

// ChangeLogChanges list of individual changes.
type ChangeLogChanges []*ChangeLogChange

// ChangeLogChange an individual change.
type ChangeLogChange struct {
	Commit string `yaml:"commit"`
	Note   string `yaml:"note"`
	// Author is the original author of the commit.
	Author *User `yaml:"author,omitempty"`
	// Committer is the one performing the commit, might be different from
	// Author.
	Committer          *User               `yaml:"committer,omitempty"`
	ConventionalCommit *ConventionalCommit `yaml:"conventional_commit,omitempty"`
}

// ConventionalCommit a parsed conventional commit message.
type ConventionalCommit struct {
	Category    string `yaml:"category"`
	Scope       string `yaml:"scope"`
	Breaking    bool   `yaml:"breaking"`
	Description string `yaml:"description"`
	Body        string `yaml:"body"`
}

// User is used to identify who created a commit or tag.
type User struct {
	// Name represents a person name. It is an arbitrary string.
	Name string `yaml:"name"`
	// Email is an email, but it cannot be assumed to be well-formed.
	Email string `yaml:"email"`
}
