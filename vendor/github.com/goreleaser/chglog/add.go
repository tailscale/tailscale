package chglog

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// ErrNoCommits happens when no commits are found for a given entry.
var ErrNoCommits = errors.New("no commits found for this entry")

// AddEntry add a ChangeLog entry to an existing ChangeLogEntries that.
func AddEntry(
	gitRepo *git.Repository,
	version fmt.Stringer,
	owner string,
	notes *ChangeLogNotes,
	deb *ChangelogDeb,
	current ChangeLogEntries,
	useConventionalCommits bool) (cle ChangeLogEntries, err error) {
	var (
		ref      *plumbing.Reference
		from, to plumbing.Hash
		commits  []*object.Commit
	)

	if ref, err = gitRepo.Head(); err != nil {
		return nil, fmt.Errorf("error adding entry: %w", err)
	}
	from = ref.Hash()

	to = plumbing.ZeroHash
	if len(current) > 0 {
		if to, err = GitHashFotTag(gitRepo, current[0].Semver); err != nil {
			return nil, fmt.Errorf("error adding entry: %w", err)
		}
	}

	cle = append(cle, current...)
	if commits, err = CommitsBetween(gitRepo, to, from); err != nil {
		return nil, fmt.Errorf("error adding entry: %w", err)
	}

	if len(commits) == 0 {
		return nil, ErrNoCommits
	}

	cle = append(cle, CreateEntry(time.Now(), version, owner, notes, deb, commits, useConventionalCommits))
	sort.Sort(sort.Reverse(cle))

	return cle, nil
}

func processMsg(msg string) string {
	msg = strings.ReplaceAll(strings.ReplaceAll(msg, "\r\n\r\n", "\n\n"), "\r", "")
	msg = regexp.MustCompile(`(?m)(?:^.*Signed-off-by:.*>$)`).ReplaceAllString(msg, "")
	msg = strings.ReplaceAll(strings.Trim(msg, "\n"), "\n\n\n", "\n")

	return msg
}

// CreateEntry create a ChangeLog object.
func CreateEntry(date time.Time, version fmt.Stringer, owner string, notes *ChangeLogNotes, deb *ChangelogDeb, commits []*object.Commit, useConventionalCommits bool) (changelog *ChangeLog) {
	var cc *ConventionalCommit
	changelog = &ChangeLog{
		Semver:   version.String(),
		Date:     date,
		Packager: owner,
		Notes:    notes,
	}
	if len(commits) == 0 {
		return
	}
	changelog.Changes = make(ChangeLogChanges, len(commits))
	changelog.Deb = deb

	for idx, c := range commits {
		msg := processMsg(c.Message)
		if useConventionalCommits {
			cc = ParseConventionalCommit(msg)
		}
		changelog.Changes[idx] = &ChangeLogChange{
			Commit: c.Hash.String(),
			Note:   msg,
			Committer: &User{
				Name:  c.Committer.Name,
				Email: c.Committer.Email,
			},
			Author: &User{
				Name:  c.Author.Name,
				Email: c.Author.Email,
			},
			ConventionalCommit: cc,
		}
	}

	return changelog
}
