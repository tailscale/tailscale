package chglog

import (
	"fmt"
	"sort"

	"github.com/Masterminds/semver/v3"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/storer"
)

// InitChangelog create a new ChangeLogEntries from a git repo.
func InitChangelog(gitRepo *git.Repository, owner string, notes *ChangeLogNotes, deb *ChangelogDeb, useConventionalCommits bool) (cle ChangeLogEntries, err error) {
	var (
		tagRefs    storer.ReferenceIter
		version    *semver.Version
		start, end plumbing.Hash
	)

	cle = make(ChangeLogEntries, 0)
	end = plumbing.ZeroHash

	tagRefs, err = gitRepo.Tags()
	defer tagRefs.Close()
	if err = tagRefs.ForEach(func(t *plumbing.Reference) error {
		var commits []*object.Commit
		tagName := t.Name().Short()

		if version, err = semver.NewVersion(tagName); err != nil || version == nil {
			return nil
		}
		if start, err = GitHashFotTag(gitRepo, tagName); err != nil {
			return nil
		}

		commitObject, _ := gitRepo.CommitObject(start)
		if owner == "" {
			owner = fmt.Sprintf("%s <%s>", commitObject.Committer.Name, commitObject.Committer.Email)
		}
		if commits, err = CommitsBetween(gitRepo, end, start); err != nil {
			return err
		}
		changelog := CreateEntry(commitObject.Committer.When, version, owner, notes, deb, commits, useConventionalCommits)
		cle = append(cle, changelog)
		end = start

		return nil
	}); err != nil {
		return nil, err
	}

	sort.Sort(sort.Reverse(cle))

	return cle, nil
}
