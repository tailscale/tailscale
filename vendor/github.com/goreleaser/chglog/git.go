package chglog

import (
	"errors"
	"fmt"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

var errReachedToCommit = errors.New("reached to commit")

// GitRepo open a GitRepo to use to build the changelog from.
func GitRepo(gitPath string, detectDotGit bool) (*git.Repository, error) {
	return git.PlainOpenWithOptions(gitPath, &git.PlainOpenOptions{
		DetectDotGit: detectDotGit,
	})
}

// GitHashFotTag return the git sha for a particular tag.
func GitHashFotTag(gitRepo *git.Repository, tagName string) (hash plumbing.Hash, err error) {
	var ref *plumbing.Reference
	ref, err = gitRepo.Tag(tagName)
	if errors.Is(err, git.ErrTagNotFound) && !strings.HasPrefix(tagName, "v") {
		ref, err = gitRepo.Tag("v" + tagName)
	}
	if err != nil {
		return plumbing.ZeroHash, fmt.Errorf("error getting commit for tag %s: %w", tagName, err)
	}

	return ref.Hash(), nil
}

// CommitsBetween return the list of commits between two commits.
func CommitsBetween(gitRepo *git.Repository, start, end plumbing.Hash) (commits []*object.Commit, err error) {
	var (
		commitIter object.CommitIter
	)
	commitIter, err = gitRepo.Log(&git.LogOptions{From: end})
	defer commitIter.Close()
	err = commitIter.ForEach(func(c *object.Commit) error {
		// If no previous tag is found then from and to are equal
		if end == start {
			return nil
		}
		if c.Hash == start {
			return errReachedToCommit
		}
		commits = append(commits, c)

		return nil
	})

	if err != nil && !errors.Is(err, errReachedToCommit) {
		return nil, fmt.Errorf("error getting commits between %v & %v: %w", start, end, err)
	}

	return commits, nil
}
