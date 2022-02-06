package fileglob

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gobwas/glob"
	"github.com/spf13/afero"
)

const (
	runeSeparator   = '/'
	stringSeparator = string(runeSeparator)
)

// FileSystem is meant to be used with WithFs.
type FileSystem afero.Fs

// globOptions allowed to be passed to Glob.
type globOptions struct {
	fs afero.Fs

	// if matchDirectories directly is set to true  a matching directory will
	// be treated just like a matching file. If set to false, a matching directory
	// will auto-match all files inside instead of the directory itself.
	matchDirectoriesDirectly bool
}

// OptFunc is a function that allow to customize Glob.
type OptFunc func(opts *globOptions)

// WithFs allows to provide another afero.Fs implementation to Glob.
func WithFs(fs FileSystem) OptFunc {
	return func(opts *globOptions) {
		opts.fs = fs
	}
}

// MatchDirectories determines weather a matching directory should
// result in only the folder name itself being returned (true) or
// in all files inside that folder being returned (false).
func MatchDirectories(v bool) OptFunc {
	return func(opts *globOptions) {
		opts.matchDirectoriesDirectly = v
	}
}

// QuoteMeta returns a string that quotes all glob pattern meta characters
// inside the argument text; For example, QuoteMeta(`{foo*}`) returns `\{foo\*\}`.
func QuoteMeta(pattern string) string {
	return glob.QuoteMeta(pattern)
}

// toNixPath converts the path to the nix style path
// Windows style path separators are escape characters so cause issues with the compiled glob.
func toNixPath(path string) string {
	return filepath.ToSlash(filepath.Clean(path))
}

// Glob returns all files that match the given pattern in the current directory.
func Glob(pattern string, opts ...OptFunc) ([]string, error) {
	return doGlob(
		strings.TrimPrefix(pattern, "."+stringSeparator),
		compileOptions(opts),
	)
}

func doGlob(pattern string, options *globOptions) ([]string, error) { // nolint:funlen
	var fs = options.fs
	var matches []string

	matcher, err := glob.Compile(pattern, runeSeparator)
	if err != nil {
		return matches, fmt.Errorf("compile glob pattern: %w", err)
	}

	prefix, err := staticPrefix(pattern)
	if err != nil {
		return nil, fmt.Errorf("cannot determine static prefix: %w", err)
	}

	prefixInfo, err := fs.Stat(prefix)
	if os.IsNotExist(err) {
		if !ContainsMatchers(pattern) {
			// glob contains no dynamic matchers so prefix is the file name that
			// the glob references directly. When the glob explicitly references
			// a single non-existing file, return an error for the user to check.
			return []string{}, fmt.Errorf(`matching "%s": %w`, prefix, os.ErrNotExist)
		}

		return []string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("stat static prefix %q: %w", prefix, err)
	}

	if !prefixInfo.IsDir() {
		// if the prefix is a file, it either has to be
		// the only match, or nothing matches at all
		if matcher.Match(prefix) {
			return []string{prefix}, nil
		}

		return []string{}, nil
	}

	return matches, afero.Walk(fs, prefix, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// The glob ast from github.com/gobwas/glob only works properly with linux paths
		path = toNixPath(path)
		if !matcher.Match(path) {
			return nil
		}

		if info.IsDir() {
			if options.matchDirectoriesDirectly {
				matches = append(matches, path)
				return nil
			}

			// a direct match on a directory implies that all files inside
			// match if options.matchFolders is false
			filesInDir, err := filesInDirectory(fs, path)
			if err != nil {
				return err
			}

			matches = append(matches, filesInDir...)
			return filepath.SkipDir
		}

		matches = append(matches, path)

		return nil
	})
}

func compileOptions(optFuncs []OptFunc) *globOptions {
	var opts = &globOptions{
		fs: afero.NewOsFs(),
	}

	for _, apply := range optFuncs {
		apply(opts)
	}

	return opts
}

func filesInDirectory(fs afero.Fs, dir string) ([]string, error) {
	var files []string

	return files, afero.Walk(fs, dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		path = toNixPath(path)
		files = append(files, path)
		return nil
	})
}
