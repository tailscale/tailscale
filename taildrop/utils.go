package taildrop

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"tailscale.com/util/quarantine"
)

// GetCompressedDirReader will compress the given directory in TAR format
// returns an io.Reader to get the raw TAR stream
func GetCompressedDirReader(dirPath string) (io.Reader, error) {
	pr, pw := io.Pipe()

	go func() {
		tarWriter := tar.NewWriter(pw)
		defer func() {
			_ = tarWriter.Close()
			_ = pw.Close()
		}()

		dirPath = filepath.Clean(dirPath)
		dirName := filepath.Base(dirPath)
		var err error
		if dirName == "." || dirName == ".." {
			// best effort to get the dir name
			dirPath, err = filepath.Abs(dirPath)
			if err != nil {
				_ = pw.CloseWithError(err)
				return
			}
			dirName = filepath.Base(dirPath)
		}
		err = filepath.Walk(dirPath, func(path string, fileInfo os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			relativePath, err := filepath.Rel(dirPath, path)
			if err != nil {
				return err
			}
			pathInTar := filepath.ToSlash(filepath.Join(dirName, relativePath))

			// try to resolve symbol link
			symbolLinkTarget := ""
			if fileInfo.Mode()&os.ModeSymlink != 0 {
				symbolLinkTarget, err = os.Readlink(path)
				if err != nil {
					symbolLinkTarget = ""
				}
			}

			header, err := tar.FileInfoHeader(fileInfo, symbolLinkTarget)
			if err != nil {
				return err
			}
			header.Name = pathInTar
			if err := tarWriter.WriteHeader(header); err != nil {
				return err
			}

			if !fileInfo.IsDir() {
				file, err := os.Open(path)
				if err != nil {
					return err
				}
				defer file.Close()

				if _, err := io.Copy(tarWriter, file); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}
	}()

	return pr, nil
}

const (
	SkipOnExist         string = "skip"
	OverwriteExisting   string = "overwrite" //  Overwrite any existing file at the target location
	CreateNumberedFiles string = "rename"    //  Create an alternately named file in the style of Chrome Downloads
)

func ReplacePrefix(str string, prefix string, replaceTo string) string {
	if strings.HasPrefix(str, prefix) && prefix != replaceTo {
		return replaceTo + strings.TrimPrefix(str, prefix)
	} else {
		return str
	}
}

// ExtractCompressedDir will uncompress the given TAR archive
// to destination directory
func ExtractCompressedDir(rc io.ReadCloser, dstDir string, conflictAction string) error {
	r := tar.NewReader(rc)

	dstDir, err := filepath.Abs(dstDir)
	if err != nil {
		return err
	}

	// Conflict check is only needed to be done once for the top-level directory in the archive
	// Get first record in archive here, find and solve conflict
	header, err := r.Next()
	if err != nil {
		// including EOF, let the caller know that the archive is empty
		return err
	}
	topLevelDirName := strings.Split(header.Name, "/")[0]
	// prevent path traversal
	topLevelDir := filepath.Clean(filepath.Join(dstDir, topLevelDirName))
	if !strings.HasPrefix(topLevelDir, dstDir) {
		return errors.New("Bad filepath in TAR: " + topLevelDir)
	}
	goodTopLevelDirName, err := processDirConflict(dstDir, topLevelDirName, conflictAction)
	if err != nil {
		return err
	}

	for {
		// replace top-level dir part in path to avoid possible conflict
		currentPathPart := ReplacePrefix(header.Name, topLevelDirName, goodTopLevelDirName)

		fpath := filepath.Clean(filepath.Join(dstDir, currentPathPart))
		// prevent path traversal
		if !strings.HasPrefix(fpath, dstDir) {
			return errors.New("Bad filepath in TAR: " + fpath)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			// extract a dir
			if err := os.MkdirAll(fpath, 0644); err != nil {
				return err
			}
		case tar.TypeReg:
			// extract a single file
			dir := filepath.Dir(fpath)
			fileName := filepath.Base(fpath)
			if err := os.MkdirAll(dir, 0644); err != nil {
				return err
			}
			outFile, err := os.OpenFile(filepath.Join(dir, fileName), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0644)
			if err != nil {
				return err
			}
			defer outFile.Close()

			// Apply quarantine attribute before copying
			if err := quarantine.SetOnFile(outFile); err != nil {
				return errors.New(fmt.Sprintf("failed to apply quarantine attribute to file %v: %v", fileName, err))
			}
			if _, err := io.Copy(outFile, r); err != nil {
				return err
			}
		default:
			// unsupported type flag, just skip it
		}

		header, err = r.Next()
		if err == io.EOF {
			break // extract finished
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// processDirConflict will check and try to solve directory conflict according
// to the strategy conflictAction. Returns the dirName that is able to use, or error.
func processDirConflict(parentDir string, dirName string, conflictAction string) (string, error) {
	dir := filepath.Join(parentDir, dirName)
	isDirExisting := checkDirExisting(dir)

	switch conflictAction {
	default:
		// This should not happen.
		return "", fmt.Errorf("bad conflictAction argument")
	case SkipOnExist:
		if isDirExisting {
			return "", fmt.Errorf("refusing to overwrite directory: %v", dir)
		}
		return dirName, nil
	case OverwriteExisting:
		if isDirExisting {
			if err := os.RemoveAll(dir); err != nil {
				return "", fmt.Errorf("unable to remove target directory: %w", err)
			}
		}
		return dirName, nil
	case CreateNumberedFiles:
		// It's possible the target directory or filesystem isn't writable by us,
		// not just that the target file(s) already exists.  For now, give up after
		// a limited number of attempts.  In future, maybe distinguish this case
		// and follow in the style of https://tinyurl.com/chromium100
		if !isDirExisting {
			return dirName, nil
		}
		maxAttempts := 100
		for i := 1; i < maxAttempts; i++ {
			newDirName := numberedDirName(dirName, i)
			if !checkDirExisting(filepath.Join(parentDir, newDirName)) {
				return newDirName, nil
			}
		}
		return "", fmt.Errorf("unable to find a name for writing %v", dir)
	}
}

func checkDirExisting(dir string) bool {
	_, statErr := os.Stat(dir)
	return statErr == nil
}

func numberedDirName(dir string, i int) string {
	return fmt.Sprintf("%s (%d)", dir, i)
}
