package taildrop

import (
	"archive/tar"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"tailscale.com/util/must"
	"testing"
)

func TestTarArchiveUtils(t *testing.T) {
	equalErrorPrefix := func(err error, prefix string) {
		t.Helper()
		assert.Error(t, err)
		assert.True(t, strings.HasPrefix(err.Error(), prefix))
	}

	var autoCloser []io.ReadCloser
	defer func() {
		for _, r := range autoCloser {
			_ = r.Close()
		}
	}()

	readerFromFile := func(file string) io.ReadCloser {
		t.Helper()
		f, err := os.Open(file)
		must.Do(err)
		autoCloser = append(autoCloser, f)
		return f
	}

	writeToFile := func(reader io.Reader, file string) {
		t.Helper()
		outFile, err := os.Create(file)
		must.Do(err)
		defer outFile.Close()

		_, err = io.Copy(outFile, reader)
		must.Do(err)
	}

	checkDirectory := func(dir string, want ...string) {
		t.Helper()
		var got []string
		for _, de := range must.Get(os.ReadDir(dir)) {
			got = append(got, de.Name())
		}
		slices.Sort(got)
		slices.Sort(want)
		if diff := cmp.Diff(got, want); diff != "" {
			t.Fatalf("directory mismatch (-got +want):\n%s", diff)
		}
	}

	checkTarArchive := func(tarFile string, want ...string) {
		t.Helper()
		r := tar.NewReader(readerFromFile(tarFile))

		var got []string
		for {
			header, err := r.Next()
			if err == io.EOF {
				break // extract finished
			}
			must.Do(err)
			got = append(got, header.Name)
		}
		slices.Sort(got)
		slices.Sort(want)
		if diff := cmp.Diff(got, want); diff != "" {
			t.Fatalf("TAR archive mismatch (-got +want):\n%s", diff)
		}
	}

	dir := t.TempDir()
	must.Do(os.MkdirAll(filepath.Join(dir, "root-dir"), 0644))
	must.Do(os.WriteFile(filepath.Join(dir, "root-dir/foo.txt"), []byte("This is foo.txt"), 0644))
	must.Do(os.WriteFile(filepath.Join(dir, "root-dir/bar"), []byte("This is bar"), 0644))
	must.Do(os.WriteFile(filepath.Join(dir, "root-dir/其他文字.docx"), []byte(""), 0644))
	must.Do(os.MkdirAll(filepath.Join(dir, "root-dir/sub-dir"), 0644))
	must.Do(os.WriteFile(filepath.Join(dir, "root-dir/sub-dir/buzz.log"), []byte("hello world..."), 0644))

	// Test Directory Compression
	tarPath := filepath.Join(dir, "root-dir.tscompresseddir")

	reader, err := GetCompressedDirReader(filepath.Join(dir, "root-dir"))
	must.Do(err)
	writeToFile(reader, tarPath)
	checkTarArchive(tarPath, "root-dir", "root-dir/foo.txt", "root-dir/bar", "root-dir/其他文字.docx",
		"root-dir/sub-dir", "root-dir/sub-dir/buzz.log")

	reader, err = GetCompressedDirReader(filepath.Join(dir, "./foo/bar/../../root-dir/sub/.."))
	must.Do(err)
	writeToFile(reader, tarPath)
	checkTarArchive(tarPath, "root-dir", "root-dir/foo.txt", "root-dir/bar", "root-dir/其他文字.docx",
		"root-dir/sub-dir", "root-dir/sub-dir/buzz.log")

	// Test Archive Extraction
	downloadDir := filepath.Join(dir, "test-download")
	must.Do(os.MkdirAll(downloadDir, 0644))

	// success first time
	err = ExtractCompressedDir(readerFromFile(tarPath), downloadDir, SkipOnExist)
	must.Do(err)
	// fail second time, due to SkipOnExist
	err = ExtractCompressedDir(readerFromFile(tarPath), downloadDir, SkipOnExist)
	equalErrorPrefix(err, "refusing to overwrite directory:")
	// success again, due to OverwriteExisting
	err = ExtractCompressedDir(readerFromFile(tarPath), downloadDir, OverwriteExisting)
	must.Do(err)

	checkDirectory(downloadDir, "root-dir")
	checkDirectory(filepath.Join(downloadDir, "root-dir"), "foo.txt", "bar", "其他文字.docx", "sub-dir")
	checkDirectory(filepath.Join(downloadDir, "root-dir/sub-dir"), "buzz.log")

	// success twice, due to CreateNumberedFiles
	err = ExtractCompressedDir(readerFromFile(tarPath), downloadDir, CreateNumberedFiles)
	must.Do(err)
	err = ExtractCompressedDir(readerFromFile(tarPath), downloadDir, CreateNumberedFiles)
	must.Do(err)

	checkDirectory(downloadDir, "root-dir", "root-dir (1)", "root-dir (2)")
	checkDirectory(filepath.Join(downloadDir, "root-dir (2)"), "foo.txt", "bar", "其他文字.docx", "sub-dir")
	checkDirectory(filepath.Join(downloadDir, "root-dir (2)/sub-dir"), "buzz.log")
}
