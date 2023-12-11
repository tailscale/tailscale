package impersonatingfs

import (
	"context"
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"golang.org/x/net/webdav"
)

func TestMkdirAllowed(t *testing.T) {
	fs, tmpdir, uid, gid := build(t)
	defer os.RemoveAll(tmpdir)

	// Change owner of parent tmpdir
	err := chown(tmpdir, uid, gid)
	if err != nil {
		t.Fatal(err)
	}

	err = fs.Mkdir(context.Background(), "somedir", 0755)
	if err != nil {
		t.Fatal(err)
	}

	filename := filepath.Join(tmpdir, "somedir")
	actualUID, err := getUID(filename)
	if err != nil {
		t.Fatal(err)
	}
	actualGID, err := getGID(filename)
	if err != nil {
		t.Fatal(err)
	}
	if actualUID != uid {
		t.Errorf("uid = %v, want %v", actualUID, uid)
	}
	if actualGID != gid {
		t.Errorf("gid = %v, want %v", actualGID, gid)
	}
}

func TestMkdirDenied(t *testing.T) {
	fs, tmpdir, _, _ := build(t)
	defer os.RemoveAll(tmpdir)

	err := fs.Mkdir(context.Background(), "somedir", 0755)
	if !errors.Is(err, os.ErrPermission) {
		t.Fatal("mkdir should have failed with permission error")
	}
}

func TestReadFileAllowed(t *testing.T) {
	fs, tmpdir, _, _ := build(t)
	defer os.RemoveAll(tmpdir)

	// make tmpdir readable
	err := chmod(tmpdir, 0755)
	if err != nil {
		t.Fatal(err)
	}

	text := "hello world"
	filename := "somefile"
	path := filepath.Join(tmpdir, filename)

	err = os.WriteFile(path, []byte(text), 0644)
	if err != nil {
		t.Fatal(err)
	}

	file, err := fs.OpenFile(context.Background(), filename, os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	b, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}

	if string(b) != text {
		t.Errorf("read %v, want %v", string(b), text)
	}

	// Make sure we didn't change the file owner
	actualUID, err := getUID(path)
	if err != nil {
		t.Fatal(err)
	}
	actualGID, err := getGID(path)
	if err != nil {
		t.Fatal(err)
	}
	if actualUID != "0" {
		t.Errorf("uid = %v, want 0", actualUID)
	}
	if actualGID != "0" {
		t.Errorf("gid = %v, want 0", actualGID)
	}
}

func TestReadFileDenied(t *testing.T) {
	fs, tmpdir, _, _ := build(t)
	defer os.RemoveAll(tmpdir)

	text := "hello world"
	filename := "somefile"
	path := filepath.Join(tmpdir, filename)

	err := os.WriteFile(path, []byte(text), 0644)
	if err != nil {
		t.Fatal(err)
	}

	_, err = fs.OpenFile(context.Background(), filename, os.O_RDONLY, 0)
	if !errors.Is(err, os.ErrPermission) {
		t.Fatal("open readonly file should have failed with permission error")
	}
}

func TestCreateFileAllowed(t *testing.T) {
	fs, tmpdir, uid, gid := build(t)
	defer os.RemoveAll(tmpdir)

	// make tmpdir writeable
	err := chmod(tmpdir, 0777)
	if err != nil {
		t.Fatal(err)
	}

	text := "hello world"
	filename := "somefile"
	path := filepath.Join(tmpdir, filename)

	file, err := fs.OpenFile(context.Background(), filename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	_, err = file.Write([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	file.Close()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if string(b) != text {
		t.Errorf("read %v, want %v", string(b), text)
	}

	// Make sure we set the right file owner
	actualUID, err := getUID(path)
	if err != nil {
		t.Fatal(err)
	}
	actualGID, err := getGID(path)
	if err != nil {
		t.Fatal(err)
	}
	if actualUID != uid {
		t.Errorf("uid = %v, want %v", actualUID, uid)
	}
	if actualGID != gid {
		t.Errorf("gid = %v, want %v", actualGID, gid)
	}
}

func TestCreateFileDenied(t *testing.T) {
	fs, tmpdir, _, _ := build(t)
	defer os.RemoveAll(tmpdir)

	filename := "somefile"
	_, err := fs.OpenFile(context.Background(), filename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0)
	if !errors.Is(err, os.ErrPermission) {
		t.Fatal("open writeable file should have failed with permission error")
	}
}

func TestOverwriteFileAllowed(t *testing.T) {
	fs, tmpdir, _, _ := build(t)
	defer os.RemoveAll(tmpdir)

	// make tmpdir writeable
	err := chmod(tmpdir, 0777)
	if err != nil {
		t.Fatal(err)
	}

	text := "hello world"
	filename := "somefile"
	path := filepath.Join(tmpdir, filename)

	// make a world writeable empty file
	err = os.WriteFile(path, []byte(""), 0666)
	if err != nil {
		t.Fatal(err)
	}
	// for some reason, os.WriteFile doesn't set the mode to 0666, do it
	// manually
	err = chmod(path, 0666)
	if err != nil {
		t.Fatal(err)
	}

	// now overwrite that file through our filesystem
	file, err := fs.OpenFile(context.Background(), filename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	_, err = file.Write([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	file.Close()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if string(b) != text {
		t.Errorf("read %v, want %v", string(b), text)
	}

	// Make sure we didn't change the file owner
	actualUID, err := getUID(path)
	if err != nil {
		t.Fatal(err)
	}
	actualGID, err := getGID(path)
	if err != nil {
		t.Fatal(err)
	}
	if actualUID != "0" {
		t.Errorf("uid = %v, want 0", actualUID)
	}
	if actualGID != "0" {
		t.Errorf("gid = %v, want 0", actualGID)
	}
}

func TestOverwriteFileDenied(t *testing.T) {
	fs, tmpdir, _, _ := build(t)
	defer os.RemoveAll(tmpdir)

	filename := "somefile"
	path := filepath.Join(tmpdir, filename)

	// make a not world writeable empty file
	err := os.WriteFile(path, []byte(""), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// attempt to overwrite that file through our filesystem
	_, err = fs.OpenFile(context.Background(), filename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0)
	if !errors.Is(err, os.ErrPermission) {
		t.Fatal("open writeable file should have failed with permission error")
	}
}

func build(t *testing.T) (webdav.FileSystem, string, string, string) {
	tmpdir, err := os.MkdirTemp("", "impersonatingfs_test")
	if err != nil {
		t.Fatal(err)
	}

	currentUser, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if currentUser.Uid != "0" {
		t.Skip("test requires root")
	}

	uid, gid := os.Args[1], os.Args[2]
	if uid == "" {
		t.Fatal("uid must be set")
	}

	if gid == "" {
		t.Fatal("gid must be set")
	}

	return New(tmpdir, uid, gid), tmpdir, uid, gid
}
