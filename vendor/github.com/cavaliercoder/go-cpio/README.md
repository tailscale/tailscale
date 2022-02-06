# go-cpio [![GoDoc](https://godoc.org/github.com/cavaliercoder/go-cpio?status.svg)](https://godoc.org/github.com/cavaliercoder/go-cpio) [![Build Status](https://travis-ci.org/cavaliercoder/go-cpio.svg?branch=master)](https://travis-ci.org/cavaliercoder/go-cpio) [![Go Report Card](https://goreportcard.com/badge/github.com/cavaliercoder/go-cpio)](https://goreportcard.com/report/github.com/cavaliercoder/go-cpio)

This package provides a Go native implementation of the CPIO archive file
format.

Currently, only the SVR4 (New ASCII) format is supported, both with and without
checksums.

```go
// Create a buffer to write our archive to.
buf := new(bytes.Buffer)

// Create a new cpio archive.
w := cpio.NewWriter(buf)

// Add some files to the archive.
var files = []struct {
  Name, Body string
}{
  {"readme.txt", "This archive contains some text files."},
  {"gopher.txt", "Gopher names:\nGeorge\nGeoffrey\nGonzo"},
  {"todo.txt", "Get animal handling license."},
}
for _, file := range files {
  hdr := &cpio.Header{
    Name: file.Name,
    Mode: 0600,
    Size: int64(len(file.Body)),
  }
  if err := w.WriteHeader(hdr); err != nil {
    log.Fatalln(err)
  }
  if _, err := w.Write([]byte(file.Body)); err != nil {
    log.Fatalln(err)
  }
}
// Make sure to check the error on Close.
if err := w.Close(); err != nil {
  log.Fatalln(err)
}

// Open the cpio archive for reading.
b := bytes.NewReader(buf.Bytes())
r := cpio.NewReader(b)

// Iterate through the files in the archive.
for {
  hdr, err := r.Next()
  if err == io.EOF {
    // end of cpio archive
    break
  }
  if err != nil {
    log.Fatalln(err)
  }
  fmt.Printf("Contents of %s:\n", hdr.Name)
  if _, err := io.Copy(os.Stdout, r); err != nil {
    log.Fatalln(err)
  }
  fmt.Println()
}
```
