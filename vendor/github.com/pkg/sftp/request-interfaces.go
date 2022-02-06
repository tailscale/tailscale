package sftp

import (
	"io"
	"os"
)

// WriterAtReaderAt defines the interface to return when a file is to
// be opened for reading and writing
type WriterAtReaderAt interface {
	io.WriterAt
	io.ReaderAt
}

// Interfaces are differentiated based on required returned values.
// All input arguments are to be pulled from Request (the only arg).

// The Handler interfaces all take the Request object as its only argument.
// All the data you should need to handle the call are in the Request object.
// The request.Method attribute is initially the most important one as it
// determines which Handler gets called.

// FileReader should return an io.ReaderAt for the filepath
// Note in cases of an error, the error text will be sent to the client.
// Called for Methods: Get
type FileReader interface {
	Fileread(*Request) (io.ReaderAt, error)
}

// FileWriter should return an io.WriterAt for the filepath.
//
// The request server code will call Close() on the returned io.WriterAt
// ojbect if an io.Closer type assertion succeeds.
// Note in cases of an error, the error text will be sent to the client.
// Note when receiving an Append flag it is important to not open files using
// O_APPEND if you plan to use WriteAt, as they conflict.
// Called for Methods: Put, Open
type FileWriter interface {
	Filewrite(*Request) (io.WriterAt, error)
}

// OpenFileWriter is a FileWriter that implements the generic OpenFile method.
// You need to implement this optional interface if you want to be able
// to read and write from/to the same handle.
// Called for Methods: Open
type OpenFileWriter interface {
	FileWriter
	OpenFile(*Request) (WriterAtReaderAt, error)
}

// FileCmder should return an error
// Note in cases of an error, the error text will be sent to the client.
// Called for Methods: Setstat, Rename, Rmdir, Mkdir, Link, Symlink, Remove
type FileCmder interface {
	Filecmd(*Request) error
}

// PosixRenameFileCmder is a FileCmder that implements the PosixRename method.
// If this interface is implemented PosixRename requests will call it
// otherwise they will be handled in the same way as Rename
type PosixRenameFileCmder interface {
	FileCmder
	PosixRename(*Request) error
}

// StatVFSFileCmder is a FileCmder that implements the StatVFS method.
// You need to implement this interface if you want to handle statvfs requests.
// Please also be sure that the statvfs@openssh.com extension is enabled
type StatVFSFileCmder interface {
	FileCmder
	StatVFS(*Request) (*StatVFS, error)
}

// FileLister should return an object that fulfils the ListerAt interface
// Note in cases of an error, the error text will be sent to the client.
// Called for Methods: List, Stat, Readlink
type FileLister interface {
	Filelist(*Request) (ListerAt, error)
}

// LstatFileLister is a FileLister that implements the Lstat method.
// If this interface is implemented Lstat requests will call it
// otherwise they will be handled in the same way as Stat
type LstatFileLister interface {
	FileLister
	Lstat(*Request) (ListerAt, error)
}

// RealPathFileLister is a FileLister that implements the Realpath method.
// We use "/" as start directory for relative paths, implementing this
// interface you can customize the start directory.
// You have to return an absolute POSIX path.
type RealPathFileLister interface {
	FileLister
	RealPath(string) string
}

// NameLookupFileLister is a FileLister that implmeents the LookupUsername and LookupGroupName methods.
// If this interface is implemented, then longname ls formatting will use these to convert usernames and groupnames.
type NameLookupFileLister interface {
	FileLister
	LookupUserName(string) string
	LookupGroupName(string) string
}

// ListerAt does for file lists what io.ReaderAt does for files.
// ListAt should return the number of entries copied and an io.EOF
// error if at end of list. This is testable by comparing how many you
// copied to how many could be copied (eg. n < len(ls) below).
// The copy() builtin is best for the copying.
// Note in cases of an error, the error text will be sent to the client.
type ListerAt interface {
	ListAt([]os.FileInfo, int64) (int, error)
}

// TransferError is an optional interface that readerAt and writerAt
// can implement to be notified about the error causing Serve() to exit
// with the request still open
type TransferError interface {
	TransferError(err error)
}
