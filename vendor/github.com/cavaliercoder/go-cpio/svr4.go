package cpio

import (
	"bytes"
	"fmt"
	"io"
	"strconv"
	"time"
)

const (
	svr4MaxNameSize = 4096 // MAX_PATH
	svr4MaxFileSize = 4294967295
)

var svr4Magic = []byte{0x30, 0x37, 0x30, 0x37, 0x30, 0x31} // 070701

func readHex(s string) int64 {
	// errors are ignored and 0 returned
	i, _ := strconv.ParseInt(s, 16, 64)
	return i
}

func writeHex(b []byte, i int64) {
	// i needs to be in range of uint32
	copy(b, fmt.Sprintf("%08X", i))
}

func readSVR4Header(r io.Reader) (*Header, error) {
	var buf [110]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return nil, err
	}

	// TODO: check endianness

	// check magic
	hasCRC := false
	if !bytes.HasPrefix(buf[:], svr4Magic[:5]) {
		return nil, ErrHeader
	}
	if buf[5] == 0x32 { // '2'
		hasCRC = true
	} else if buf[5] != 0x31 { // '1'
		return nil, ErrHeader
	}

	asc := string(buf[:])
	hdr := &Header{}

	hdr.Inode = readHex(asc[6:14])
	hdr.Mode = FileMode(readHex(asc[14:22]))
	hdr.UID = int(readHex(asc[22:30]))
	hdr.GID = int(readHex(asc[30:38]))
	hdr.Links = int(readHex(asc[38:46]))
	hdr.ModTime = time.Unix(readHex(asc[46:54]), 0)
	hdr.Size = readHex(asc[54:62])
	if hdr.Size > svr4MaxFileSize {
		return nil, ErrHeader
	}
	nameSize := readHex(asc[94:102])
	if nameSize < 1 || nameSize > svr4MaxNameSize {
		return nil, ErrHeader
	}
	hdr.Checksum = Checksum(readHex(asc[102:110]))
	if !hasCRC && hdr.Checksum != 0 {
		return nil, ErrHeader
	}

	name := make([]byte, nameSize)
	if _, err := io.ReadFull(r, name); err != nil {
		return nil, err
	}
	hdr.Name = string(name[:nameSize-1])
	if hdr.Name == headerEOF {
		return nil, io.EOF
	}

	// store padding between end of file and next header
	hdr.pad = (4 - (hdr.Size % 4)) % 4

	// skip to end of header/start of file
	pad := (4 - (len(buf)+len(name))%4) % 4
	if pad > 0 {
		if _, err := io.ReadFull(r, buf[:pad]); err != nil {
			return nil, err
		}
	}

	// read link name
	if hdr.Mode&^ModePerm == ModeSymlink {
		if hdr.Size < 1 || hdr.Size > svr4MaxNameSize {
			return nil, ErrHeader
		}
		b := make([]byte, hdr.Size)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		hdr.Linkname = string(b)
		hdr.Size = 0
	}

	return hdr, nil
}

func writeSVR4Header(w io.Writer, hdr *Header) (pad int64, err error) {
	var hdrBuf [110]byte
	for i := 0; i < len(hdrBuf); i++ {
		hdrBuf[i] = '0'
	}
	magic := svr4Magic
	if hdr.Checksum != 0 {
		magic[5] = 0x32
	}
	copy(hdrBuf[:], magic)
	writeHex(hdrBuf[6:14], hdr.Inode)
	writeHex(hdrBuf[14:22], int64(hdr.Mode))
	writeHex(hdrBuf[22:30], int64(hdr.UID))
	writeHex(hdrBuf[30:38], int64(hdr.GID))
	writeHex(hdrBuf[38:46], int64(hdr.Links))
	if !hdr.ModTime.IsZero() {
		writeHex(hdrBuf[46:54], hdr.ModTime.Unix())
	}
	writeHex(hdrBuf[54:62], hdr.Size)
	writeHex(hdrBuf[94:102], int64(len(hdr.Name)+1))
	if hdr.Checksum != 0 {
		writeHex(hdrBuf[102:110], int64(hdr.Checksum))
	}

	// write header
	_, err = w.Write(hdrBuf[:])
	if err != nil {
		return
	}

	// write filename
	_, err = io.WriteString(w, hdr.Name+"\x00")
	if err != nil {
		return
	}

	// pad to end of filename
	npad := (4 - ((len(hdrBuf) + len(hdr.Name) + 1) % 4)) % 4
	_, err = w.Write(zeroBlock[:npad])
	if err != nil {
		return
	}

	// compute padding to end of file
	pad = (4 - (hdr.Size % 4)) % 4
	return
}
