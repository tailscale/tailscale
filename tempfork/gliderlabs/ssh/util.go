package ssh

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"

	"github.com/tailscale/golang-x-crypto/ssh"
)

func generateSigner() (ssh.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(key)
}

func parsePtyRequest(payload []byte) (pty Pty, ok bool) {
	// See https://datatracker.ietf.org/doc/html/rfc4254#section-6.2
	// 6.2.  Requesting a Pseudo-Terminal
	// A pseudo-terminal can be allocated for the session by sending the
	// following message.
	//    byte      SSH_MSG_CHANNEL_REQUEST
	//    uint32    recipient channel
	//    string    "pty-req"
	//    boolean   want_reply
	//    string    TERM environment variable value (e.g., vt100)
	//    uint32    terminal width, characters (e.g., 80)
	//    uint32    terminal height, rows (e.g., 24)
	//    uint32    terminal width, pixels (e.g., 640)
	//    uint32    terminal height, pixels (e.g., 480)
	//    string    encoded terminal modes

	// The payload starts from the TERM variable.
	term, rem, ok := parseString(payload)
	if !ok {
		return
	}
	win, rem, ok := parseWindow(rem)
	if !ok {
		return
	}
	modes, ok := parseTerminalModes(rem)
	if !ok {
		return
	}
	pty = Pty{
		Term:   term,
		Window: win,
		Modes:  modes,
	}
	return
}

func parseTerminalModes(in []byte) (modes ssh.TerminalModes, ok bool) {
	// See https://datatracker.ietf.org/doc/html/rfc4254#section-8
	// 8.  Encoding of Terminal Modes
	//
	//  All 'encoded terminal modes' (as passed in a pty request) are encoded
	//  into a byte stream.  It is intended that the coding be portable
	//  across different environments.  The stream consists of opcode-
	//  argument pairs wherein the opcode is a byte value.  Opcodes 1 to 159
	//  have a single uint32 argument.  Opcodes 160 to 255 are not yet
	//  defined, and cause parsing to stop (they should only be used after
	//  any other data).  The stream is terminated by opcode TTY_OP_END
	//  (0x00).
	//
	//  The client SHOULD put any modes it knows about in the stream, and the
	//  server MAY ignore any modes it does not know about.  This allows some
	//  degree of machine-independence, at least between systems that use a
	//  POSIX-like tty interface.  The protocol can support other systems as
	//  well, but the client may need to fill reasonable values for a number
	//  of parameters so the server pty gets set to a reasonable mode (the
	//  server leaves all unspecified mode bits in their default values, and
	//  only some combinations make sense).
	_, rem, ok := parseUint32(in)
	if !ok {
		return
	}
	const ttyOpEnd = 0
	for len(rem) > 0 {
		if modes == nil {
			modes = make(ssh.TerminalModes)
		}
		code := uint8(rem[0])
		rem = rem[1:]
		if code == ttyOpEnd || code > 160 {
			break
		}
		var val uint32
		val, rem, ok = parseUint32(rem)
		if !ok {
			return
		}
		modes[code] = val
	}
	ok = true
	return
}

func parseWindow(s []byte) (win Window, rem []byte, ok bool) {
	// See https://datatracker.ietf.org/doc/html/rfc4254#section-6.7
	// 6.7. Window Dimension Change Message
	// When the window (terminal) size changes on the client side, it MAY
	// send a message to the other side to inform it of the new dimensions.

	//   byte      SSH_MSG_CHANNEL_REQUEST
	//   uint32    recipient channel
	//   string    "window-change"
	//   boolean   FALSE
	//   uint32    terminal width, columns
	//   uint32    terminal height, rows
	//   uint32    terminal width, pixels
	//   uint32    terminal height, pixels
	wCols, rem, ok := parseUint32(s)
	if !ok {
		return
	}
	hRows, rem, ok := parseUint32(rem)
	if !ok {
		return
	}
	wPixels, rem, ok := parseUint32(rem)
	if !ok {
		return
	}
	hPixels, rem, ok := parseUint32(rem)
	if !ok {
		return
	}
	win = Window{
		Width:        int(wCols),
		Height:       int(hRows),
		WidthPixels:  int(wPixels),
		HeightPixels: int(hPixels),
	}
	return
}

func parseString(in []byte) (out string, rem []byte, ok bool) {
	length, rem, ok := parseUint32(in)
	if uint32(len(rem)) < length || !ok {
		ok = false
		return
	}
	out, rem = string(rem[:length]), rem[length:]
	ok = true
	return
}

func parseUint32(in []byte) (uint32, []byte, bool) {
	if len(in) < 4 {
		return 0, nil, false
	}
	return binary.BigEndian.Uint32(in), in[4:], true
}
