// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.


/*
Package term implements a subset of the C termios library to interface with Terminals.

This package allows the caller to get and set most Terminal capabilites
and sizes as well as create PTYs to enable writing things like script,
screen, tmux, and expect.

The Termios type is used for setting/getting Terminal capabilities while
the PTY type is used for handling virtual terminals.

Currently this part of this lib is Linux specific.

Also implements a simple version of readline in pure Go and some Stringers
for terminal colors and attributes.
*/
package term

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// IOCTL terminal stuff.
const (
	TCGETS     = 0x5401     // TCGETS get terminal attributes
	TCSETS     = 0x5402     // TCSETS set terminal attributes
	TIOCGWINSZ = 0x5413     // TIOCGWINSZ used to get the terminal window size
	TIOCSWINSZ = 0x5414     // TIOCSWINSZ used to set the terminal window size
	TIOCGPTN   = 0x80045430 // TIOCGPTN IOCTL used to get the PTY number
	TIOCSPTLCK = 0x40045431 // TIOCSPTLCK IOCT used to lock/unlock PTY
	CBAUD      = 0010017    // CBAUD Serial speed settings
	CBAUDEX    = 0010000    // CBAUDX Serial speed settings
)

// INPUT handling terminal flags
// see 'man stty' for further info about most of the constants
const (
	IGNBRK  = 0000001 // IGNBRK ignore break characters
	BRKINT  = 0000002 // BRKINT Break genereates an interrupt signal
	IGNPAR  = 0000004 // IGNPAR Ignore characters with parity errors
	PARMRK  = 0000010 // PARMRK Mark parity errors byte{ff,0}
	INPCK   = 0000020 // INPCK enable parity checking
	ISTRIP  = 0000040 // ISTRIP Clear 8th bit of input characters
	INLCR   = 0000100 // INLCR Translate LF => CR
	IGNCR   = 0000200 // IGNCR Ignore Carriage Return
	ICRNL   = 0000400 // ICRNL Translate CR => NL
	IUCLC   = 0001000 // IUCLC Translate uppercase to lowercase
	IXON    = 0002000 // IXON Enable flow control
	IXANY   = 0004000 // IXANY let any char restart input
	IXOFF   = 0010000 // IXOFF start sending start/stop chars
	IMAXBEL = 0020000 // IMAXBEL Sound the bell and skip flushing input buffer
	IUTF8   = 0040000 // IUTF8 assume input being utf-8
)

// OUTPUT treatment terminal flags
const (
	OPOST  = 0000001 // OPOST post process output
	OLCUC  = 0000002 // OLCUC translate lower case to upper case
	ONLCR  = 0000004 // ONLCR Map NL -> CR-NL
	OCRNL  = 0000010 // OCRNL Map CR -> NL
	ONOCR  = 0000020 // ONOCR No CR at col 0
	ONLRET = 0000040 // ONLRET NL also do CR
	OFILL  = 0000100 // OFILL Fillchar for delay
	OFDEL  = 0000200 // OFDEL use delete instead of null
)

// TERM control modes.
const (
	CSIZE  = 0000060 // CSIZE used as mask when setting character size
	CS5    = 0000000 // CS5 char size 5bits
	CS6    = 0000020 // CS6 char size 6bits
	CS7    = 0000040 // CS7 char size 7bits
	CS8    = 0000060 // CS8 char size 8bits
	CSTOPB = 0000100 // CSTOPB two stop bits
	CREAD  = 0000200 // CREAD enable input
	PARENB = 0000400 // PARENB generate and expect parity bit
	PARODD = 0001000 // PARODD set odd parity
	HUPCL  = 0002000 // HUPCL send HUP when last process closes term
	CLOCAL = 0004000 // CLOCAL no modem control signals
)

// TERM modes
const (
	ISIG    = 0000001 // ISIG enable Interrupt,quit and suspend chars
	ICANON  = 0000002 // ICANON enable erase,kill ,werase and rprnt chars
	XCASE   = 0000004 // XCASE preceedes all uppercase chars with '\'
	ECHO    = 0000010 // ECHO echo input characters
	ECHOE   = 0000020 // ECHOE erase => BS - SPACE - BS
	ECHOK   = 0000040 // ECHOK add newline after kill char
	ECHONL  = 0000100 // ECHONL echo NL even without other characters
	NOFLSH  = 0000200 // NOFLSH no flush after interrupt and kill characters
	TOSTOP  = 0000400 // TOSTOP stop BG jobs trying to write to term
	ECHOCTL = 0001000 // ECHOCTL will echo control characters as ^c
	ECHOPRT = 0002000 // ECHOPRT will print erased characters between \ /
	ECHOKE  = 0004000 // ECHOKE kill all line considering ECHOPRT and ECHOE flags
	IEXTEN  = 0100000 // IEXTEN enable non POSIX special characters
)

// Control characters
const (
	VINTR    = 0  // VINTR 		char will send an interrupt signal
	VQUIT    = 1  // VQUIT 		char will send a quit signal
	VERASE   = 2  // VEREASE 	char will erase last typed char
	VKILL    = 3  // VKILL 		char will erase current line
	VEOF     = 4  // VEOF 		char will send EOF
	VTIME    = 5  // VTIME 		set read timeout in tenths of seconds
	VMIN     = 6  // VMIN 		set min characters for a complete read
	VSWTC    = 7  // VSWTC 		char will switch to a different shell layer
	VSTART   = 8  // VSTART 	char will restart output after stopping it
	VSTOP    = 9  // VSTOP 		char will stop output
	VSUSP    = 10 // VSUSP 		char will send a stop signal
	VEOL     = 11 // VEOL 		char will end the line
	VREPRINT = 12 // VREPRINT will redraw the current line
	VDISCARD = 13 // VDISCARD
	VWERASE  = 14 // VWERASE 	char will erase last word typed
	VLNEXT   = 15 // VLNEXT 	char will enter the next char quoted
	VEOL2    = 16 // VEOL2 		char alternate to end line
	tNCCS    = 32 // tNCCS    Termios CC size
)

// Termios merge of the C Terminal and Kernel termios structs.
type Termios struct {
	Iflag  uint32      // Iflag Handles the different Input modes
	Oflag  uint32      // Oflag For the different Output modes
	Cflag  uint32      // Cflag Control modes
	Lflag  uint32      // Lflag Local modes
	Line   byte        // Line
	Cc     [tNCCS]byte // Cc Control characters. How to handle special Characters eg. Backspace being ^H or ^? and so on
	Ispeed uint32      // Ispeed Hardly ever used speed of terminal
	Ospeed uint32      // Ospeed "
	Wz     Winsize     // Wz Terminal size information.
}

// Winsize handle the terminal window size.
type Winsize struct {
	WsRow    uint16 // WsRow 		Terminal number of rows
	WsCol    uint16 // WsCol 		Terminal number of columns
	WsXpixel uint16 // WsXpixel Terminal width in pixels
	WsYpixel uint16 // WsYpixel Terminal height in pixels
}

// PTY the PTY Master/Slave are always bundled together so makes sense to bundle here too.
//
// Slave  - implements the virtual terminal functionality and the place you connect client applications
// Master - Things written to the Master are forwarded to the Slave terminal and the other way around.
//					This gives reading from Master would give you nice line-by-line with no strange characters in
//					Cooked() Mode and every char in Raw() mode.
//
// Since Slave is a virtual terminal it depends on the terminal settings ( in this lib the Termios ) what
// and when data is forwarded through the terminal.
//
// See 'man pty' for further info
type PTY struct {
	Master *os.File // Master The Master part of the PTY
	Slave  *os.File // Slave The Slave part of the PTY
}

// Raw Sets terminal t to raw mode.
// This gives that the terminal will do the absolut minimal of processing, pretty much send everything through.
// This is normally what Shells and such want since they have their own readline and movement code.
func (t *Termios) Raw() {
	t.Iflag &^= IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON
	// t.Iflag &^= BRKINT | ISTRIP | ICRNL | IXON // Stevens RAW
	t.Oflag &^= OPOST
	t.Lflag &^= ECHO | ECHONL | ICANON | ISIG | IEXTEN
	t.Cflag &^= CSIZE | PARENB
	t.Cflag |= CS8
	t.Cc[VMIN] = 1
	t.Cc[VTIME] = 0
}

// Cook Set the Terminal to Cooked mode.
// In this mode the Terminal process the information before sending it on to the application.
func (t *Termios) Cook() {
	t.Iflag |= BRKINT | IGNPAR | ISTRIP | ICRNL | IXON
	t.Oflag |= OPOST
	t.Lflag |= ISIG | ICANON
}

// Sane reset Term to sane values.
// Should be pretty much what the shell command "reset" does to the terminal.
func (t *Termios) Sane() {
	t.Iflag &^= IGNBRK | INLCR | IGNCR | IUTF8 | IXOFF | IUCLC | IXANY
	t.Iflag |= BRKINT | ICRNL | IMAXBEL
	t.Oflag |= OPOST | ONLCR
	t.Oflag &^= OLCUC | OCRNL | ONOCR | ONLRET
	t.Cflag |= CREAD
}

// Set Sets terminal t attributes on file.
func (t *Termios) Set(file *os.File) error {
	fd := file.Fd()
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(TCSETS), uintptr(unsafe.Pointer(t)))
	if errno != 0 {
		return errno
	}
	return nil
}

// Attr Gets (terminal related) attributes from file.
func Attr(file *os.File) (Termios, error) {
	var t Termios
	fd := file.Fd()
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(TCGETS), uintptr(unsafe.Pointer(&t)))
	if errno != 0 {
		return t, errno
	}
	t.Ispeed &= CBAUD | CBAUDEX
	t.Ospeed &= CBAUD | CBAUDEX
	return t, nil
}

// Isatty returns true if file is a tty.
func Isatty(file *os.File) bool {
	_, err := Attr(file)
	return err == nil
}

// GetPass reads password from a TTY with no echo.
func GetPass(prompt string, f *os.File, pbuf []byte) ([]byte, error) {
	t, err := Attr(f)
	if err != nil {
		return nil, err
	}
	defer t.Set(f)
	noecho := t
	noecho.Lflag = noecho.Lflag &^ ECHO
	if err := noecho.Set(f); err != nil {
		return nil, err
	}
	b := make([]byte, 1, 1)
	i := 0
	if _, err := f.Write([]byte(prompt)); err != nil {
		return nil, err
	}
	for ; i < len(pbuf); i++ {
		if _, err := f.Read(b); err != nil {
			b[0] = 0
			clearbuf(pbuf[:i+1])
		}
		if b[0] == '\n' || b[0] == '\r' {
			return pbuf[:i], nil
		}
		pbuf[i] = b[0]
		b[0] = 0
	}
	clearbuf(pbuf[:i+1])
	return nil, errors.New("ran out of bufferspace")
}

// clearbuf clears out the buffer incase we couldn't read the full password.
func clearbuf(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// GetChar reads a single byte.
func GetChar(f *os.File) (b byte, err error) {
	bs := make([]byte, 1, 1)
	if _, err = f.Read(bs); err != nil {
		return 0, err
	}
	return bs[0], err
}

// PTSName return the name of the pty.
func (p *PTY) PTSName() (string, error) {
	n, err := p.PTSNumber()
	if err != nil {
		return "", err
	}
	return "/dev/pts/" + strconv.Itoa(int(n)), nil
}

// PTSNumber return the pty number.
func (p *PTY) PTSNumber() (uint, error) {
	var ptyno uint
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(p.Master.Fd()), uintptr(TIOCGPTN), uintptr(unsafe.Pointer(&ptyno)))
	if errno != 0 {
		return 0, errno
	}
	return ptyno, nil
}

// Winsz Fetches the current terminal windowsize.
// example handling changing window sizes with PTYs:
//
// import "os"
// import "os/signal"
//
// var sig = make(chan os.Signal,2) 		// Channel to listen for UNIX SIGNALS on
// signal.Notify(sig, syscall.SIGWINCH) // That'd be the window changing
//
// for {
//	<-sig
// 	term.Winsz(os.Stdin)			// We got signaled our terminal changed size so we read in the new value
//  term.Setwinsz(pty.Slave) // Copy it to our virtual Terminal
// }
func (t *Termios) Winsz(file *os.File) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(file.Fd()), uintptr(TIOCGWINSZ), uintptr(unsafe.Pointer(&t.Wz)))
	if errno != 0 {
		return errno
	}
	return nil
}

// Setwinsz Sets the terminal window size.
func (t *Termios) Setwinsz(file *os.File) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(file.Fd()), uintptr(TIOCSWINSZ), uintptr(unsafe.Pointer(&t.Wz)))
	if errno != 0 {
		return errno
	}
	return nil
}

// OpenPTY Creates a new Master/Slave PTY pair.
func OpenPTY() (*PTY, error) {
	// Opening ptmx gives you the FD of a brand new PTY
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	// unlock pty slave
	var unlock int // 0 => Unlock
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(master.Fd()), uintptr(TIOCSPTLCK), uintptr(unsafe.Pointer(&unlock))); errno != 0 {
		master.Close()
		return nil, errno
	}

	// get path of pts slave
	pty := &PTY{Master: master}
	slaveStr, err := pty.PTSName()
	if err != nil {
		master.Close()
		return nil, err
	}

	// open pty slave
	pty.Slave, err = os.OpenFile(slaveStr, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		master.Close()
		return nil, err
	}

	return pty, nil
}

// Close closes the PTYs that OpenPTY created.
func (p *PTY) Close() error {
	slaveErr := errors.New("Slave FD nil")
	if p.Slave != nil {
		slaveErr = p.Slave.Close()
	}
	masterErr := errors.New("Master FD nil")
	if p.Master != nil {
		masterErr = p.Master.Close()
	}
	if slaveErr != nil || masterErr != nil {
		var errs []string
		if slaveErr != nil {
			errs = append(errs, "Slave: "+slaveErr.Error())
		}
		if masterErr != nil {
			errs = append(errs, "Master: "+masterErr.Error())
		}
		return errors.New(strings.Join(errs, " "))
	}
	return nil
}

// ReadByte implements the io.ByteReader interface to read single char from the PTY.
func (p *PTY) ReadByte() (byte, error) {
	bs := make([]byte, 1, 1)
	_, err := p.Master.Read(bs)
	return bs[0], err
}

// GetChar fine old getchar() for a PTY.
func (p *PTY) GetChar() (byte, error) {
	return p.ReadByte()
}
