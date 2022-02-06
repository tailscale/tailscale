// Package sdnotify implements systemd readiness notifications as described in
// https://www.freedesktop.org/software/systemd/man/sd_notify.html.
package sdnotify

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

// Socket is the predefined systemd notification socket environment variable.
const Socket = "NOTIFY_SOCKET"

// Common notification values. For a description of each, see:
// https://www.freedesktop.org/software/systemd/man/sd_notify.html#Description.
const (
	Ready     = "READY=1"
	Reloading = "RELOADING=1"
	Stopping  = "STOPPING=1"
)

// Statusf creates a formatted STATUS notification with the input format string
// and values.
func Statusf(format string, v ...interface{}) string {
	return fmt.Sprintf("STATUS=%s", fmt.Sprintf(format, v...))
}

// A Notifier can notify systemd of service status and readiness. Any methods
// called on a nil Notifier will result in a no-op, allowing graceful
// functionality degradation when a Go program is not running under systemd
// supervision.
type Notifier struct {
	wc io.WriteCloser
}

// New creates a Notifier which sends notifications to the UNIX socket specified
// by the NOTIFY_SOCKET environment variable. See Open for more details.
func New() (*Notifier, error) {
	s := os.Getenv(Socket)
	if s == "" {
		// Don't bother stat'ing an empty socket, just return now.
		return nil, os.ErrNotExist
	}

	return Open(s)
}

// Open creates a Notifier which sends notifications to the UNIX socket
// specified by sock.
//
// If sock does not exist or is unset (meaning the service is not running under
// systemd supervision, or is not using systemd unit Type=notify), Open will
// return an error which can be checked with 'errors.Is(err, os.ErrNotExist)'.
// Calling any of the resulting nil Notifier's methods will result in a no-op.
func Open(sock string) (*Notifier, error) {
	// Don't stat Linux abstract namespace sockets, as would be created with a
	// net.ListenPacket with no path.
	if !strings.HasPrefix(sock, "@") {
		if _, err := os.Stat(sock); err != nil {
			return nil, fmt.Errorf("failed to stat notify socket: %w", err)
		}
	}

	c, err := net.Dial("unixgram", sock)
	if err != nil {
		return nil, err
	}

	return &Notifier{wc: c}, nil
}

// Notify sends zero or more notifications to systemd. See the package constants
// for a list of common notifications or use the Statusf function to create a
// STATUS notification.
//
// For advanced use cases, see:
// https://www.freedesktop.org/software/systemd/man/sd_notify.html#Description.
//
// If n is nil or no strings are specified, Notify is a no-op.
func (n *Notifier) Notify(s ...string) error {
	if n == nil || len(s) == 0 {
		return nil
	}

	_, err := io.WriteString(n.wc, strings.Join(s, "\n"))
	return err
}

// Close closes the Notifier's socket. If n is nil, Close is a no-op.
func (n *Notifier) Close() error {
	if n == nil {
		return nil
	}

	return n.wc.Close()
}
