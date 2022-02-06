// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package expect is a Go version of the classic TCL Expect.
package expect

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/goterm/term"
	"golang.org/x/crypto/ssh"
)

// DefaultTimeout is the default Expect timeout.
const DefaultTimeout = 60 * time.Second

const (
	checkDuration     = 2 * time.Second // checkDuration how often to check for new output.
	defaultBufferSize = 8192            // defaultBufferSize is the default io buffer size.
)

// Status contains an errormessage and a status code.
type Status struct {
	code Code
	msg  string
}

// NewStatus creates a Status with the provided code and message.
func NewStatus(code Code, msg string) *Status {
	return &Status{code, msg}
}

// NewStatusf returns a Status with the provided code and a formatted message.
func NewStatusf(code Code, format string, a ...interface{}) *Status {
	return NewStatus(code, fmt.Sprintf(fmt.Sprintf(format, a...)))
}

// Err is a helper to handle errors.
func (s *Status) Err() error {
	if s == nil || s.code == StatusOK {
		return nil
	}
	return s
}

// Error is here to adhere to the error interface.
func (s *Status) Error() string {
	return s.msg
}

// Option represents one Expecter option.
type Option func(*GExpect) Option

// CheckDuration changes the default duration checking for new incoming data.
func CheckDuration(d time.Duration) Option {
	return func(e *GExpect) Option {
		prev := e.chkDuration
		e.chkDuration = d
		return CheckDuration(prev)
	}
}

// SendTimeout set timeout for Send commands
func SendTimeout(timeout time.Duration) Option {
	return func(e *GExpect) Option {
		prev := e.sendTimeout
		e.sendTimeout = timeout
		return SendTimeout(prev)
	}
}

// Verbose enables/disables verbose logging of matches and sends.
func Verbose(v bool) Option {
	return func(e *GExpect) Option {
		prev := e.verbose
		e.verbose = v
		return Verbose(prev)
	}
}

// VerboseWriter sets an alternate destination for verbose logs.
func VerboseWriter(w io.Writer) Option {
	return func(e *GExpect) Option {
		prev := e.verboseWriter
		e.verboseWriter = w
		return VerboseWriter(prev)
	}
}

// Tee duplicates all of the spawned process's output to the given writer and
// closes the writer when complete. Writes occur from another thread, so
// synchronization may be necessary.
func Tee(w io.WriteCloser) Option {
	return func(e *GExpect) Option {
		prev := e.teeWriter
		e.teeWriter = w
		return Tee(prev)
	}
}

// NoCheck turns off the Expect alive checks.
func NoCheck() Option {
	return changeChk(func(*GExpect) bool {
		return true
	})
}

// DebugCheck adds logging to the check function.
// The check function for the spawners are called at creation/timeouts and I/O so can
// be usable for printing current state during debugging.
func DebugCheck(l *log.Logger) Option {
	lg := log.Printf
	if l != nil {
		lg = l.Printf
	}
	return func(e *GExpect) Option {
		prev := e.chk
		e.chkMu.Lock()
		e.chk = func(ge *GExpect) bool {
			res := prev(ge)
			ge.mu.Lock()
			lg("chk: %t, ge: %v", res, ge)
			ge.mu.Unlock()
			return res
		}
		e.chkMu.Unlock()
		return changeChk(prev)
	}
}

// ChangeCheck changes the Expect check function.
func ChangeCheck(f func() bool) Option {
	return changeChk(func(*GExpect) bool {
		return f()
	})
}

func changeChk(f func(*GExpect) bool) Option {
	return func(e *GExpect) Option {
		prev := e.chk
		e.chkMu.Lock()
		e.chk = f
		e.chkMu.Unlock()
		return changeChk(prev)
	}
}

// SetEnv sets the environmental variables of the spawned process.
func SetEnv(env []string) Option {
	return func(e *GExpect) Option {
		prev := e.cmd.Env
		e.cmd.Env = env
		return SetEnv(prev)
	}
}

// SetSysProcAttr sets the SysProcAttr syscall values for the spawned process.
// Because this modifies cmd, it will only work with the process spawners
// and not effect the GExpect option method.
func SetSysProcAttr(args *syscall.SysProcAttr) Option {
	return func(e *GExpect) Option {
		prev := e.cmd.SysProcAttr
		e.cmd.SysProcAttr = args
		return SetSysProcAttr(prev)
	}
}

// PartialMatch enables/disables the returning of unmatched buffer so that consecutive expect call works.
func PartialMatch(v bool) Option {
	return func(e *GExpect) Option {
		prev := e.partialMatch
		e.partialMatch = v
		return PartialMatch(prev)
	}
}

// BufferSize sets the size of receive buffer in bytes.
func BufferSize(bufferSize int) Option {
	return func(e *GExpect) Option {
		e.bufferSizeIsSet = true
		prev := e.bufferSize
		e.bufferSize = bufferSize
		return BufferSize(prev)
	}
}

// BatchCommands.
const (
	// BatchSend for invoking Send in a batch
	BatchSend = iota
	// BatchExpect for invoking Expect in a batch
	BatchExpect
	// BatchSwitchCase for invoking ExpectSwitchCase in a batch
	BatchSwitchCase
	// BatchSendSignal for invoking SendSignal in a batch.
	BatchSendSignal
)

// TimeoutError is the error returned by all Expect functions upon timer expiry.
type TimeoutError int

// Error implements the Error interface.
func (t TimeoutError) Error() string {
	return fmt.Sprintf("expect: timer expired after %d seconds", time.Duration(t)/time.Second)
}

// BatchRes returned from ExpectBatch for every Expect command executed.
type BatchRes struct {
	// Idx is used to match the result with the []Batcher commands sent in.
	Idx int
	// Out output buffer for the expect command at Batcher[Idx].
	Output string
	// Match regexp matches for expect command at Batcher[Idx].
	Match []string
}

// Batcher interface is used to make it more straightforward and readable to create
// batches of Expects.
//
// var batch = []Batcher{
//	&BExpT{"password",8},
//	&BSnd{"password\n"},
//	&BExp{"olakar@router>"},
//	&BSnd{ "show interface description\n"},
//	&BExp{ "olakar@router>"},
// }
//
// var batchSwCaseReplace = []Batcher{
//	&BCasT{[]Caser{
//		&BCase{`([0-9]) -- .*\(MASTER\)`, `\1` + "\n"}}, 1},
//	&BExp{`prompt/>`},
// }
type Batcher interface {
	// cmd returns the Batch command.
	Cmd() int
	// Arg returns the command argument.
	Arg() string
	// Timeout returns the timeout duration for the command , <0 gives default value.
	Timeout() time.Duration
	// Cases returns the Caser structure for SwitchCase commands.
	Cases() []Caser
}

// BSig implements the Batcher interface for SendSignal commands.
type BSig struct {
	// S contains the signal.
	S syscall.Signal
}

// Cmd returns the SendSignal command (BatchSendSignal).
func (bs *BSig) Cmd() int {
	return BatchSendSignal
}

// Arg returns the signal integer.
func (bs *BSig) Arg() string {
	return strconv.Itoa(int(bs.S))
}

// Timeout always returns 0 for BSig.
func (bs *BSig) Timeout() time.Duration {
	return time.Duration(0)
}

// Cases always returns nil for BSig.
func (bs *BSig) Cases() []Caser {
	return nil
}

// BExp implements the Batcher interface for Expect commands using the default timeout.
type BExp struct {
	// R contains the Expect command regular expression.
	R string
}

// Cmd returns the Expect command (BatchExpect).
func (be *BExp) Cmd() int {
	return BatchExpect
}

// Arg returns the Expect regular expression.
func (be *BExp) Arg() string {
	return be.R
}

// Timeout always returns -1 which sets it to the value used to call the ExpectBatch function.
func (be *BExp) Timeout() time.Duration {
	return -1
}

// Cases always returns nil for the Expect command.
func (be *BExp) Cases() []Caser {
	return nil
}

// BExpT implements the Batcher interface for Expect commands adding a timeout option to the BExp
// type.
type BExpT struct {
	// R contains the Expect command regular expression.
	R string
	// T holds the Expect command timeout in seconds.
	T int
}

// Cmd returns the Expect command (BatchExpect).
func (bt *BExpT) Cmd() int {
	return BatchExpect
}

// Timeout returns the timeout in seconds.
func (bt *BExpT) Timeout() time.Duration {
	return time.Duration(bt.T) * time.Second
}

// Arg returns the Expect regular expression.
func (bt *BExpT) Arg() string {
	return bt.R
}

// Cases always return nil for the Expect command.
func (bt *BExpT) Cases() []Caser {
	return nil
}

// BSnd implements the Batcher interface for Send commands.
type BSnd struct {
	S string
}

// Cmd returns the Send command(BatchSend).
func (bs *BSnd) Cmd() int {
	return BatchSend
}

// Arg returns the data to be sent.
func (bs *BSnd) Arg() string {
	return bs.S
}

// Timeout always returns 0 , Send doesn't have a timeout.
func (bs *BSnd) Timeout() time.Duration {
	return 0
}

// Cases always returns nil , not used for Send commands.
func (bs *BSnd) Cases() []Caser {
	return nil
}

// BCas implements the Batcher interface for SwitchCase commands.
type BCas struct {
	// C holds the Caser array for the SwitchCase command.
	C []Caser
}

// Cmd returns the SwitchCase command(BatchSwitchCase).
func (bc *BCas) Cmd() int {
	return BatchSwitchCase
}

// Arg returns an empty string , not used for SwitchCase.
func (bc *BCas) Arg() string {
	return ""
}

// Timeout returns -1 , setting it to the default value.
func (bc *BCas) Timeout() time.Duration {
	return -1
}

// Cases returns the Caser structure.
func (bc *BCas) Cases() []Caser {
	return bc.C
}

// BCasT implements the Batcher interfacs for SwitchCase commands, adding a timeout option
// to the BCas type.
type BCasT struct {
	// Cs holds the Caser array for the SwitchCase command.
	C []Caser
	// Tout holds the SwitchCase timeout in seconds.
	T int
}

// Timeout returns the timeout in seconds.
func (bct *BCasT) Timeout() time.Duration {
	return time.Duration(bct.T) * time.Second
}

// Cmd returns the SwitchCase command(BatchSwitchCase).
func (bct *BCasT) Cmd() int {
	return BatchSwitchCase
}

// Arg returns an empty string , not used for SwitchCase.
func (bct *BCasT) Arg() string {
	return ""
}

// Cases returns the Caser structure.
func (bct *BCasT) Cases() []Caser {
	return bct.C
}

// Tag represents the state for a Caser.
type Tag int32

const (
	// OKTag marks the desired state was reached.
	OKTag = Tag(iota)
	// FailTag means reaching this state will fail the Switch/Case.
	FailTag
	// ContinueTag will recheck for matches.
	ContinueTag
	// NextTag skips match and continues to the next one.
	NextTag
	// NoTag signals no tag was set for this case.
	NoTag
)

// OK returns the OK Tag and status.
func OK() func() (Tag, *Status) {
	return func() (Tag, *Status) {
		return OKTag, NewStatus(StatusOK, "state reached")
	}
}

// Fail returns Fail Tag and status.
func Fail(s *Status) func() (Tag, *Status) {
	return func() (Tag, *Status) {
		return FailTag, s
	}
}

// Continue returns the Continue Tag and status.
func Continue(s *Status) func() (Tag, *Status) {
	return func() (Tag, *Status) {
		return ContinueTag, s
	}
}

// Next returns the Next Tag and status.
func Next() func() (Tag, *Status) {
	return func() (Tag, *Status) {
		return NextTag, NewStatus(Unimplemented, "Next returns not implemented")
	}
}

// LogContinue logs the message and returns the Continue Tag and status.
func LogContinue(msg string, s *Status) func() (Tag, *Status) {
	return func() (Tag, *Status) {
		log.Print(msg)
		return ContinueTag, s
	}
}

// Caser is an interface for ExpectSwitchCase and Batch to be able to handle
// both the Case struct and the more script friendly BCase struct.
type Caser interface {
	// RE returns a compiled regexp
	RE() (*regexp.Regexp, error)
	// Send returns the send string
	String() string
	// Tag returns the Tag.
	Tag() (Tag, *Status)
	// Retry returns true if there are retries left.
	Retry() bool
}

// Case used by the ExpectSwitchCase to take different Cases.
// Implements the Caser interface.
type Case struct {
	// R is the compiled regexp to match.
	R *regexp.Regexp
	// S is the string to send if Regexp matches.
	S string
	// T is the Tag for this Case.
	T func() (Tag, *Status)
	// Rt specifies number of times to retry, only used for cases tagged with Continue.
	Rt int
}

// Tag returns the tag for this case.
func (c *Case) Tag() (Tag, *Status) {
	if c.T == nil {
		return NoTag, NewStatus(StatusOK, "no Tag set")
	}
	return c.T()
}

// RE returns the compiled regular expression.
func (c *Case) RE() (*regexp.Regexp, error) {
	return c.R, nil
}

// Retry decrements the Retry counter and checks if there are any retries left.
func (c *Case) Retry() bool {
	defer func() { c.Rt-- }()
	return c.Rt > 0
}

// Send returns the string to send if regexp matches
func (c *Case) String() string {
	return c.S
}

// BCase with just a string is a bit more friendly to scripting.
// Implements the Caser interface.
type BCase struct {
	// R contains the string regular expression.
	R string
	// S contains the string to be sent if R matches.
	S string
	// T contains the Tag.
	T func() (Tag, *Status)
	// Rt contains the number of retries.
	Rt int
}

// RE returns the compiled regular expression.
func (b *BCase) RE() (*regexp.Regexp, error) {
	if b.R == "" {
		return nil, nil
	}
	return regexp.Compile(b.R)
}

// Send returns the string to send.
func (b *BCase) String() string {
	return b.S
}

// Tag returns the BCase Tag.
func (b *BCase) Tag() (Tag, *Status) {
	if b.T == nil {
		return NoTag, NewStatus(StatusOK, "no Tag set")
	}
	return b.T()
}

// Retry decrements the Retry counter and checks if there are any retries left.
func (b *BCase) Retry() bool {
	b.Rt--
	return b.Rt > -1
}

// Expecter interface primarily to make testing easier.
type Expecter interface {
	// Expect reads output from a spawned session and tries matching it with the provided regular expression.
	// It returns  all output found until match.
	Expect(*regexp.Regexp, time.Duration) (string, []string, error)
	// ExpectBatch takes an array of BatchEntries and runs through them in order. For every Expect
	// command a BatchRes entry is created with output buffer and sub matches.
	// Failure of any of the batch commands will stop the execution, returning the results up to the
	// failure.
	ExpectBatch([]Batcher, time.Duration) ([]BatchRes, error)
	// ExpectSwitchCase makes it possible to Expect with multiple regular expressions and actions. Returns the
	// full output and submatches of the commands together with an index for the matching Case.
	ExpectSwitchCase([]Caser, time.Duration) (string, []string, int, error)
	// Send sends data into the spawned session.
	Send(string) error
	// Close closes the spawned session and files.
	Close() error
}

// GExpect implements the Expecter interface.
type GExpect struct {
	// pty holds the virtual terminal used to interact with the spawned commands.
	pty *term.PTY
	// cmd contains the cmd information for the spawned process.
	cmd *exec.Cmd
	ssh *ssh.Session
	// snd is the channel used by the Send command to send data into the spawned command.
	snd chan string
	// rcv is used to signal the Expect commands that new data arrived.
	rcv chan struct{}
	// chkMu lock protecting the check function.
	chkMu sync.RWMutex
	// chk contains the function to check if the spawned command is alive.
	chk func(*GExpect) bool
	// cls contains the function to close spawned command.
	cls func(*GExpect) error
	// timeout contains the default timeout for a spawned command.
	timeout time.Duration
	// sendTimeout contains the default timeout for a send command.
	sendTimeout time.Duration
	// chkDuration contains the duration between checks for new incoming data.
	chkDuration time.Duration
	// verbose enables verbose logging.
	verbose bool
	// verboseWriter if set specifies where to write verbose information.
	verboseWriter io.Writer
	// teeWriter receives a duplicate of the spawned process's output when set.
	teeWriter io.WriteCloser
	// PartialMatch enables the returning of unmatched buffer so that consecutive expect call works.
	partialMatch bool
	// bufferSize is the size of the io buffers in bytes.
	bufferSize int
	// bufferSizeIsSet tracks whether the bufferSize was set for a given GExpect instance.
	bufferSizeIsSet bool

	// mu protects the output buffer. It must be held for any operations on out.
	mu  sync.Mutex
	out bytes.Buffer
}

// String implements the stringer interface.
func (e *GExpect) String() string {
	res := fmt.Sprintf("%p: ", e)
	if e.pty != nil {
		_, name := e.pty.PTSName()
		res += fmt.Sprintf("pty: %s ", name)
	}
	switch {
	case e.cmd != nil:
		res += fmt.Sprintf("cmd: %s(%d) ", e.cmd.Path, e.cmd.Process.Pid)
	case e.ssh != nil:
		res += fmt.Sprint("ssh session ")
	}
	res += fmt.Sprintf("buf: %q", e.out.String())
	return res
}

// ExpectBatch takes an array of BatchEntry and executes them in order filling in the BatchRes
// array for any Expect command executed.
func (e *GExpect) ExpectBatch(batch []Batcher, timeout time.Duration) ([]BatchRes, error) {
	res := []BatchRes{}
	for i, b := range batch {
		switch b.Cmd() {
		case BatchExpect:
			re, err := regexp.Compile(b.Arg())
			if err != nil {
				return res, err
			}
			to := b.Timeout()
			if to < 0 {
				to = timeout
			}
			out, match, err := e.Expect(re, to)
			res = append(res, BatchRes{i, out, match})
			if err != nil {
				return res, err
			}
		case BatchSend:
			if err := e.Send(b.Arg()); err != nil {
				return res, err
			}
		case BatchSwitchCase:
			to := b.Timeout()
			if to < 0 {
				to = timeout
			}
			out, match, _, err := e.ExpectSwitchCase(b.Cases(), to)
			res = append(res, BatchRes{i, out, match})
			if err != nil {
				return res, err
			}
		case BatchSendSignal:
			sigNr, err := strconv.Atoi(b.Arg())
			if err != nil {
				return res, err
			}
			if err := e.SendSignal(syscall.Signal(sigNr)); err != nil {
				return res, err
			}
		default:
			return res, errors.New("unknown command:" + strconv.Itoa(b.Cmd()))
		}
	}
	return res, nil
}

func (e *GExpect) check() bool {
	e.chkMu.RLock()
	defer e.chkMu.RUnlock()
	return e.chk(e)
}

// SendSignal sends a signal to the Expect controlled process.
// Only works on Process Expecters.
func (e *GExpect) SendSignal(sig os.Signal) error {
	if e.cmd == nil {
		return fmt.Errorf("only process Expecters supported: %v", Unimplemented)
	}
	return e.cmd.Process.Signal(sig)
}

// ExpectSwitchCase checks each Case against the accumulated out buffer, sending specified
// string back. Leaving Send empty will Send nothing to the process.
// Substring expansion can be used eg.
// 	Case{`vf[0-9]{2}.[a-z]{3}[0-9]{2}\.net).*UP`,`show arp \1`}
// 	Given: vf11.hnd01.net            UP      35 (4)        34 (4)          CONNECTED         0              0/0
// 	Would send: show arp vf11.hnd01.net
func (e *GExpect) ExpectSwitchCase(cs []Caser, timeout time.Duration) (string, []string, int, error) {
	// Compile all regexps
	rs := make([]*regexp.Regexp, 0, len(cs))
	for _, c := range cs {
		re, err := c.RE()
		if err != nil {
			return "", []string{""}, -1, err
		}
		rs = append(rs, re)
	}
	// Setup timeouts
	// timeout == 0 => Just dump the buffer and exit.
	// timeout < 0  => Set default value.
	if timeout < 0 {
		timeout = e.timeout
	}
	timer := time.NewTimer(timeout)
	check := e.chkDuration
	// Check if any new data arrived every checkDuration interval.
	// If timeout/4 is less than the checkout interval we set the checkout to
	// timeout/4. If timeout ends up being 0 we bump it to one to keep the Ticker from
	// panicking.
	// All this b/c of the unreliable channel send setup in the read function,making it
	// possible for Expect* functions to miss the rcv signal.
	//
	// from read():
	//		// Ping Expect function
	//		select {
	//		case e.rcv <- struct{}{}:
	//		default:
	//		}
	//
	// A signal is only sent if any Expect function is running. Expect could miss it
	// while playing around with buffers and matching regular expressions.
	if timeout>>2 < check {
		check = timeout >> 2
		if check <= 0 {
			check = 1
		}
	}
	chTicker := time.NewTicker(check)
	defer chTicker.Stop()
	// Read in current data and start actively check for matches.
	var tbuf bytes.Buffer
	if _, err := io.Copy(&tbuf, e); err != nil {
		return tbuf.String(), nil, -1, fmt.Errorf("io.Copy failed: %v", err)
	}
	for {
	L1:
		for i, c := range cs {
			if rs[i] == nil {
				continue
			}
			match := rs[i].FindStringSubmatch(tbuf.String())
			if match == nil {
				continue
			}

			t, s := c.Tag()
			if t == NextTag && !c.Retry() {
				continue
			}

			if e.verbose {
				if e.verboseWriter != nil {
					vStr := fmt.Sprintln(term.Green("Match for RE:").String() + fmt.Sprintf(" %q found: %q Buffer: %s", rs[i].String(), match, tbuf.String()))
					for n, bytesRead, err := 0, 0, error(nil); bytesRead < len(vStr); bytesRead += n {
						n, err = e.verboseWriter.Write([]byte(vStr)[n:])
						if err != nil {
							log.Printf("Write to Verbose Writer failed: %v", err)
							break
						}
					}
				} else {
					log.Printf("Match for RE: %q found: %q Buffer: %q", rs[i].String(), match, tbuf.String())
				}
			}

			tbufString := tbuf.String()
			o := tbufString

			if e.partialMatch {
				// Return the part of the buffer that is not matched by the regular expression so that the next expect call will be able to match it.
				matchIndex := rs[i].FindStringIndex(tbufString)
				o = tbufString[0:matchIndex[1]]
				e.returnUnmatchedSuffix(tbufString[matchIndex[1]:])
			}

			tbuf.Reset()

			st := c.String()
			// Replace the submatches \[0-9]+ in the send string.
			if len(match) > 1 && len(st) > 0 {
				for i := 1; i < len(match); i++ {
					// \(submatch) will be expanded in the Send string.
					// To escape use \\(number).
					si := strconv.Itoa(i)
					r := strings.NewReplacer(`\\`+si, `\`+si, `\`+si, `\\`+si)
					st = r.Replace(st)
					st = strings.Replace(st, `\\`+si, match[i], -1)
				}
			}
			// Don't send anything if string is empty.
			if st != "" {
				if err := e.Send(st); err != nil {
					return o, match, i, fmt.Errorf("failed to send: %q err: %v", st, err)
				}
			}
			// Tag handling.
			switch t {
			case OKTag, FailTag, NoTag:
				return o, match, i, s.Err()
			case ContinueTag:
				if !c.Retry() {
					return o, match, i, s.Err()
				}
				break L1
			case NextTag:
				break L1
			default:
				s = NewStatusf(Unknown, "Tag: %d unknown, err: %v", t, s)
			}
			return o, match, i, s.Err()
		}
		if !e.check() {
			nr, err := io.Copy(&tbuf, e)
			if err != nil {
				return tbuf.String(), nil, -1, fmt.Errorf("io.Copy failed: %v", err)
			}
			if nr == 0 {
				return tbuf.String(), nil, -1, errors.New("expect: Process not running")
			}
		}
		select {
		case <-timer.C:
			// Expect timeout.
			nr, err := io.Copy(&tbuf, e)
			if err != nil {
				return tbuf.String(), nil, -1, fmt.Errorf("io.Copy failed: %v", err)
			}
			// If we got no new data we return otherwise give it another chance to match.
			if nr == 0 {
				return tbuf.String(), nil, -1, TimeoutError(timeout)
			}
			timer = time.NewTimer(timeout)
		case <-chTicker.C:
			// Periodical timer to make sure data is handled in case the <-e.rcv channel
			// was missed.
			if _, err := io.Copy(&tbuf, e); err != nil {
				return tbuf.String(), nil, -1, fmt.Errorf("io.Copy failed: %v", err)
			}
		case <-e.rcv:
			// Data to fetch.
			nr, err := io.Copy(&tbuf, e)
			if err != nil {
				return tbuf.String(), nil, -1, fmt.Errorf("io.Copy failed: %v", err)
			}
			// timer shoud be reset when new output is available.
			if nr > 0 {
				timer = time.NewTimer(timeout)
			}
		}
	}
}

// GenOptions contains the options needed to set up a generic Spawner.
type GenOptions struct {
	// In is where Expect Send messages will be written.
	In io.WriteCloser
	// Out will be read and matched by the expecter.
	Out io.Reader
	// Wait is used by expect to know when the session is over and cleanup of io Go routines should happen.
	Wait func() error
	// Close will be called as part of the expect Close, should normally include a Close of the In WriteCloser.
	Close func() error
	// Check is called everytime a Send or Expect function is called to makes sure the session is still running.
	Check func() bool
}

// SpawnGeneric is used to write generic Spawners. It returns an Expecter. The returned channel will give the return
// status of the spawned session, in practice this means the return value of the provided Wait function.
func SpawnGeneric(opt *GenOptions, timeout time.Duration, opts ...Option) (*GExpect, <-chan error, error) {
	switch {
	case opt == nil:
		return nil, nil, errors.New("GenOptions is <nil>")
	case opt.In == nil:
		return nil, nil, errors.New("In can't be <nil>")
	case opt.Out == nil:
		return nil, nil, errors.New("Out can't be <nil>")
	case opt.Wait == nil:
		return nil, nil, errors.New("Wait can't be <nil>")
	case opt.Close == nil:
		return nil, nil, errors.New("Close can't be <nil>")
	case opt.Check == nil:
		return nil, nil, errors.New("Check can't be <nil>")
	}
	if timeout < 1 {
		timeout = DefaultTimeout
	}
	e := &GExpect{
		rcv:         make(chan struct{}),
		snd:         make(chan string),
		timeout:     timeout,
		chkDuration: checkDuration,
		cls: func(e *GExpect) error {
			return opt.Close()
		},
		chk: func(e *GExpect) bool {
			return opt.Check()
		},
	}

	for _, o := range opts {
		o(e)
	}

	// Set the buffer size to the default if expect.BufferSize(...) is not utilized.
	if !e.bufferSizeIsSet {
		e.bufferSize = defaultBufferSize
	}

	errCh := make(chan error, 1)
	go e.waitForSession(errCh, opt.Wait, opt.In, opt.Out, nil)
	return e, errCh, nil
}

// SpawnFake spawns an expect.Batcher.
func SpawnFake(b []Batcher, timeout time.Duration, opt ...Option) (*GExpect, <-chan error, error) {
	rr, rw := io.Pipe()
	wr, ww := io.Pipe()
	done := make(chan struct{})
	srv, _, err := SpawnGeneric(&GenOptions{
		In:  ww,
		Out: rr,
		Wait: func() error {
			<-done
			return nil
		},
		Close: func() error {
			return ww.Close()
		},
		Check: func() bool { return true },
	}, timeout, opt...)
	if err != nil {
		return nil, nil, err
	}
	// The Tee option should only affect the output not the batcher
	srv.teeWriter = nil

	go func() {
		res, err := srv.ExpectBatch(b, timeout)
		if err != nil {
			log.Printf("ExpectBatch(%v,%v) failed: %v, out: %v", b, timeout, err, res)
		}
		close(done)
	}()

	return SpawnGeneric(&GenOptions{
		In:  rw,
		Out: wr,
		Close: func() error {
			srv.Close()
			return rw.Close()
		},
		Check: func() bool { return true },
		Wait: func() error {
			<-done
			return nil
		},
	}, timeout, opt...)
}

// SpawnWithArgs starts a new process and collects the output. The error
// channel returns the result of the command Spawned when it finishes.
// Arguments may contain spaces.
func SpawnWithArgs(command []string, timeout time.Duration, opts ...Option) (*GExpect, <-chan error, error) {
	pty, err := term.OpenPTY()
	if err != nil {
		return nil, nil, err
	}
	var t term.Termios
	t.Raw()
	t.Set(pty.Slave)

	if timeout < 1 {
		timeout = DefaultTimeout
	}
	// Get the command up and running
	cmd := exec.Command(command[0], command[1:]...)
	// This ties the commands Stdin,Stdout & Stderr to the virtual terminal we created
	cmd.Stdin, cmd.Stdout, cmd.Stderr = pty.Slave, pty.Slave, pty.Slave
	// New process needs to be the process leader and control of a tty
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid:  true,
		Setctty: true}
	e := &GExpect{
		rcv:         make(chan struct{}),
		snd:         make(chan string),
		cmd:         cmd,
		timeout:     timeout,
		chkDuration: checkDuration,
		pty:         pty,
		cls: func(e *GExpect) error {
			if e.cmd != nil {
				return e.cmd.Process.Kill()
			}
			return nil
		},
		chk: func(e *GExpect) bool {
			if e.cmd.Process == nil {
				return false
			}
			// Sending Signal 0 to a process returns nil if process can take a signal , something else if not.
			return e.cmd.Process.Signal(syscall.Signal(0)) == nil
		},
	}
	for _, o := range opts {
		o(e)
	}

	// Set the buffer size to the default if expect.BufferSize(...) is not utilized.
	if !e.bufferSizeIsSet {
		e.bufferSize = defaultBufferSize
	}

	res := make(chan error, 1)
	go e.runcmd(res)
	// Wait until command started
	return e, res, <-res
}

// Spawn starts a new process and collects the output. The error channel
// returns the result of the command Spawned when it finishes. Arguments may
// not contain spaces.
func Spawn(command string, timeout time.Duration, opts ...Option) (*GExpect, <-chan error, error) {
	return SpawnWithArgs(strings.Fields(command), timeout, opts...)
}

// SpawnSSH starts an interactive SSH session,ties it to a PTY and collects the output. The returned channel sends the
// state of the SSH session after it finishes.
func SpawnSSH(sshClient *ssh.Client, timeout time.Duration, opts ...Option) (*GExpect, <-chan error, error) {
	tios := term.Termios{}
	tios.Raw()
	tios.Wz.WsCol, tios.Wz.WsRow = sshTermWidth, sshTermHeight
	return SpawnSSHPTY(sshClient, timeout, tios, opts...)
}

const (
	sshTerm       = "xterm"
	sshTermWidth  = 132
	sshTermHeight = 43
)

// SpawnSSHPTY starts an interactive SSH session and ties it to a local PTY, optionally requests a remote PTY.
func SpawnSSHPTY(sshClient *ssh.Client, timeout time.Duration, term term.Termios, opts ...Option) (*GExpect, <-chan error, error) {
	if sshClient == nil {
		return nil, nil, errors.New("*ssh.Client is nil")
	}
	if timeout < 1 {
		timeout = DefaultTimeout
	}
	// Setup interactive session
	session, err := sshClient.NewSession()
	if err != nil {
		return nil, nil, err
	}
	e := &GExpect{
		rcv: make(chan struct{}),
		snd: make(chan string),
		chk: func(e *GExpect) bool {
			if e.ssh == nil {
				return false
			}
			_, err := e.ssh.SendRequest("dummy", false, nil)
			return err == nil
		},
		cls: func(e *GExpect) error {
			if e.ssh != nil {
				return e.ssh.Close()
			}
			return nil
		},
		ssh:         session,
		timeout:     timeout,
		chkDuration: checkDuration,
	}
	for _, o := range opts {
		o(e)
	}

	// Set the buffer size to the default if expect.BufferSize(...) is not utilized.
	if !e.bufferSizeIsSet {
		e.bufferSize = defaultBufferSize
	}

	if term.Wz.WsCol == 0 {
		term.Wz.WsCol = sshTermWidth
	}
	if term.Wz.WsRow == 0 {
		term.Wz.WsRow = sshTermHeight
	}
	if err := session.RequestPty(sshTerm, int(term.Wz.WsRow), int(term.Wz.WsCol), term.ToSSH()); err != nil {
		return nil, nil, err
	}
	inPipe, err := session.StdinPipe()
	if err != nil {
		return nil, nil, err
	}
	outPipe, err := session.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	errPipe, err := session.StderrPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := session.Shell(); err != nil {
		return nil, nil, err
	}
	// Shell started.
	errCh := make(chan error, 1)
	go e.waitForSession(errCh, session.Wait, inPipe, outPipe, errPipe)
	return e, errCh, nil
}

func (e *GExpect) waitForSession(r chan error, wait func() error, sIn io.WriteCloser, sOut io.Reader, sErr io.Reader) {
	chDone := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-chDone:
				return
			case sstr, ok := <-e.snd:
				if !ok {
					log.Printf("Send channel closed")
					return
				}
				if _, err := sIn.Write([]byte(sstr)); err != nil || !e.check() {
					log.Printf("Write failed: %v", err)
					return
				}
			}
		}
	}()
	rdr := func(out io.Reader) {
		defer wg.Done()
		buf := make([]byte, e.bufferSize)
		for {
			nr, err := out.Read(buf)
			if err != nil || !e.check() {
				if e.teeWriter != nil {
					e.teeWriter.Close()
				}
				if err == io.EOF {
					if e.verbose {
						log.Printf("read closing down: %v", err)
					}
					return
				}
				return
			}
			// Tee output to writer
			if e.teeWriter != nil {
				e.teeWriter.Write(buf[:nr])
			}
			// Add to buffer
			e.mu.Lock()
			e.out.Write(buf[:nr])
			e.mu.Unlock()
			// Inform Expect (if it's currently running) that there's some new data to look through.
			select {
			case e.rcv <- struct{}{}:
			default:
			}
		}
	}
	wg.Add(1)
	go rdr(sOut)
	if sErr != nil {
		wg.Add(1)
		go rdr(sErr)
	}
	err := wait()
	close(chDone)
	wg.Wait()
	r <- err
}

// Close closes the Spawned session.
func (e *GExpect) Close() error {
	return e.cls(e)
}

// Read implements the reader interface for the out buffer.
func (e *GExpect) Read(p []byte) (nr int, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.out.Read(p)
}

func (e *GExpect) returnUnmatchedSuffix(p string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	newBuffer := bytes.NewBufferString(p)
	newBuffer.WriteString(e.out.String())
	e.out = *newBuffer
}

// Send sends a string to spawned process.
func (e *GExpect) Send(in string) error {
	if !e.check() {
		return errors.New("expect: Process not running")
	}

	if e.sendTimeout == 0 {
		e.snd <- in
	} else {
		select {
		case <-time.After(e.sendTimeout):
			return fmt.Errorf("send to spawned process command reached the timeout %v", e.sendTimeout)
		case e.snd <- in:
		}
	}

	if e.verbose {
		if e.verboseWriter != nil {
			vStr := fmt.Sprintln(term.Blue("Sent:").String() + fmt.Sprintf(" %q", in))
			_, err := e.verboseWriter.Write([]byte(vStr))
			if err != nil {
				log.Printf("Write to Verbose Writer failed: %v", err)
			}
		} else {
			log.Printf("Sent: %q", in)
		}
	}

	return nil
}

// runcmd executes the command and Wait for the return value.
func (e *GExpect) runcmd(res chan error) {
	if err := e.cmd.Start(); err != nil {
		res <- err
		return
	}
	// Moving the go read/write functions here makes sure the command is started before first checking if it's running.
	clean := make(chan struct{})
	chDone := e.goIO(clean)
	// Signal command started
	res <- nil
	cErr := e.cmd.Wait()
	close(chDone)
	e.pty.Slave.Close()
	// make sure the read/send routines are done before closing the pty.
	<-clean
	res <- cErr
}

// goIO starts the io handlers.
func (e *GExpect) goIO(clean chan struct{}) (done chan struct{}) {
	done = make(chan struct{})
	var ptySync sync.WaitGroup
	ptySync.Add(2)
	go e.read(done, &ptySync)
	go e.send(done, &ptySync)
	go func() {
		ptySync.Wait()
		e.pty.Master.Close()
		close(clean)
	}()
	return done
}

// Expect reads spawned processes output looking for input regular expression.
// Timeout set to 0 makes Expect return the current buffer.
// Negative timeout value sets it to Default timeout.
func (e *GExpect) Expect(re *regexp.Regexp, timeout time.Duration) (string, []string, error) {
	out, match, _, err := e.ExpectSwitchCase([]Caser{&Case{re, "", nil, 0}}, timeout)
	return out, match, err
}

// Options sets the specified options.
func (e *GExpect) Options(opts ...Option) (prev Option) {
	for _, o := range opts {
		prev = o(e)
	}
	return prev
}

// read reads from the PTY master and forwards to active Expect function.
func (e *GExpect) read(done chan struct{}, ptySync *sync.WaitGroup) {
	defer ptySync.Done()
	buf := make([]byte, e.bufferSize)
	for {
		nr, err := e.pty.Master.Read(buf)
		if err != nil && !e.check() {
			if e.teeWriter != nil {
				e.teeWriter.Close()
			}
			if err == io.EOF {
				if e.verbose {
					log.Printf("read closing down: %v", err)
				}
				return
			}
			return
		}
		// Tee output to writer
		if e.teeWriter != nil {
			e.teeWriter.Write(buf[:nr])
		}
		// Add to buffer
		e.mu.Lock()
		e.out.Write(buf[:nr])
		e.mu.Unlock()
		// Ping Expect function
		select {
		case e.rcv <- struct{}{}:
		default:
		}
	}
}

// send writes to the PTY master.
func (e *GExpect) send(done chan struct{}, ptySync *sync.WaitGroup) {
	defer ptySync.Done()
	for {
		select {
		case <-done:
			return
		case sstr, ok := <-e.snd:
			if !ok {
				return
			}
			if _, err := e.pty.Master.Write([]byte(sstr)); err != nil || !e.check() {
				log.Printf("send failed: %v", err)
			}
		}
	}
}
