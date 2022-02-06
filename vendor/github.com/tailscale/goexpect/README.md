[![CircleCI](https://circleci.com/gh/google/goexpect.svg?style=svg)](https://circleci.com/gh/google/goexpect)

This package is an implementation of [Expect](https://en.wikipedia.org/wiki/Expect) in [Go](https://golang.org).


## Features:
 - Spawning and controlling local processes with real PTYs.
 - Native SSH spawner.
 - Expect backed spawner for testing.
 - Generic spawner to make implementing additional Spawners simple.
 - Has a batcher for implementing workflows without having to write extra logic
   and code.

## Options

All Spawn functions accept a variadic of type expect.Option , these are used for changing
options of the Expecter.

### CheckDuration

The Go Expecter checks for new data every two seconds as default. This can be changed by using
the CheckDuration `func CheckDuration(d time.Duration) Option`.

### Verbose

The Verbose option is used to turn on/off verbose logging for Expect/Send statements.
This option can be very useful when troubleshooting workflows since it will log every interaction
with the device.

### VerboseWriter

The VerboseWriter option can be used to change where the verbose session logs are written.
Using this option will start writing verbose output to the provided io.Writer instead of the log default.

See the [ExampleVerbose](https://github.com/google/goexpect/blob/5c8d637b0287a2ae7bb805554056728c453871e4/expect_test.go#L585) code for an example of how to use this. 

### NoCheck

The Go Expecter periodically checks that the spawned process/ssh/session/telnet etc. session is alive.
This option turns that check off.

### DebugCheck

The DebugCheck option adds debugging to the alive Check done by the Expecter, this will start logging information
every time the check is run. Can be used for troubleshooting and debugging of Spawners.

### ChangeCheck

The ChangeCheck option makes it possible to replace the Spawner Check function with a brand new one.

### SendTimeout

The SendTimeout set timeout on the `Send` command, without timeout the `Send` command will wait forewer for the expecter process.

### BufferSize

The BufferSize option provides a mechanism to configure the client io buffer size in bytes.

## Basic Examples

### networkbit.ch

An [article](http://networkbit.ch/golang-regular-expression/) with some examples was written about goexpect on [networkbit.ch](http://networkbit.ch). 

### The [Wikipedia Expect](https://en.wikipedia.org/wiki/Expect) examples.

#### Telnet

First we try to replicate the Telnet example from wikipedia as close as possible.

Interaction:

```diff
+ username:
- user\n
+ password:
- pass\n
+ %
- cmd\n
+ %
- exit\n
```

*Error checking was omitted to keep the example short*

```
package main

import (
	"flag"
	"fmt"
	"log"
	"regexp"
	"time"

	"github.com/google/goexpect"
	"github.com/google/goterm/term"
)

const (
	timeout = 10 * time.Minute
)

var (
	addr = flag.String("address", "", "address of telnet server")
	user = flag.String("user", "", "username to use")
	pass = flag.String("pass", "", "password to use")
	cmd  = flag.String("cmd", "", "command to run")

	userRE   = regexp.MustCompile("username:")
	passRE   = regexp.MustCompile("password:")
	promptRE = regexp.MustCompile("%")
)

func main() {
	flag.Parse()
	fmt.Println(term.Bluef("Telnet 1 example"))

	e, _, err := expect.Spawn(fmt.Sprintf("telnet %s", *addr), -1)
	if err != nil {
		log.Fatal(err)
	}
	defer e.Close()

	e.Expect(userRE, timeout)
	e.Send(*user + "\n")
	e.Expect(passRE, timeout)
	e.Send(*pass + "\n")
	e.Expect(promptRE, timeout)
	e.Send(*cmd + "\n")
	result, _, _ := e.Expect(promptRE, timeout)
	e.Send("exit\n")

	fmt.Println(term.Greenf("%s: result: %s\n", *cmd, result))
}

```

In essence to run and attach to a process the `expect.Spawn(<cmd>,<timeout>)` is used.
The spawn returns an Expecter `e` that can run `e.Expect` and `e.Send` commands to match information
in the output and Send information in.

*See the https://github.com/google/goexpect/blob/master/examples/newspawner/telnet.go  example for a slightly more fleshed out version*

#### FTP

For the FTP example we use the expect.Batch for the following interaction.

```diff
+ username:
- user\n
+ password:
- pass\n
+ ftp>
- prompt\n
+ ftp>
- mget *\n
+ ftp>'
- bye\n
```

*ftp_example.go*

```
package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/google/goexpect"
	"github.com/google/goterm/term"
)

const (
	timeout = 10 * time.Minute
)

var (
	addr = flag.String("address", "", "address of telnet server")
	user = flag.String("user", "", "username to use")
	pass = flag.String("pass", "", "password to use")
)

func main() {
	flag.Parse()
	fmt.Println(term.Bluef("Ftp 1 example"))

	e, _, err := expect.Spawn(fmt.Sprintf("ftp %s", *addr), -1)
	if err != nil {
		log.Fatal(err)
	}
	defer e.Close()

	e.ExpectBatch([]expect.Batcher{
		&expect.BExp{R: "username:"},
		&expect.BSnd{S: *user + "\n"},
		&expect.BExp{R: "password:"},
		&expect.BSnd{S: *pass + "\n"},
		&expect.BExp{R: "ftp>"},
		&expect.BSnd{S: "bin\n"},
		&expect.BExp{R: "ftp>"},
		&expect.BSnd{S: "prompt\n"},
		&expect.BExp{R: "ftp>"},
		&expect.BSnd{S: "mget *\n"},
		&expect.BExp{R: "ftp>"},
		&expect.BSnd{S: "bye\n"},
	}, timeout)

	fmt.Println(term.Greenf("All done"))
}

```

Using the expect.Batcher makes the standard Send/Expect interactions more compact and simpler to write.

#### SSH

With the SSH login example we test out the [expect.Caser](https://github.com/google/goexpect/blob/7f68e6ee0bc89860ff53a5c0d50bcfae61853506/expect.go#L388-L397)
and the [Case Tags](https://github.com/google/goexpect/blob/7f68e6ee0bc89860ff53a5c0d50bcfae61853506/expect.go#L324-L335).

Also for this we'll use the Go Expect native [SSH Spawner](https://github.com/google/goexpect/blob/7f68e6ee0bc89860ff53a5c0d50bcfae61853506/expect.go#L872-L879)
instead of spawning a process.


Interaction:

```diff
+ "Login: "
- user
+ "Password: "
- pass1
+ "Wrong password"
+ "Login"
- user
+ "Password: "
- pass2
+ router#
```

*ssh_example.go*

```
package main

import (
	"flag"
	"fmt"
	"log"
	"regexp"
	"time"

	"golang.org/x/crypto/ssh"

	"google.golang.org/grpc/codes"

	"github.com/google/goexpect"
	"github.com/google/goterm/term"
)

const (
	timeout = 10 * time.Minute
)

var (
	addr  = flag.String("address", "", "address of telnet server")
	user  = flag.String("user", "user", "username to use")
	pass1 = flag.String("pass1", "pass1", "password to use")
	pass2 = flag.String("pass2", "pass2", "alternate password to use")
)

func main() {
	flag.Parse()
	fmt.Println(term.Bluef("SSH Example"))

	sshClt, err := ssh.Dial("tcp", *addr, &ssh.ClientConfig{
		User:            *user,
		Auth:            []ssh.AuthMethod{ssh.Password(*pass1)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		log.Fatalf("ssh.Dial(%q) failed: %v", *addr, err)
	}
	defer sshClt.Close()

	e, _, err := expect.SpawnSSH(sshClt, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer e.Close()

	e.ExpectBatch([]expect.Batcher{
		&expect.BCas{[]expect.Caser{
			&expect.Case{R: regexp.MustCompile(`router#`), T: expect.OK()},
			&expect.Case{R: regexp.MustCompile(`Login: `), S: *user,
				T: expect.Continue(expect.NewStatus(codes.PermissionDenied, "wrong username")), Rt: 3},
			&expect.Case{R: regexp.MustCompile(`Password: `), S: *pass1, T: expect.Next(), Rt: 1},
			&expect.Case{R: regexp.MustCompile(`Password: `), S: *pass2,
				T: expect.Continue(expect.NewStatus(codes.PermissionDenied, "wrong password")), Rt: 1},
		}},
	}, timeout)

	fmt.Println(term.Greenf("All done"))
}
```

### Generic Spawner

The Go Expect package supports adding new Spawners with the `func SpawnGeneric(opt *GenOptions, timeout time.Duration, opts ...Option) (*GExpect, <-chan error, error)`
function. 

*telnet spawner*

From the [newspawner](https://github.com/google/goexpect/blob/master/examples/newspawner/telnet.go) example.

```
func telnetSpawn(addr string, timeout time.Duration, opts ...expect.Option) (expect.Expecter, <-chan error, error) {
	conn, err := telnet.Dial(network, addr)
	if err != nil {
		return nil, nil, err
	}

	resCh := make(chan error)

	return expect.SpawnGeneric(&expect.GenOptions{
		In:  conn,
		Out: conn,
		Wait: func() error {
			return <-resCh
		},
		Close: func() error {
			close(resCh)
			return conn.Close()
		},
		Check: func() bool { return true },
	}, timeout, opts...)
}
```

### Fake Spawner

The Go Expect package includes a Fake Spawner `func SpawnFake(b []Batcher, timeout time.Duration, opt ...Option) (*GExpect, <-chan error, error)`. 
This is expected to be used to simplify testing and faking of interactive workflows.

*Fake Spawner*

```
// TestExpect tests the Expect function.
func TestExpect(t *testing.T) {
	tests := []struct {
		name    string
		fail    bool
		srv     []Batcher
		timeout time.Duration
		re      *regexp.Regexp
	}{{
		name: "Match prompt",
		srv: []Batcher{
			&BSnd{`
Pretty please don't hack my chassis

router1> `},
		},
		re:      regexp.MustCompile("router1>"),
		timeout: 2 * time.Second,
	}, {
		name: "Match fail",
		fail: true,
		re:   regexp.MustCompile("router1>"),
		srv: []Batcher{
			&BSnd{`
Welcome

Router42>`},
		},
		timeout: 1 * time.Second,
	}}

	for _, tst := range tests {
		exp, _, err := SpawnFake(tst.srv, tst.timeout)
		if err != nil {
			if !tst.fail {
				t.Errorf("%s: SpawnFake failed: %v", tst.name, err)
			}
			continue
		}
		out, _, err := exp.Expect(tst.re, tst.timeout)
		if got, want := err != nil, tst.fail; got != want {
			t.Errorf("%s: Expect(%q,%v) = %t want: %t , err: %v, out: %q", tst.name, tst.re.String(), tst.timeout, got, want, err, out)
			continue
		}
	}
}
```

*Disclaimer: This is not an official Google product.*
