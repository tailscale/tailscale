// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientAuthRestrictedPublicKeyAlgos(t *testing.T) {
	for _, tt := range []struct {
		name      string
		key       Signer
		wantError bool
	}{
		{"rsa", testSigners["rsa"], false},
		{"dsa", testSigners["dsa"], true},
		{"ed25519", testSigners["ed25519"], true},
	} {
		c1, c2, err := netPipe()
		if err != nil {
			t.Fatalf("netPipe: %v", err)
		}
		defer c1.Close()
		defer c2.Close()
		serverConf := &ServerConfig{
			PublicKeyAuthAlgorithms: []string{KeyAlgoRSASHA256, KeyAlgoRSASHA512},
			PublicKeyCallback: func(conn ConnMetadata, key PublicKey) (*Permissions, error) {
				return nil, nil
			},
		}
		serverConf.AddHostKey(testSigners["ecdsap256"])

		done := make(chan struct{})
		go func() {
			defer close(done)
			NewServerConn(c1, serverConf)
		}()

		clientConf := ClientConfig{
			User: "user",
			Auth: []AuthMethod{
				PublicKeys(tt.key),
			},
			HostKeyCallback: InsecureIgnoreHostKey(),
		}

		_, _, _, err = NewClientConn(c2, "", &clientConf)
		if err != nil {
			if !tt.wantError {
				t.Errorf("%s: got unexpected error %q", tt.name, err.Error())
			}
		} else if tt.wantError {
			t.Errorf("%s: succeeded, but want error", tt.name)
		}
		<-done
	}
}

func TestMaxAuthTriesNoneMethod(t *testing.T) {
	username := "testuser"
	serverConfig := &ServerConfig{
		MaxAuthTries: 2,
		PasswordCallback: func(conn ConnMetadata, password []byte) (*Permissions, error) {
			if conn.User() == username && string(password) == clientPassword {
				return nil, nil
			}
			return nil, errors.New("invalid credentials")
		},
	}
	c1, c2, err := netPipe()
	if err != nil {
		t.Fatalf("netPipe: %v", err)
	}
	defer c1.Close()
	defer c2.Close()

	var serverAuthErrors []error

	serverConfig.AddHostKey(testSigners["rsa"])
	serverConfig.AuthLogCallback = func(conn ConnMetadata, method string, err error) {
		serverAuthErrors = append(serverAuthErrors, err)
	}
	go newServer(c1, serverConfig)

	clientConfig := ClientConfig{
		User:            username,
		HostKeyCallback: InsecureIgnoreHostKey(),
	}
	clientConfig.SetDefaults()
	// Our client will send 'none' auth only once, so we need to send the
	// requests manually.
	c := &connection{
		sshConn: sshConn{
			conn:          c2,
			user:          username,
			clientVersion: []byte(packageVersion),
		},
	}
	c.serverVersion, err = exchangeVersions(c.sshConn.conn, c.clientVersion)
	if err != nil {
		t.Fatalf("unable to exchange version: %v", err)
	}
	c.transport = newClientTransport(
		newTransport(c.sshConn.conn, clientConfig.Rand, true /* is client */),
		c.clientVersion, c.serverVersion, &clientConfig, "", c.sshConn.RemoteAddr())
	if err := c.transport.waitSession(); err != nil {
		t.Fatalf("unable to wait session: %v", err)
	}
	c.sessionID = c.transport.getSessionID()
	if err := c.transport.writePacket(Marshal(&serviceRequestMsg{serviceUserAuth})); err != nil {
		t.Fatalf("unable to send ssh-userauth message: %v", err)
	}
	packet, err := c.transport.readPacket()
	if err != nil {
		t.Fatal(err)
	}
	if len(packet) > 0 && packet[0] == msgExtInfo {
		packet, err = c.transport.readPacket()
		if err != nil {
			t.Fatal(err)
		}
	}
	var serviceAccept serviceAcceptMsg
	if err := Unmarshal(packet, &serviceAccept); err != nil {
		t.Fatal(err)
	}
	for i := 0; i <= serverConfig.MaxAuthTries; i++ {
		auth := new(noneAuth)
		_, _, err := auth.auth(c.sessionID, clientConfig.User, c.transport, clientConfig.Rand, nil)
		if i < serverConfig.MaxAuthTries {
			if err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err == nil {
			t.Fatal("client: got no error")
		} else if !strings.Contains(err.Error(), "too many authentication failures") {
			t.Fatalf("client: got unexpected error: %v", err)
		}
	}
	if len(serverAuthErrors) != 3 {
		t.Fatalf("unexpected number of server auth errors: %v, errors: %+v", len(serverAuthErrors), serverAuthErrors)
	}
	for _, err := range serverAuthErrors {
		if !errors.Is(err, ErrNoAuth) {
			t.Errorf("go error: %v; want: %v", err, ErrNoAuth)
		}
	}
}

func TestMaxAuthTriesFirstNoneAuthErrorIgnored(t *testing.T) {
	username := "testuser"
	serverConfig := &ServerConfig{
		MaxAuthTries: 1,
		PasswordCallback: func(conn ConnMetadata, password []byte) (*Permissions, error) {
			if conn.User() == username && string(password) == clientPassword {
				return nil, nil
			}
			return nil, errors.New("invalid credentials")
		},
	}
	clientConfig := &ClientConfig{
		User: username,
		Auth: []AuthMethod{
			Password(clientPassword),
		},
		HostKeyCallback: InsecureIgnoreHostKey(),
	}

	serverAuthErrors, err := doClientServerAuth(t, serverConfig, clientConfig)
	if err != nil {
		t.Fatalf("client login error: %s", err)
	}
	if len(serverAuthErrors) != 2 {
		t.Fatalf("unexpected number of server auth errors: %v, errors: %+v", len(serverAuthErrors), serverAuthErrors)
	}
	if !errors.Is(serverAuthErrors[0], ErrNoAuth) {
		t.Errorf("go error: %v; want: %v", serverAuthErrors[0], ErrNoAuth)
	}
	if serverAuthErrors[1] != nil {
		t.Errorf("unexpected error: %v", serverAuthErrors[1])
	}
}

func TestNewServerConnValidationErrors(t *testing.T) {
	serverConf := &ServerConfig{
		PublicKeyAuthAlgorithms: []string{CertAlgoRSAv01},
	}
	c := &markerConn{}
	_, _, _, err := NewServerConn(c, serverConf)
	if err == nil {
		t.Fatal("NewServerConn with invalid public key auth algorithms succeeded")
	}
	if !c.isClosed() {
		t.Fatal("NewServerConn with invalid public key auth algorithms left connection open")
	}
	if c.isUsed() {
		t.Fatal("NewServerConn with invalid public key auth algorithms used connection")
	}

	serverConf = &ServerConfig{
		Config: Config{
			KeyExchanges: []string{kexAlgoDHGEXSHA256},
		},
	}
	c = &markerConn{}
	_, _, _, err = NewServerConn(c, serverConf)
	if err == nil {
		t.Fatal("NewServerConn with unsupported key exchange succeeded")
	}
	if !c.isClosed() {
		t.Fatal("NewServerConn with unsupported key exchange left connection open")
	}
	if c.isUsed() {
		t.Fatal("NewServerConn with unsupported key exchange used connection")
	}
}

func TestBannerError(t *testing.T) {
	serverConfig := &ServerConfig{
		BannerCallback: func(ConnMetadata) string {
			return "banner from BannerCallback"
		},
		NoClientAuth: true,
		NoClientAuthCallback: func(ConnMetadata) (*Permissions, error) {
			err := &BannerError{
				Err:     errors.New("error from NoClientAuthCallback"),
				Message: "banner from NoClientAuthCallback",
			}
			return nil, fmt.Errorf("wrapped: %w", err)
		},
		PasswordCallback: func(conn ConnMetadata, password []byte) (*Permissions, error) {
			return &Permissions{}, nil
		},
		PublicKeyCallback: func(conn ConnMetadata, key PublicKey) (*Permissions, error) {
			return nil, &BannerError{
				Err:     errors.New("error from PublicKeyCallback"),
				Message: "banner from PublicKeyCallback",
			}
		},
		KeyboardInteractiveCallback: func(conn ConnMetadata, client KeyboardInteractiveChallenge) (*Permissions, error) {
			return nil, &BannerError{
				Err:     nil, // make sure that a nil inner error is allowed
				Message: "banner from KeyboardInteractiveCallback",
			}
		},
	}
	serverConfig.AddHostKey(testSigners["rsa"])

	var banners []string
	clientConfig := &ClientConfig{
		User: "test",
		Auth: []AuthMethod{
			PublicKeys(testSigners["rsa"]),
			KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
				return []string{"letmein"}, nil
			}),
			Password(clientPassword),
		},
		HostKeyCallback: InsecureIgnoreHostKey(),
		BannerCallback: func(msg string) error {
			banners = append(banners, msg)
			return nil
		},
	}

	c1, c2, err := netPipe()
	if err != nil {
		t.Fatalf("netPipe: %v", err)
	}
	defer c1.Close()
	defer c2.Close()
	go newServer(c1, serverConfig)
	c, _, _, err := NewClientConn(c2, "", clientConfig)
	if err != nil {
		t.Fatalf("client connection failed: %v", err)
	}
	defer c.Close()

	wantBanners := []string{
		"banner from BannerCallback",
		"banner from NoClientAuthCallback",
		"banner from PublicKeyCallback",
		"banner from KeyboardInteractiveCallback",
	}
	if !reflect.DeepEqual(banners, wantBanners) {
		t.Errorf("got banners:\n%q\nwant banners:\n%q", banners, wantBanners)
	}
}

func TestPublicKeyCallbackLastSeen(t *testing.T) {
	var lastSeenKey PublicKey

	c1, c2, err := netPipe()
	if err != nil {
		t.Fatalf("netPipe: %v", err)
	}
	defer c1.Close()
	defer c2.Close()
	serverConf := &ServerConfig{
		PublicKeyCallback: func(conn ConnMetadata, key PublicKey) (*Permissions, error) {
			lastSeenKey = key
			fmt.Printf("seen %#v\n", key)
			if _, ok := key.(*dsaPublicKey); !ok {
				return nil, errors.New("nope")
			}
			return nil, nil
		},
	}
	serverConf.AddHostKey(testSigners["ecdsap256"])

	done := make(chan struct{})
	go func() {
		defer close(done)
		NewServerConn(c1, serverConf)
	}()

	clientConf := ClientConfig{
		User: "user",
		Auth: []AuthMethod{
			PublicKeys(testSigners["rsa"], testSigners["dsa"], testSigners["ed25519"]),
		},
		HostKeyCallback: InsecureIgnoreHostKey(),
	}

	_, _, _, err = NewClientConn(c2, "", &clientConf)
	if err != nil {
		t.Fatal(err)
	}
	<-done

	expectedPublicKey := testSigners["dsa"].PublicKey().Marshal()
	lastSeenMarshalled := lastSeenKey.Marshal()
	if !bytes.Equal(lastSeenMarshalled, expectedPublicKey) {
		t.Errorf("unexpected key: got %#v, want %#v", lastSeenKey, testSigners["dsa"].PublicKey())
	}
}

func TestPreAuthConnAndBanners(t *testing.T) {
	testDone := make(chan struct{})
	defer close(testDone)

	authConnc := make(chan ServerPreAuthConn, 1)
	serverConfig := &ServerConfig{
		PreAuthConnCallback: func(c ServerPreAuthConn) {
			t.Logf("got ServerPreAuthConn: %v", c)
			authConnc <- c // for use later in the test
			for _, s := range []string{"hello1", "hello2"} {
				if err := c.SendAuthBanner(s); err != nil {
					t.Errorf("failed to send banner %q: %v", s, err)
				}
			}
			// Now start a goroutine to spam SendAuthBanner in hopes
			// of hitting a race.
			go func() {
				for {
					select {
					case <-testDone:
						return
					default:
						if err := c.SendAuthBanner("attempted-race"); err != nil && err != errSendBannerPhase {
							t.Errorf("unexpected error from SendAuthBanner: %v", err)
						}
						time.Sleep(5 * time.Millisecond)
					}
				}
			}()
		},
		NoClientAuth: true,
		NoClientAuthCallback: func(ConnMetadata) (*Permissions, error) {
			t.Logf("got NoClientAuthCallback")
			return &Permissions{}, nil
		},
	}
	serverConfig.AddHostKey(testSigners["rsa"])

	var banners []string
	clientConfig := &ClientConfig{
		User:            "test",
		HostKeyCallback: InsecureIgnoreHostKey(),
		BannerCallback: func(msg string) error {
			if msg != "attempted-race" {
				banners = append(banners, msg)
			}
			return nil
		},
	}

	c1, c2, err := netPipe()
	if err != nil {
		t.Fatalf("netPipe: %v", err)
	}
	defer c1.Close()
	defer c2.Close()
	go newServer(c1, serverConfig)
	c, _, _, err := NewClientConn(c2, "", clientConfig)
	if err != nil {
		t.Fatalf("client connection failed: %v", err)
	}
	defer c.Close()

	wantBanners := []string{
		"hello1",
		"hello2",
	}
	if !reflect.DeepEqual(banners, wantBanners) {
		t.Errorf("got banners:\n%q\nwant banners:\n%q", banners, wantBanners)
	}

	// Now that we're authenticated, verify that use of SendBanner
	// is an error.
	var bc ServerPreAuthConn
	select {
	case bc = <-authConnc:
	default:
		t.Fatal("expected ServerPreAuthConn")
	}
	if err := bc.SendAuthBanner("wrong-phase"); err == nil {
		t.Error("unexpected success of SendAuthBanner after authentication")
	} else if err != errSendBannerPhase {
		t.Errorf("unexpected error: %v; want %v", err, errSendBannerPhase)
	}
}

type markerConn struct {
	closed uint32
	used   uint32
}

func (c *markerConn) isClosed() bool {
	return atomic.LoadUint32(&c.closed) != 0
}

func (c *markerConn) isUsed() bool {
	return atomic.LoadUint32(&c.used) != 0
}

func (c *markerConn) Close() error {
	atomic.StoreUint32(&c.closed, 1)
	return nil
}

func (c *markerConn) Read(b []byte) (n int, err error) {
	atomic.StoreUint32(&c.used, 1)
	if atomic.LoadUint32(&c.closed) != 0 {
		return 0, net.ErrClosed
	} else {
		return 0, io.EOF
	}
}

func (c *markerConn) Write(b []byte) (n int, err error) {
	atomic.StoreUint32(&c.used, 1)
	if atomic.LoadUint32(&c.closed) != 0 {
		return 0, net.ErrClosed
	} else {
		return 0, io.ErrClosedPipe
	}
}

func (*markerConn) LocalAddr() net.Addr  { return nil }
func (*markerConn) RemoteAddr() net.Addr { return nil }

func (*markerConn) SetDeadline(t time.Time) error      { return nil }
func (*markerConn) SetReadDeadline(t time.Time) error  { return nil }
func (*markerConn) SetWriteDeadline(t time.Time) error { return nil }
