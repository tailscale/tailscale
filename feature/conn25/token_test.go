// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package conn25

import (
	"bytes"
	"math"
	"net/netip"
	"strings"
	"testing"

	"tailscale.com/types/logger"
)

func TestConnectorTokenSecretInit(t *testing.T) {
	c := newConn25(logger.Discard)

	if c.connector.tokenSecret == ([tokenSecretLen]byte{}) {
		t.Fatal("token secret is all zero bytes, expected random bytes")
	}
}

func TestConnectorTokenSecretRandomAcrossInstances(t *testing.T) {
	a := newConn25(logger.Discard)
	b := newConn25(logger.Discard)

	if a.connector.tokenSecret == b.connector.tokenSecret {
		t.Fatal("two connectors minted identical token secrets, expected distinct random secrets")
	}
}

func TestConnectorResetRotatesTokenSecret(t *testing.T) {
	c := newConn25(logger.Discard)

	before := c.connector.tokenSecret
	c.connector.reset()
	after := c.connector.tokenSecret

	if before == after {
		t.Fatal("token secret unchanged after reset, expected rotation")
	}
}

var (
	testTokenAddr      = netip.MustParseAddr("1.2.3.4")
	testTokenOtherAddr = netip.MustParseAddr("1.2.3.5")
)

func mustMint(t *testing.T, c *connector, app string, dst netip.Addr) []byte {
	t.Helper()
	tok, err := c.mintToken(app, dst)
	if err != nil {
		t.Fatalf("mintToken(%q): unexpected error: %v", app, err)
	}
	return tok
}

func TestConnectorMintTokenDeterministic(t *testing.T) {
	c := newConn25(logger.Discard).connector
	a := mustMint(t, c, "app", testTokenAddr)
	b := mustMint(t, c, "app", testTokenAddr)
	if !bytes.Equal(a, b) {
		t.Fatalf("mintToken not deterministic: %x != %x", a, b)
	}
}

func TestConnectorMintTokenVersionAndLength(t *testing.T) {
	c := newConn25(logger.Discard).connector
	tok := mustMint(t, c, "app", testTokenAddr)
	if got, want := len(tok), 1+16; got != want {
		t.Fatalf("token length = %d, want %d", got, want)
	}
	if tok[0] != tokenVersion1 {
		t.Fatalf("token version byte = %d, want %d", tok[0], tokenVersion1)
	}
}

func TestConnectorMintTokenDistinctInputs(t *testing.T) {
	c := newConn25(logger.Discard).connector
	base := mustMint(t, c, "app", testTokenAddr)

	cases := []struct {
		name string
		tok  []byte
	}{
		{"different app", mustMint(t, c, "other", testTokenAddr)},
		{"different dst", mustMint(t, c, "app", testTokenOtherAddr)},
	}
	for _, tc := range cases {
		if bytes.Equal(base, tc.tok) {
			t.Errorf("%s: token matched base token, expected a different MAC", tc.name)
		}
	}

	// A rotated secret must change the MAC for otherwise-identical inputs.
	c.reset()
	if rotated := mustMint(t, c, "app", testTokenAddr); bytes.Equal(base, rotated) {
		t.Error("token unchanged after secret rotation, expected a different MAC")
	}
}

func TestConnectorMintTokenCanonicalizesDst(t *testing.T) {
	c := newConn25(logger.Discard).connector
	v4 := testTokenAddr
	v4in6 := netip.AddrFrom16(v4.As16()) // the ::ffff:1.2.3.4 form
	if v4 == v4in6 {
		t.Fatal("test setup: expected distinct v4 and v4-in-6 representations")
	}
	if a, b := mustMint(t, c, "app", v4), mustMint(t, c, "app", v4in6); !bytes.Equal(a, b) {
		t.Fatalf("v4 and v4-in-6 dst minted different tokens: %x != %x", a, b)
	}
}

func TestConnectorMintTokenAppTooLong(t *testing.T) {
	c := newConn25(logger.Discard).connector
	// An app name that fits in the uint16 length prefix must succeed.
	if _, err := c.mintToken(strings.Repeat("a", math.MaxUint16), testTokenAddr); err != nil {
		t.Fatalf("mintToken with max-length app: unexpected error: %v", err)
	}
	// One byte past the uint16 limit must fail closed rather than mint an
	// ambiguously-framed token.
	tok, err := c.mintToken(strings.Repeat("a", math.MaxUint16+1), testTokenAddr)
	if err == nil {
		t.Fatal("mintToken with over-length app: got nil error, want failure")
	}
	if tok != nil {
		t.Fatalf("mintToken with over-length app: got token %x, want nil", tok)
	}
}

func TestConnectorVerifyTokenRoundTrip(t *testing.T) {
	c := newConn25(logger.Discard).connector
	tok := mustMint(t, c, "app", testTokenAddr)
	if !c.verifyToken(tok, "app", testTokenAddr) {
		t.Fatal("verifyToken rejected a freshly minted token for its own inputs")
	}
}

func TestConnectorVerifyTokenCanonicalizesDst(t *testing.T) {
	c := newConn25(logger.Discard).connector
	v4 := testTokenAddr
	v4in6 := netip.AddrFrom16(v4.As16()) // the ::ffff:1.2.3.4 form
	tok := mustMint(t, c, "app", v4)
	if !c.verifyToken(tok, "app", v4in6) {
		t.Fatal("verifyToken rejected a token minted for the v4-in-6 form of its dst")
	}
}

func TestConnectorVerifyTokenRejectsWrongInputs(t *testing.T) {
	c := newConn25(logger.Discard).connector
	tok := mustMint(t, c, "app", testTokenAddr)
	cases := []struct {
		name string
		app  string
		dst  netip.Addr
	}{
		{"wrong app", "other", testTokenAddr},
		{"wrong dst", "app", testTokenOtherAddr},
	}
	for _, tc := range cases {
		if c.verifyToken(tok, tc.app, tc.dst) {
			t.Errorf("%s: verifyToken accepted token for mismatched inputs", tc.name)
		}
	}
}

func TestConnectorVerifyTokenRejectsRotatedSecret(t *testing.T) {
	c := newConn25(logger.Discard).connector
	tok := mustMint(t, c, "app", testTokenAddr)
	c.reset()
	if c.verifyToken(tok, "app", testTokenAddr) {
		t.Fatal("verifyToken accepted a token minted under the pre-rotation secret")
	}
}

func TestConnectorVerifyTokenRejectsMalformed(t *testing.T) {
	c := newConn25(logger.Discard).connector
	tok := mustMint(t, c, "app", testTokenAddr)

	cases := []struct {
		name string
		tok  []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"too short", tok[:len(tok)-1]},
		{"too long", append(append([]byte{}, tok...), 0)},
		{"wrong version", append([]byte{tokenVersion1 + 1}, tok[1:]...)},
		{"flipped mac bit", func() []byte {
			bad := append([]byte{}, tok...)
			bad[len(bad)-1] ^= 0x01
			return bad
		}()},
	}
	for _, tc := range cases {
		if c.verifyToken(tc.tok, "app", testTokenAddr) {
			t.Errorf("%s: verifyToken accepted a malformed token", tc.name)
		}
	}
}

func TestConnectorVerifyTokenAppTooLong(t *testing.T) {
	c := newConn25(logger.Discard).connector
	tok := mustMint(t, c, "app", testTokenAddr)

	if c.verifyToken(tok, strings.Repeat("a", math.MaxUint16+1), testTokenAddr) {
		t.Fatal("verifyToken accepted an app name too long to have ever minted a token")
	}
}
