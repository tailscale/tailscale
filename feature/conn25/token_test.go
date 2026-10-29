// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package conn25

import (
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
