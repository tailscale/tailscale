// Copyright 2020 Tailscale Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"compress/gzip"
	"io/ioutil"
	"strings"
	"sync"
)

func certUncompressor(zcertBytes string) func() (*Certificate, error) {
	var once sync.Once
	var c *Certificate
	var err error
	return func() (*Certificate, error) {
		once.Do(func() {
			var certBytes []byte
			var zr *gzip.Reader
			zr, err = gzip.NewReader(strings.NewReader(zcertBytes))
			if err != nil {
				return
			}
			certBytes, err = ioutil.ReadAll(zr)
			if err != nil {
				return
			}
			c, err = ParseCertificate(certBytes)
		})
		return c, err
	}
}
