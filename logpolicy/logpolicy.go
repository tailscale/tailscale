// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package logpolicy

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/crypto/ssh/terminal"
	"tailscale.com/atomicfile"
	"tailscale.com/logtail"
	"tailscale.com/logtail/filch"
	"tailscale.com/version"
)

type Config struct {
	Collection string
	PrivateID  logtail.PrivateID
	PublicID   logtail.PublicID
}

type Policy struct {
	Logtail  logtail.Logger
	PublicID logtail.PublicID
}

func (c *Config) ToBytes() []byte {
	data, err := json.MarshalIndent(c, "", "\t")
	if err != nil {
		log.Fatalf("logpolicy.Config marshal: %v\n", err)
	}
	return data
}

func (c *Config) Save(statefile string) {
	c.PublicID = c.PrivateID.Public()
	os.MkdirAll(filepath.Dir(statefile), 0777)
	data := c.ToBytes()
	if err := atomicfile.WriteFile(statefile, data, 0600); err != nil {
		log.Printf("logpolicy.Config write: %v\n", err)
	}
}

func ConfigFromBytes(b []byte) (*Config, error) {
	c := &Config{}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, err
	}
	return c, nil
}

type stderrWriter struct{}

// Always writes to the latest os.Stderr, even if os.Stderr changes
// during the lifetime of this object.
func (l *stderrWriter) Write(buf []byte) (int, error) {
	return os.Stderr.Write(buf)
}

type logWriter struct {
	logger *log.Logger
}

func (l *logWriter) Write(buf []byte) (int, error) {
	l.logger.Print(string(buf))
	return len(buf), nil
}

func New(collection string, filePrefix string) *Policy {
	statefile := filePrefix + ".log.conf"
	var lflags int
	if terminal.IsTerminal(2) || runtime.GOOS == "windows" {
		lflags = 0
	} else {
		lflags = log.LstdFlags
	}
	console := log.New(&stderrWriter{}, "", lflags)

	var oldc *Config
	data, err := ioutil.ReadFile(statefile)
	if err != nil {
		log.Printf("logpolicy.Read %v: %v\n", statefile, err)
		oldc = &Config{}
		oldc.Collection = collection
	} else {
		oldc, err = ConfigFromBytes(data)
		if err != nil {
			log.Printf("logpolicy.Config unmarshal: %v\n", err)
			oldc = &Config{}
		}
	}

	newc := *oldc
	if newc.Collection != collection {
		log.Printf("logpolicy.Config: config collection %q does not match %q", newc.Collection, collection)
		// We picked up an incompatible config file.
		// Regenerate the private ID.
		newc.PrivateID = logtail.PrivateID{}
		newc.Collection = collection
	}
	if newc.PrivateID == (logtail.PrivateID{}) {
		newc.PrivateID, err = logtail.NewPrivateID()
		if err != nil {
			log.Fatalf("logpolicy: NewPrivateID() should never fail")
		}
	}
	newc.PublicID = newc.PrivateID.Public()
	if newc != *oldc {
		newc.Save(statefile)
	}

	c := logtail.Config{
		Collection: newc.Collection,
		PrivateID:  newc.PrivateID,
		Stderr:     &logWriter{console},
		NewZstdEncoder: func() logtail.Encoder {
			w, err := zstd.NewWriter(nil)
			if err != nil {
				panic(err)
			}
			return w
		},
	}

	// TODO(crawshaw): filePrefix is a place meant to store configuration.
	//                 OS policies usually have other preferred places to
	//                 store logs. Use one of them?
	filchBuf, filchErr := filch.New(filePrefix, filch.Options{})
	if filchBuf != nil {
		c.Buffer = filchBuf
	}
	lw := logtail.Log(c)
	log.SetFlags(0) // other logflags are set on console, not here
	log.SetOutput(lw)

	log.Printf("Program starting: v%v: %#v\n", version.LONG, os.Args)
	log.Printf("LogID: %v\n", newc.PublicID)
	if filchErr != nil {
		log.Printf("filch failed: %v", err)
	}

	return &Policy{
		Logtail:  lw,
		PublicID: newc.PublicID,
	}
}

// Close immediately shuts down the logger.
func (p *Policy) Close() {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p.Shutdown(ctx)
}

// Shutdown gracefully shuts down the logger, finishing any current
// log upload if it can be done before ctx is canceled.
func (p *Policy) Shutdown(ctx context.Context) error {
	log.Printf("flushing log.\n")
	if p.Logtail != nil {
		return p.Logtail.Shutdown(ctx)
	}
	return nil
}
