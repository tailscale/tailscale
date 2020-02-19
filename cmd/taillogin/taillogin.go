// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// The taillogin command, invoked via the tailscale-login shell script, is shipped
// with the current (old) Linux client, to log in to Tailscale on a Linux box.
//
// Deprecated: this will be deleted, to be replaced by cmd/tailscale.
package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/pborman/getopt/v2"
	"tailscale.com/atomicfile"
	"tailscale.com/control/controlclient"
	"tailscale.com/logpolicy"
)

func main() {
	config := getopt.StringLong("config", 'f', "", "path to config file")
	server := getopt.StringLong("server", 's', "https://login.tailscale.com", "URL to tailgate server")
	getopt.Parse()
	if len(getopt.Args()) > 0 {
		log.Fatal("too many non-flag arguments")
	}
	if *config == "" {
		log.Fatal("no --config file specified")
	}
	pol := logpolicy.New("tailnode.log.tailscale.io")
	defer pol.Close()

	cfg, err := loadConfig(*config)
	if err != nil {
		log.Fatal(err)
	}

	hi := controlclient.NewHostinfo()
	hi.FrontendLogID = pol.PublicID.String()
	hi.BackendLogID = pol.PublicID.String()

	done := make(chan struct{}, 1)
	c, err := controlclient.New(controlclient.Options{
		Persist:   cfg,
		ServerURL: *server,
		Hostinfo:  &hi,
	})
	if err != nil {
		log.Fatal(err)
	}
	c.SetStatusFunc(func(new controlclient.Status) {
		if new.URL != "" {
			fmt.Fprintf(os.Stderr, "To authenticate, visit:\n\n\t%s\n\n", new.URL)
			return
		}
		if new.Err != "" {
			log.Print(new.Err)
			return
		}
		if new.Persist != nil {
			if err := saveConfig(*config, *new.Persist); err != nil {
				log.Println(err)
			}
		}
		if new.NetMap != nil {
			done <- struct{}{}
		}
	})
	c.Login(nil, 0)
	<-done
	log.Printf("Success.\n")
}

func loadConfig(path string) (cfg controlclient.Persist, err error) {
	b, err := ioutil.ReadFile(path)
	if os.IsNotExist(err) {
		log.Printf("config %s does not exist", path)
		return controlclient.Persist{}, nil
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return controlclient.Persist{}, fmt.Errorf("load config: %v", err)
	}
	return cfg, nil
}

func saveConfig(path string, cfg controlclient.Persist) error {
	b, err := json.MarshalIndent(cfg, "", "\t")
	if err != nil {
		return fmt.Errorf("save config: %v", err)
	}
	if err := atomicfile.WriteFile(path, b, 0666); err != nil {
		return fmt.Errorf("save config: %v", err)
	}
	return nil
}
