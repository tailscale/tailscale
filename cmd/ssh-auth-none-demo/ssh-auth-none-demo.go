// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// ssh-auth-none-demo is a demo SSH server that's meant to run on the
// public internet (at 188.166.70.128 port 2222) and
// highlight the unique parts of the Tailscale SSH server so SSH
// client authors can hit it easily and fix their SSH clients without
// needing to set up Tailscale and Tailscale SSH.
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"time"

	gossh "github.com/tailscale/golang-x-crypto/ssh"
	"tailscale.com/tempfork/gliderlabs/ssh"
)

// keyTypes are the SSH key types that we either try to read from the
// system's OpenSSH keys.
var keyTypes = []string{"rsa", "ecdsa", "ed25519"}

var (
	addr = flag.String("addr", ":2222", "address to listen on")
)

func main() {
	flag.Parse()

	cacheDir, err := os.UserCacheDir()
	if err != nil {
		log.Fatal(err)
	}
	dir := filepath.Join(cacheDir, "ssh-auth-none-demo")
	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Fatal(err)
	}

	keys, err := getHostKeys(dir)
	if err != nil {
		log.Fatal(err)
	}
	if len(keys) == 0 {
		log.Fatal("no host keys")
	}

	srv := &ssh.Server{
		Addr:    *addr,
		Version: "Tailscale",
		Handler: handleSessionPostSSHAuth,
		ServerConfigCallback: func(ctx ssh.Context) *gossh.ServerConfig {
			start := time.Now()
			return &gossh.ServerConfig{
				ImplicitAuthMethod: "tailscale",
				NoClientAuth:       true, // required for the NoClientAuthCallback to run
				NoClientAuthCallback: func(cm gossh.ConnMetadata) (*gossh.Permissions, error) {
					cm.SendAuthBanner(fmt.Sprintf("# Banner: doing none auth at %v\r\n", time.Since(start)))

					totalBanners := 2
					if cm.User() == "banners" {
						totalBanners = 5
					}
					for banner := 2; banner <= totalBanners; banner++ {
						time.Sleep(time.Second)
						if banner == totalBanners {
							cm.SendAuthBanner(fmt.Sprintf("# Banner%d: access granted at %v\r\n", banner, time.Since(start)))
						} else {
							cm.SendAuthBanner(fmt.Sprintf("# Banner%d at %v\r\n", banner, time.Since(start)))
						}
					}
					return nil, nil
				},
				BannerCallback: func(cm gossh.ConnMetadata) string {
					log.Printf("Got connection from user %q, %q from %v", cm.User(), cm.ClientVersion(), cm.RemoteAddr())
					return fmt.Sprintf("# Banner for user %q, %q\n", cm.User(), cm.ClientVersion())
				},
			}
		},
	}

	for _, signer := range keys {
		srv.AddHostKey(signer)
	}

	log.Printf("Running on %s ...", srv.Addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
	log.Printf("done")
}

func handleSessionPostSSHAuth(s ssh.Session) {
	log.Printf("Started session from user %q", s.User())
	fmt.Fprintf(s, "Hello user %q, it worked.\n", s.User())

	// Abort the session on Control-C or Control-D.
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := s.Read(buf)
			for _, b := range buf[:n] {
				if b <= 4 { // abort on Control-C (3) or Control-D (4)
					io.WriteString(s, "bye\n")
					s.Exit(1)
				}
			}
			if err != nil {
				return
			}
		}
	}()

	for i := 10; i > 0; i-- {
		fmt.Fprintf(s, "%v ...\n", i)
		time.Sleep(time.Second)
	}
	s.Exit(0)
}

func getHostKeys(dir string) (ret []ssh.Signer, err error) {
	for _, typ := range keyTypes {
		hostKey, err := hostKeyFileOrCreate(dir, typ)
		if err != nil {
			return nil, err
		}
		signer, err := gossh.ParsePrivateKey(hostKey)
		if err != nil {
			return nil, err
		}
		ret = append(ret, signer)
	}
	return ret, nil
}

func hostKeyFileOrCreate(keyDir, typ string) ([]byte, error) {
	path := filepath.Join(keyDir, "ssh_host_"+typ+"_key")
	v, err := ioutil.ReadFile(path)
	if err == nil {
		return v, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	var priv any
	switch typ {
	default:
		return nil, fmt.Errorf("unsupported key type %q", typ)
	case "ed25519":
		_, priv, err = ed25519.GenerateKey(rand.Reader)
	case "ecdsa":
		// curve is arbitrary. We pick whatever will at
		// least pacify clients as the actual encryption
		// doesn't matter: it's all over WireGuard anyway.
		curve := elliptic.P256()
		priv, err = ecdsa.GenerateKey(curve, rand.Reader)
	case "rsa":
		// keySize is arbitrary. We pick whatever will at
		// least pacify clients as the actual encryption
		// doesn't matter: it's all over WireGuard anyway.
		const keySize = 2048
		priv, err = rsa.GenerateKey(rand.Reader, keySize)
	}
	if err != nil {
		return nil, err
	}
	mk, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	pemGen := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mk})
	err = os.WriteFile(path, pemGen, 0700)
	return pemGen, err
}
