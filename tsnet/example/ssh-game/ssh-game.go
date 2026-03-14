// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// The ssh-game server demonstrates how to use tsnet's ListenSSH to build
// a custom SSH application. It runs a simple "guess the number" game.
//
// Usage:
//
//	go run ./tsnet/example/ssh-game
//
// Then from another Tailscale node:
//
//	ssh -p 2222 <hostname>
package main

import (
	"bufio"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"strings"

	_ "tailscale.com/feature/ssh"
	"tailscale.com/ssh/tailssh"
	"tailscale.com/tsnet"
)

func main() {
	s := &tsnet.Server{
		Hostname: "ssh-game",
	}
	defer s.Close()

	ln, err := s.ListenSSH(":2222")
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	log.Println("Listening on :2222")

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go handleGame(conn)
	}
}

func handleGame(c net.Conn) {
	sess, ok := c.(*tailssh.Session)
	if !ok {
		fmt.Fprintf(c, "unexpected connection type\n")
		c.Close()
		return
	}
	defer sess.Exit(0)

	peer := sess.PeerIdentity()
	target := rand.IntN(100) + 1
	scanner := bufio.NewScanner(sess)

	fmt.Fprintf(sess, "Welcome, %s from %s!\r\n",
		peer.UserProfile.LoginName,
		peer.Node.ComputedName())
	fmt.Fprintf(sess, "I'm thinking of a number between 1 and 100.\r\n")
	fmt.Fprintf(sess, "Can you guess it?\r\n\r\n")

	for attempts := 1; ; attempts++ {
		fmt.Fprintf(sess, "Your guess: ")
		if !scanner.Scan() {
			return
		}
		line := strings.TrimSpace(scanner.Text())
		var guess int
		if _, err := fmt.Sscanf(line, "%d", &guess); err != nil {
			fmt.Fprintf(sess, "Please enter a number.\r\n")
			continue
		}
		switch {
		case guess < target:
			fmt.Fprintf(sess, "Higher!\r\n")
		case guess > target:
			fmt.Fprintf(sess, "Lower!\r\n")
		default:
			fmt.Fprintf(sess, "Correct! You got it in %d attempts.\r\n", attempts)
			return
		}
	}
}
