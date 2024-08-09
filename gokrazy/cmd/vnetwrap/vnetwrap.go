package main

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
)

const path = "/tmp/vnet.sock"

func serve(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("Accept: %v", err)
			continue
		}
		go serveConn(c)
	}
}

func serveConn(c net.Conn) {
	log.Printf("Got conn")
	defer c.Close()

	buf := make([]byte, 4<<10)
	for {
		if _, err := io.ReadFull(c, buf[:4]); err != nil {
			log.Printf("ReadFull header: %v", err)
			return
		}
		n := binary.BigEndian.Uint32(buf[:4])

		if _, err := io.ReadFull(c, buf[:n]); err != nil {
			log.Printf("ReadFull pkt: %v", err)
			return
		}

		log.Printf("pkt %d bytes: % 02x", n, buf[:n])
	}
}

func main() {
	srv, err := net.Listen("unix", path)
	if err != nil {
		log.Fatal(err)
	}
	go serve(srv)
	conn, err := net.Dial("unix", path)
	if err != nil {
		log.Fatal(err)
	}
	fd, err := conn.(*net.UnixConn).File()
	if err != nil {
		log.Fatal(err)
	}
	cmd := exec.Command(os.Args[1], os.Args[2:]...) // #nosec G204
	cmd.ExtraFiles = append(cmd.ExtraFiles, fd)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatal(err)
	}
}
