package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"

	"golang.zx2c4.com/wireguard/tun"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
}

const ifaceName = "hack0"

func run() error {
	dev, err := tun.CreateTUN(ifaceName, 1280)
	if err != nil {
		return fmt.Errorf("creating tun: %v", err)
	}
	defer dev.Close()

	if err := exec.Command("ip", "link", "set", ifaceName, "addrgenmode", "none").Run(); err != nil {
		return fmt.Errorf("bringing up iface: %v", err)
	}
	if err := exec.Command("ip", "link", "set", ifaceName, "up").Run(); err != nil {
		return fmt.Errorf("bringing up iface: %v", err)
	}

	for {
		var b [1284]byte
		n, err := dev.Read(b[:], 4)
		if err != nil {
			return fmt.Errorf("reading from tun: %v", err)
		}

		bs := b[4 : 4+n]

		fmt.Printf("received packet of %d bytes\n", len(bs))
		hexdump(bs)
	}
}

func hexdump(bs []byte) {
	for i := range bs {
		switch {
		case i == 0:
		case i%16 == 0:
			fmt.Println("")
		case i%8 == 0:
			fmt.Printf("  ")
		}
		fmt.Printf("%02x ", bs[i])
	}
	fmt.Printf("\n\n")
}
