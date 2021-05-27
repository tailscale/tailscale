package main

import (
	"fmt"
	"net"

	"tailscale.com/net/uring"
)

func main() {
	listen, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 9999})
	check(err)
	fmt.Println("listening UDP on", listen.LocalAddr())

	conn, err := uring.NewUDPConn(listen)
	check(err)
	for {
		b := make([]byte, 2000)
		n, ipp, err := conn.ReadFromNetaddr(b)
		check(err)
		fmt.Printf("received %q from %v\n", b[:n], ipp)
	}
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
