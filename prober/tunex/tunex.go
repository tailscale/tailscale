package main

import (
	"io"
	"log"
	"net"
	"net/netip"

	"tailscale.com/net/tstun"
	"tailscale.com/wgengine/router"
)

func main() {
	dev, name, err := tstun.New(log.Printf, "utun9")
	if err != nil {
		log.Fatal(err)
	}
	defer dev.Close()
	log.Printf("Interface is %s", name)

	r, err := router.New(log.Printf, dev, nil, nil)
	if err != nil {
		log.Fatal(err)
	}

	r.Set(&router.Config{
		LocalAddrs: []netip.Prefix{netip.MustParsePrefix("172.16.0.1/30")},
		Routes:     []netip.Prefix{netip.MustParsePrefix("172.16.0.1/30")},
	})

	mtu, err := dev.MTU()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("MTU is %d", mtu)

	go func() {
		bufs := [][]byte{
			make([]byte, mtu+16),
		}
		sizes := []int{0}
		for {
			n, err := dev.Read(bufs, sizes, 16)
			if err != nil {
				return
			}
			for i := range n {
				pkt := bufs[i][16 : sizes[i]+16]
				src, dst := make([]byte, 4), make([]byte, 4)
				srcPort, dstPort := make([]byte, 2), make([]byte, 2)
				copy(src, pkt[12:16])
				copy(dst, pkt[16:20])
				// TODO: the below assumes no IP options in header
				copy(srcPort, pkt[20:22])
				copy(dstPort, pkt[22:24])

				// Swap
				copy(pkt[12:], dst)
				copy(pkt[16:], src)
				copy(pkt[20:], dstPort)
				copy(pkt[22:], srcPort)
			}
			dev.Write(bufs, 16)
		}
	}()

	// l, err := net.Listen("tcp", "*:5201")
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// var wg sync.WaitGroup
	// go func() {
	// 	defer wg.Done()
	// 	conn, err := l.Accept()
	// 	if err != nil {
	// 		log.Fatal(err)
	// 	}
	// 	b, err := io.ReadAll(conn)
	// 	if err != nil {
	// 		log.Fatal(err)
	// 	}
	// 	fmt.Println(string(b))
	// }()

	// log.Println("Waiting 10 seconds before starting")
	// time.Sleep(10 * time.Second)
	// defer time.Sleep(10 * time.Second)
	// log.Println("Starting")

	conn, err := net.Dial("tcp", "172.16.0.2:5201")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	log.Println("Connected!")
	go func() {
		_, err = conn.Write([]byte("hello world"))
		if err != nil {
			log.Fatal(err)
		}
	}()

	b := make([]byte, 11)
	n, err := io.ReadFull(conn, b)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(string([]byte(b[:n])))

	// wg.Wait()
}
