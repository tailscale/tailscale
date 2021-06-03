package main

import (
	"os"

	"tailscale.com/net/uring"
)

func main() {
	const msg = "hello, I am here\n"
	err := os.WriteFile("junk", []byte(msg), 0644)
	check(err)

	f, err := os.Open("junk")
	check(err)
	defer f.Close()

	uf, err := uring.NewFile(f)
	check(err)
	for i := 0; i < 1000; i++ {
		go func() {
			buf := make([]byte, 100)
			n, err := uf.Read(buf)
			check(err)
			if n != len(msg) || string(buf[:n]) != msg {
				panic("OOPS")
			}
		}()
	}
	// fmt.Println("read", n, "bytes")
	// fmt.Println(string(buf[:n]))
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
