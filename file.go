package main

import (
	"fmt"
	"os"
	"syscall"
	"time"

	"tailscale.com/net/uring"
)

func main() {
	// f, err := os.Create("junk")
	// check(err)
	// _, err = f.Write([]byte("CMON\n"))
	// check(err)

	fd, err := syscall.Open("trash", syscall.O_RDWR|syscall.O_CREAT|syscall.O_TRUNC, 0644)
	check(err)
	n, err := syscall.Write(int(fd), []byte("part two\n"))
	check(err)
	fmt.Println("N", n)

	ff := os.NewFile(uintptr(fd), "trash")
	uf, err := uring.NewFile(ff)
	check(err)
	for i := 0; i < 1; i++ {
		s := fmt.Sprintf("i can count to %d\x00\n", i)
		n, err := uf.Write([]byte(s), n)
		check(err)
		fmt.Println("wrote", n, "bytes")
		time.Sleep(3 * time.Second)
	}
	syscall.Close(fd)
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
