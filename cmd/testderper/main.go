package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"tailscale.com/derp/derphttp"
	"tailscale.com/types/key"
)

// import derp client

func main() {

	dothestuff()

}

func dothestuff() {

	clientPriv := key.NewNode()

	c, err := derphttp.NewClient(clientPriv, "http://localhost:3340/derp", log.Printf)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	err = c.Connect(context.Background())
	if err != nil {
		fmt.Println(err)
		panic("connect")
	}

	n := key.NewNode()

	nc, err := derphttp.NewClient(clientPriv, "http://localhost:3340/derp", log.Printf)
	if err != nil {
		log.Fatal(err)
	}
	defer nc.Close()

	err = nc.Connect(context.Background())
	if err != nil {
		fmt.Println(err)
		panic("connect")
	}

	fmt.Println(c.ServerPublicKey())

	for i := 0; i < 2; i++ {

		fmt.Println("hi?")

		if err := c.SendPing([8]byte{1, 2, 3, 4, 5, 6, 7, 8}); err != nil {
			fmt.Println(err)
		}
		time.Sleep(time.Millisecond * 100)

		if err := c.Send(n.Public(), []byte{1, 2, 3, 4, 5, 6, 7, 8}); err != nil {
			fmt.Println(err)
		}

		time.Sleep(time.Millisecond * 100)

		if err := nc.Send(clientPriv.Public(), []byte{1, 2, 3, 4, 5, 6, 7, 8}); err != nil {
			fmt.Println(err)
		}

		c.NotePreferred(true)

		time.Sleep(time.Millisecond * 100)

	}

}
