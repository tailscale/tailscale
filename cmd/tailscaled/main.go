package main

import (
	"os"
	"strings"
)

func main() {
	if strings.HasSuffix(os.Args[0], "tailscaled") {
		tailscaled_main()
	} else if strings.HasSuffix(os.Args[0], "tailscale") {
		tailscale_main()
	} else {
		panic(os.Args[0])
	}
}
