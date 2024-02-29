//go:build gen

package main

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
)

func main() {
	for _, name := range []string{"comp.bash", "comp.zsh", "comp.fish", "comp.ps1"} {
		err := compress(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, "compressing "+name+":", err)
			os.Exit(1)
		}
	}
}

func compress(name string) error {
	src, err := os.Open(name)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.Create(name + ".gz")
	if err != nil {
		return err
	}
	defer dst.Close()

	z := gzip.NewWriter(dst)
	_, err = io.Copy(z, src)
	if err != nil {
		return err
	}

	return z.Close()
}
