package ssh_test

import (
	"errors"
	"io"
	"os"

	"tailscale.com/tempfork/gliderlabs/ssh"
)

func ExampleListenAndServe() {
	ssh.ListenAndServe(":2222", func(s ssh.Session) {
		io.WriteString(s, "Hello world\n")
	})
}

func ExamplePasswordAuth() {
	ssh.ListenAndServe(":2222", nil,
		ssh.PasswordAuth(func(ctx ssh.Context, pass string) bool {
			return pass == "secret"
		}),
	)
}

func ExampleNoPty() {
	ssh.ListenAndServe(":2222", nil, ssh.NoPty())
}

func ExamplePublicKeyAuth() {
	ssh.ListenAndServe(":2222", nil,
		ssh.PublicKeyAuth(func(ctx ssh.Context, key ssh.PublicKey) error {
			data, err := os.ReadFile("/path/to/allowed/key.pub")
			if err != nil {
				return err
			}
			allowed, _, _, _, err := ssh.ParseAuthorizedKey(data)
			if err != nil {
				return err
			}
			if !ssh.KeysEqual(key, allowed) {
				return errors.New("some error")
			}
			return nil
		}),
	)
}

func ExampleHostKeyFile() {
	ssh.ListenAndServe(":2222", nil, ssh.HostKeyFile("/path/to/host/key"))
}
