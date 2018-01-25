package sshd_test

import (
	"io"
	"io/ioutil"

	"ireul.com/sshd"
)

func ExampleListenAndServe() {
	sshd.ListenAndServe(":2222", func(s sshd.Session) {
		io.WriteString(s, "Hello world\n")
	})
}

func ExamplePasswordAuth() {
	sshd.ListenAndServe(":2222", nil,
		sshd.PasswordAuth(func(ctx sshd.Context, pass string) bool {
			return pass == "secret"
		}),
	)
}

func ExampleNoPty() {
	sshd.ListenAndServe(":2222", nil, sshd.NoPty())
}

func ExamplePublicKeyAuth() {
	sshd.ListenAndServe(":2222", nil,
		sshd.PublicKeyAuth(func(ctx sshd.Context, key sshd.PublicKey) bool {
			data, _ := ioutil.ReadFile("/path/to/allowed/key.pub")
			allowed, _, _, _, _ := sshd.ParseAuthorizedKey(data)
			return sshd.KeysEqual(key, allowed)
		}),
	)
}

func ExampleHostKeyFile() {
	sshd.ListenAndServe(":2222", nil, sshd.HostKeyFile("/path/to/host/key"))
}
