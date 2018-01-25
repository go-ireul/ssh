package main

import (
	"fmt"
	"io"
	"log"

	"ireul.com/sshd"
)

func main() {
	ssh.Handle(func(s sshd.Session) {
		io.WriteString(s, fmt.Sprintf("Hello %s\n", s.User()))
	})

	log.Println("starting ssh server on port 2222...")
	log.Fatal(ssh.ListenAndServe(":2222", nil))
}
