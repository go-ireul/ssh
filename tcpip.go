package sshd

import (
	"fmt"
	"io"
	"net"

	"golang.org/x/crypto/ssh"
)

// direct-tcpip data struct as specified in RFC4254, Section 7.2
type forwardData struct {
	DestinationHost string
	DestinationPort uint32

	OriginatorHost string
	OriginatorPort uint32
}

func directTcpipHandler(srv *Server, conn *ssh.ServerConn, newChan ssh.NewChannel, ctx Context) {
	d := forwardData{}
	if err := ssh.Unmarshal(newChan.ExtraData(), &d); err != nil {
		newChan.Reject(ssh.ConnectionFailed, "error parsing forward data: "+err.Error())
		return
	}

	if srv.LocalPortForwardingCallback == nil || !srv.LocalPortForwardingCallback(ctx, d.DestinationHost, d.DestinationPort) {
		newChan.Reject(ssh.Prohibited, "port forwarding is disabled")
		return
	}

	dest := fmt.Sprintf("%s:%d", d.DestinationHost, d.DestinationPort)

	var dialer net.Dialer
	dconn, err := dialer.DialContext(ctx, "tcp", dest)
	if err != nil {
		newChan.Reject(ssh.ConnectionFailed, err.Error())
		return
	}

	ch, reqs, err := newChan.Accept()
	if err != nil {
		dconn.Close()
		return
	}
	go ssh.DiscardRequests(reqs)

	go func() {
		defer ch.Close()
		defer dconn.Close()
		io.Copy(ch, dconn)
	}()
	go func() {
		defer ch.Close()
		defer dconn.Close()
		io.Copy(dconn, ch)
	}()
}
