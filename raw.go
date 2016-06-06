// Package raw enables reading and writing data at the device driver level for
// a network interface.
package raw

import (
	"errors"
	"net"
	"time"

	"golang.org/x/net/bpf"
)

const (
	// ProtocolAoE specifies the ATA over Ethernet protocol (AoEr11).
	ProtocolAoE Protocol = 0x88a2

	// ProtocolARP specifies the Address Resolution Protocol (RFC 826).
	ProtocolARP Protocol = 0x0806

	// ProtocolWoL specifies the Wake-on-LAN protocol.
	ProtocolWoL Protocol = 0x0842
)

var (
	// ErrNotImplemented is returned when certain functionality is not yet
	// implemented for the host operating system.
	ErrNotImplemented = errors.New("raw: not implemented")
)

var _ net.Addr = &Addr{}

// Addr is a network address which can be used to contact other machines, using
// their hardware addresses.
type Addr struct {
	HardwareAddr net.HardwareAddr
}

// Network returns the address's network name, "raw".
func (a *Addr) Network() string {
	return "raw"
}

// String returns the address's hardware address.
func (a *Addr) String() string {
	return a.HardwareAddr.String()
}

var _ net.PacketConn = &Conn{}

// Conn is an implementation of the net.PacketConn interface which can send
// and receive data at the network interface device driver level.
type Conn struct {
	// packetConn is the operating system-specific implementation of
	// a raw connection.
	p *packetConn
}

// ReadFrom implements the net.PacketConn ReadFrom method.
func (c *Conn) ReadFrom(b []byte) (int, net.Addr, error) {
	return c.p.ReadFrom(b)
}

// WriteTo implements the net.PacketConn WriteTo method.
func (c *Conn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return c.p.WriteTo(b, addr)
}

// Close closes the connection.
func (c *Conn) Close() error {
	return c.p.Close()
}

// LocalAddr returns the local network address.
func (c *Conn) LocalAddr() net.Addr {
	return c.p.LocalAddr()
}

// SetDeadline implements the net.PacketConn SetDeadline method.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.p.SetDeadline(t)
}

// SetReadDeadline implements the net.PacketConn SetReadDeadline method.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.p.SetReadDeadline(t)
}

// SetWriteDeadline implements the net.PacketConn SetWriteDeadline method.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.p.SetWriteDeadline(t)
}

// SetBPF attaches an assembled BPF program to the connection.
func (c *Conn) SetBPF(filter []bpf.RawInstruction) error {
	return c.p.SetBPF(filter)
}

// A Protocol is a network protocol constant which identifies the type of
// traffic a raw socket should send and receive.
type Protocol uint16

// ListenPacket creates a net.PacketConn which can be used to send and receive
// data at the network interface device driver level.
//
// ifi specifies the network interface which will be used to send and receive
// data.  proto specifies the protocol which should be captured and
// transmitted.  proto, if needed, is automatically converted to network byte
// order (big endian), akin to the htons() function in C.
func ListenPacket(ifi *net.Interface, proto Protocol) (*Conn, error) {
	p, err := listenPacket(ifi, proto)
	if err != nil {
		return nil, err
	}

	return &Conn{
		p: p,
	}, nil
}

// htons converts a short (uint16) from host-to-network byte order.
// Thanks to mikioh for this neat trick:
// https://github.com/mikioh/-stdyng/blob/master/afpacket.go
func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

// Copyright (c) 2012 The Go Authors. All rights reserved.
// Source code in this file is based on src/net/interface_linux.go,
// from the Go standard library.  The Go license can be found here:
// https://golang.org/LICENSE.

// Taken from:
// https://github.com/golang/go/blob/master/src/net/net.go#L417-L421.
type timeoutError struct{}

func (e *timeoutError) Error() string   { return "i/o timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }
