// Package raw enables reading and writing data at the device driver level for
// a network interface.
package raw

import (
	"errors"
	"net"
)

var (
	// ErrNotImplemented is returned when certain functionality is not yet
	// implemented for the host operating system.
	ErrNotImplemented = errors.New("not implemented")
)

// Addr is a network address which can be used to contact other machines, using
// their hardware addresses.
type Addr struct {
	HardwareAddr net.HardwareAddr
}

// Network returns the address's network name, "raw".
func (a Addr) Network() string {
	return "raw"
}

// String returns the address's hardware address.
func (a Addr) String() string {
	return a.HardwareAddr.String()
}

// A Protocol is a network protocol constant which identifies the type of
// traffic a raw socket should send and receive.
type Protocol uint16

// ListenPacket creates a net.PacketConn which can be used to send and receive
// data at the network interface device driver level.
//
// ifi specifies the network interface which will be used to send and receive
// data.  proto specifies the protocol which should be captured and
// transmitted.  proto is automatically converted to network byte
// order (big endian), akin to the htons() function in C.
func ListenPacket(ifi *net.Interface, proto Protocol) (net.PacketConn, error) {
	return listenPacket(ifi, proto)
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
