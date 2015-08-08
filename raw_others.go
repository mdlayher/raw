// +build !linux

package raw

import (
	"net"
	"time"
)

const (
	// ProtocolAoE specifies the ATA over Ethernet protocol (AoEr11).
	ProtocolAoE Protocol = 0

	// ProtocolARP specifies the Address Resolution Protocol (RFC 826).
	ProtocolARP Protocol = 0

	// ProtocolWoL specifies the Wake-on-LAN protocol.
	ProtocolWoL Protocol = 0
)

var (
	// Must implement net.PacketConn at compile-time.
	_ net.PacketConn = &packetConn{}
)

// packetConn is the generic implementation of net.PacketConn for this package.
type packetConn struct{}

// listenPacket is not currently implemented on this platform.
func listenPacket(ifi *net.Interface, proto Protocol) (*packetConn, error) {
	return nil, ErrNotImplemented
}

// ReadFrom is not currently implemented on this platform.
func (p *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	return 0, nil, ErrNotImplemented
}

// WriteTo is not currently implemented on this platform.
func (p *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return 0, ErrNotImplemented
}

// Close is not currently implemented on this platform.
func (p *packetConn) Close() error {
	return ErrNotImplemented
}

// LocalAddr is not currently implemented on this platform.
func (p *packetConn) LocalAddr() net.Addr {
	return nil
}

// SetDeadline is not currently implemented on this platform.
func (p *packetConn) SetDeadline(t time.Time) error {
	return ErrNotImplemented
}

// SetReadDeadline is not currently implemented on this platform.
func (p *packetConn) SetReadDeadline(t time.Time) error {
	return ErrNotImplemented
}

// SetWriteDeadline is not currently implemented on this platform.
func (p *packetConn) SetWriteDeadline(t time.Time) error {
	return ErrNotImplemented
}
