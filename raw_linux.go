//go:build linux
// +build linux

package raw

import (
	"net"
	"sync/atomic"
	"time"

	"github.com/mdlayher/packet"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// Must implement net.PacketConn at compile-time.
var _ net.PacketConn = &packetConn{}

// packetConn is the Linux-specific implementation of net.PacketConn for this
// package.
type packetConn struct {
	ifi *net.Interface
	c   *packet.Conn

	// Should stats be accumulated instead of reset on each call?
	noCumulativeStats bool

	// Internal storage for cumulative stats.
	stats Stats
}

// listenPacket creates a net.PacketConn which can be used to send and receive
// data at the device driver level.
func listenPacket(ifi *net.Interface, proto uint16, cfg Config) (*packetConn, error) {
	typ := packet.Raw
	if cfg.LinuxSockDGRAM {
		typ = packet.Datagram
	}

	c, err := packet.Listen(ifi, typ, int(proto), &packet.Config{
		// Propagate matching options.
		Filter: cfg.Filter,
	})
	if err != nil {
		return nil, err
	}

	return &packetConn{
		ifi: ifi,
		c:   c,

		noCumulativeStats: cfg.NoCumulativeStats,
	}, nil
}

// ReadFrom implements the net.PacketConn.ReadFrom method.
func (p *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := p.c.ReadFrom(b)
	if err != nil {
		return n, nil, err
	}

	raddr := &Addr{HardwareAddr: addr.(*packet.Addr).HardwareAddr}
	return n, raddr, nil
}

// WriteTo implements the net.PacketConn.WriteTo method.
func (p *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	raddr, ok := addr.(*Addr)
	if !ok {
		return 0, unix.EINVAL
	}

	paddr := &packet.Addr{HardwareAddr: raddr.HardwareAddr}
	return p.c.WriteTo(b, paddr)
}

// Close closes the connection.
func (p *packetConn) Close() error {
	return p.c.Close()
}

// LocalAddr returns the local network address.
func (p *packetConn) LocalAddr() net.Addr {
	addr := p.c.LocalAddr().(*packet.Addr)
	return &Addr{
		HardwareAddr: addr.HardwareAddr,
	}
}

// SetDeadline implements the net.PacketConn.SetDeadline method.
func (p *packetConn) SetDeadline(t time.Time) error {
	return p.c.SetDeadline(t)
}

// SetReadDeadline implements the net.PacketConn.SetReadDeadline method.
func (p *packetConn) SetReadDeadline(t time.Time) error {
	return p.c.SetReadDeadline(t)
}

// SetWriteDeadline implements the net.PacketConn.SetWriteDeadline method.
func (p *packetConn) SetWriteDeadline(t time.Time) error {
	return p.c.SetWriteDeadline(t)
}

// SetBPF attaches an assembled BPF program to a raw net.PacketConn.
func (p *packetConn) SetBPF(filter []bpf.RawInstruction) error {
	return p.c.SetBPF(filter)
}

// SetPromiscuous enables or disables promiscuous mode on the interface, allowing it
// to receive traffic that is not addressed to the interface.
func (p *packetConn) SetPromiscuous(enable bool) error {
	return p.c.SetPromiscuous(enable)
}

// Stats retrieves statistics from the Conn.
func (p *packetConn) Stats() (*Stats, error) {
	stats, err := p.c.Stats()
	if err != nil {
		return nil, err
	}

	return p.handleStats(stats), nil
}

// handleStats handles creation of Stats structures from *packet.Stats.
func (p *packetConn) handleStats(s *packet.Stats) *Stats {
	// Does the caller want instantaneous stats as provided by Linux?  If so,
	// return the structure directly.
	if p.noCumulativeStats {
		return &Stats{
			Packets: uint64(s.Packets),
			Drops:   uint64(s.Drops),
		}
	}

	// The caller wants cumulative stats.  Add stats with the internal stats
	// structure and return a copy of the resulting stats.
	packets := atomic.AddUint64(&p.stats.Packets, uint64(s.Packets))
	drops := atomic.AddUint64(&p.stats.Drops, uint64(s.Drops))

	return &Stats{
		Packets: packets,
		Drops:   drops,
	}
}
