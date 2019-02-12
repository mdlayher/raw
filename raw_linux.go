// +build linux

package raw

import (
	"net"
	"os"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

var (
	// Must implement net.PacketConn at compile-time.
	_ net.PacketConn = &packetConn{}
)

// packetConn is the Linux-specific implementation of net.PacketConn for this
// package.
type packetConn struct {
	ifi *net.Interface
	s   socket
	pbe uint16

	// Should timeouts be set at all?
	noTimeouts bool

	// Should stats be accumulated instead of reset on each call?
	noCumulativeStats bool

	// Internal storage for cumulative stats.
	stats Stats
}

// socket is an interface which enables swapping out socket syscalls for
// testing.
type socket interface {
	Bind(unix.Sockaddr) error
	Close() error
	GetSockopt(level, name int, v unsafe.Pointer, l uintptr) error
	Recvfrom([]byte, int) (int, unix.Sockaddr, error)
	Sendto([]byte, int, unix.Sockaddr) error
	SetSockopt(level, name int, v unsafe.Pointer, l uint32) error

	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

// listenPacket creates a net.PacketConn which can be used to send and receive
// data at the device driver level.
func listenPacket(ifi *net.Interface, proto uint16, cfg Config) (*packetConn, error) {
	// Convert proto to big endian.
	pbe := htons(proto)

	// Enabling overriding the socket type via config.
	typ := unix.SOCK_RAW
	if cfg.LinuxSockDGRAM {
		typ = unix.SOCK_DGRAM
	}

	// Open a packet socket using specified socket and protocol types.
	sock, err := unix.Socket(unix.AF_PACKET, typ, int(pbe))
	if err != nil {
		return nil, err
	}

	if err := unix.SetNonblock(sock, true); err != nil {
		return nil, err
	}

	f := os.NewFile(uintptr(sock), "raw")

	// Wrap raw socket in socket interface.
	pc, err := newPacketConn(ifi, &sysSocket{f: f}, pbe)
	if err != nil {
		return nil, err
	}

	pc.noTimeouts = cfg.NoTimeouts
	pc.noCumulativeStats = cfg.NoCumulativeStats
	return pc, nil
}

// newPacketConn creates a net.PacketConn using the specified network
// interface, wrapped socket and big endian protocol number.
//
// It is the entry point for tests in this package.
func newPacketConn(ifi *net.Interface, s socket, pbe uint16) (*packetConn, error) {
	// Bind the packet socket to the interface specified by ifi
	// packet(7):
	//   Only the sll_protocol and the sll_ifindex address fields are used for
	//   purposes of binding.
	err := s.Bind(&unix.SockaddrLinklayer{
		Protocol: pbe,
		Ifindex:  ifi.Index,
	})
	if err != nil {
		return nil, err
	}

	return &packetConn{
		ifi: ifi,
		s:   s,
		pbe: pbe,
	}, nil
}

// ReadFrom implements the net.PacketConn.ReadFrom method.
func (p *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	// Attempt to receive on socket
	// The recvfrom sycall will NOT be interrupted by closing of the socket
	n, addr, err := p.s.Recvfrom(b, 0)
	switch err {
	case nil:
		// Got data, break this loop shortly.
	default:
		// Return on any other error.
		return n, nil, err
	}

	// Retrieve hardware address and other information from addr.
	sa, ok := addr.(*unix.SockaddrLinklayer)
	if !ok || sa.Halen < 6 {
		return n, nil, unix.EINVAL
	}

	// Use length specified to convert byte array into a hardware address slice.
	mac := make(net.HardwareAddr, sa.Halen)
	copy(mac, sa.Addr[:])

	// packet(7):
	//   sll_hatype and sll_pkttype are set on received packets for your
	//   information.
	// TODO(mdlayher): determine if similar fields exist and are useful on
	// non-Linux platforms
	return n, &Addr{
		HardwareAddr: mac,
	}, nil
}

// WriteTo implements the net.PacketConn.WriteTo method.
func (p *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	// Ensure correct Addr type.
	a, ok := addr.(*Addr)
	if !ok || a.HardwareAddr == nil || len(a.HardwareAddr) < 6 {
		return 0, unix.EINVAL
	}

	// Convert hardware address back to byte array form.
	var baddr [8]byte
	copy(baddr[:], a.HardwareAddr)

	// Send message on socket to the specified hardware address from addr
	// packet(7):
	//   When you send packets it is enough to specify sll_family, sll_addr,
	//   sll_halen, sll_ifindex, and sll_protocol. The other fields should
	//   be 0.
	// In this case, sll_family is taken care of automatically by unix.
	err := p.s.Sendto(b, 0, &unix.SockaddrLinklayer{
		Ifindex:  p.ifi.Index,
		Halen:    uint8(len(a.HardwareAddr)),
		Addr:     baddr,
		Protocol: p.pbe,
	})
	return len(b), err
}

// Close closes the connection.
func (p *packetConn) Close() error {
	return p.s.Close()
}

// LocalAddr returns the local network address.
func (p *packetConn) LocalAddr() net.Addr {
	return &Addr{
		HardwareAddr: p.ifi.HardwareAddr,
	}
}

// SetDeadline implements the net.PacketConn.SetDeadline method.
func (p *packetConn) SetDeadline(t time.Time) error {
	return p.s.SetDeadline(t)
}

// SetReadDeadline implements the net.PacketConn.SetReadDeadline method.
func (p *packetConn) SetReadDeadline(t time.Time) error {
	return p.s.SetReadDeadline(t)
}

// SetWriteDeadline implements the net.PacketConn.SetWriteDeadline method.
func (p *packetConn) SetWriteDeadline(t time.Time) error {
	return p.s.SetWriteDeadline(t)
}

// SetBPF attaches an assembled BPF program to a raw net.PacketConn.
func (p *packetConn) SetBPF(filter []bpf.RawInstruction) error {
	prog := unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: (*unix.SockFilter)(unsafe.Pointer(&filter[0])),
	}

	err := p.s.SetSockopt(
		unix.SOL_SOCKET,
		unix.SO_ATTACH_FILTER,
		unsafe.Pointer(&prog),
		uint32(unsafe.Sizeof(prog)),
	)
	if err != nil {
		return os.NewSyscallError("setsockopt", err)
	}

	return nil
}

// SetPromiscuous enables or disables promiscuous mode on the interface, allowing it
// to receive traffic that is not addressed to the interface.
func (p *packetConn) SetPromiscuous(b bool) error {
	mreq := unix.PacketMreq{
		Ifindex: int32(p.ifi.Index),
		Type:    unix.PACKET_MR_PROMISC,
	}

	membership := unix.PACKET_ADD_MEMBERSHIP
	if !b {
		membership = unix.PACKET_DROP_MEMBERSHIP
	}

	return p.s.SetSockopt(unix.SOL_PACKET, membership, unsafe.Pointer(&mreq), unix.SizeofPacketMreq)
}

// Stats retrieves statistics from the Conn.
func (p *packetConn) Stats() (*Stats, error) {
	var s unix.TpacketStats
	if err := p.s.GetSockopt(unix.SOL_PACKET, unix.PACKET_STATISTICS, unsafe.Pointer(&s), unsafe.Sizeof(s)); err != nil {
		return nil, err
	}

	return p.handleStats(s), nil
}

// handleStats handles creation of Stats structures from raw packet socket stats.
func (p *packetConn) handleStats(s unix.TpacketStats) *Stats {
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

// sysSocket is the default socket implementation.  It makes use of
// Linux-specific system calls to handle raw socket functionality.
type sysSocket struct {
	f *os.File
}

// Method implementations simply invoke the syscall of the same name, but pass
// the file descriptor stored in the sysSocket as the socket to use.
func (s *sysSocket) Bind(sa unix.Sockaddr) error {
	var err error
	doErr := fdcontrol(s.f, func(fd int) {
		err = unix.Bind(fd, sa)
	})
	if doErr != nil {
		return doErr
	}

	return err
}

func (s *sysSocket) Close() error {
	var err error
	doErr := fdcontrol(s.f, func(fd int) {
		err = unix.Close(fd)
	})
	if doErr != nil {
		return doErr
	}

	return err
}

func (s *sysSocket) GetSockopt(level, name int, v unsafe.Pointer, l uintptr) error {
	var err error
	doErr := fdcontrol(s.f, func(fd int) {
		_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), uintptr(level), uintptr(name), uintptr(v), uintptr(unsafe.Pointer(&l)), 0)
		if errno != 0 {
			err = unix.Errno(errno)
		}
	})
	if doErr != nil {
		return doErr
	}

	return err

}
func (s *sysSocket) Recvfrom(p []byte, flags int) (int, unix.Sockaddr, error) {
	var (
		n    int
		from unix.Sockaddr
		err  error
	)

	doErr := fdread(s.f, func(fd int) bool {
		n, from, err = unix.Recvfrom(fd, p, flags)
		if err == unix.EAGAIN {
			return false
		}

		return true
	})
	if doErr != nil {
		return 0, nil, doErr
	}

	return n, from, err

}
func (s *sysSocket) Sendto(p []byte, flags int, to unix.Sockaddr) error {
	var err error
	doErr := fdwrite(s.f, func(fd int) bool {
		err = unix.Sendto(fd, p, flags, to)
		if err == unix.EAGAIN {
			return false
		}

		return true
	})
	if doErr != nil {
		return doErr
	}

	return err
}

func (s *sysSocket) SetSockopt(level, name int, v unsafe.Pointer, l uint32) error {
	var err error
	doErr := fdcontrol(s.f, func(fd int) {
		_, _, errno := unix.Syscall6(unix.SYS_SETSOCKOPT, uintptr(fd), uintptr(level), uintptr(name), uintptr(v), uintptr(l), 0)
		if errno != 0 {
			err = unix.Errno(errno)
		}
	})
	if doErr != nil {
		return doErr
	}

	return err
}

func (s *sysSocket) SetDeadline(t time.Time) error {
	return s.f.SetDeadline(t)
}

func (s *sysSocket) SetReadDeadline(t time.Time) error {
	return s.f.SetReadDeadline(t)
}

func (s *sysSocket) SetWriteDeadline(t time.Time) error {
	return s.f.SetWriteDeadline(t)
}

func fdread(fd *os.File, f func(int) (done bool)) error {
	rc, err := fd.SyscallConn()
	if err != nil {
		return err
	}
	return rc.Read(func(sysfd uintptr) bool {
		return f(int(sysfd))
	})
}

func fdwrite(fd *os.File, f func(int) (done bool)) error {
	rc, err := fd.SyscallConn()
	if err != nil {
		return err
	}
	return rc.Write(func(sysfd uintptr) bool {
		return f(int(sysfd))
	})
}

func fdcontrol(fd *os.File, f func(int)) error {
	rc, err := fd.SyscallConn()
	if err != nil {
		return err
	}
	return rc.Control(func(sysfd uintptr) {
		f(int(sysfd))
	})
}
