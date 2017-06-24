// +build linux

package raw

import (
	"net"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/net/context"
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

	// Sleep function implementation
	sleeper sleeper

	// Timeouts set via Set{Read,}Deadline, guarded by mutex
	timeoutMu   sync.RWMutex
	nonblocking bool
	rtimeout    time.Time
}

// socket is an interface which enables swapping out socket syscalls for
// testing.
type socket interface {
	Bind(syscall.Sockaddr) error
	Close() error
	FD() int
	Recvfrom([]byte, int) (int, syscall.Sockaddr, error)
	Sendto([]byte, int, syscall.Sockaddr) error
	SetNonblock(bool) error
	SetSockopt(level, name int, v unsafe.Pointer, l uint32) error
}

// sleeper is an interface which enables swapping out an actual time.Sleep
// call for testing.
type sleeper interface {
	Sleep(time.Duration)
}

// listenPacket creates a net.PacketConn which can be used to send and receive
// data at the device driver level.
//
// ifi specifies the network interface which will be used to send and receive
// data.  proto specifies the protocol which should be captured and
// transmitted.  proto is automatically converted to network byte
// order (big endian), akin to the htons() function in C.
func listenPacket(ifi *net.Interface, proto Protocol) (*packetConn, error) {
	// Convert proto to big endian
	pbe := htons(uint16(proto))

	// Open a packet socket using specified socket and protocol types
	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(pbe))
	if err != nil {
		return nil, err
	}

	// Wrap raw socket in socket interface, use actual time package sleeper
	return newPacketConn(
		ifi,
		&sysSocket{
			fd: sock,
		},
		pbe,
		&timeSleeper{},
	)
}

// newPacketConn creates a net.PacketConn using the specified network
// interface, wrapped socket, big endian protocol number, and Sleep
// implementation used for read/write retries.
//
// It is the entry point for tests in this package.
func newPacketConn(ifi *net.Interface, s socket, pbe uint16, sleeper sleeper) (*packetConn, error) {
	// Bind the packet socket to the interface specified by ifi
	// packet(7):
	//   Only the sll_protocol and the sll_ifindex address fields are used for
	//   purposes of binding.
	err := s.Bind(&syscall.SockaddrLinklayer{
		Protocol: pbe,
		Ifindex:  ifi.Index,
	})

	return &packetConn{
		ifi:     ifi,
		s:       s,
		sleeper: sleeper,
	}, err
}

// ReadFrom implements the net.PacketConn.ReadFrom method.
func (p *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	// Set up deadline context if needed, if a read timeout is set
	ctx, cancel := context.TODO(), func() {}
	p.timeoutMu.RLock()
	if p.rtimeout.After(time.Now()) {
		ctx, cancel = context.WithDeadline(context.Background(), p.rtimeout)
	}
	p.timeoutMu.RUnlock()

	// Information returned by syscall.Recvfrom
	var n int
	var addr syscall.Sockaddr
	var err error

	for {
		// Continue looping, or if deadline is set and has expired, return
		// an error
		select {
		case <-ctx.Done():
			// We only know how to handle deadline exceeded, so return any
			// other errors for the caller to deal with
			if err := ctx.Err(); err != context.DeadlineExceeded {
				return n, nil, err
			}

			// Return standard net.OpError so caller can detect timeouts and retry
			return n, nil, &net.OpError{
				Op:   "read",
				Net:  "raw",
				Addr: nil,
				Err:  &timeoutError{},
			}
		default:
			// Not timed out, keep trying
		}

		// Attempt to receive on socket
		n, addr, err = p.s.Recvfrom(b, 0)
		if err != nil {
			n = 0

			// EAGAIN is returned when no data is available for non-blocking
			// I/O, so keep trying after a short delay
			if err == syscall.EAGAIN {
				p.sleeper.Sleep(2 * time.Millisecond)
				continue
			}

			// Return other errors
			return n, nil, err
		}

		// Got data, cancel the deadline
		cancel()
		break
	}

	// Retrieve hardware address and other information from addr
	sa, ok := addr.(*syscall.SockaddrLinklayer)
	if !ok || sa.Halen < 6 {
		return n, nil, syscall.EINVAL
	}

	// Use length specified to convert byte array into a hardware address slice
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
	// Ensure correct Addr type
	a, ok := addr.(*Addr)
	if !ok || len(a.HardwareAddr) < 6 {
		return 0, syscall.EINVAL
	}

	// Convert hardware address back to byte array form
	var baddr [8]byte
	copy(baddr[:], a.HardwareAddr)

	// Send message on socket to the specified hardware address from addr
	// packet(7):
	//   When you send packets it is enough to specify sll_family, sll_addr,
	//   sll_halen, sll_ifindex.  The other fields should  be 0.
	// In this case, sll_family is taken care of automatically by syscall
	err := p.s.Sendto(b, 0, &syscall.SockaddrLinklayer{
		Ifindex: p.ifi.Index,
		Halen:   uint8(len(a.HardwareAddr)),
		Addr:    baddr,
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

// TODO(mdlayher): it is unfortunate that we have to implement deadlines using
// a context, but it appears that there may not be a better solution until
// Go 1.6 or later.  See here: https://github.com/golang/go/issues/10565.

// SetDeadline implements the net.PacketConn.SetDeadline method.
func (p *packetConn) SetDeadline(t time.Time) error {
	return p.SetReadDeadline(t)
}

// SetReadDeadline implements the net.PacketConn.SetReadDeadline method.
func (p *packetConn) SetReadDeadline(t time.Time) error {
	p.timeoutMu.Lock()

	// Set nonblocking I/O so we can time out reads and writes
	//
	// This is set only if timeouts are used, because a server probably
	// does not want timeouts by default, and a client can request them
	// itself if needed.
	var err error

	// If already nonblocking and the zero-value for t is entered, disable
	// nonblocking mode
	if p.nonblocking && t.IsZero() {
		err = p.s.SetNonblock(false)
		p.nonblocking = false
	} else if !p.nonblocking && t.After(time.Now()) {
		// If not nonblocking and t is after current time, enable nonblocking
		// mode
		err = p.s.SetNonblock(true)
		p.nonblocking = true
	}

	p.rtimeout = t
	p.timeoutMu.Unlock()

	return err
}

// SetWriteDeadline implements the net.PacketConn.SetWriteDeadline method.
func (p *packetConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// SetBPF attaches an assembled BPF program to a raw net.PacketConn.
func (p *packetConn) SetBPF(filter []bpf.RawInstruction) error {
	prog := syscall.SockFprog{
		Len:    uint16(len(filter)),
		Filter: (*syscall.SockFilter)(unsafe.Pointer(&filter[0])),
	}

	return os.NewSyscallError(
		"setsockopt",
		setsockopt(
			p.s.FD(),
			syscall.SOL_SOCKET,
			syscall.SO_ATTACH_FILTER,
			unsafe.Pointer(&prog),
			uint32(unsafe.Sizeof(prog)),
		),
	)
}

// sysSocket is the default socket implementation.  It makes use of
// Linux-specific system calls to handle raw socket functionality.
type sysSocket struct {
	fd int
}

// Method implementations simply invoke the syscall of the same name, but pass
// the file descriptor stored in the sysSocket as the socket to use.
func (s *sysSocket) Bind(sa syscall.Sockaddr) error { return syscall.Bind(s.fd, sa) }
func (s *sysSocket) Close() error                   { return syscall.Close(s.fd) }
func (s *sysSocket) FD() int                        { return s.fd }
func (s *sysSocket) Recvfrom(p []byte, flags int) (int, syscall.Sockaddr, error) {
	return syscall.Recvfrom(s.fd, p, flags)
}
func (s *sysSocket) Sendto(p []byte, flags int, to syscall.Sockaddr) error {
	return syscall.Sendto(s.fd, p, flags, to)
}
func (s *sysSocket) SetNonblock(nonblocking bool) error { return syscall.SetNonblock(s.fd, nonblocking) }
func (s *sysSocket) SetSockopt(level, name int, v unsafe.Pointer, l uint32) error {
	return setsockopt(s.fd, level, name, v, l)
}

// timeSleeper sleeps using time.Sleep.
type timeSleeper struct{}

func (timeSleeper) Sleep(d time.Duration) {
	time.Sleep(d)
}
