// +build linux

package raw

import (
	"bytes"
	"errors"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// Test to ensure that socket is bound with correct sockaddr_ll information

type bindSocket struct {
	bind syscall.Sockaddr
	noopSocket
}

func (s *bindSocket) Bind(sa syscall.Sockaddr) error {
	s.bind = sa
	return nil
}

func Test_newPacketConnBind(t *testing.T) {
	s := &bindSocket{}

	ifIndex := 1
	protocol := uint16(1)

	_, err := newPacketConn(
		&net.Interface{
			Index: ifIndex,
		},
		s,
		protocol,
		&testSleeper{},
	)
	if err != nil {
		t.Fatal(err)
	}

	sall, ok := s.bind.(*syscall.SockaddrLinklayer)
	if !ok {
		t.Fatalf("bind sockaddr has incorrect type: %T", s.bind)
	}

	if want, got := ifIndex, sall.Ifindex; want != got {
		t.Fatalf("unexpected network interface index:\n- want: %v\n-  got: %v", want, got)
	}
	if want, got := protocol, sall.Protocol; want != got {
		t.Fatalf("unexpected protocol:\n- want: %v\n-  got: %v", want, got)
	}
}

// Test for errors which occur after several retries while attempting to
// recvfrom on a socket.

type errRetryNRecvfromSocket struct {
	n   int
	try int
	err error
	noopSocket
}

func (s *errRetryNRecvfromSocket) Recvfrom(p []byte, flags int) (int, syscall.Sockaddr, error) {
	if s.try == s.n {
		return 0, nil, s.err
	}

	s.try++
	return 0, nil, syscall.EAGAIN
}

func Test_packetConnReadFromRecvfromRetryNError(t *testing.T) {
	fooErr := errors.New("foo")

	ts := &testSleeper{}

	const n = 5

	p, err := newPacketConn(
		&net.Interface{},
		&errRetryNRecvfromSocket{
			n:   n,
			err: fooErr,
		},
		0,
		ts,
	)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = p.ReadFrom(nil)
	if want, got := fooErr, err; want != got {
		t.Fatalf("unexpected error:\n- want: %v\n-  got: %v", want, got)
	}

	if want, got := n*(2*time.Millisecond), time.Duration(ts.slept); want != got {
		t.Fatalf("unexpected mock sleep time:\n- want: %v\n-  got: %v", want, got)
	}
}

// Test for incorrect sockaddr type after recvfrom on a socket.

type addrRecvfromSocket struct {
	addr syscall.Sockaddr
	noopSocket
}

func (s *addrRecvfromSocket) Recvfrom(p []byte, flags int) (int, syscall.Sockaddr, error) {
	return 0, s.addr, nil
}

func Test_packetConnReadFromRecvfromInvalidSockaddr(t *testing.T) {
	p, err := newPacketConn(
		&net.Interface{},
		&addrRecvfromSocket{
			addr: &syscall.SockaddrInet4{},
		},
		0,
		&testSleeper{},
	)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = p.ReadFrom(nil)
	if want, got := syscall.EINVAL, err; want != got {
		t.Fatalf("unexpected error:\n- want: %v\n-  got: %v", want, got)
	}
}

// Test for malformed hardware address after recvfrom on a socket

func Test_packetConnReadFromRecvfromInvalidHardwareAddr(t *testing.T) {
	p, err := newPacketConn(
		&net.Interface{},
		&addrRecvfromSocket{
			addr: &syscall.SockaddrLinklayer{
				Halen: 5,
			},
		},
		0,
		&testSleeper{},
	)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = p.ReadFrom(nil)
	if want, got := syscall.EINVAL, err; want != got {
		t.Fatalf("unexpected error:\n- want: %v\n-  got: %v", want, got)
	}
}

// Test for a correct ReadFrom with data and address.

type recvfromSocket struct {
	p     []byte
	flags int
	addr  syscall.Sockaddr
	noopSocket
}

func (s *recvfromSocket) Recvfrom(p []byte, flags int) (int, syscall.Sockaddr, error) {
	copy(p, s.p)
	s.flags = flags
	return len(s.p), s.addr, nil
}

func Test_packetConnReadFromRecvfromOK(t *testing.T) {
	const wantN = 4
	data := []byte{0, 1, 2, 3}
	deadbeefHW := net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad}

	s := &recvfromSocket{
		p: data,
		addr: &syscall.SockaddrLinklayer{
			Halen: 6,
			Addr:  [8]byte{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0x00, 0x00},
		},
	}

	p, err := newPacketConn(
		&net.Interface{},
		s,
		0,
		&testSleeper{},
	)
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 8)
	n, addr, err := p.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}

	if want, got := 0, s.flags; want != got {
		t.Fatalf("unexpected flags:\n- want: %v\n-  got: %v", want, got)
	}

	raddr, ok := addr.(*Addr)
	if !ok {
		t.Fatalf("read sockaddr has incorrect type: %T", addr)
	}
	if want, got := deadbeefHW, raddr.HardwareAddr; !bytes.Equal(want, got) {
		t.Fatalf("unexpected hardware address:\n- want: %v\n-  got: %v", want, got)
	}

	if want, got := wantN, n; want != got {
		t.Fatalf("unexpected data length:\n- want: %v\n-  got: %v", want, got)
	}

	if want, got := data, buf[:n]; !bytes.Equal(want, got) {
		t.Fatalf("unexpected data:\n- want: %v\n-  got: %v", want, got)
	}
}

// Test for incorrect sockaddr type for WriteTo.

func Test_packetConnWriteToInvalidSockaddr(t *testing.T) {
	_, err := (&packetConn{}).WriteTo(nil, &net.IPAddr{})
	if want, got := syscall.EINVAL, err; want != got {
		t.Fatalf("unexpected error:\n- want: %v\n-  got: %v", want, got)
	}
}

// Test for malformed hardware address with WriteTo.

func Test_packetConnWriteToInvalidHardwareAddr(t *testing.T) {
	_, err := (&packetConn{}).WriteTo(nil, &Addr{
		HardwareAddr: net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0xde},
	})
	if want, got := syscall.EINVAL, err; want != got {
		t.Fatalf("unexpected error:\n- want: %v\n-  got: %v", want, got)
	}
}

// Test for a correct WriteTo with data and address.

type sendtoSocket struct {
	p     []byte
	flags int
	addr  syscall.Sockaddr
	noopSocket
}

func (s *sendtoSocket) Sendto(p []byte, flags int, to syscall.Sockaddr) error {
	copy(s.p, p)
	s.flags = flags
	s.addr = to
	return nil
}

func Test_packetConnWriteToSendtoOK(t *testing.T) {
	const wantN = 4
	data := []byte{0, 1, 2, 3}

	deadbeefHW := net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad}

	s := &sendtoSocket{
		p: make([]byte, wantN),
	}

	p, err := newPacketConn(
		&net.Interface{},
		s,
		0,
		&testSleeper{},
	)
	if err != nil {
		t.Fatal(err)
	}

	n, err := p.WriteTo(data, &Addr{
		HardwareAddr: deadbeefHW,
	})
	if err != nil {
		t.Fatal(err)
	}

	if want, got := 0, s.flags; want != got {
		t.Fatalf("unexpected flags:\n- want: %v\n-  got: %v", want, got)
	}

	if want, got := wantN, n; want != got {
		t.Fatalf("unexpected data length:\n- want: %v\n-  got: %v", want, got)
	}
	if want, got := data, s.p; !bytes.Equal(want, got) {
		t.Fatalf("unexpected data:\n- want: %v\n-  got: %v", want, got)
	}

	sall, ok := s.addr.(*syscall.SockaddrLinklayer)
	if !ok {
		t.Fatalf("write sockaddr has incorrect type: %T", s.addr)
	}

	if want, got := deadbeefHW, sall.Addr[:][:sall.Halen]; !bytes.Equal(want, got) {
		t.Fatalf("unexpected hardware address:\n- want: %v\n-  got: %v", want, got)
	}
}

// Test that socket close functions as intended.

type captureCloseSocket struct {
	closed bool
	noopSocket
}

func (s *captureCloseSocket) Close() error {
	s.closed = true
	return nil
}

func Test_packetConnClose(t *testing.T) {
	s := &captureCloseSocket{}
	p := &packetConn{
		s: s,
	}

	if err := p.Close(); err != nil {
		t.Fatal(err)
	}

	if !s.closed {
		t.Fatalf("socket should be closed, but is not")
	}
}

// Test that LocalAddr returns the hardware address of the network interface
// which is being used by the socket.

func Test_packetConnLocalAddr(t *testing.T) {
	deadbeefHW := net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad}

	p := &packetConn{
		ifi: &net.Interface{
			HardwareAddr: deadbeefHW,
		},
	}

	if want, got := deadbeefHW, p.LocalAddr().(*Addr).HardwareAddr; !bytes.Equal(want, got) {
		t.Fatalf("unexpected hardware address:\n- want: %v\n-  got: %v", want, got)
	}
}

// Test to ensure that nonblocking mode appropriately toggles depending on
// input, and that it remains toggled correctly for various inputs.

type setNonblockSocket struct {
	nonblocking bool
	triggered   bool
	noopSocket
}

func (s *setNonblockSocket) SetNonblock(nonblocking bool) error {
	s.nonblocking = nonblocking
	s.triggered = true
	return nil
}

func Test_packetConnSetNonblock(t *testing.T) {
	s := &setNonblockSocket{}

	p, err := newPacketConn(
		&net.Interface{},
		s,
		0,
		&testSleeper{},
	)
	if err != nil {
		t.Fatal(err)
	}

	// Test 1: socket should remain blocking due to zero time, SetNonblock
	// should never have been triggered
	if err := p.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if want, got := false, s.triggered; want != got {
		t.Fatalf("unexpected triggered boolean:\n- want: %v\n-  got: %v", want, got)
	}
	if want, got := false, s.nonblocking; want != got {
		t.Fatalf("unexpected nonblocking boolean:\n- want: %v\n-  got: %v", want, got)
	}

	// Reset trigger
	s.triggered = false

	// Test 2: socket should become nonblocking due to time after now
	if err := p.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if want, got := true, s.triggered; want != got {
		t.Fatalf("unexpected triggered boolean:\n- want: %v\n-  got: %v", want, got)
	}
	if want, got := true, s.nonblocking; want != got {
		t.Fatalf("unexpected nonblocking boolean:\n- want: %v\n-  got: %v", want, got)
	}

	// Reset trigger
	s.triggered = false

	// Test 3: socket should remain nonblocking due to time after now, but not
	// trigger the system call again
	if err := p.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if want, got := false, s.triggered; want != got {
		t.Fatalf("unexpected triggered boolean:\n- want: %v\n-  got: %v", want, got)
	}
	if want, got := true, s.nonblocking; want != got {
		t.Fatalf("unexpected nonblocking boolean:\n- want: %v\n-  got: %v", want, got)
	}

	// Reset trigger
	s.triggered = false

	// Test 4: socket should become blocking due to zero time
	if err := p.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if want, got := true, s.triggered; want != got {
		t.Fatalf("unexpected triggered boolean:\n- want: %v\n-  got: %v", want, got)
	}
	if want, got := false, s.nonblocking; want != got {
		t.Fatalf("unexpected nonblocking boolean:\n- want: %v\n-  got: %v", want, got)
	}

	// Reset trigger
	s.triggered = false

	// Test 5: socket should remain blocking due to zero time, but not trigger
	// the system call again
	if err := p.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if want, got := false, s.triggered; want != got {
		t.Fatalf("unexpected triggered boolean:\n- want: %v\n-  got: %v", want, got)
	}
	if want, got := false, s.nonblocking; want != got {
		t.Fatalf("unexpected nonblocking boolean:\n- want: %v\n-  got: %v", want, got)
	}
}

// testSleeper is a sleeper implementation which atomically increments a
// counter to indicate how long it has slept.
type testSleeper struct {
	slept int64
}

func (t *testSleeper) Sleep(d time.Duration) {
	atomic.AddInt64(&t.slept, int64(d))
}

// noopSocket is a socket implementation which noops every operation.  It is
// the basis for more specific socket implementations.
type noopSocket struct{}

func (noopSocket) Bind(sa syscall.Sockaddr) error                               { return nil }
func (noopSocket) Close() error                                                 { return nil }
func (noopSocket) FD() int                                                      { return 0 }
func (noopSocket) Recvfrom(p []byte, flags int) (int, syscall.Sockaddr, error)  { return 0, nil, nil }
func (noopSocket) Sendto(p []byte, flags int, to syscall.Sockaddr) error        { return nil }
func (noopSocket) SetNonblock(nonblocking bool) error                           { return nil }
func (noopSocket) SetSockopt(level, name int, v unsafe.Pointer, l uint32) error { return nil }
