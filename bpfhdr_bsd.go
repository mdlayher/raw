// +build darwin dragonfly freebsd netbsd

package raw

import "golang.org/x/sys/unix"

type bpfHdr struct {
	_       unix.Timeval // 8 or 16 bytes depending on arch
	caplen  uint32
	datalen uint32
	hdrlen  uint16
}
