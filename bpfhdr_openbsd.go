package raw

type bpfHdr struct {
	_       uint64 // unix.Timeval is 16 bytes on OpenBSD.
	caplen  uint32
	datalen uint32
	hdrlen  uint16
}
