# raw [![builds.sr.ht status](https://builds.sr.ht/~mdlayher/raw.svg)](https://builds.sr.ht/~mdlayher/raw?) [![GoDoc](https://godoc.org/github.com/mdlayher/raw?status.svg)](https://godoc.org/github.com/mdlayher/raw) [![Go Report Card](https://goreportcard.com/badge/github.com/mdlayher/raw)](https://goreportcard.com/report/github.com/mdlayher/raw)

Package `raw` enables reading and writing data at the device driver level for
a network interface.  MIT Licensed.

For more information about using raw sockets with Ethernet frames in Go, check
out my blog post: [Network Protocol Breakdown: Ethernet and Go](https://medium.com/@mdlayher/network-protocol-breakdown-ethernet-and-go-de985d726cc1).

Portions of this code are taken from the Go standard library.  The Go
standard library is Copyright (c) 2012 The Go Authors. All rights reserved.
The Go license can be found at https://golang.org/LICENSE.

## Stability

At this time, package `raw` is in a pre-v1.0.0 state. Changes are being made
which may impact the exported API of this package and others in its ecosystem.

The general policy of this package is to only support the latest, stable version
of Go. Compatibility shims may be added for prior versions of Go on an as-needed
basis. If you would like to raise a concern, please [file an issue](https://github.com/mdlayher/raw/issues/new).

**If you depend on this package in your applications, please vendor it or use Go
modules when building your application.**

## Examples

### ICMP Ping

```go
package main

import (
	"encoding/binary"
	"fmt"
	"github.com/mdlayher/raw"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"log"
	"net"
	"os"
	"runtime"
)

const etherTypeIPv4 uint16 = 0x0800

var (
	// update accordingly
	interfaceName = "en0"
	srcMAC        = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	dstMAC        = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	srcIP         = net.ParseIP("192.168.1.1")
	dstIP         = net.ParseIP("192.168.1.2")
)

func main() {

	ifi, err := net.InterfaceByName(interfaceName)
	if err != nil {
		log.Fatalf("interface by name %s: %v", interfaceName, err)
	}

	c, err := raw.ListenPacket(ifi, etherTypeIPv4, nil)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	pingPacket, err := getICMPPingPacket("hello ...")
	if err != nil {
		log.Fatalf("get icmp ping packet: %v", err)
	}

	ipPacket, err := getIPPacket(srcIP, dstIP, 1, pingPacket)
	if err != nil {
		log.Fatalf("get ip packet: %v", err)
	}
	sendMessage(c, srcMAC, dstMAC, etherTypeIPv4, ipPacket)
}

func getICMPPingPacket(data string) ([]byte, error) {

	ping := &icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: os.Getpid() & 0xffff, Seq: 1,
			Data: []byte(data),
		},
	}
	return ping.Marshal(nil)
}

func getIPPacket(src, dst net.IP, protocol int, msg []byte) ([]byte, error) {

	iph := &ipv4.Header{
		Version:  ipv4.Version,
		Len:      ipv4.HeaderLen,
		TOS:      0,
		TotalLen: ipv4.HeaderLen + len(msg),
		TTL:      64,
		Protocol: protocol,
		Dst:      dst,
		Src:      src,
	}

	ip, err := iph.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal ip request: %w", err)
	}

	// this is currently broken in golang, need to set total len correctly
	if runtime.GOOS == "darwin" {
		binary.BigEndian.PutUint16(ip[2:4], uint16(iph.TotalLen))
	}
	return append(ip, msg...), nil
}

func sendMessage(c net.PacketConn, src net.HardwareAddr, dst net.HardwareAddr, etherType uint16, payload []byte) {

	// minPayload is the minimum payload size for an Ethernet frame, assuming
	payloadLength := len(payload)
	if payloadLength < 46 {
		payloadLength = 46
	}

	// 6 destination, 6 source hardware address, 2 ether type + payload
	frameLength := 14 + payloadLength

	frame := make([]byte, frameLength)
	copy(frame[0:6], dst)
	copy(frame[6:12], src)
	binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv4)
	copy(frame[14:], payload)

	addr := &raw.Addr{HardwareAddr: dst}
	if _, err := c.WriteTo(frame, addr); err != nil {
		log.Fatalf("failed to send message: %v", err)
	}
}
```