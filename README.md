# raw [![Test Status](https://github.com/mdlayher/raw/workflows/Test/badge.svg)](https://github.com/mdlayher/raw/actions) [![Go Reference](https://pkg.go.dev/badge/github.com/mdlayher/raw.svg)](https://pkg.go.dev/github.com/mdlayher/raw)  [![Go Report Card](https://goreportcard.com/badge/github.com/mdlayher/raw)](https://goreportcard.com/report/github.com/mdlayher/raw)

Package `raw` enables reading and writing data at the device driver level for a
network interface. MIT Licensed.

Deprecated: use
[`github.com/mdlayher/packet`](https://github.com/mdlayher/packet) on Linux
instead. This package is unmaintained.

For more information about using sockets with Ethernet frames in Go, check out
my blog post: [Network Protocol Breakdown: Ethernet and
Go](https://mdlayher.com/blog/network-protocol-breakdown-ethernet-and-go/).

## Unmaintained

This repository was one of my first major Go networking libraries. Although I
have updated it on Linux to incorporate modern Go best practices (asynchronous
I/O, runtime network poller integration), the non-Linux platform code is
effectively unmaintained and does not have the same level of functionality.

I encourage all Linux users of this package to migrate to
[`github.com/mdlayher/packet`](https://github.com/mdlayher/packet), which is a
modern `AF_PACKET` library. The existing `*raw.Conn` APIs now call directly into
the equivalent `*packet.Conn` APIs, and a level of indirection can be removed by
migrating to that package.
