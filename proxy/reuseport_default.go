//go:build !linux && !darwin && !dragonfly && !freebsd && !netbsd && !openbsd

package proxy

import (
	"net"
)

func listenReusePort(network, address string) (net.Listener, error) {
	return net.Listen(network, address)
}
