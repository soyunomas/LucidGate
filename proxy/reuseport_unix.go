//go:build linux || darwin || dragonfly || freebsd || netbsd || openbsd

package proxy

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func listenReusePort(network, address string) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			})
			if err != nil {
				return err
			}
			return opErr
		},
	}
	return lc.Listen(context.Background(), network, address)
}
