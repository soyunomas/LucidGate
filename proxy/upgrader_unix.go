//go:build linux || darwin || dragonfly || freebsd || netbsd || openbsd

package proxy

import (
	"fmt"
	"net"
	"runtime"
	"strings"

	"github.com/cloudflare/tableflip"
)

type tableflipUpgrader struct {
	upg *tableflip.Upgrader
}

func NewUpgrader() (Upgrader, error) {
	upg, err := tableflip.New(tableflip.Options{})
	if err != nil {
		return nil, err
	}
	return &tableflipUpgrader{upg: upg}, nil
}

func (u *tableflipUpgrader) Listen(network, addr string, reusePort bool) ([]net.Listener, error) {
	numListeners := 1
	if reusePort {
		numListeners = runtime.GOMAXPROCS(0)
		if numListeners <= 0 {
			numListeners = 1
		}
	}

	var listeners []net.Listener
	for i := 0; i < numListeners; i++ {
		var ln net.Listener
		var err error
		if reusePort {
			key := fmt.Sprintf("%s-%d", addr, i)
			idx := i
			ln, err = u.upg.ListenWithCallback(network, key, func(netw, address string) (net.Listener, error) {
				actualAddr := strings.TrimSuffix(address, fmt.Sprintf("-%d", idx))
				return listenReusePort(netw, actualAddr)
			})
		} else {
			ln, err = u.upg.Listen(network, addr)
		}

		if err != nil {
			// clean up previously opened listeners
			for _, l := range listeners {
				l.Close()
			}
			return nil, err
		}
		listeners = append(listeners, ln)
	}

	return listeners, nil
}

func (u *tableflipUpgrader) Ready() error {
	return u.upg.Ready()
}

func (u *tableflipUpgrader) Upgrade() error {
	return u.upg.Upgrade()
}

func (u *tableflipUpgrader) Exit() <-chan struct{} {
	return u.upg.Exit()
}

func (u *tableflipUpgrader) Close() {
	u.upg.Stop()
}
