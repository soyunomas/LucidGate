package proxy

import (
	"net"
	"runtime"
)

type Upgrader interface {
	Listen(network, addr string, reusePort bool) ([]net.Listener, error)
	Ready() error
	Upgrade() error
	Exit() <-chan struct{}
	Close()
}

type fallbackUpgrader struct {
	exitCh chan struct{}
}

func NewFallbackUpgrader() Upgrader {
	return &fallbackUpgrader{
		exitCh: make(chan struct{}),
	}
}

func (u *fallbackUpgrader) Listen(network, addr string, reusePort bool) ([]net.Listener, error) {
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
			ln, err = listenReusePort(network, addr)
		} else {
			ln, err = net.Listen(network, addr)
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

func (u *fallbackUpgrader) Ready() error {
	return nil
}

func (u *fallbackUpgrader) Upgrade() error {
	return nil
}

func (u *fallbackUpgrader) Exit() <-chan struct{} {
	return u.exitCh
}

func (u *fallbackUpgrader) Close() {
	close(u.exitCh)
}
