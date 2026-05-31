//go:build !linux && !darwin && !dragonfly && !freebsd && !netbsd && !openbsd

package proxy

func NewUpgrader() (Upgrader, error) {
	return NewFallbackUpgrader(), nil
}
