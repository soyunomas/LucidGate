package proxy

import (
	"net"
	"sync"
	"time"

	"github.com/sony/gobreaker"
)

type CircuitBreakers struct {
	breakers sync.Map
	enabled  bool
	failures int
	timeout  time.Duration
}

func NewCircuitBreakers(enabled bool, failures int, timeout time.Duration) *CircuitBreakers {
	return &CircuitBreakers{
		enabled:  enabled,
		failures: failures,
		timeout:  timeout,
	}
}

func (cb *CircuitBreakers) Execute(host string, dialFunc func() (net.Conn, error)) (net.Conn, error) {
	if !cb.enabled {
		return dialFunc()
	}

	val, _ := cb.breakers.LoadOrStore(host, gobreaker.NewCircuitBreaker(gobreaker.Settings{
		Name:    "upstream:" + host,
		Timeout: cb.timeout,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= uint32(cb.failures)
		},
	}))

	breaker := val.(*gobreaker.CircuitBreaker)
	res, err := breaker.Execute(func() (interface{}, error) {
		return dialFunc()
	})

	if err != nil {
		return nil, err
	}
	return res.(net.Conn), nil
}
