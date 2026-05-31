package proxy

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/sony/gobreaker"
)

func TestCircuitBreakerStates(t *testing.T) {
	// Enable breaker, trip on 3 consecutive failures, 50ms timeout to transition to half-open
	breakers := NewCircuitBreakers(true, 3, 50*time.Millisecond)

	host := "test-upstream-breaker"

	// 1. Success calls should not trip
	for i := 0; i < 5; i++ {
		dummyConn := &net.IPConn{}
		conn, err := breakers.Execute(host, func() (net.Conn, error) {
			return dummyConn, nil
		})
		if err != nil {
			t.Fatalf("unexpected error on success call %d: %v", i, err)
		}
		if conn != dummyConn {
			t.Fatalf("unexpected connection returned")
		}
	}

	// 2. Consecutive failures should trip the breaker after 3 attempts
	dialErr := errors.New("connection failed")
	for i := 0; i < 3; i++ {
		_, err := breakers.Execute(host, func() (net.Conn, error) {
			return nil, dialErr
		})
		if !errors.Is(err, dialErr) {
			t.Fatalf("expected error %v, got %v", dialErr, err)
		}
	}

	// 3. The 4th call should fail immediately with ErrOpenState without calling the dial function
	called := false
	_, err := breakers.Execute(host, func() (net.Conn, error) {
		called = true
		return &net.IPConn{}, nil
	})
	if !errors.Is(err, gobreaker.ErrOpenState) {
		t.Fatalf("expected ErrOpenState, got: %v", err)
	}
	if called {
		t.Fatalf("dial function should not have been called in open state")
	}

	// 4. Wait for the timeout (50ms) to transition to Half-Open
	time.Sleep(60 * time.Millisecond)

	// In Half-Open, a successful call will close the breaker again
	dummyConn := &net.IPConn{}
	conn, err := breakers.Execute(host, func() (net.Conn, error) {
		return dummyConn, nil
	})
	if err != nil {
		t.Fatalf("unexpected error in half-open state: %v", err)
	}
	if conn != dummyConn {
		t.Fatalf("unexpected connection returned in half-open state")
	}

	// The breaker should now be closed again; a normal call succeeds
	called = false
	_, err = breakers.Execute(host, func() (net.Conn, error) {
		called = true
		return &net.IPConn{}, nil
	})
	if err != nil {
		t.Fatalf("unexpected error after breaker closed: %v", err)
	}
	if !called {
		t.Fatalf("dial function should have been called since breaker is closed")
	}
}

func TestCircuitBreakerDisabled(t *testing.T) {
	// Disabled breaker
	breakers := NewCircuitBreakers(false, 3, 50*time.Millisecond)
	host := "disabled-breaker"

	dialErr := errors.New("connection failed")
	// Make 5 consecutive failures
	for i := 0; i < 5; i++ {
		_, err := breakers.Execute(host, func() (net.Conn, error) {
			return nil, dialErr
		})
		if !errors.Is(err, dialErr) {
			t.Fatalf("expected error %v, got %v", dialErr, err)
		}
	}

	// Even after 5 failures, the 6th call still executes the function because the breaker is disabled
	called := false
	_, err := breakers.Execute(host, func() (net.Conn, error) {
		called = true
		return &net.IPConn{}, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Fatalf("dial function should have been called since breaker is disabled")
	}
}
