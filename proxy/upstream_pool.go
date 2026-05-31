package proxy

import (
	"bufio"
	"context"
	"net"
	"sync"
	"time"
)

const (
	defaultUpstreamMaxIdlePerHost = 32
	defaultUpstreamIdleTimeout    = 90 * time.Second
)

type UpstreamPoolConfig struct {
	MaxIdlePerHost int
	IdleTimeout    time.Duration
}

type upstreamPoolKey struct {
	scheme     string
	address    string
	serverName string
	alpn       string
	specID     string
}

type upstreamConnPool struct {
	mu             sync.Mutex
	idle           map[upstreamPoolKey][]*pooledUpstreamConn
	maxIdlePerHost int
	idleTimeout    time.Duration
}

type pooledUpstreamConn struct {
	conn     net.Conn
	reader   *bufio.Reader
	lastUsed time.Time
}

type upstreamConnLease struct {
	conn    net.Conn
	reader  *bufio.Reader
	release func(bool)
}

func newUpstreamConnPool(cfg UpstreamPoolConfig) *upstreamConnPool {
	if cfg.MaxIdlePerHost <= 0 {
		return nil
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = defaultUpstreamIdleTimeout
	}
	return &upstreamConnPool{
		idle:           make(map[upstreamPoolKey][]*pooledUpstreamConn),
		maxIdlePerHost: cfg.MaxIdlePerHost,
		idleTimeout:    cfg.IdleTimeout,
	}
}

func (p *upstreamConnPool) acquire(ctx context.Context, key upstreamPoolKey, dial func(context.Context) (net.Conn, error)) (*upstreamConnLease, error) {
	if p == nil {
		conn, err := dial(ctx)
		if err != nil {
			return nil, err
		}
		return &upstreamConnLease{
			conn:   conn,
			reader: bufio.NewReader(conn),
			release: func(bool) {
				_ = conn.Close()
			},
		}, nil
	}

	now := time.Now()
	if pooled := p.takeIdle(key, now); pooled != nil {
		return &upstreamConnLease{
			conn:   pooled.conn,
			reader: pooled.reader,
			release: func(reusable bool) {
				p.release(key, pooled.conn, pooled.reader, reusable)
			},
		}, nil
	}

	conn, err := dial(ctx)
	if err != nil {
		return nil, err
	}
	reader := bufio.NewReader(conn)
	return &upstreamConnLease{
		conn:   conn,
		reader: reader,
		release: func(reusable bool) {
			p.release(key, conn, reader, reusable)
		},
	}, nil
}

func (p *upstreamConnPool) takeIdle(key upstreamPoolKey, now time.Time) *pooledUpstreamConn {
	p.mu.Lock()
	defer p.mu.Unlock()

	idle := p.idle[key]
	for len(idle) > 0 {
		last := len(idle) - 1
		pooled := idle[last]
		idle[last] = nil
		idle = idle[:last]
		if now.Sub(pooled.lastUsed) <= p.idleTimeout {
			if len(idle) == 0 {
				delete(p.idle, key)
			} else {
				p.idle[key] = idle
			}
			return pooled
		}
		_ = pooled.conn.Close()
	}
	delete(p.idle, key)
	return nil
}

func (p *upstreamConnPool) release(key upstreamPoolKey, conn net.Conn, reader *bufio.Reader, reusable bool) {
	if p == nil {
		_ = conn.Close()
		return
	}
	if !reusable || reader == nil || reader.Buffered() != 0 {
		_ = conn.Close()
		return
	}
	_ = conn.SetDeadline(time.Time{})

	p.mu.Lock()
	defer p.mu.Unlock()

	idle := p.idle[key]
	if len(idle) >= p.maxIdlePerHost {
		p.idle[key] = idle[1:]
		_ = idle[0].conn.Close()
		idle = p.idle[key]
	}
	p.idle[key] = append(idle, &pooledUpstreamConn{
		conn:     conn,
		reader:   reader,
		lastUsed: time.Now(),
	})
}

func (p *upstreamConnPool) closeIdle() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for key, conns := range p.idle {
		for _, pooled := range conns {
			_ = pooled.conn.Close()
		}
		delete(p.idle, key)
	}
}
