package proxy

import (
	"sync"

	"golang.org/x/time/rate"
)

// ipRateLimiter is a bounded thread-safe LRU cache for IP rate limiters.
// Storing limiters in a bounded LRU prevents memory leaks from long-running
// IP scans (e.g. internet crawlers or scans inside school subnets) which
// would otherwise fill up a standard sync.Map indefinitely.
type ipRateLimiter struct {
	mu  sync.Mutex
	cap int
	ll  *rateList
	idx map[string]*rateNode
}

type rateNode struct {
	prev, next *rateNode
	key        string
	limiter    *rate.Limiter
}

type rateList struct {
	head, tail *rateNode
}

func newIPRateLimiter(cap int) *ipRateLimiter {
	if cap <= 0 {
		cap = 16384
	}
	return &ipRateLimiter{
		cap: cap,
		ll:  &rateList{},
		idx: make(map[string]*rateNode, cap),
	}
}

func (c *ipRateLimiter) getOrCreate(ip string, r float64, burst int) *rate.Limiter {
	c.mu.Lock()
	defer c.mu.Unlock()

	if n, ok := c.idx[ip]; ok {
		c.ll.moveFront(n)
		return n.limiter
	}

	limiter := rate.NewLimiter(rate.Limit(r), burst)
	n := &rateNode{key: ip, limiter: limiter}
	c.ll.pushFront(n)
	c.idx[ip] = n

	if len(c.idx) > c.cap {
		victim := c.ll.tail
		if victim != nil {
			c.ll.remove(victim)
			delete(c.idx, victim.key)
		}
	}

	return limiter
}

func (c *ipRateLimiter) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ll.head = nil
	c.ll.tail = nil
	c.idx = make(map[string]*rateNode, c.cap)
}

func (l *rateList) pushFront(n *rateNode) {
	n.next = l.head
	n.prev = nil
	if l.head != nil {
		l.head.prev = n
	}
	l.head = n
	if l.tail == nil {
		l.tail = n
	}
}

func (l *rateList) moveFront(n *rateNode) {
	if l.head == n {
		return
	}
	l.remove(n)
	l.pushFront(n)
}

func (l *rateList) remove(n *rateNode) {
	if n.prev != nil {
		n.prev.next = n.next
	} else {
		l.head = n.next
	}
	if n.next != nil {
		n.next.prev = n.prev
	} else {
		l.tail = n.prev
	}
	n.prev = nil
	n.next = nil
}
