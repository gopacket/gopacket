// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package reassembly

import (
	"flag"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket/layers"
)

var memLog = flag.Bool("assembly_memuse_log", defaultDebug, "If true, the github.com/gopacket/gopacket/reassembly library will log information regarding its memory use every once in a while.")

/*
 * pageCache
 */
// pageCache is a concurrency-unsafe store of page objects we use to avoid
// memory allocation as much as we can.  Assemblers sharing a StreamPool pop
// each other's pages off a connection, so used is charged to the owning
// cache and may be updated by other Assemblers.
type pageCache struct {
	pagePool     *sync.Pool
	used         atomic.Int64
	pageRequests int64
}

func newPageCache() *pageCache {
	pc := &pageCache{
		pagePool: &sync.Pool{
			New: func() interface{} { return new(page) },
		}}
	return pc
}

// next returns a clean, ready-to-use page object.
func (c *pageCache) next(ts time.Time) (p *page) {
	if *memLog {
		c.pageRequests++
		if c.pageRequests&0xFFFF == 0 {
			log.Println("PageCache:", c.pageRequests, "requested,", c.used.Load(), "used,")
		}
	}
	p = c.pagePool.Get().(*page)
	p.seen = ts
	p.bytes = p.buf[:0]
	p.owner = c
	c.used.Add(1)
	if *memLog {
		log.Printf("allocator returns %s\n", p)
	}

	return p
}

// replace replaces a page into the pageCache.
func (c *pageCache) replace(p *page) {
	p.owner.used.Add(-1)
	if *memLog {
		log.Printf("replacing %s\n", p)
	}
	p.prev = nil
	p.next = nil
	c.pagePool.Put(p)
}

/*
 * StreamPool
 */

// StreamPool stores all streams created by Assemblers, allowing multiple
// assemblers to work together on stream processing while enforcing the fact
// that a single stream receives its data serially.  It is safe
// for concurrency, usable by multiple Assemblers at once.
//
// StreamPool handles the creation and storage of Stream objects used by one or
// more Assembler objects.  When a new TCP stream is found by an Assembler, it
// creates an associated Stream by calling its StreamFactory's New method.
// Thereafter (until the stream is closed), that Stream object will receive
// assembled TCP data via Assembler's calls to the stream's Reassembled
// function.
//
// Like the Assembler, StreamPool attempts to minimize allocation.  Unlike the
// Assembler, though, it does have to do some locking to make sure that the
// connection objects it stores are accessible to multiple Assemblers.
type StreamPool struct {
	conns              map[key]*connection
	users              int
	mu                 sync.RWMutex
	factory            StreamFactory
	free               []*connection
	all                [][]connection
	nextAlloc          int
	newConnectionCount int64
}

const initialAllocSize = 1024

func (p *StreamPool) grow() {
	conns := make([]connection, p.nextAlloc)
	p.all = append(p.all, conns)
	for i := range conns {
		p.free = append(p.free, &conns[i])
	}
	if *memLog {
		log.Println("StreamPool: created", p.nextAlloc, "new connections")
	}
	p.nextAlloc *= 2
}

// Dump logs all connections
func (p *StreamPool) Dump() {
	p.mu.Lock()
	defer p.mu.Unlock()
	log.Printf("Remaining %d connections: ", len(p.conns))
	for _, conn := range p.conns {
		log.Printf("%v %s", conn.key, conn)
	}
}

// remove takes conn out of the pool and parks it on the free list.  The
// caller must hold conn.mu.
func (p *StreamPool) remove(conn *connection) {
	if conn.removed {
		return
	}
	p.mu.Lock()
	if _, ok := p.conns[conn.key]; ok {
		delete(p.conns, conn.key)
		p.free = append(p.free, conn)
	}
	p.mu.Unlock()

	// A parked connection must keep neither its Stream nor its pages alive,
	// and an Assembler still waiting for its lock must see it is gone.
	conn.removed = true
	for _, half := range []*halfconnection{&conn.c2s, &conn.s2c} {
		half.stream, half.saved, half.first, half.last = nil, nil, nil, nil
	}
}

// NewStreamPool creates a new connection pool.  Streams will
// be created as necessary using the passed-in StreamFactory.
func NewStreamPool(factory StreamFactory) *StreamPool {
	return &StreamPool{
		conns:     make(map[key]*connection, initialAllocSize),
		free:      make([]*connection, 0, initialAllocSize),
		factory:   factory,
		nextAlloc: initialAllocSize,
	}
}

func (p *StreamPool) connections() []*connection {
	p.mu.RLock()
	conns := make([]*connection, 0, len(p.conns))
	for _, conn := range p.conns {
		conns = append(conns, conn)
	}
	p.mu.RUnlock()
	return conns
}

func (p *StreamPool) newConnection(k key, s Stream, ts time.Time) (c *connection, h *halfconnection, r *halfconnection) {
	if *memLog {
		p.newConnectionCount++
		if p.newConnectionCount&0x7FFF == 0 {
			log.Println("StreamPool:", p.newConnectionCount, "requests,", len(p.conns), "used,", len(p.free), "free")
		}
	}
	if len(p.free) == 0 {
		p.grow()
	}
	index := len(p.free) - 1
	c, p.free = p.free[index], p.free[:index]
	// An Assembler that looked c up before it was removed may still hold its
	// lock.  It never waits for p.mu once c is removed, so this can't deadlock.
	c.mu.Lock()
	c.reset(k, s, ts)
	c.mu.Unlock()
	return c, &c.c2s, &c.s2c
}

func (p *StreamPool) getHalf(k key) (*connection, *halfconnection, *halfconnection) {
	conn := p.conns[k]
	if conn != nil {
		return conn, &conn.c2s, &conn.s2c
	}
	rk := k.Reverse()
	conn = p.conns[rk]
	if conn != nil {
		return conn, &conn.s2c, &conn.c2s
	}
	return nil, nil, nil
}

// getConnection returns a connection.  If end is true and a connection
// does not already exist, returns nil.  This allows us to check for a
// connection without actually creating one if it doesn't already exist.
func (p *StreamPool) getConnection(k key, end bool, ts time.Time, tcp *layers.TCP, ac AssemblerContext) (*connection, *halfconnection, *halfconnection) {
	p.mu.RLock()
	conn, half, rev := p.getHalf(k)
	p.mu.RUnlock()
	if end || conn != nil {
		return conn, half, rev
	}
	s := p.factory.New(k[0], k[1], tcp, ac)
	if s == nil {
		return nil, nil, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	// Another Assembler may have added the connection in the meantime, from
	// either direction: getHalf orders the halves for k in both cases.
	conn, half, rev = p.getHalf(k)
	if conn != nil {
		// FIXME: delete s ?
		return conn, half, rev
	}
	conn, half, rev = p.newConnection(k, s, ts)
	p.conns[k] = conn
	return conn, half, rev
}
