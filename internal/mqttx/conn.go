package mqttx

import (
	"net"
	"sync"
	"sync/atomic"
)

// packetConn wraps the connection handed to paho.golang. paho serialises
// each control packet write by calling Lock/Unlock when the connection
// implements sync.Locker; packetConn buffers the writes made under the lock
// and flushes the packet with a single Write (one TLS record / one
// WebSocket frame per MQTT packet). While flushing it records the packet
// identifier of outgoing QoS>0 PUBLISH packets, which paho does not expose.
type packetConn struct {
	net.Conn
	mu        sync.Mutex
	locked    bool
	buf       []byte
	werr      error
	lastPubID atomic.Uint32
}

func newPacketConn(c net.Conn) *packetConn { return &packetConn{Conn: c} }

// Lock starts a packet.
func (c *packetConn) Lock() {
	c.mu.Lock()
	c.locked = true
}

// Unlock flushes the buffered packet.
func (c *packetConn) Unlock() {
	if len(c.buf) > 0 {
		if id, ok := publishPacketID(c.buf); ok {
			c.lastPubID.Store(uint32(id))
		}
		if c.werr == nil {
			if _, err := c.Conn.Write(c.buf); err != nil {
				c.werr = err
			}
		}
		if cap(c.buf) > 64<<10 {
			c.buf = nil
		} else {
			c.buf = c.buf[:0]
		}
	}
	c.locked = false
	c.mu.Unlock()
}

// Write buffers inside a Lock/Unlock section, otherwise writes through.
// paho.golang only writes inside Lock/Unlock (packets.ControlPacket.WriteTo).
func (c *packetConn) Write(p []byte) (int, error) {
	if c.locked {
		if c.werr != nil {
			return 0, c.werr
		}
		c.buf = append(c.buf, p...)
		return len(p), nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.werr != nil {
		return 0, c.werr
	}
	return c.Conn.Write(p)
}

// publishPacketID extracts the packet identifier from an encoded PUBLISH
// packet with QoS > 0.
func publishPacketID(b []byte) (uint16, bool) {
	if len(b) < 2 || b[0]>>4 != 3 {
		return 0, false
	}
	qos := (b[0] >> 1) & 3
	if qos == 0 {
		return 0, false
	}
	i := 1
	for n := 0; ; n++ {
		if i >= len(b) || n >= 4 {
			return 0, false
		}
		cont := b[i]&0x80 != 0
		i++
		if !cont {
			break
		}
	}
	if i+2 > len(b) {
		return 0, false
	}
	tl := int(b[i])<<8 | int(b[i+1])
	i += 2 + tl
	if i+2 > len(b) {
		return 0, false
	}
	return uint16(b[i])<<8 | uint16(b[i+1]), true
}
