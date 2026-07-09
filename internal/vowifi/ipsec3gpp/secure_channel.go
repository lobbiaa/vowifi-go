package ipsec3gpp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// SecureChannelConn wraps a TCP connection with userspace ESP transport-mode transforms.
type SecureChannelConn struct {
	conn      net.Conn
	transport *Transport
	policy    Policy
	readBuf   []byte
	mu        sync.Mutex
}

// WrapSecureChannel wraps conn with outbound ESP transforms for SIP-over-TCP.
func WrapSecureChannel(conn net.Conn, transport *Transport, policy Policy) *SecureChannelConn {
	return &SecureChannelConn{
		conn:      conn,
		transport: transport,
		policy:    policy,
	}
}

func (c *SecureChannelConn) Read(p []byte) (int, error) {
	if c == nil || c.conn == nil {
		return 0, errors.New("ipsec3gpp: secure channel is not ready")
	}
	for {
		payload, err := c.readSIPPayload()
		if err != nil {
			return 0, err
		}
		if len(payload) == 0 {
			continue
		}
		n := copy(p, payload)
		if n < len(payload) {
			c.mu.Lock()
			c.readBuf = append(c.readBuf, payload[n:]...)
			c.mu.Unlock()
		}
		return n, nil
	}
}

func (c *SecureChannelConn) Write(p []byte) (int, error) {
	if c == nil || c.conn == nil || c.transport == nil {
		return 0, errors.New("ipsec3gpp: secure channel is not ready")
	}
	packet, err := buildOutboundTCPPacket(c.policy, p)
	if err != nil {
		return 0, err
	}
	encrypted, err := c.transport.TransformOutbound(packet)
	if err != nil {
		return 0, err
	}
	if _, err := c.conn.Write(encrypted); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *SecureChannelConn) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

func (c *SecureChannelConn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *SecureChannelConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

func (c *SecureChannelConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *SecureChannelConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *SecureChannelConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

func (c *SecureChannelConn) readSIPPayload() ([]byte, error) {
	c.mu.Lock()
	if len(c.readBuf) > 0 {
		out := c.readBuf
		c.readBuf = nil
		c.mu.Unlock()
		return out, nil
	}
	c.mu.Unlock()

	for {
		ipPacket, err := c.readIPPacket()
		if err != nil {
			return nil, err
		}
		plain, err := c.transport.TransformInbound(ipPacket)
		if err != nil {
			return nil, err
		}
		parsed, err := parseIPPacket(plain)
		if err != nil {
			return nil, err
		}
		if parsed.nextHeader != ipProtoTCP {
			continue
		}
		if len(parsed.transportPayload) <= 20 {
			return parsed.transportPayload, nil
		}
		return parsed.transportPayload[20:], nil
	}
}

func (c *SecureChannelConn) readIPPacket() ([]byte, error) {
	header := make([]byte, 1)
	if _, err := io.ReadFull(c.conn, header); err != nil {
		return nil, err
	}
	version := header[0] >> 4
	switch version {
	case 4:
		rest := make([]byte, 19)
		if _, err := io.ReadFull(c.conn, rest); err != nil {
			return nil, err
		}
		packet := append(header, rest...)
		totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
		if totalLen < 20 {
			return nil, errors.New("ipsec3gpp: invalid IPv4 total length")
		}
		if totalLen > 20 {
			extra := make([]byte, totalLen-20)
			if _, err := io.ReadFull(c.conn, extra); err != nil {
				return nil, err
			}
			packet = append(packet, extra...)
		}
		return packet, nil
	case 6:
		rest := make([]byte, 39)
		if _, err := io.ReadFull(c.conn, rest); err != nil {
			return nil, err
		}
		packet := append(header, rest...)
		payloadLen := int(binary.BigEndian.Uint16(packet[4:6]))
		if payloadLen > 0 {
			extra := make([]byte, payloadLen)
			if _, err := io.ReadFull(c.conn, extra); err != nil {
				return nil, err
			}
			packet = append(packet, extra...)
		}
		return packet, nil
	default:
		return nil, fmt.Errorf("ipsec3gpp: unsupported IP version %d", version)
	}
}

func buildOutboundTCPPacket(policy Policy, sipPayload []byte) ([]byte, error) {
	tcpSegment := buildMinimalTCPSegment(policy.FlowC.LocalPort, policy.FlowC.RemotePort, sipPayload)
	if len(policy.LocalIP) == 4 {
		return buildIPv4Packet(policy.LocalIP, policy.RemoteIP, ipProtoTCP, tcpSegment), nil
	}
	if len(policy.LocalIP) == 16 {
		return buildIPv6Packet(policy.LocalIP, policy.RemoteIP, ipProtoTCP, tcpSegment), nil
	}
	return nil, errors.New("ipsec3gpp: unsupported local IP length")
}

func buildMinimalTCPSegment(srcPort, dstPort int, payload []byte) []byte {
	hdr := make([]byte, 20)
	binary.BigEndian.PutUint16(hdr[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(hdr[2:4], uint16(dstPort))
	binary.BigEndian.PutUint32(hdr[4:8], 1)
	binary.BigEndian.PutUint32(hdr[8:12], 1)
	hdr[12] = 0x50
	hdr[13] = 0x18 // PSH+ACK
	binary.BigEndian.PutUint16(hdr[14:16], 65535)
	return append(hdr, payload...)
}

func buildIPv4Packet(src, dst []byte, proto uint8, payload []byte) []byte {
	hdr := make([]byte, 20)
	hdr[0] = 0x45
	total := uint16(20 + len(payload))
	binary.BigEndian.PutUint16(hdr[2:4], total)
	hdr[8] = 64
	hdr[9] = proto
	copy(hdr[12:16], src)
	copy(hdr[16:20], dst)
	updateIPv4HeaderChecksum(hdr)
	return append(hdr, payload...)
}

func buildIPv6Packet(src, dst []byte, nextHeader uint8, payload []byte) []byte {
	hdr := make([]byte, 40)
	hdr[0] = 0x60
	binary.BigEndian.PutUint16(hdr[4:6], uint16(len(payload)))
	hdr[6] = nextHeader
	copy(hdr[8:24], src)
	copy(hdr[24:40], dst)
	return append(hdr, payload...)
}