package imscore

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/1239t/vowifi-go/internal/vowifi/ipsec3gpp"
	"github.com/1239t/vowifi-go/runtimehost/voiceclient"
)

func newSWUNetstack(localIP net.IP, dp voiceclient.PacketDataplane) (voiceclient.SWUTCPDialer, error) {
	// In TUN mode, return nil to force IMS to use OS TCP stack through the TUN interface
	// This allows proper routing and IPsec-3GPP protection at the network layer
	if dp == nil {
		return nil, nil
	}
	// Check if we're in netstack mode by testing if dp has SendInnerPacket method
	// In TUN mode, we intentionally return nil so IMS uses net.Dialer
	return nil, nil
}

func dialPlainTCP(ctx context.Context, cfg Config, swu voiceclient.SWUTCPDialer) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(cfg.PCSCFAddr)
	if err != nil {
		return nil, err
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return nil, err
	}
	rip := net.ParseIP(host)
	if rip == nil {
		return nil, fmt.Errorf("imscore: invalid P-CSCF %q", cfg.PCSCFAddr)
	}
	if swu != nil {
		return swu.DialContextTCP(ctx, cfg.LocalIP, 5060, rip, port)
	}
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: cfg.LocalIP, Port: 5060}}
	return d.DialContext(ctx, "tcp", cfg.PCSCFAddr)
}

type fixedConnDialer struct {
	mu   sync.Mutex
	conn net.Conn
}

func (d *fixedConnDialer) set(conn net.Conn) {
	d.mu.Lock()
	d.conn = conn
	d.mu.Unlock()
}

func (d *fixedConnDialer) dial(ctx context.Context, laddr net.Addr, raddr net.Addr) (net.Conn, error) {
	d.mu.Lock()
	conn := d.conn
	d.mu.Unlock()
	if conn == nil {
		return nil, fmt.Errorf("imscore: SIP connection not ready")
	}
	return conn, nil
}

func newRegisterSIPStack(cfg Config, conn net.Conn, swu voiceclient.SWUTCPDialer, localPort int) (*sipgo.UserAgent, *sipgo.Client, error) {
	if localPort <= 0 {
		localPort = 5060
	}
	dialer := &fixedConnDialer{}
	if conn != nil {
		dialer.set(conn)
	}
	return newSIPStack(cfg, dialer, swu, localPort)
}

func newSecureRegisterSIPStack(cfg Config, conn *ipsec3gpp.SecureChannelConn) (*sipgo.UserAgent, *sipgo.Client, error) {
	localPort := 5060
	if conn != nil && conn.LocalAddr() != nil {
		if ta, ok := conn.LocalAddr().(*net.TCPAddr); ok && ta.Port > 0 {
			localPort = ta.Port
		}
	}
	dialer := &fixedConnDialer{}
	if conn != nil {
		dialer.set(conn)
	}
	return newSIPStack(cfg, dialer, nil, localPort)
}

func newSIPStack(cfg Config, dialer *fixedConnDialer, swu voiceclient.SWUTCPDialer, localPort int) (*sipgo.UserAgent, *sipgo.Client, error) {
	installSIPTrace(cfg.TraceID, cfg.DeviceID)

	// [CRITICAL FIX] Use DialContext field (lobbiaa/sipgo fork) to inject custom dialer
	// This allows us to return pre-established secure connection (6060) instead of creating new one (5060)
	tcpTransport := &sip.TransportTCP{}

	// Set DialContext to check fixedConnDialer first, then swu, then fallback to standard dial
	tcpTransport.DialContext = func(ctx context.Context, laddr net.Addr, raddr net.Addr) (net.Conn, error) {
		log.Printf("[DialContext] called with laddr=%v raddr=%v dialer=%v swu=%v", laddr, raddr, dialer != nil, swu != nil)

		// Priority 1: Check if we have a pre-established secure connection (IMS ESP case)
		if dialer != nil {
			conn, err := dialer.dial(ctx, laddr, raddr)
			log.Printf("[DialContext] fixedConnDialer.dial returned conn=%v err=%v", conn != nil, err)
			if err == nil && conn != nil {
				log.Printf("[DialContext] using pre-established secure connection: %v -> %v", conn.LocalAddr(), conn.RemoteAddr())
				return conn, nil
			}
		}

		// Priority 2: Use swu tunnel if available
		if swu != nil {
			tcpAddr, ok := raddr.(*net.TCPAddr)
			if !ok || tcpAddr == nil {
				return nil, fmt.Errorf("imscore: invalid TCP remote addr %v", raddr)
			}
			port := localPort
			if localTCP, ok := laddr.(*net.TCPAddr); ok && localTCP != nil && localTCP.Port > 0 {
				port = localTCP.Port
			}
			transportAddr := effectiveTransportAddr(cfg)
			transportHost, transportPortStr, err := net.SplitHostPort(transportAddr)
			if err != nil {
				return nil, err
			}
			transportPort, err := strconv.Atoi(transportPortStr)
			if err != nil {
				return nil, err
			}
			transportIP := net.ParseIP(transportHost)
			if transportIP == nil {
				return nil, fmt.Errorf("imscore: invalid transport P-CSCF %q", transportAddr)
			}
			return swu.DialContextTCP(ctx, cfg.LocalIP, port, transportIP, transportPort)
		}

		// Priority 3: Standard OS dial
		return net.DialTimeout("tcp", raddr.String(), registerTransactionTimeout)
	}

	uaOpts := []sipgo.UserAgentOption{
		sipgo.WithUserAgent(cfg.UserAgent),
		sipgo.WithUserAgentTransportLayerOptions(
			sip.WithTransportLayerTransports(sip.TransportsConfig{
				TCP: tcpTransport,
			}),
		),
	}
	ua, err := sipgo.NewUA(uaOpts...)
	if err != nil {
		return nil, nil, err
	}
	client, err := sipgo.NewClient(ua,
		sipgo.WithClientHostname(cfg.LocalIP.String()),
		sipgo.WithClientPort(localPort),
		sipgo.WithClientConnectionAddr(net.JoinHostPort(cfg.LocalIP.String(), fmt.Sprintf("%d", localPort))),
	)
	if err != nil {
		_ = ua.Close()
		return nil, nil, err
	}
	return ua, client, nil
}