package imscore

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/emiago/sipgo/sip"
	"github.com/1239t/swu-go/pkg/logger"

	"github.com/1239t/vowifi-go/internal/vowifi/ipsec3gpp"
	"github.com/1239t/vowifi-go/runtimehost/voiceclient"
)

type sipWriteTask struct {
	payload []byte
	done    chan error
}

type transportRuntime struct {
	cfg       Config
	policy    ipsec3gpp.Policy
	transport *ipsec3gpp.Transport

	portSListener *singleConnListener
	tcpWriteCh    chan sipWriteTask

	portCConn *ipsec3gpp.SecureChannelConn

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func startTransportRuntime(parent context.Context, cfg Config, swu voiceclient.SWUTCPDialer, policy ipsec3gpp.Policy, transport *ipsec3gpp.Transport, portCConn *ipsec3gpp.SecureChannelConn) (*transportRuntime, error) {
	if portCConn == nil || transport == nil {
		return nil, fmt.Errorf("imscore: transport runtime requires secure port-c connection")
	}
	if swu == nil {
		return nil, fmt.Errorf("imscore: transport runtime requires SWu dialer")
	}
	if policy.LocalPortS <= 0 {
		return nil, fmt.Errorf("imscore: transport runtime missing port-s")
	}

	// Create independent context for runtime goroutines
	// This prevents premature cancellation when parent (request) context expires,
	// while still allowing explicit shutdown via Close().
	// The parent context is only used for startup validation above.
	runtimeCtx, cancel := context.WithCancel(context.Background())
	rt := &transportRuntime{
		cfg:       cfg,
		policy:    policy,
		transport: transport,
		portCConn: portCConn,
		tcpWriteCh: make(chan sipWriteTask, 8),
		cancel:    cancel,
	}
	rt.portSListener = newSingleConnListener(&net.TCPAddr{
		IP:   cfg.LocalIP,
		Port: policy.LocalPortS,
	})

	rt.wg.Add(1)
	go rt.runTCPWriteChannel(runtimeCtx)

	rt.wg.Add(1)
	go rt.runPortSListener(runtimeCtx, swu)

	logger.Info("IMS transport runtime started",
		logger.String("trace_id", strings.TrimSpace(cfg.TraceID)),
		logger.String("device_id", strings.TrimSpace(cfg.DeviceID)),
		logger.Int("port_c", policy.LocalPortC),
		logger.Int("port_s", policy.LocalPortS),
		logger.String("registrar", cfg.PCSCFAddr),
		logger.String("transport_target", effectiveTransportAddr(cfg)))
	return rt, nil
}

func (rt *transportRuntime) Close() {
	if rt == nil {
		return
	}
	if rt.cancel != nil {
		rt.cancel()
	}
	if rt.portSListener != nil {
		_ = rt.portSListener.Close()
	}
	if rt.portCConn != nil {
		_ = rt.portCConn.Close()
	}
	rt.wg.Wait()
}

func (rt *transportRuntime) runTCPWriteChannel(ctx context.Context) {
	defer rt.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case task := <-rt.tcpWriteCh:
			_, err := rt.portCConn.Write(task.payload)
			if task.done != nil {
				task.done <- err
				close(task.done)
			}
			if err != nil {
				logger.Warn("IMS port-c write failed",
					logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
					logger.String("error", err.Error()))
			}
		}
	}
}

func (rt *transportRuntime) enqueueWrite(payload []byte) error {
	if rt == nil || rt.tcpWriteCh == nil {
		return fmt.Errorf("imscore: tcp write channel unavailable")
	}
	done := make(chan error, 1)
	rt.tcpWriteCh <- sipWriteTask{payload: append([]byte(nil), payload...), done: done}
	return <-done
}

func (rt *transportRuntime) runPortSListener(ctx context.Context, swu voiceclient.SWUTCPDialer) {
	defer rt.wg.Done()
	listener, err := swu.ListenContextTCP(ctx, rt.cfg.LocalIP, rt.policy.LocalPortS)
	if err != nil {
		logger.Warn("IMS port-s listen failed",
			logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
			logger.Int("port_s", rt.policy.LocalPortS),
			logger.String("error", err.Error()))
		return
	}
	defer listener.Close()

	logger.Info(fmt.Sprintf("[%s] 准备启动 IMS TCP 入站监听", strings.TrimSpace(rt.cfg.DeviceID)),
		logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
		logger.Int("port", rt.policy.LocalPortS))

	for {
		rawConn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				logger.Warn("IMS port-s accept failed",
					logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
					logger.String("error", err.Error()))
				return
			}
		}
		secure := ipsec3gpp.WrapSecureChannel(rawConn, rt.transport, rt.policy)
		logger.Info("IMS port-s accepted inbound push",
			logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
			logger.String("remote", rawConn.RemoteAddr().String()),
			logger.String("local", rawConn.LocalAddr().String()))
		rt.portSListener.deliver(secure)
		rt.wg.Add(1)
		go rt.drainInboundPortS(ctx, secure)
	}
}

func (rt *transportRuntime) drainInboundPortS(ctx context.Context, conn *ipsec3gpp.SecureChannelConn) {
	defer rt.wg.Done()
	defer conn.Close()

	logger.Info("IMS port-s starting drain goroutine",
		logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
		logger.String("local", conn.LocalAddr().String()),
		logger.String("remote", conn.RemoteAddr().String()))

	// Use buffered reader to handle TCP segmentation
	// Large NOTIFY messages with XML content arrive in multiple TCP segments
	reader := bufio.NewReader(conn)
	parser := sip.NewParser().NewSIPStream()

	buf := make([]byte, 8192)
	for {
		select {
		case <-ctx.Done():
			logger.Info("IMS port-s drain context cancelled",
				logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)))
			return
		default:
		}

		n, err := reader.Read(buf)
		if err != nil {
			if err != io.EOF {
				logger.Warn("IMS port-s read error",
					logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
					logger.String("error", err.Error()))
			} else {
				logger.Info("IMS port-s connection closed (EOF)",
					logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)))
			}
			return
		}

		if n == 0 {
			continue
		}

		// Parse SIP stream with callback
		parseErr := parser.ParseSIPStream(buf[:n], func(msg sip.Message) {
			// Log incoming message
			installSIPTrace(rt.cfg.TraceID, rt.cfg.DeviceID)
			sipTraceLogger{traceID: rt.cfg.TraceID, deviceID: rt.cfg.DeviceID}.
				SIPTraceRead("tcp", conn.LocalAddr().String(), conn.RemoteAddr().String(), []byte(msg.String()))

			// Handle the message based on type
			switch v := msg.(type) {
			case *sip.Request:
				rt.handleInboundRequest(ctx, conn, v)
			case *sip.Response:
				logger.Info("IMS port-s received response (unexpected)",
					logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
					logger.Int("status", int(v.StatusCode)))
			}
		})

		if parseErr != nil {
			logger.Warn("IMS port-s SIP parse error",
				logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
				logger.String("error", parseErr.Error()))
			return
		}
	}
}

func (rt *transportRuntime) handleInboundRequest(ctx context.Context, conn *ipsec3gpp.SecureChannelConn, req *sip.Request) {
	method := req.Method
	logger.Info("IMS port-s received request",
		logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
		logger.String("method", string(method)),
		logger.String("request_uri", req.Recipient.String()))

	switch method {
	case sip.NOTIFY:
		rt.handleNotify(ctx, conn, req)
	case sip.INVITE:
		logger.Info("IMS port-s received INVITE (not implemented yet)",
			logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)))
		rt.sendSimpleResponse(conn, req, 501)
	default:
		logger.Warn("IMS port-s received unsupported method",
			logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
			logger.String("method", string(method)))
		rt.sendSimpleResponse(conn, req, 405)
	}
}

func (rt *transportRuntime) handleNotify(ctx context.Context, conn *ipsec3gpp.SecureChannelConn, req *sip.Request) {
	// Log NOTIFY event type
	eventHeader := req.GetHeader("Event")
	var eventType string
	if eventHeader != nil {
		eventType = eventHeader.Value()
	}

	logger.Info("IMS NOTIFY received",
		logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
		logger.String("device_id", strings.TrimSpace(rt.cfg.DeviceID)),
		logger.String("event", eventType),
		logger.Int("content_length", len(req.Body())))

	// Send 200 OK response
	rt.sendSimpleResponse(conn, req, 200)
}

func (rt *transportRuntime) sendSimpleResponse(conn *ipsec3gpp.SecureChannelConn, req *sip.Request, statusCode int) {
	// Create response
	res := sip.NewResponseFromRequest(req, statusCode, "", nil)

	// Send response
	resBytes := []byte(res.String())
	if _, err := conn.Write(resBytes); err != nil {
		logger.Warn("IMS port-s response write failed",
			logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
			logger.Int("status", statusCode),
			logger.String("error", err.Error()))
		return
	}

	// Log outgoing response
	installSIPTrace(rt.cfg.TraceID, rt.cfg.DeviceID)
	sipTraceLogger{traceID: rt.cfg.TraceID, deviceID: rt.cfg.DeviceID}.
		SIPTraceWrite("tcp", conn.LocalAddr().String(), conn.RemoteAddr().String(), resBytes)

	logger.Info("IMS port-s response sent",
		logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
		logger.Int("status", statusCode),
		logger.String("method", string(req.Method)))
}


