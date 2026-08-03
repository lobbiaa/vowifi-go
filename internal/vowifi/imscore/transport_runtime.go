package imscore

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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

	// Registration routing state (from REGISTER 200 OK), needed to build
	// UE-originated requests such as the RP-ACK MESSAGE for MT-SMS.
	serviceRoute string
	verifyHeader string

	portSListener *singleConnListener
	tcpWriteCh    chan sipWriteTask

	portCConn *ipsec3gpp.SecureChannelConn

	cseq uint32 // atomic CSeq counter for UE-originated standalone requests

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func startTransportRuntime(parent context.Context, cfg Config, swu voiceclient.SWUTCPDialer, policy ipsec3gpp.Policy, transport *ipsec3gpp.Transport, portCConn *ipsec3gpp.SecureChannelConn, serviceRoute, verifyHeader string) (*transportRuntime, error) {
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
		cfg:          cfg,
		policy:       policy,
		transport:    transport,
		serviceRoute: serviceRoute,
		verifyHeader: verifyHeader,
		portCConn:    portCConn,
		tcpWriteCh:   make(chan sipWriteTask, 8),
		cancel:       cancel,
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
		// [CRITICAL FIX] IMS ESP is applied by the kernel via XFRM (see dialSecureRegisterConn
		// in register.go). The kernel decrypts inbound ESP transparently, so the accepted TCP
		// connection already delivers plaintext SIP. Using WrapSecureChannel here (userspace ESP)
		// would make Read() parse the plaintext "NOTIFY ..." bytes as an IP/ESP packet: 'N'=0x4E
		// is read as IP version 4, bytes [2:4] as an IPv4 total-length, and io.ReadFull then
		// blocks forever waiting for bytes that never arrive — until the peer RSTs. Use the
		// passthrough wrapper to read the raw (already-decrypted) TCP stream, matching port-c.
		secure := ipsec3gpp.WrapSecureChannelPassthrough(rawConn)
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

		logger.Debug("IMS port-s about to read",
			logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
			logger.String("local", conn.LocalAddr().String()),
			logger.String("remote", conn.RemoteAddr().String()))

		n, err := reader.Read(buf)

		logger.Info("IMS port-s read returned",
			logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
			logger.Int("bytes", n),
			logger.Bool("has_error", err != nil))

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
			// [CRITICAL FIX] ParseSIPStream is a *stateful streaming* parser. A large
			// NOTIFY (Content-Length: 1700 + headers ~ 2KB) does not fit in a single TCP
			// segment, so the first Read returns only a partial message and the parser
			// returns ErrParseSipPartial. This is NOT fatal: the parser retains its buffer
			// and content offset, so we must keep looping and feed it the next segment(s)
			// until the full body arrives and the callback fires. Returning here (the old
			// behavior) killed the goroutine on the very first partial read, so the NOTIFY
			// was never handled and no 200 OK was ever sent.
			if errors.Is(parseErr, sip.ErrParseSipPartial) {
				logger.Debug("IMS port-s awaiting more SIP data (partial)",
					logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)))
				continue
			}
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
	case sip.MESSAGE:
		rt.handleInboundMessage(ctx, conn, req)
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

func (rt *transportRuntime) handleInboundMessage(ctx context.Context, conn *ipsec3gpp.SecureChannelConn, req *sip.Request) {
	// Verify Content-Type
	ct := req.GetHeader("Content-Type")
	if ct == nil || !strings.EqualFold(strings.TrimSpace(ct.Value()), "application/vnd.3gpp.sms") {
		logger.Warn("IMS MESSAGE with unsupported Content-Type",
			logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
			logger.String("content_type", func() string {
				if ct != nil {
					return ct.Value()
				}
				return "<nil>"
			}()))
		rt.sendSimpleResponse(conn, req, 415)
		return
	}

	body := req.Body()
	if len(body) < 2 {
		logger.Warn("IMS MESSAGE body too short",
			logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
			logger.Int("body_len", len(body)))
		rt.sendSimpleResponse(conn, req, 400)
		return
	}

	// Send 200 OK immediately (satisfies SIP transaction)
	rt.sendSimpleResponse(conn, req, 200)

	// Classify RP message type from first byte
	rpMTI := body[0]
	rpMR := body[1]

	switch rpMTI {
	case 0x00, 0x01: // RP-DATA (Network→MS or MS→Network)
		// This is an inbound MT-SMS
		logger.Info("IMS MESSAGE: MT-SMS received (RP-DATA)",
			logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
			logger.String("device_id", strings.TrimSpace(rt.cfg.DeviceID)),
			logger.Int("rp_mr", int(rpMR)),
			logger.Int("body_len", len(body)))

		// Surface to vohive for decode and processing
		if rt.cfg.InboundSMS != nil {
			rt.cfg.InboundSMS.DeliverInboundSMS(rt.cfg.DeviceID, body, time.Now())
		} else {
			logger.Warn("IMS MT-SMS received but InboundSMS sink is nil",
				logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
				logger.String("device_id", strings.TrimSpace(rt.cfg.DeviceID)))
		}

		// Send RP-ACK back to network (new UE-originated MESSAGE per 3GPP TS 24.341)
		rt.sendRPAck(req, rpMR)

	case 0x02, 0x03: // RP-ACK (MS→Network or Network→MS)
		// Delivery report: our outbound SMS was acked
		logger.Info("IMS MESSAGE: delivery report (RP-ACK)",
			logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
			logger.String("device_id", strings.TrimSpace(rt.cfg.DeviceID)),
			logger.Int("rp_mr", int(rpMR)))

		// Record via DeliveryStore (reuses existing voiceclient pattern)
		if rt.cfg.DeliveryStore != nil {
			inReplyTo := ""
			if irt := req.GetHeader("In-Reply-To"); irt != nil {
				inReplyTo = irt.Value()
			}
			callID := req.CallID().Value()
			_, _ = rt.cfg.DeliveryStore.MarkSMSDeliveryPartReport(
				inReplyTo, callID, rt.cfg.DeviceID, int(rpMR),
				"acked", 200, 0, "", time.Now(),
			)
		}

	case 0x04, 0x05: // RP-ERROR (MS→Network or Network→MS)
		// Delivery report: our outbound SMS failed
		cause := 0
		if len(body) >= 4 {
			cause = int(body[3] & 0x7F)
		}
		logger.Info("IMS MESSAGE: delivery report (RP-ERROR)",
			logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
			logger.String("device_id", strings.TrimSpace(rt.cfg.DeviceID)),
			logger.Int("rp_mr", int(rpMR)),
			logger.Int("rp_cause", cause))

		if rt.cfg.DeliveryStore != nil {
			inReplyTo := ""
			if irt := req.GetHeader("In-Reply-To"); irt != nil {
				inReplyTo = irt.Value()
			}
			callID := req.CallID().Value()
			_, _ = rt.cfg.DeliveryStore.MarkSMSDeliveryPartReport(
				inReplyTo, callID, rt.cfg.DeviceID, int(rpMR),
				"failed", 200, cause, "", time.Now(),
			)
		}

	default:
		logger.Warn("IMS MESSAGE: unknown RP message type",
			logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
			logger.Int("rp_mti", int(rpMTI)))
	}
}

// sendRPAck sends an RP-ACK back to the network as a new UE-originated SIP
// MESSAGE, per 3GPP TS 24.341 §5.3.2.4. This is what the SMSC waits for before
// it considers the MT-SMS delivered; without it the network retransmits the
// RP-DATA (and never advances to later segments of a concatenated SMS).
//
// The RP-ACK MESSAGE is addressed back to the SMSC/SMS-GMSC, whose URI is taken
// from the incoming request's P-Asserted-Identity (fallback: From). It reuses
// the same IMS routing state (Service-Route, Security-Verify, sec-agree) as the
// SUBSCRIBE path and is sent over the protected port-c connection so the TCP
// source port matches the port-c in Security-Client (P-CSCF ESP integrity).
func (rt *transportRuntime) sendRPAck(orig *sip.Request, rpMR byte) {
	// RP-ACK RPDU per 3GPP TS 24.011 §7.3.3: {MTI=0x02 (MS->Network), RP-MR}.
	rpAck := []byte{0x02, rpMR}

	// Target = SMSC address from the incoming MESSAGE. Prefer P-Asserted-Identity
	// (the network-asserted originator), fall back to the From header URI.
	target := ""
	if pai := orig.GetHeader("P-Asserted-Identity"); pai != nil {
		target = extractURI(pai.Value())
	}
	if target == "" {
		if from := orig.From(); from != nil {
			target = "sip:" + from.Address.User + "@" + from.Address.Host
			if from.Address.User == "" {
				target = extractURI(from.Value())
			}
		}
	}
	if target == "" {
		logger.Warn("IMS RP-ACK skipped: no target URI in incoming MESSAGE",
			logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
			logger.String("device_id", strings.TrimSpace(rt.cfg.DeviceID)),
			logger.Int("rp_mr", int(rpMR)))
		return
	}

	recipient := sip.Uri{}
	if err := sip.ParseUri(target, &recipient); err != nil {
		logger.Warn("IMS RP-ACK failed to parse target URI",
			logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
			logger.String("target", target),
			logger.String("error", err.Error()))
		return
	}

	impu := strings.TrimSpace(rt.cfg.PublicURI)

	req := sip.NewRequest(sip.MESSAGE, recipient)
	req.SetTransport("TCP")
	req.SetDestination(rt.cfg.PCSCFAddr)

	// Via must reflect the protected client port (port-c): the RP-ACK is a
	// Flow-1 (UE port-c -> P-CSCF port-s) request, and the P-CSCF validates the
	// TCP source port against the port-c in Security-Client.
	req.RemoveHeader("Via")
	viaHost := fmt.Sprintf("[%s]:%d", rt.cfg.LocalIP.String(), rt.policy.LocalPortC)
	viaValue := fmt.Sprintf("SIP/2.0/TCP %s;rport;branch=%s", viaHost, sip.GenerateBranchN(16))
	req.AppendHeader(sip.NewHeader("Via", viaValue))

	// Route from REGISTER 200 OK Service-Route.
	if rt.serviceRoute != "" {
		req.AppendHeader(sip.NewHeader("Route", rt.serviceRoute))
	}

	// From = our IMPU; To = SMSC.
	req.AppendHeader(sip.NewHeader("From", fmt.Sprintf("<%s>;tag=%s", impu, sip.GenerateTagN(16))))
	req.AppendHeader(sip.NewHeader("To", fmt.Sprintf("<%s>", target)))

	req.AppendHeader(sip.NewHeader("Call-ID", fmt.Sprintf("%x", time.Now().UnixNano())))

	cseq := atomic.AddUint32(&rt.cseq, 1)
	req.AppendHeader(sip.NewHeader("CSeq", fmt.Sprintf("%d MESSAGE", cseq)))

	req.AppendHeader(sip.NewHeader("Max-Forwards", "70"))

	// sec-agree + identity, matching the SUBSCRIBE path the P-CSCF already accepts.
	req.AppendHeader(sip.NewHeader("Require", "sec-agree"))
	req.AppendHeader(sip.NewHeader("Proxy-Require", "sec-agree"))
	req.AppendHeader(sip.NewHeader("Supported", "path, sec-agree, 100rel, replaces, outbound, gruu"))
	if impu != "" {
		req.AppendHeader(sip.NewHeader("P-Preferred-Identity", fmt.Sprintf("<%s>", impu)))
	}
	if rt.verifyHeader != "" {
		req.AppendHeader(sip.NewHeader("Security-Verify", rt.verifyHeader))
	}
	if ua := strings.TrimSpace(rt.cfg.UserAgent); ua != "" {
		req.AppendHeader(sip.NewHeader("User-Agent", ua))
	}

	req.AppendHeader(sip.NewHeader("Content-Type", "application/vnd.3gpp.sms"))
	req.SetBody(rpAck)

	if err := rt.enqueueWrite([]byte(req.String())); err != nil {
		logger.Warn("IMS RP-ACK send failed",
			logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
			logger.String("device_id", strings.TrimSpace(rt.cfg.DeviceID)),
			logger.Int("rp_mr", int(rpMR)),
			logger.String("error", err.Error()))
		return
	}

	logger.Info("IMS RP-ACK sent",
		logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
		logger.String("device_id", strings.TrimSpace(rt.cfg.DeviceID)),
		logger.Int("rp_mr", int(rpMR)),
		logger.String("target", target))
}

// extractURI pulls the bare sip:/sips:/tel: URI out of a header value that may
// carry a display name, angle brackets, and trailing parameters, e.g.
// `"SMSC" <sip:10.1.1.1:5060>;tag=abc` -> `sip:10.1.1.1:5060`.
func extractURI(value string) string {
	value = strings.TrimSpace(value)
	if lt := strings.Index(value, "<"); lt >= 0 {
		if gt := strings.Index(value[lt:], ">"); gt >= 0 {
			return strings.TrimSpace(value[lt+1 : lt+gt])
		}
	}
	// No angle brackets: strip any params after the first ';'.
	if semi := strings.Index(value, ";"); semi >= 0 {
		value = value[:semi]
	}
	return strings.TrimSpace(value)
}



