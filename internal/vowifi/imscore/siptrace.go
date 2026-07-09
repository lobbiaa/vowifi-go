package imscore

import (
	"os"
	"strings"

	"github.com/emiago/sipgo/sip"
	"github.com/1239t/swu-go/pkg/logger"
)

type sipTraceLogger struct {
	traceID  string
	deviceID string
}

func (s sipTraceLogger) SIPTraceRead(transport string, laddr string, raddr string, sipmsg []byte) {
	logger.Info("IMS SIP read",
		logger.String("trace_id", strings.TrimSpace(s.traceID)),
		logger.String("device_id", strings.TrimSpace(s.deviceID)),
		logger.String("transport", strings.ToLower(strings.TrimSpace(transport))),
		logger.String("local_addr", laddr),
		logger.String("remote_addr", raddr),
		logger.String("sip", string(sipmsg)))
}

func (s sipTraceLogger) SIPTraceWrite(transport string, laddr string, raddr string, sipmsg []byte) {
	logger.Info("IMS SIP write",
		logger.String("trace_id", strings.TrimSpace(s.traceID)),
		logger.String("device_id", strings.TrimSpace(s.deviceID)),
		logger.String("transport", strings.ToLower(strings.TrimSpace(transport))),
		logger.String("local_addr", laddr),
		logger.String("remote_addr", raddr),
		logger.String("sip", string(sipmsg)))
}

func installSIPTrace(traceID, deviceID string) {
	if strings.TrimSpace(os.Getenv("VOHIVE_SIP_TRACE")) == "" {
		return
	}
	sip.SIPDebug = true
	sip.SIPDebugTracer(sipTraceLogger{
		traceID:  traceID,
		deviceID: deviceID,
	})
}

func logRegisterRouting(cfg Config, req *sip.Request) {
	if req == nil {
		return
	}
	route := ""
	if h := req.GetHeader("Route"); h != nil {
		route = strings.TrimSpace(h.Value())
	}
	contact := ""
	if h := req.GetHeader("Contact"); h != nil {
		contact = strings.TrimSpace(h.Value())
	}
	logger.Info("IMS REGISTER routing",
		logger.String("trace_id", strings.TrimSpace(cfg.TraceID)),
		logger.String("device_id", strings.TrimSpace(cfg.DeviceID)),
		logger.String("registrar", strings.TrimSpace(cfg.PCSCFAddr)),
		logger.String("transport_target", effectiveTransportAddr(cfg)),
		logger.String("ipsec_gateway", effectiveIPSecGatewayAddr(cfg)),
		logger.String("route", route),
		logger.String("request_uri", req.Recipient.String()),
		logger.String("destination", strings.TrimSpace(req.Destination())),
		logger.String("contact", contact))
}