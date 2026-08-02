package imscore

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/emiago/sipgo/sip"
	"github.com/1239t/swu-go/pkg/logger"
)

const subscribeTransactionTimeout = 12 * time.Second

// sendSubscribe sends a SUBSCRIBE request through the existing transport runtime.
// This must be called after REGISTER 200 OK, when transport runtime is established.
func (s *Service) sendSubscribe(ctx context.Context) error {
	if s.transportRuntime == nil {
		return fmt.Errorf("imscore: transport runtime not available")
	}
	if s.pAssociatedURI == "" {
		logger.Warn("IMS SUBSCRIBE skipped: no P-Associated-URI",
			logger.String("trace_id", s.cfg.TraceID),
			logger.String("device_id", s.cfg.DeviceID))
		return nil
	}

	logger.Info("IMS sending SUBSCRIBE for registration state",
		logger.String("trace_id", s.cfg.TraceID),
		logger.String("device_id", s.cfg.DeviceID),
		logger.String("p_associated_uri", s.pAssociatedURI),
		logger.String("service_route", s.serviceRoute))

	// Parse P-Associated-URI to get the first SIP URI
	targetURI := s.pAssociatedURI
	uris := strings.Split(s.pAssociatedURI, ",")
	for _, uri := range uris {
		uri = strings.TrimSpace(uri)
		if strings.HasPrefix(uri, "<sip:") || strings.HasPrefix(uri, "sip:") {
			targetURI = strings.Trim(uri, "<>")
			break
		}
	}

	logger.Info("IMS SUBSCRIBE using target URI",
		logger.String("trace_id", s.cfg.TraceID),
		logger.String("target_uri", targetURI))

	// Parse target URI for Request-URI
	recipient := sip.Uri{}
	if err := sip.ParseUri(targetURI, &recipient); err != nil {
		logger.Error("IMS SUBSCRIBE failed to parse target URI",
			logger.String("trace_id", s.cfg.TraceID),
			logger.String("target_uri", targetURI),
			logger.String("error", err.Error()))
		return fmt.Errorf("imscore: parse target URI: %w", err)
	}

	// Create SUBSCRIBE request - sip.NewRequest will add Via automatically
	req := sip.NewRequest(sip.SUBSCRIBE, recipient)
	req.SetTransport("TCP")
	req.SetDestination(s.cfg.PCSCFAddr)

	// From/To headers use target URI
	fromTag := sip.GenerateTagN(16)
	req.AppendHeader(sip.NewHeader("From", fmt.Sprintf("<%s>;tag=%s", targetURI, fromTag)))
	req.AppendHeader(sip.NewHeader("To", fmt.Sprintf("<%s>", targetURI)))

	// Contact header
	contactURI := fmt.Sprintf("sip:imscore-%x@[%s]:%d", time.Now().UnixNano()&0xffffffff, s.cfg.LocalIP.String(), s.transportRuntime.policy.LocalPortS)
	sipInstanceURN := s.cfg.SIPInstanceURN
	if sipInstanceURN == "" {
		sipInstanceURN = "<urn:gsma:imei:35022564-930064-6>"
	}
	contactStr := fmt.Sprintf("<%s>;+sip.instance=\"%s\"", contactURI, sipInstanceURN)
	req.AppendHeader(sip.NewHeader("Contact", contactStr))

	// Call-ID
	callID := fmt.Sprintf("%x", time.Now().UnixNano())
	req.AppendHeader(sip.NewHeader("Call-ID", callID))

	// CSeq
	req.AppendHeader(sip.NewHeader("CSeq", "5 SUBSCRIBE"))

	// Max-Forwards
	req.AppendHeader(sip.NewHeader("Max-Forwards", "70"))

	// Route header with Service-Route
	if s.serviceRoute != "" {
		req.AppendHeader(sip.NewHeader("Route", s.serviceRoute))
	}

	// Security headers
	req.AppendHeader(sip.NewHeader("Require", "sec-agree"))
	req.AppendHeader(sip.NewHeader("Proxy-Require", "sec-agree"))
	req.AppendHeader(sip.NewHeader("Supported", "path, sec-agree, 100rel, replaces, outbound, gruu"))

	// P-Access-Network-Info
	pani := fmt.Sprintf("IEEE-802.11; i-wlan-node-id=\"22e537707c11\";country=DE")
	req.AppendHeader(sip.NewHeader("P-Access-Network-Info", pani))

	// P-Preferred-Identity
	req.AppendHeader(sip.NewHeader("P-Preferred-Identity", targetURI))

	// Security-Verify
	if s.verifyHeader != "" {
		req.AppendHeader(sip.NewHeader("Security-Verify", s.verifyHeader))
	}

	// User-Agent
	req.AppendHeader(sip.NewHeader("User-Agent", "iOS/18.2.1 iPhone (iPhone15,4)"))

	// Event: reg
	req.AppendHeader(sip.NewHeader("Event", "reg"))

	// Expires
	req.AppendHeader(sip.NewHeader("Expires", "600000"))

	// Accept
	req.AppendHeader(sip.NewHeader("Accept", "application/reginfo+xml"))

	// Content-Length
	req.AppendHeader(sip.NewHeader("Content-Length", "0"))

	logger.Info("IMS SUBSCRIBE request built",
		logger.String("trace_id", s.cfg.TraceID),
		logger.String("request_uri", req.Recipient.String()))

	// Send via transport runtime
	reqBytes := []byte(req.String())

	logger.Info("IMS SUBSCRIBE sending via transport runtime",
		logger.String("trace_id", s.cfg.TraceID),
		logger.Int("payload_size", len(reqBytes)))

	if err := s.transportRuntime.enqueueWrite(reqBytes); err != nil {
		logger.Error("IMS SUBSCRIBE send failed",
			logger.String("trace_id", s.cfg.TraceID),
			logger.String("error", err.Error()))
		return fmt.Errorf("imscore: send SUBSCRIBE: %w", err)
	}

	logger.Info("IMS SUBSCRIBE sent successfully",
		logger.String("trace_id", s.cfg.TraceID),
		logger.String("device_id", s.cfg.DeviceID))

	return nil
}
