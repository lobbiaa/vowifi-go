package voiceclient

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/emiago/sipgo/sip"
	"github.com/1239t/swu-go/pkg/logger"
)

// subscribeTransactionTimeout matches the REGISTER timeout pattern
const subscribeTransactionTimeout = 12 * time.Second

// Subscribe sends a SIP SUBSCRIBE request to register for registration state events.
// This should be called after a successful REGISTER 200 OK to subscribe to the
// user's registration state changes per 3GPP TS 24.229 and RFC 3680.
func (c *Client) Subscribe(ctx context.Context) error {
	logger.Info("IMS sending SUBSCRIBE for registration state",
		logger.String("trace_id", strings.TrimSpace(c.cfg.TraceID)),
		logger.String("device_id", strings.TrimSpace(c.cfg.DeviceID)),
		logger.String("public_uri", c.cfg.PublicURI),
		logger.String("p_associated_uri", c.pAssociatedURI))

	// Use P-Associated-URI as the Request-URI if available, otherwise fall back to PublicURI
	targetURI := c.cfg.PublicURI
	if c.pAssociatedURI != "" {
		// P-Associated-URI may have multiple URIs comma-separated, use the first SIP URI
		uris := strings.Split(c.pAssociatedURI, ",")
		for _, uri := range uris {
			uri = strings.TrimSpace(uri)
			if strings.HasPrefix(uri, "<sip:") || strings.HasPrefix(uri, "sip:") {
				// Remove angle brackets if present
				uri = strings.Trim(uri, "<>")
				targetURI = uri
				break
			}
		}
	}

	// Parse target URI for Request-URI
	recipient := sip.Uri{}
	if err := sip.ParseUri(targetURI, &recipient); err != nil {
		return fmt.Errorf("voiceclient: parse target URI: %w", err)
	}

	// Create SUBSCRIBE request with the target URI as Request-URI
	req := sip.NewRequest(sip.SUBSCRIBE, recipient)

	// Set transport
	if c.cfg.transportNetwork() == "tcp" {
		req.SetTransport("TCP")
	} else {
		req.SetTransport("UDP")
	}

	// Set destination to P-CSCF
	req.SetDestination(c.cfg.PCSCFAddr)

	// From/To headers use the same URI as Request-URI
	fromTag := sip.GenerateTagN(16)
	req.AppendHeader(sip.NewHeader("From", "<"+targetURI+">;tag="+fromTag))
	req.AppendHeader(sip.NewHeader("To", "<"+targetURI+">"))

	// Contact header - use simpler contact without all feature tags
	contactUser := c.contactUser
	if contactUser == "" {
		contactUser = newContactUserUUID()
	}
	contactURI := fmt.Sprintf("sip:%s@[%s]:%d", contactUser, c.cfg.LocalIP.String(), c.cfg.localPort())
	if c.cfg.transportNetwork() == "tcp" {
		contactURI = fmt.Sprintf("sip:%s@[%s]:%d;transport=tcp", contactUser, c.cfg.LocalIP.String(), c.cfg.localPort())
	}
	contactStr := fmt.Sprintf("<%s>;+sip.instance=\"%s\"", contactURI, c.sipInstanceURN)
	req.AppendHeader(sip.NewHeader("Contact", contactStr))

	// Call-ID
	callID := fmt.Sprintf("%x", time.Now().UnixNano())
	req.AppendHeader(sip.NewHeader("Call-ID", callID))

	// CSeq
	req.AppendHeader(sip.NewHeader("CSeq", "5 SUBSCRIBE"))

	// Max-Forwards
	req.AppendHeader(sip.NewHeader("Max-Forwards", "70"))

	// Add Service-Route as Route header if available
	if c.serviceRoute != "" {
		req.AppendHeader(sip.NewHeader("Route", c.serviceRoute))
	}

	// Security headers
	req.AppendHeader(sip.NewHeader("Require", "sec-agree"))
	req.AppendHeader(sip.NewHeader("Proxy-Require", "sec-agree"))
	req.AppendHeader(sip.NewHeader("Supported", "path, sec-agree, 100rel, replaces, outbound, gruu"))

	// P-Access-Network-Info (same as REGISTER)
	if c.registerProfile.IncludePAccessNetworkInfo {
		req.AppendHeader(sip.NewHeader("P-Access-Network-Info", buildPAccessNetworkInfo(c.registerProfile)))
	}

	// P-Preferred-Identity if we have P-Associated-URI
	if targetURI != c.cfg.PublicURI {
		req.AppendHeader(sip.NewHeader("P-Preferred-Identity", targetURI))
	}

	// Security-Verify header - use saved value from REGISTER 401 response
	if c.securityVerify != "" {
		req.AppendHeader(sip.NewHeader("Security-Verify", c.securityVerify))
	}

	// User-Agent
	req.AppendHeader(sip.NewHeader("User-Agent", c.registerProfile.UserAgent))

	// Event: reg (registration state events per RFC 3680)
	req.AppendHeader(sip.NewHeader("Event", "reg"))

	// Expires: 600000 seconds (matching REGISTER)
	req.AppendHeader(sip.NewHeader("Expires", "600000"))

	// Accept: application/reginfo+xml
	req.AppendHeader(sip.NewHeader("Accept", "application/reginfo+xml"))

	// Content-Length
	req.AppendHeader(sip.NewHeader("Content-Length", "0"))

	// Send SUBSCRIBE with timeout
	txCtx, cancel := context.WithTimeout(ctx, subscribeTransactionTimeout)
	defer cancel()

	resp, err := c.doTransaction(txCtx, req)
	if err != nil {
		return fmt.Errorf("voiceclient: SUBSCRIBE transaction: %w", err)
	}

	logger.Info("IMS SUBSCRIBE response received",
		logger.String("trace_id", strings.TrimSpace(c.cfg.TraceID)),
		logger.String("device_id", strings.TrimSpace(c.cfg.DeviceID)),
		logger.Int("status", int(resp.StatusCode)),
		logger.String("reason", resp.Reason))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("voiceclient: SUBSCRIBE failed with status %d %s", resp.StatusCode, resp.Reason)
	}

	logger.Info("IMS SUBSCRIBE successful",
		logger.String("trace_id", strings.TrimSpace(c.cfg.TraceID)),
		logger.String("device_id", strings.TrimSpace(c.cfg.DeviceID)))

	return nil
}
