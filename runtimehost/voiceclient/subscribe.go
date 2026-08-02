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
		logger.String("public_uri", c.cfg.PublicURI))

	req, err := c.newRequest(sip.SUBSCRIBE, c.cfg.PublicURI, false)
	if err != nil {
		return fmt.Errorf("voiceclient: new SUBSCRIBE request: %w", err)
	}

	// Event: reg (registration state events per RFC 3680)
	req.AppendHeader(sip.NewHeader("Event", "reg"))

	// Expires: 3600 seconds (1 hour)
	req.AppendHeader(sip.NewHeader("Expires", "3600"))

	// Accept: application/reginfo+xml
	req.AppendHeader(sip.NewHeader("Accept", "application/reginfo+xml"))

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
