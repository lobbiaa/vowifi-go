// Command message is the minimal SMS-over-SIP (3GPP TS 24.341) validation:
// submit an SMS-shaped MESSAGE, get the immediate 202 Accepted, then
// receive the delivery report as a SEPARATE, asynchronous MESSAGE from the
// network back to the UE -- correlated via In-Reply-To: <original Call-ID>,
// exactly the shape vohive's messaging.DeliveryStore already expects
// (confirmed by the earlier research into vohive's
// MarkSMSDeliveryPartReport correlation cascade: In-Reply-To first, then
// Call-ID, then an (rp_mr, time-window) fallback).
//
// Per RFC 3428 + TS 24.341 (confirmed by web search, not reconstructed from
// memory):
//   - the network's immediate ack to a submitted SMS-carrying MESSAGE is
//     202 Accepted, not 200 OK
//   - both the submission and the delivery report use
//     Content-Type: application/vnd.3gpp.sms
//   - the delivery report is a NEW MESSAGE request (its own transaction,
//     own Call-ID) carrying In-Reply-To: <the original MESSAGE's Call-ID>
//   - the UE just answers that delivery-report MESSAGE with 200 OK
//
// This still uses placeholder bytes for the body rather than a real
// RP-DATA(SUBMIT) encoding -- deliberately: the encoding-ownership question
// (vohive's pkg/smscodec can't be imported by vowifi-go, wrong dependency
// direction) is resolved as of runtimehost/messaging.SMSPart -- vohive
// pre-encodes and hands vowifi-go opaque, already-framed bytes plus the
// RPMR (see messaging.go's doc comment and internal/device's
// SendVoWiFiSMSWithOptions on the vohive side). This spike only proves the
// SIP-level MESSAGE/202/async-report/200 mechanics that SMSPart.Body rides
// on top of; it isn't exercising the encoder itself.
package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
)

const (
	networkAddr = "127.0.0.1:15068"
	ueAddr      = "127.0.0.1:15069"
	contentType = "application/vnd.3gpp.sms"
)

// Placeholder for a real RP-DATA-wrapped SUBMIT TPDU -- see package doc.
var fakeSubmitBody = []byte{0x01, 0x02, 0x03, 0x04} // stand-in RP-DATA(SUBMIT)
var fakeAckBody = []byte{0x02, 0x02}                // stand-in RP-ACK

func main() {
	// --- "network" side: a Server to receive the submitted MESSAGE, a
	// Client to later push the async delivery-report MESSAGE to the UE.
	networkUA, err := sipgo.NewUA(sipgo.WithUserAgent("sipspike-network"))
	if err != nil {
		log.Fatalf("network UA: %v", err)
	}
	networkSrv, err := sipgo.NewServer(networkUA)
	if err != nil {
		log.Fatalf("network server: %v", err)
	}
	networkClient, err := sipgo.NewClient(networkUA, sipgo.WithClientHostname("127.0.0.1"))
	if err != nil {
		log.Fatalf("network client: %v", err)
	}
	defer networkClient.Close()

	submittedCount := 0
	var originalCallID string

	networkSrv.OnMessage(func(req *sip.Request, tx sip.ServerTransaction) {
		ct := req.GetHeader("Content-Type")
		if ct == nil || ct.Value() != contentType {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 415, "Unsupported Media Type", nil))
			return
		}
		submittedCount++
		originalCallID = req.CallID().Value()
		fmt.Printf("network: received SMS submission (Call-ID=%s, body=% x)\n", originalCallID, req.Body())

		// RFC 3428 / TS 24.341: acknowledge submission immediately with 202,
		// not 200 -- the actual delivery outcome comes later, separately.
		_ = tx.Respond(sip.NewResponseFromRequest(req, 202, "Accepted", nil))

		// Asynchronously push the delivery report as its own MESSAGE.
		go func() {
			time.Sleep(150 * time.Millisecond)
			sendDeliveryReport(networkClient, originalCallID)
		}()
	})

	// --- "UE" side: a Client to submit the SMS, a Server to receive the
	// (unsolicited, from the UE's perspective) delivery-report MESSAGE.
	ueUA, err := sipgo.NewUA(sipgo.WithUserAgent("sipspike-ue"))
	if err != nil {
		log.Fatalf("ue UA: %v", err)
	}
	ueClient, err := sipgo.NewClient(ueUA, sipgo.WithClientHostname("127.0.0.1"))
	if err != nil {
		log.Fatalf("ue client: %v", err)
	}
	defer ueClient.Close()
	ueSrv, err := sipgo.NewServer(ueUA)
	if err != nil {
		log.Fatalf("ue server: %v", err)
	}

	reportReceived := make(chan struct{}, 1)
	var reportInReplyTo string

	ueSrv.OnMessage(func(req *sip.Request, tx sip.ServerTransaction) {
		ct := req.GetHeader("Content-Type")
		if ct == nil || ct.Value() != contentType {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 415, "Unsupported Media Type", nil))
			return
		}
		irt := req.GetHeader("In-Reply-To")
		if irt != nil {
			reportInReplyTo = irt.Value()
		}
		fmt.Printf("ue: received delivery report (In-Reply-To=%s, body=% x)\n", reportInReplyTo, req.Body())
		_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
		select {
		case reportReceived <- struct{}{}:
		default:
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	networkDone := make(chan error, 1)
	go func() { networkDone <- networkSrv.ListenAndServe(ctx, "udp", networkAddr) }()
	ueDone := make(chan error, 1)
	go func() { ueDone <- ueSrv.ListenAndServe(ctx, "udp", ueAddr) }()
	time.Sleep(200 * time.Millisecond)

	// UE submits the SMS.
	recipient := sip.Uri{}
	if err := sip.ParseUri(fmt.Sprintf("sip:%s", networkAddr), &recipient); err != nil {
		log.Fatalf("parse uri: %v", err)
	}
	req := sip.NewRequest(sip.MESSAGE, recipient)
	req.AppendHeader(sip.NewHeader("Contact", fmt.Sprintf("<sip:vohive-ue@%s>", ueAddr)))
	req.AppendHeader(sip.NewHeader("Content-Type", contentType))
	req.SetBody(fakeSubmitBody)
	req.SetTransport("UDP")

	reqCtx, reqCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer reqCancel()
	tx, err := ueClient.TransactionRequest(reqCtx, req)
	if err != nil {
		log.Fatalf("ue: submit transaction: %v", err)
	}
	defer tx.Terminate()

	var res *sip.Response
	select {
	case <-tx.Done():
		log.Fatal("ue: submit transaction died without a response")
	case res = <-tx.Responses():
	case <-reqCtx.Done():
		log.Fatal("ue: timed out waiting for submit response")
	}
	fmt.Printf("ue: submit response %d %s\n", res.StatusCode, res.Reason)
	sentCallID := req.CallID().Value()

	// Wait for the async delivery report to arrive at the UE's server side.
	select {
	case <-reportReceived:
	case <-time.After(5 * time.Second):
		log.Fatal("FAIL: delivery report never arrived")
	}

	cancel()
	<-networkDone
	<-ueDone

	if res.StatusCode != 202 {
		log.Fatalf("FAIL: expected 202 Accepted for submission, got %d", res.StatusCode)
	}
	if submittedCount != 1 {
		log.Fatalf("FAIL: network saw %d submission(s), want 1", submittedCount)
	}
	if !strings.Contains(reportInReplyTo, sentCallID) {
		log.Fatalf("FAIL: delivery report In-Reply-To=%q does not reference submitted Call-ID=%q",
			reportInReplyTo, sentCallID)
	}
	fmt.Println("PASS: SMS submit -> 202 Accepted -> async delivery-report MESSAGE (In-Reply-To) -> 200 OK")
}

func sendDeliveryReport(client *sipgo.Client, inReplyToCallID string) {
	recipient := sip.Uri{}
	if err := sip.ParseUri(fmt.Sprintf("sip:%s", ueAddr), &recipient); err != nil {
		fmt.Println("network: parse UE uri:", err)
		return
	}
	req := sip.NewRequest(sip.MESSAGE, recipient)
	req.AppendHeader(sip.NewHeader("Contact", fmt.Sprintf("<sip:vohive-network@%s>", networkAddr)))
	req.AppendHeader(sip.NewHeader("Content-Type", contentType))
	req.AppendHeader(sip.NewHeader("In-Reply-To", inReplyToCallID))
	req.SetBody(fakeAckBody)
	req.SetTransport("UDP")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := client.TransactionRequest(ctx, req)
	if err != nil {
		fmt.Println("network: delivery report transaction:", err)
		return
	}
	defer tx.Terminate()

	select {
	case <-tx.Done():
		fmt.Println("network: delivery report transaction died without a response")
	case res := <-tx.Responses():
		fmt.Printf("network: delivery report response %d %s\n", res.StatusCode, res.Reason)
	case <-ctx.Done():
		fmt.Println("network: timed out waiting for delivery report ack")
	}
}
