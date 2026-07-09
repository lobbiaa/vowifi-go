// Command voiceclienttest validates the real production
// runtimehost/voiceclient package end to end: a fake P-CSCF server
// (AKAv1-MD5 REGISTER challenge + SMS MESSAGE submission + async delivery
// report, same shapes already proven individually in spike/sipspike/*)
// against the actual voiceclient.Dial/Client.SendSMS, with a fake
// DeliveryStore recording what gets called so the whole chain -- REGISTER,
// SendSMS, 202 Accepted, async delivery report, DeliveryStore correlation
// -- can be asserted, not just "it didn't crash".
package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/icholy/digest"

	swusim "github.com/iniwex5/vowifi-go/engine/sim"
	"github.com/iniwex5/vowifi-go/runtimehost/messaging"
	"github.com/iniwex5/vowifi-go/runtimehost/voiceclient"
)

const (
	pcscfAddr   = "127.0.0.1:15070"
	clientPort  = 15071
	identity    = "0001010000000001@nai.epc.mnc001.mcc001.3gppnetwork.org"
	realm       = "ims.mnc001.mcc001.3gppnetwork.org"
	smsContentT = "application/vnd.3gpp.sms"
)

var (
	fixedRAND = bytesOf(0xAA, 16)
	fixedAUTN = bytesOf(0xBB, 16)
	fixedRES  = []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18}
)

func bytesOf(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

type fakeAKA struct{}

func (fakeAKA) CalculateAKA(rand16, autn16 []byte) (swusim.AKAResult, error) {
	if string(rand16) != string(fixedRAND) || string(autn16) != string(fixedAUTN) {
		return swusim.AKAResult{}, fmt.Errorf("unrecognized RAND/AUTN")
	}
	return swusim.AKAResult{RES: fixedRES, CK: bytesOf(0x21, 16), IK: bytesOf(0x22, 16)}, nil
}

// fakeStore implements messaging.DeliveryStore, recording calls for the
// test's own assertions instead of touching a real database.
type fakeStore struct {
	mu       sync.Mutex
	created  []string
	parts    []string
	reports  []string
	reported chan struct{}
}

func newFakeStore() *fakeStore {
	return &fakeStore{reported: make(chan struct{}, 1)}
}

func (s *fakeStore) CreateSMSDelivery(messageID, imsi, deviceID, peer, content string, partsTotal int, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.created = append(s.created, fmt.Sprintf("%s peer=%s content=%q parts=%d", messageID, peer, content, partsTotal))
	return nil
}

func (s *fakeStore) UpsertSMSDeliveryPart(messageID string, partNo int, callID string, rpMR int, state string, sentAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.parts = append(s.parts, fmt.Sprintf("%s#%d callID=%s rpMR=%d state=%s", messageID, partNo, callID, rpMR, state))
	return nil
}

func (s *fakeStore) MarkSMSDeliveryPartReport(inReplyTo, callID, deviceID string, rpMR int, state string, sipCode int, rpCause int, errText string, at time.Time) (messaging.DeliveryPartMatch, error) {
	s.mu.Lock()
	s.reports = append(s.reports, fmt.Sprintf("inReplyTo=%s callID=%s rpMR=%d state=%s cause=%d", inReplyTo, callID, rpMR, state, rpCause))
	s.mu.Unlock()
	select {
	case s.reported <- struct{}{}:
	default:
	}
	return messaging.DeliveryPartMatch{MessageID: "msg", PartNo: 0, State: state}, nil
}

func (s *fakeStore) RecomputeSMSDelivery(messageID string, at time.Time) error { return nil }
func (s *fakeStore) UpdateSMSDeliveryState(messageID, state, lastError string, acks int, at time.Time) error {
	return nil
}
func (s *fakeStore) GetSMSDeliveryStatus(messageID string) (*messaging.DeliveryStatus, error) {
	return nil, nil
}

func main() {
	// --- fake P-CSCF/network side ---
	networkUA, err := sipgo.NewUA(sipgo.WithUserAgent("fake-pcscf"))
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

	nonce := base64.StdEncoding.EncodeToString(append(append([]byte{}, fixedRAND...), fixedAUTN...))
	var chal digest.Challenge
	registerAccepted := 0

	networkSrv.OnRegister(func(req *sip.Request, tx sip.ServerTransaction) {
		h := req.GetHeader("Authorization")
		if h == nil {
			chal = digest.Challenge{Realm: realm, Nonce: nonce, Opaque: "voiceclienttest", Algorithm: "AKAv1-MD5"}
			res := sip.NewResponseFromRequest(req, 401, "Unauthorized", nil)
			res.AppendHeader(sip.NewHeader("WWW-Authenticate", chal.String()))
			fmt.Println("network: challenging REGISTER")
			_ = tx.Respond(res)
			return
		}
		cred, err := digest.ParseCredentials(h.Value())
		if err != nil {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 400, "Bad Request", nil))
			return
		}
		mathChal := chal
		mathChal.Algorithm = "MD5"
		want, err := digest.Digest(&mathChal, digest.Options{
			Method: "REGISTER", URI: cred.URI, Username: identity,
			Password: hex.EncodeToString(fixedRES),
		})
		if err != nil || cred.Response != want.Response {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 401, "Unauthorized", nil))
			return
		}
		registerAccepted++
		fmt.Println("network: REGISTER accepted")
		_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
	})

	networkSrv.OnMessage(func(req *sip.Request, tx sip.ServerTransaction) {
		ct := req.GetHeader("Content-Type")
		if ct == nil || !strings.EqualFold(ct.Value(), smsContentT) {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 415, "Unsupported Media Type", nil))
			return
		}
		callID := req.CallID().Value()
		fmt.Printf("network: SMS submission received (Call-ID=%s, body=%x)\n", callID, req.Body())
		_ = tx.Respond(sip.NewResponseFromRequest(req, 202, "Accepted", nil))

		go func(replyTo string) {
			time.Sleep(150 * time.Millisecond)
			recipient := sip.Uri{}
			_ = sip.ParseUri(fmt.Sprintf("sip:127.0.0.1:%d", clientPort), &recipient)
			r := sip.NewRequest(sip.MESSAGE, recipient)
			r.AppendHeader(sip.NewHeader("Contact", fmt.Sprintf("<sip:fake-pcscf@%s>", pcscfAddr)))
			r.AppendHeader(sip.NewHeader("Content-Type", smsContentT))
			r.AppendHeader(sip.NewHeader("In-Reply-To", replyTo))
			r.SetBody([]byte{0x03, 0x2a}) // RP-ACK (Network->MS), rp_mr = 0x2a
			r.SetTransport("UDP")

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			tx2, err := networkClient.TransactionRequest(ctx, r)
			if err != nil {
				fmt.Println("network: delivery report transaction:", err)
				return
			}
			defer tx2.Terminate()
			select {
			case res := <-tx2.Responses():
				fmt.Printf("network: delivery report response %d %s\n", res.StatusCode, res.Reason)
			case <-tx2.Done():
				fmt.Println("network: delivery report transaction died")
			case <-ctx.Done():
				fmt.Println("network: delivery report timed out")
			}
		}(callID)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	networkDone := make(chan error, 1)
	go func() { networkDone <- networkSrv.ListenAndServe(ctx, "udp", pcscfAddr) }()
	time.Sleep(200 * time.Millisecond)

	// --- real voiceclient under test ---
	store := newFakeStore()
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer dialCancel()

	client, err := voiceclient.Dial(dialCtx, voiceclient.Config{
		DeviceID:      "dev-voiceclienttest",
		LocalIP:       net.ParseIP("127.0.0.1"),
		LocalPort:     clientPort,
		PCSCFAddr:     pcscfAddr,
		Realm:         realm,
		Identity:      identity,
		AKA:           fakeAKA{},
		DeliveryStore: store,
	})
	if err != nil {
		log.Fatalf("voiceclient.Dial: %v", err)
	}
	fmt.Println("voiceclient.Dial succeeded (REGISTER completed)")

	sendCtx, sendCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer sendCancel()
	outcome, err := client.SendSMS(sendCtx, "+8615389819315", "hello from voiceclienttest", []messaging.SMSPart{
		{RPMR: 0x2a, Body: []byte{0x00, 0x2a, 0x00, 0x91, 0x99, 0x04, 0xAB, 0xCD}}, // placeholder RP-DATA(SUBMIT)
	})
	if err != nil {
		log.Fatalf("client.SendSMS: %v", err)
	}
	fmt.Printf("SendSMS outcome: %+v\n", outcome)

	select {
	case <-store.reported:
		fmt.Println("fakeStore: delivery report recorded")
	case <-time.After(5 * time.Second):
		log.Fatal("FAIL: delivery report never reached DeliveryStore")
	}

	closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer closeCancel()
	if err := client.Close(closeCtx); err != nil {
		fmt.Println("client.Close:", err)
	}
	cancel()
	<-networkDone

	fmt.Println()
	fmt.Println("=== fakeStore recorded calls ===")
	for _, s := range store.created {
		fmt.Println("CreateSMSDelivery:", s)
	}
	for _, s := range store.parts {
		fmt.Println("UpsertSMSDeliveryPart:", s)
	}
	for _, s := range store.reports {
		fmt.Println("MarkSMSDeliveryPartReport:", s)
	}

	if registerAccepted != 1 {
		log.Fatalf("FAIL: network accepted %d REGISTER(s), want 1", registerAccepted)
	}
	if outcome.PartsTotal != 1 || outcome.DeliveryState != "pending" {
		log.Fatalf("FAIL: unexpected outcome %+v", outcome)
	}
	if len(store.created) != 1 || len(store.parts) != 1 || len(store.reports) != 1 {
		log.Fatalf("FAIL: expected 1 create/1 part/1 report, got %d/%d/%d",
			len(store.created), len(store.parts), len(store.reports))
	}
	if !strings.Contains(store.reports[0], "state=acked") {
		log.Fatalf("FAIL: expected an acked report, got %q", store.reports[0])
	}
	fmt.Println()
	fmt.Println("PASS: voiceclient.Dial (REGISTER) -> SendSMS (202) -> async delivery report -> DeliveryStore, all through real production code")
}
