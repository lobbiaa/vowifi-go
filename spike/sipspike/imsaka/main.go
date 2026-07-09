// Command imsaka is the full-stack version of the AKAv1-MD5 validation:
// same real sipgo UDP transaction as before, but the client side now calls
// the actual production runtimehost/simauth.ComputeDigest instead of
// bespoke inline digest math -- this is what confirms the package works
// end to end through a real SIP exchange, not just in isolation (simauth
// already has its own unit tests covering the crypto/protocol edge cases;
// this spike is the "does it actually work wired into a real transaction"
// check, the same shape as spike/managertest validating engine/swu.Manager
// after its own unit-level pieces were already proven).
//
// The server side intentionally does NOT use simauth (a real IMS network
// element wouldn't either) -- it independently verifies the client's
// response using bare digest.Digest, so a passing test means simauth
// produces output a real S-CSCF-shaped verifier would actually accept.
package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/icholy/digest"

	"github.com/iniwex5/vowifi-go/engine/sim"
	"github.com/iniwex5/vowifi-go/runtimehost/simauth"
)

const (
	listenAddr = "127.0.0.1:15064"
	username   = "0001010000000001@nai.epc.mnc001.mcc001.3gppnetwork.org"
	realm      = "ims.mnc001.mcc001.3gppnetwork.org"
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

// fakeProvider stands in for vohive's real APDU/QMI-backed sim.AKAProvider
// (the same one runtimehost.Start already extracts for the SWu tunnel's
// EAP-AKA -- this is a second, independent AKA run against it, same as a
// real UE does for IMS on top of the ePDG).
type fakeProvider struct{}

func (fakeProvider) CalculateAKA(rand16, autn16 []byte) (sim.AKAResult, error) {
	if string(rand16) != string(fixedRAND) || string(autn16) != string(fixedAUTN) {
		return sim.AKAResult{}, fmt.Errorf("imsaka: unrecognized RAND/AUTN")
	}
	return sim.AKAResult{RES: fixedRES, CK: bytesOf(0x21, 16), IK: bytesOf(0x22, 16)}, nil
}

func main() {
	serverUA, err := sipgo.NewUA(sipgo.WithUserAgent("sipspike-server"))
	if err != nil {
		log.Fatalf("server UA: %v", err)
	}
	srv, err := sipgo.NewServer(serverUA)
	if err != nil {
		log.Fatalf("server: %v", err)
	}

	nonce := base64.StdEncoding.EncodeToString(append(append([]byte{}, fixedRAND...), fixedAUTN...))
	challengeCount, acceptedCount := 0, 0
	var chal digest.Challenge

	srv.OnRegister(func(req *sip.Request, tx sip.ServerTransaction) {
		h := req.GetHeader("Authorization")
		if h == nil {
			challengeCount++
			chal = digest.Challenge{
				Realm:     realm,
				Nonce:     nonce,
				Opaque:    "sipspike-imsaka",
				Algorithm: "AKAv1-MD5",
			}
			res := sip.NewResponseFromRequest(req, 401, "Unauthorized", nil)
			res.AppendHeader(sip.NewHeader("WWW-Authenticate", chal.String()))
			fmt.Println("server: challenging with AKAv1-MD5, nonce =", nonce)
			_ = tx.Respond(res)
			return
		}

		cred, err := digest.ParseCredentials(h.Value())
		if err != nil {
			fmt.Println("server: bad credentials header:", err)
			_ = tx.Respond(sip.NewResponseFromRequest(req, 400, "Bad Request", nil))
			return
		}

		// The network side independently knows RES for this RAND/AUTN
		// (it generated the challenge from the subscriber's own AKA
		// vector). This verification path deliberately does NOT call
		// simauth -- see the package doc comment above.
		mathChal := chal
		mathChal.Algorithm = "MD5"
		want, err := digest.Digest(&mathChal, digest.Options{
			Method:   "REGISTER",
			URI:      cred.URI,
			Username: username,
			Password: hex.EncodeToString(fixedRES),
		})
		if err != nil {
			fmt.Println("server: digest compute error:", err)
			_ = tx.Respond(sip.NewResponseFromRequest(req, 500, "Server Error", nil))
			return
		}
		if cred.Response != want.Response {
			fmt.Println("server: digest response mismatch, rejecting")
			_ = tx.Respond(sip.NewResponseFromRequest(req, 401, "Unauthorized", nil))
			return
		}

		acceptedCount++
		fmt.Println("server: AKA digest verified, accepting REGISTER")
		_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverDone := make(chan error, 1)
	go func() {
		serverDone <- srv.ListenAndServe(ctx, "udp", listenAddr)
	}()
	time.Sleep(200 * time.Millisecond)

	clientUA, err := sipgo.NewUA(sipgo.WithUserAgent("sipspike-client"))
	if err != nil {
		log.Fatalf("client UA: %v", err)
	}
	client, err := sipgo.NewClient(clientUA, sipgo.WithClientHostname("127.0.0.1"))
	if err != nil {
		log.Fatalf("client: %v", err)
	}
	defer client.Close()

	recipient := sip.Uri{}
	if err := sip.ParseUri(fmt.Sprintf("sip:%s", listenAddr), &recipient); err != nil {
		log.Fatalf("parse uri: %v", err)
	}
	req := sip.NewRequest(sip.REGISTER, recipient)
	req.AppendHeader(sip.NewHeader("Contact", "<sip:vohive-imsaka-test@127.0.0.1:15065>"))
	req.SetTransport("UDP")

	reqCtx, reqCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer reqCancel()

	tx, err := client.TransactionRequest(reqCtx, req, sipgo.ClientRequestRegisterBuild)
	if err != nil {
		log.Fatalf("client: initial transaction: %v", err)
	}

	var res *sip.Response
	select {
	case <-tx.Done():
		tx.Terminate()
		log.Fatal("client: transaction died without a response")
	case res = <-tx.Responses():
	case <-reqCtx.Done():
		tx.Terminate()
		log.Fatal("client: timed out waiting for initial response")
	}
	fmt.Printf("client: initial response %d %s\n", res.StatusCode, res.Reason)

	if res.StatusCode == 401 {
		wwwAuth := res.GetHeader("WWW-Authenticate")
		if wwwAuth == nil {
			log.Fatal("client: 401 with no WWW-Authenticate header")
		}
		parsedChal, err := digest.ParseChallenge(wwwAuth.Value())
		if err != nil {
			log.Fatalf("client: parse challenge: %v", err)
		}
		fmt.Println("client: challenge algorithm =", parsedChal.Algorithm)

		result, err := simauth.ComputeDigest(fakeProvider{}, parsedChal, digest.Options{
			Method:   "REGISTER",
			URI:      recipient.Host,
			Username: username,
		})
		if err != nil {
			log.Fatalf("client: simauth.ComputeDigest: %v", err)
		}
		if result.SyncFailure {
			log.Fatal("client: unexpected sync failure for the recognized test vector")
		}
		fmt.Println("client: simauth produced Authorization header:", result.Header)

		newReq := req.Clone()
		newReq.RemoveHeader("Via")
		newReq.AppendHeader(sip.NewHeader("Authorization", result.Header))

		authCtx, authCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer authCancel()
		tx2, err := client.TransactionRequest(authCtx, newReq, sipgo.ClientRequestIncreaseCSEQ, sipgo.ClientRequestAddVia)
		if err != nil {
			log.Fatalf("client: retry transaction: %v", err)
		}
		defer tx2.Terminate()

		select {
		case <-tx2.Done():
			log.Fatal("client: retry transaction died without a response")
		case res = <-tx2.Responses():
		case <-authCtx.Done():
			log.Fatal("client: timed out waiting for retry response")
		}
		fmt.Printf("client: post-challenge response %d %s\n", res.StatusCode, res.Reason)
	}
	tx.Terminate()

	cancel()
	<-serverDone

	if res.StatusCode != 200 {
		log.Fatalf("FAIL: expected 200 after AKA digest retry, got %d", res.StatusCode)
	}
	if challengeCount != 1 || acceptedCount != 1 {
		log.Fatalf("FAIL: challengeCount=%d acceptedCount=%d, want 1/1", challengeCount, acceptedCount)
	}
	fmt.Println("PASS: sipgo REGISTER -> AKAv1-MD5 challenge -> simauth.ComputeDigest -> 200 OK")
}
