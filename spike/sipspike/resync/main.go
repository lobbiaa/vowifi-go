// Command resync validates the full RFC 3310 two-round resync flow that
// simauth_test.go only checks in isolation (header format, byte-correct
// response/auts values) -- here it actually plays out over a real SIP
// transaction sequence:
//
//  1. REGISTER (no Authorization)
//  2. 401 challenge #1, nonce encodes an out-of-sync RAND/AUTN
//  3. REGISTER with Authorization: empty-password response + auts=
//     (simauth.ComputeDigest's SyncFailure result, unmodified)
//  4. Server detects auts=, does NOT accept -- issues a FRESH 401
//     challenge #2 with a new, synced RAND/AUTN
//  5. REGISTER with Authorization: normal RES-derived response
//     (simauth.ComputeDigest again, this time SyncFailure=false)
//  6. 200 OK
//
// icholy/digest's ParseCredentials silently drops the auts= parameter (not
// in its fixed field set), so the server side extracts it itself with a
// small regexp -- a real S-CSCF's digest stack would do the equivalent.
package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"regexp"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/icholy/digest"

	"github.com/iniwex5/vowifi-go/engine/sim"
	"github.com/iniwex5/vowifi-go/runtimehost/simauth"
)

const (
	listenAddr = "127.0.0.1:15066"
	username   = "0001010000000001@nai.epc.mnc001.mcc001.3gppnetwork.org"
	realm      = "ims.mnc001.mcc001.3gppnetwork.org"
)

var (
	unsyncedRAND = bytesOf(0xCC, 16)
	unsyncedAUTN = bytesOf(0xDD, 16)
	fixedAUTS    = bytesOf(0xEE, 14)

	syncedRAND = bytesOf(0xAA, 16)
	syncedAUTN = bytesOf(0xBB, 16)
	fixedRES   = []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18}
)

func bytesOf(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func nonceFor(randBytes, autnBytes []byte) string {
	return base64.StdEncoding.EncodeToString(append(append([]byte{}, randBytes...), autnBytes...))
}

// fakeProvider models a SIM whose sequence number is out of sync with the
// network's first guess: it rejects the "unsynced" vector with
// sim.ErrSyncFailure (carrying AUTS), and accepts the "synced" one the
// network is expected to reissue after processing that AUTS.
type fakeProvider struct{}

func (fakeProvider) CalculateAKA(rand16, autn16 []byte) (sim.AKAResult, error) {
	switch {
	case string(rand16) == string(unsyncedRAND) && string(autn16) == string(unsyncedAUTN):
		return sim.AKAResult{AUTS: fixedAUTS}, sim.ErrSyncFailure
	case string(rand16) == string(syncedRAND) && string(autn16) == string(syncedAUTN):
		return sim.AKAResult{RES: fixedRES, CK: bytesOf(0x21, 16), IK: bytesOf(0x22, 16)}, nil
	default:
		return sim.AKAResult{}, fmt.Errorf("resync: unrecognized RAND/AUTN")
	}
}

var autsParam = regexp.MustCompile(`auts="([^"]*)"`)

func extractAuts(authHeaderValue string) (string, bool) {
	m := autsParam.FindStringSubmatch(authHeaderValue)
	if m == nil {
		return "", false
	}
	return m[1], true
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

	firstNonce := nonceFor(unsyncedRAND, unsyncedAUTN)
	secondNonce := nonceFor(syncedRAND, syncedAUTN)

	var (
		challenge1Count, resyncSeenCount, challenge2Count, acceptedCount int
		currentNonce                                                     = firstNonce
	)

	challenge := func(tx sip.ServerTransaction, req *sip.Request, nonce string) {
		chal := digest.Challenge{
			Realm:     realm,
			Nonce:     nonce,
			Opaque:    "sipspike-resync",
			Algorithm: "AKAv1-MD5",
		}
		res := sip.NewResponseFromRequest(req, 401, "Unauthorized", nil)
		res.AppendHeader(sip.NewHeader("WWW-Authenticate", chal.String()))
		_ = tx.Respond(res)
	}

	srv.OnRegister(func(req *sip.Request, tx sip.ServerTransaction) {
		h := req.GetHeader("Authorization")
		if h == nil {
			challenge1Count++
			fmt.Println("server: no Authorization, issuing challenge #1 (out-of-sync nonce)")
			challenge(tx, req, currentNonce)
			return
		}

		if auts, ok := extractAuts(h.Value()); ok {
			resyncSeenCount++
			fmt.Println("server: saw auts =", auts, "-- resyncing SQN and issuing a FRESH challenge")
			currentNonce = secondNonce
			challenge2Count++
			challenge(tx, req, currentNonce)
			return
		}

		cred, err := digest.ParseCredentials(h.Value())
		if err != nil {
			fmt.Println("server: bad credentials header:", err)
			_ = tx.Respond(sip.NewResponseFromRequest(req, 400, "Bad Request", nil))
			return
		}

		mathChal := digest.Challenge{Realm: realm, Nonce: currentNonce, Opaque: "sipspike-resync", Algorithm: "MD5"}
		want, err := digest.Digest(&mathChal, digest.Options{
			Method:   "REGISTER",
			URI:      cred.URI,
			Username: username,
			Password: hex.EncodeToString(fixedRES),
		})
		if err != nil {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 500, "Server Error", nil))
			return
		}
		if cred.Response != want.Response {
			fmt.Println("server: post-resync digest mismatch, rejecting")
			_ = tx.Respond(sip.NewResponseFromRequest(req, 401, "Unauthorized", nil))
			return
		}

		acceptedCount++
		fmt.Println("server: post-resync digest verified, accepting REGISTER")
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

	newRequest := func() *sip.Request {
		req := sip.NewRequest(sip.REGISTER, recipient)
		req.AppendHeader(sip.NewHeader("Contact", "<sip:vohive-resync-test@127.0.0.1:15067>"))
		req.SetTransport("UDP")
		return req
	}

	doTransaction := func(req *sip.Request, opts ...sipgo.ClientRequestOption) *sip.Response {
		reqCtx, reqCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer reqCancel()
		tx, err := client.TransactionRequest(reqCtx, req, opts...)
		if err != nil {
			log.Fatalf("client: transaction request: %v", err)
		}
		defer tx.Terminate()
		select {
		case <-tx.Done():
			log.Fatal("client: transaction died without a response")
		case res := <-tx.Responses():
			return res
		case <-reqCtx.Done():
			log.Fatal("client: timed out waiting for response")
		}
		return nil
	}

	// Round 1: bare REGISTER.
	req1 := newRequest()
	res := doTransaction(req1, sipgo.ClientRequestRegisterBuild)
	fmt.Printf("client: round 1 response %d %s\n", res.StatusCode, res.Reason)
	if res.StatusCode != 401 {
		log.Fatalf("FAIL: expected 401 for round 1, got %d", res.StatusCode)
	}

	// Round 2: respond to the out-of-sync challenge with simauth's
	// SyncFailure result (empty-password response + auts=), unmodified.
	chal1, err := digest.ParseChallenge(res.GetHeader("WWW-Authenticate").Value())
	if err != nil {
		log.Fatalf("client: parse challenge #1: %v", err)
	}
	result1, err := simauth.ComputeDigest(fakeProvider{}, chal1, digest.Options{
		Method: "REGISTER", URI: recipient.Host, Username: username,
	})
	if err != nil {
		log.Fatalf("client: simauth.ComputeDigest (round 2): %v", err)
	}
	if !result1.SyncFailure {
		log.Fatal("FAIL: expected SyncFailure=true for the out-of-sync vector")
	}
	fmt.Println("client: round 2 sending simauth's resync header:", result1.Header)

	req2 := req1.Clone()
	req2.RemoveHeader("Via")
	req2.AppendHeader(sip.NewHeader("Authorization", result1.Header))
	res = doTransaction(req2, sipgo.ClientRequestIncreaseCSEQ, sipgo.ClientRequestAddVia)
	fmt.Printf("client: round 2 response %d %s\n", res.StatusCode, res.Reason)
	if res.StatusCode != 401 {
		log.Fatalf("FAIL: expected a fresh 401 after resync, got %d", res.StatusCode)
	}

	// Round 3: the server issued a fresh, synced challenge -- normal path.
	chal2, err := digest.ParseChallenge(res.GetHeader("WWW-Authenticate").Value())
	if err != nil {
		log.Fatalf("client: parse challenge #2: %v", err)
	}
	if chal2.Nonce == chal1.Nonce {
		log.Fatal("FAIL: server's post-resync challenge reused the old nonce")
	}
	result2, err := simauth.ComputeDigest(fakeProvider{}, chal2, digest.Options{
		Method: "REGISTER", URI: recipient.Host, Username: username,
	})
	if err != nil {
		log.Fatalf("client: simauth.ComputeDigest (round 3): %v", err)
	}
	if result2.SyncFailure {
		log.Fatal("FAIL: expected a normal response for the fresh, synced challenge")
	}
	fmt.Println("client: round 3 sending simauth's normal header:", result2.Header)

	req3 := req2.Clone()
	req3.RemoveHeader("Via")
	req3.RemoveHeader("Authorization")
	req3.AppendHeader(sip.NewHeader("Authorization", result2.Header))
	res = doTransaction(req3, sipgo.ClientRequestIncreaseCSEQ, sipgo.ClientRequestAddVia)
	fmt.Printf("client: round 3 response %d %s\n", res.StatusCode, res.Reason)

	cancel()
	<-serverDone

	if res.StatusCode != 200 {
		log.Fatalf("FAIL: expected 200 after full resync flow, got %d", res.StatusCode)
	}
	if challenge1Count != 1 || resyncSeenCount != 1 || challenge2Count != 1 || acceptedCount != 1 {
		log.Fatalf("FAIL: counts challenge1=%d resyncSeen=%d challenge2=%d accepted=%d, want all 1",
			challenge1Count, resyncSeenCount, challenge2Count, acceptedCount)
	}
	fmt.Println("PASS: full RFC 3310 resync flow (401 -> auts -> fresh 401 -> 200) works end to end")
}
