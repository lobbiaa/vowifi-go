// Command challenge extends sipspike with the next minimal increment: a
// 401 challenge/retry cycle using sipgo's built-in DoDigestAuth helper and
// plain username/password digest (RFC 2617). This validates the
// challenge-retry mechanics (CSeq bump, Via regeneration, Authorization
// header) that will structurally stay the same for IMS-AKA digest
// (RFC 3310) later -- only how the response is computed differs there (RES
// from AKA instead of a static password). Proving the generic mechanics
// first, before adding AKA-specific nonce decoding, is the same
// one-step-at-a-time approach as the vici spike.
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/icholy/digest"
)

const (
	listenAddr = "127.0.0.1:15062"
	username   = "testuser"
	password   = "s3cret"
	realm      = "sipspike-realm"
)

func main() {
	serverUA, err := sipgo.NewUA(sipgo.WithUserAgent("sipspike-server"))
	if err != nil {
		log.Fatalf("server UA: %v", err)
	}
	srv, err := sipgo.NewServer(serverUA)
	if err != nil {
		log.Fatalf("server: %v", err)
	}

	challengeCount := 0
	acceptedCount := 0
	var chal digest.Challenge

	srv.OnRegister(func(req *sip.Request, tx sip.ServerTransaction) {
		h := req.GetHeader("Authorization")
		if h == nil {
			challengeCount++
			chal = digest.Challenge{
				Realm:     realm,
				Nonce:     fmt.Sprintf("%d", time.Now().UnixNano()),
				Opaque:    "sipspike",
				Algorithm: "MD5",
			}
			res := sip.NewResponseFromRequest(req, 401, "Unauthorized", nil)
			res.AppendHeader(sip.NewHeader("WWW-Authenticate", chal.String()))
			fmt.Println("server: no Authorization header, challenging with 401")
			_ = tx.Respond(res)
			return
		}

		cred, err := digest.ParseCredentials(h.Value())
		if err != nil {
			fmt.Println("server: bad credentials header:", err)
			_ = tx.Respond(sip.NewResponseFromRequest(req, 400, "Bad Request", nil))
			return
		}
		if cred.Username != username {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 404, "Not Found", nil))
			return
		}

		want, err := digest.Digest(&chal, digest.Options{
			Method:   "REGISTER",
			URI:      cred.URI,
			Username: username,
			Password: password,
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
		fmt.Println("server: digest verified, accepting REGISTER")
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
	if err := sip.ParseUri(fmt.Sprintf("sip:%s@%s", username, listenAddr), &recipient); err != nil {
		log.Fatalf("parse uri: %v", err)
	}
	req := sip.NewRequest(sip.REGISTER, recipient)
	req.AppendHeader(sip.NewHeader("Contact", fmt.Sprintf("<sip:%s@127.0.0.1:15063>", username)))
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
		authCtx, authCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer authCancel()
		res, err = client.DoDigestAuth(authCtx, req, res, sipgo.DigestAuth{
			Username: username,
			Password: password,
		})
		if err != nil {
			log.Fatalf("client: DoDigestAuth: %v", err)
		}
		fmt.Printf("client: post-challenge response %d %s\n", res.StatusCode, res.Reason)
	}
	tx.Terminate()

	cancel()
	<-serverDone

	if res.StatusCode != 200 {
		log.Fatalf("FAIL: expected 200 after digest retry, got %d", res.StatusCode)
	}
	if challengeCount != 1 || acceptedCount != 1 {
		log.Fatalf("FAIL: challengeCount=%d acceptedCount=%d, want 1/1", challengeCount, acceptedCount)
	}
	fmt.Println("PASS: sipgo REGISTER -> 401 challenge -> DoDigestAuth retry -> 200 OK")
}
