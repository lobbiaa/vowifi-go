// Command sipspike is the minimal validation this phase asked for: sipgo
// UAC sends REGISTER, gets 200 OK back. No auth challenge yet (that's the
// next phase, once this basic round trip is proven) -- server accepts any
// REGISTER unconditionally. Runs a bare sipgo UAS and UAC against each
// other on loopback UDP, in one process, similar in spirit to the earlier
// vici loopback spike (prove the mechanism before adding real complexity).
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
)

func main() {
	const listenAddr = "127.0.0.1:15060"

	serverUA, err := sipgo.NewUA(sipgo.WithUserAgent("sipspike-server"))
	if err != nil {
		log.Fatalf("server UA: %v", err)
	}
	srv, err := sipgo.NewServer(serverUA)
	if err != nil {
		log.Fatalf("server: %v", err)
	}

	registerCount := 0
	srv.OnRegister(func(req *sip.Request, tx sip.ServerTransaction) {
		registerCount++
		fmt.Printf("server: got REGISTER from %s (Contact: %s)\n",
			req.From().Address.String(), req.Contact().Address.String())
		res := sip.NewResponseFromRequest(req, 200, "OK", nil)
		if err := tx.Respond(res); err != nil {
			fmt.Println("server: respond error:", err)
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverDone := make(chan error, 1)
	go func() {
		serverDone <- srv.ListenAndServe(ctx, "udp", listenAddr)
	}()

	// Give the listener a moment to bind before the client dials.
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
	if err := sip.ParseUri(fmt.Sprintf("sip:testuser@%s", listenAddr), &recipient); err != nil {
		log.Fatalf("parse uri: %v", err)
	}
	req := sip.NewRequest(sip.REGISTER, recipient)
	req.AppendHeader(sip.NewHeader("Contact", "<sip:testuser@127.0.0.1:15061>"))
	req.SetTransport("UDP")

	fmt.Println("client:", req.StartLine())

	reqCtx, reqCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer reqCancel()

	tx, err := client.TransactionRequest(reqCtx, req, sipgo.ClientRequestRegisterBuild)
	if err != nil {
		log.Fatalf("client: transaction request: %v", err)
	}
	defer tx.Terminate()

	var res *sip.Response
	select {
	case <-tx.Done():
		log.Fatal("client: transaction died without a response")
	case res = <-tx.Responses():
	case <-reqCtx.Done():
		log.Fatal("client: timed out waiting for response")
	}

	fmt.Printf("client: received status %d %s\n", res.StatusCode, res.Reason)

	cancel()
	<-serverDone

	if res.StatusCode != 200 {
		log.Fatalf("FAIL: expected 200, got %d", res.StatusCode)
	}
	if registerCount != 1 {
		log.Fatalf("FAIL: server saw %d REGISTER(s), want 1", registerCount)
	}
	fmt.Println("PASS: sipgo REGISTER -> 200 OK round trip works")
}
