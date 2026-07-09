// Command akabridgetest runs a real akabridge.Bridge with fixed test
// vectors, for the C plugin test harness (../../engine/swu/akabridge/plugin/test/card_test.c)
// to call get_quintuplet/resync against. Bypasses charon and real IKE
// entirely on purpose: this validates the new artifact (the C plugin <->
// Go bridge wire protocol), not the already-separately-validated vici
// control surface or tunnel plumbing.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/1239t/vowifi-go/engine/sim"
	"github.com/1239t/vowifi-go/engine/swu/akabridge"
)

const (
	registeredIdentity = "test@vohive"
	// Fixed test vectors -- arbitrary, just need to be checked byte-for-byte
	// on the C side.
)

var (
	fixedRES  = []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18}
	fixedCK   = bytesOf(0x21, 16)
	fixedIK   = bytesOf(0x22, 16)
	fixedAUTS = bytesOf(0x33, 14)
)

func bytesOf(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// fakeProvider simulates a sync failure whenever RAND's first byte is 0xFF,
// otherwise returns the fixed success vectors -- lets one provider exercise
// both response shapes the wire protocol needs to carry.
type fakeProvider struct{}

func (fakeProvider) CalculateAKA(rand16, autn16 []byte) (sim.AKAResult, error) {
	if len(rand16) > 0 && rand16[0] == 0xFF {
		return sim.AKAResult{AUTS: fixedAUTS}, sim.ErrSyncFailure
	}
	return sim.AKAResult{RES: fixedRES, CK: fixedCK, IK: fixedIK}, nil
}

func main() {
	socketPath := "/tmp/akabridge-test.sock"
	if len(os.Args) > 1 {
		socketPath = os.Args[1]
	}

	b := akabridge.New()
	b.Register(registeredIdentity, fakeProvider{})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	fmt.Printf("akabridgetest: serving %s on %s\n", registeredIdentity, socketPath)
	if err := b.ListenAndServe(ctx, socketPath); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "ListenAndServe:", err)
		os.Exit(1)
	}
}
