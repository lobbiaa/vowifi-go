// Command cacertsloadtest confirms a real charon process actually accepts
// the split system CA bundle (129 individual certificates on this host) via
// a real load-conn call through engine/swu.Manager.Dial -- not just that
// loadCACerts's own output looks like well-formed PEM (already covered by
// engine/swu's unit tests). It doesn't attempt a real IKE_AUTH: EPDGAddr
// points at an address nothing listens on, so initiate fails fast, but
// load-conn (where charon actually parses every cacerts entry into a
// certificate_t) happens first and is what this checks.
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	swusim "github.com/iniwex5/vowifi-go/engine/sim"
	"github.com/iniwex5/vowifi-go/engine/swu"
	"github.com/iniwex5/vowifi-go/engine/swu/charon"
)

type fakeAKA struct{}

func (fakeAKA) CalculateAKA(rand16, autn16 []byte) (swusim.AKAResult, error) {
	return swusim.AKAResult{}, fmt.Errorf("not used by this test")
}

func main() {
	m, err := swu.NewManager(swu.ManagerOptions{
		Charon: charon.Options{
			RunDir:                "/tmp/vohive-cacertsloadtest-run",
			ConfFragmentPath:      "/etc/strongswan.d/92-vohive-cacertsloadtest.conf",
			AKABridgeSocketPath:   "/run/charon.vohive-aka-cacertsloadtest",
			PCSCFBridgeSocketPath: "/run/charon.vohive-pcscf-cacertsloadtest",
		},
	})
	if err != nil {
		log.Fatalf("new manager: %v", err)
	}

	startCtx, startCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer startCancel()
	if err := m.Start(startCtx); err != nil {
		log.Fatalf("start manager: %v", err)
	}
	fmt.Println("charon started")
	defer func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer stopCancel()
		if err := m.Stop(stopCtx); err != nil {
			log.Printf("stop manager: %v", err)
		}
	}()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()
	sess, err := m.Dial(dialCtx, swu.Config{
		DeviceID:        "cacertsloadtest",
		EPDGAddr:        "127.0.0.1:1", // nothing listens here; initiate should fail fast
		Identity:        "test@vohive",
		AKA:             fakeAKA{},
		CACerts:         []string{"/etc/ssl/certs/ca-certificates.crt"},
		InitiateTimeout: 2 * time.Second,
	})
	if err != nil {
		log.Fatalf("FAIL: Dial (load-conn with real 129-cert system bundle) rejected: %v", err)
	}
	fmt.Println("PASS: load-conn accepted the split system CA bundle (129 certs) without error")

	// Drain a couple of events so initiate's background goroutine doesn't
	// log after Close (best-effort, not asserted).
	select {
	case ev := <-sess.Events():
		fmt.Printf("event (expected, no real ePDG at 127.0.0.1:1): %+v\n", ev)
	case <-time.After(3 * time.Second):
	}

	closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer closeCancel()
	_ = sess.Close(closeCtx)
}
