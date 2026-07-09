// Command managertest exercises engine/swu.Manager end-to-end against a
// real charon: start the manager (charon + akabridge), Dial with a fake AKA
// provider, observe events, then Close. The EAP-AKA handshake itself can't
// complete for real here (no matching network-side provider, see
// spike/vicispike/MAPPING.md), but this validates every mechanical step
// around it: config load, event subscription/translation, initiate,
// teardown -- the actual new wiring this phase adds.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/iniwex5/vowifi-go/engine/sim"
	"github.com/iniwex5/vowifi-go/engine/swu"
	"github.com/iniwex5/vowifi-go/engine/swu/charon"
)

type fakeAKA struct{}

func (fakeAKA) CalculateAKA(rand16, autn16 []byte) (sim.AKAResult, error) {
	return sim.AKAResult{RES: []byte{1, 2, 3, 4}, CK: make([]byte, 16), IK: make([]byte, 16)}, nil
}

func main() {
	rundir := "/tmp/vohive-manager-test"
	os.RemoveAll(rundir)

	mgr, err := swu.NewManager(swu.ManagerOptions{
		Charon: charon.Options{
			RunDir:        rundir,
			DataplaneMode: charon.DataplaneModeUserspace,
		},
	})
	if err != nil {
		log.Fatalf("NewManager: %v", err)
	}

	ctx := context.Background()
	if err := mgr.Start(ctx); err != nil {
		log.Fatalf("Manager.Start: %v", err)
	}
	fmt.Println("manager started (charon + akabridge)")

	sess, err := mgr.Dial(ctx, swu.Config{
		DeviceID:        "dev-managertest",
		EPDGAddr:        "epdg.epc.mnc001.mcc001.pub.3gppnetwork.org",
		Identity:        "0001010000000001@nai.epc.mnc001.mcc001.3gppnetwork.org",
		AKA:             fakeAKA{},
		InitiateTimeout: 8 * time.Second,
	})
	if err != nil {
		log.Fatalf("Dial: %v", err)
	}
	fmt.Println("Dial succeeded, session created; InterfaceName =", sess.InterfaceName())

	timeout := time.After(45 * time.Second)
	eventCount := 0
loop:
	for {
		select {
		case ev, ok := <-sess.Events():
			if !ok {
				break loop
			}
			eventCount++
			fmt.Printf("event %d: state=%s localIP=%v err=%v\n", eventCount, ev.State, ev.LocalIP, ev.Err)
		case <-timeout:
			break loop
		}
	}
	fmt.Printf("observed %d event(s) in the wait window\n", eventCount)

	closeCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := sess.Close(closeCtx); err != nil {
		fmt.Println("Close returned:", err)
	} else {
		fmt.Println("Close: ok")
	}

	stopCtx, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	if err := mgr.Stop(stopCtx); err != nil {
		log.Fatalf("Manager.Stop: %v", err)
	}
	fmt.Println("manager stopped")
}
