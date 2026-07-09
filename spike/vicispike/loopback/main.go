// Command loopback is a plumbing-only check: it validates that this process's
// vici event subscription/parsing code actually receives real ike-updown and
// child-updown events with up=yes and up=no, end to end, against the real
// charon instance used for the SWu spike. It deliberately uses PSK auth
// (not EAP-AKA) against 127.0.0.1 -- i.e. charon talking to itself -- purely
// to exercise the event mechanics cheaply, since eap-simaka-file isn't
// packaged in this Debian build (only libsimaka.so + eap-aka itself; the
// static-test-vector backend plugin isn't present) and standing up a second
// charon + certs + AKA test vectors is out of scope for confirming event
// plumbing.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/strongswan/govici/vici"
)

func main() {
	socket := flag.String("socket", "/run/charon.vici", "path to charon's vici socket")
	flag.Parse()

	s, err := vici.NewSession(vici.WithSocketPath(*socket))
	if err != nil {
		log.Fatalf("connect to vici socket: %v", err)
	}
	defer s.Close()

	events := []string{"ike-updown", "child-updown"}
	if err := s.Subscribe(events...); err != nil {
		log.Fatalf("subscribe: %v", err)
	}
	evCh := make(chan vici.Event, 32)
	s.NotifyEvents(evCh)
	defer s.StopEvents(evCh)

	go func() {
		for ev := range evCh {
			fmt.Printf("EVENT %s @ %s\n%s\n", ev.Name, ev.Timestamp.Format(time.RFC3339Nano), ev.Message)
		}
	}()

	secretMsg := vici.NewMessage()
	_ = secretMsg.Set("type", "ike")
	_ = secretMsg.Set("data", "spike-plumbing-psk-not-for-real-use")
	resp, err := s.Call(context.Background(), "load-shared", secretMsg)
	if err != nil {
		log.Fatalf("load-shared call: %v", err)
	}
	fmt.Println("load-shared response:", resp)
	if err := resp.Err(); err != nil {
		log.Fatalf("load-shared rejected: %v", err)
	}

	type child struct {
		ESPProposals []string `vici:"esp_proposals"`
		LocalTS      []string `vici:"local_ts"`
		RemoteTS     []string `vici:"remote_ts"`
		Mode         string   `vici:"mode"`
		StartAction  string   `vici:"start_action"`
	}
	type pool struct {
		Addrs string `vici:"addrs"`
	}
	poolMsg, err := vici.MarshalMessage(map[string]pool{"loopback-pool": {Addrs: "10.99.0.0/28"}})
	if err != nil {
		log.Fatalf("marshal pool: %v", err)
	}
	resp, err = s.Call(context.Background(), "load-pool", poolMsg)
	if err != nil {
		log.Fatalf("load-pool call: %v", err)
	}
	fmt.Println("load-pool response:", resp)
	if err := resp.Err(); err != nil {
		log.Fatalf("load-pool rejected: %v", err)
	}

	type localAuth struct {
		Auth string `vici:"auth"`
	}
	type conn struct {
		Version     string           `vici:"version"`
		LocalAddrs  []string         `vici:"local_addrs"`
		RemoteAddrs []string         `vici:"remote_addrs"`
		Proposals   []string         `vici:"proposals"`
		Vips        []string         `vici:"vips"`
		Pools       []string         `vici:"pools"`
		Local1      localAuth        `vici:"local-1"`
		Remote1     localAuth        `vici:"remote-1"`
		Children    map[string]child `vici:"children"`
	}

	c := conn{
		Version:     "2",
		LocalAddrs:  []string{"127.0.0.1"},
		RemoteAddrs: []string{"127.0.0.1"},
		Proposals:   []string{"default"},
		Vips:        []string{"0.0.0.0"},
		Pools:       []string{"loopback-pool"},
		Local1:      localAuth{Auth: "psk"},
		Remote1:     localAuth{Auth: "psk"},
		Children: map[string]child{
			"lo": {
				ESPProposals: []string{"default"},
				LocalTS:      []string{"0.0.0.0/0"},
				RemoteTS:     []string{"0.0.0.0/0"},
				Mode:         "tunnel",
				StartAction:  "none",
			},
		},
	}
	loadMsg, err := vici.MarshalMessage(map[string]conn{"loopback": c})
	if err != nil {
		log.Fatalf("marshal: %v", err)
	}
	resp, err = s.Call(context.Background(), "load-conn", loadMsg)
	if err != nil {
		log.Fatalf("load-conn call: %v", err)
	}
	fmt.Println("load-conn response:", resp)
	if err := resp.Err(); err != nil {
		log.Fatalf("load-conn rejected: %v", err)
	}

	initMsg := vici.NewMessage()
	_ = initMsg.Set("ike", "loopback")
	_ = initMsg.Set("child", "lo")
	_ = initMsg.Set("timeout", "5000")

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	for m, err := range s.CallStreaming(ctx, "initiate", "control-log", initMsg) {
		if err != nil {
			log.Printf("initiate ended: %v", err)
			break
		}
		_ = m // control-log is noisy; events already printed by the goroutine above
	}

	time.Sleep(1 * time.Second)

	fmt.Println("---- list-sas (looking for the vip field) ----")
	listCtx, listCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer listCancel()
	for m, err := range s.CallStreaming(listCtx, "list-sas", "list-sa", vici.NewMessage()) {
		if err != nil {
			log.Printf("list-sas ended: %v", err)
			break
		}
		fmt.Println(m)
	}

	termMsg := vici.NewMessage()
	_ = termMsg.Set("ike", "loopback")
	termCtx, termCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer termCancel()
	for m, err := range s.CallStreaming(termCtx, "terminate", "control-log", termMsg) {
		if err != nil {
			log.Printf("terminate ended: %v", err)
			break
		}
		_ = m
	}

	time.Sleep(1 * time.Second)

	unloadMsg := vici.NewMessage()
	_ = unloadMsg.Set("name", "loopback")
	if resp, err := s.Call(context.Background(), "unload-conn", unloadMsg); err == nil {
		fmt.Println("unload-conn response:", resp)
	}
}
