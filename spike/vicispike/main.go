// Command vicispike is a throwaway control-surface spike: it loads a SWu-shaped
// IKEv2/EAP-AKA/libipsec connection into a running charon via vici, subscribes
// to lifecycle events, initiates it, and dumps SA state. It is not meant to
// complete a real handshake (there's no live ePDG or AKA backend here) — the
// point is to confirm charon accepts the config shape and that the vici event
// stream gives us everything needed to drive engine/swu's Session state
// machine later.
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
	epdg := flag.String("epdg", "epdg.epc.mnc001.mcc001.pub.3gppnetwork.org", "ePDG FQDN (3GPP TS 23.003 default for a PLMN)")
	identity := flag.String("identity", "0001010000000001@nai.epc.mnc001.mcc001.3gppnetwork.org", "IKE_ID / EAP identity (root NAI or IMPI)")
	connName := flag.String("conn", "swu-spike", "connection name to load")
	childName := flag.String("child", "ims", "CHILD_SA name within the connection")
	waitSecs := flag.Int("wait", 8, "seconds to wait for events/initiate before giving up")
	flag.Parse()

	s, err := vici.NewSession(vici.WithSocketPath(*socket))
	if err != nil {
		log.Fatalf("connect to vici socket %s: %v", *socket, err)
	}
	defer s.Close()
	log.Printf("connected to %s", *socket)

	events := []string{"ike-updown", "child-updown", "ike-rekey", "child-rekey"}
	if err := s.Subscribe(events...); err != nil {
		log.Fatalf("subscribe %v: %v", events, err)
	}
	evCh := make(chan vici.Event, 32)
	s.NotifyEvents(evCh)
	defer s.StopEvents(evCh)

	stopPrinting := make(chan struct{})
	go func() {
		for {
			select {
			case ev, ok := <-evCh:
				if !ok {
					return
				}
				printEvent(ev)
			case <-stopPrinting:
				return
			}
		}
	}()

	conn := BuildConn(*epdg, *identity, nil /* no cacerts in the spike */, true)
	loadMsg, err := vici.MarshalMessage(map[string]*Conn{*connName: conn})
	if err != nil {
		log.Fatalf("marshal load-conn message: %v", err)
	}
	fmt.Println("---- load-conn request ----")
	fmt.Println(loadMsg)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*waitSecs)*time.Second)
	defer cancel()

	resp, err := s.Call(ctx, "load-conn", loadMsg)
	if err != nil {
		log.Fatalf("load-conn call: %v", err)
	}
	fmt.Println("---- load-conn response ----")
	fmt.Println(resp)
	if err := resp.Err(); err != nil {
		log.Fatalf("load-conn rejected by charon: %v", err)
	}
	log.Printf("charon accepted the connection config for %q", *connName)

	initMsg := vici.NewMessage()
	_ = initMsg.Set("ike", *connName)
	_ = initMsg.Set("child", *childName)
	_ = initMsg.Set("timeout", fmt.Sprintf("%d", (*waitSecs-2)*1000))
	_ = initMsg.Set("loglevel", "2")

	fmt.Println("---- initiate (streaming control-log) ----")
	initCtx, initCancel := context.WithTimeout(context.Background(), time.Duration(*waitSecs)*time.Second)
	defer initCancel()

	for m, err := range s.CallStreaming(initCtx, "initiate", "control-log", initMsg) {
		if err != nil {
			log.Printf("initiate stream ended: %v", err)
			break
		}
		fmt.Println(m)
	}

	fmt.Println("---- list-sas (post-initiate SA state) ----")
	listCtx, listCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer listCancel()
	sawAny := false
	for m, err := range s.CallStreaming(listCtx, "list-sas", "list-sa", vici.NewMessage()) {
		if err != nil {
			log.Printf("list-sas stream ended: %v", err)
			break
		}
		sawAny = true
		fmt.Println(m)
	}
	if !sawAny {
		fmt.Println("(no SAs currently tracked — expected if IKE_AUTH never got past EAP-AKA/cert validation)")
	}

	unloadMsg := vici.NewMessage()
	_ = unloadMsg.Set("name", *connName)
	if resp, err := s.Call(context.Background(), "unload-conn", unloadMsg); err != nil {
		log.Printf("unload-conn call: %v", err)
	} else if err := resp.Err(); err != nil {
		log.Printf("unload-conn rejected: %v", err)
	} else {
		log.Printf("unloaded %q", *connName)
	}

	close(stopPrinting)
}

func printEvent(ev vici.Event) {
	fmt.Printf("---- event %q @ %s ----\n%s\n", ev.Name, ev.Timestamp.Format(time.RFC3339), ev.Message)
}
