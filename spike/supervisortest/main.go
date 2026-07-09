// Command supervisortest exercises engine/swu/charon.Supervisor against a
// real charon install: start, confirm a vici session works and the config
// (vici socket path, kernel-libipsec priority) took effect, load+unload a
// throwaway conn to prove the session is genuinely usable, then stop and
// confirm the process and socket are actually gone.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/iniwex5/vowifi-go/engine/swu/charon"
	"github.com/strongswan/govici/vici"
)

func main() {
	rundir := "/tmp/vohive-swu-test"
	os.RemoveAll(rundir)

	sup, err := charon.NewSupervisor(charon.Options{
		RunDir:        rundir,
		DataplaneMode: charon.DataplaneModeUserspace,
	})
	if err != nil {
		log.Fatalf("NewSupervisor: %v", err)
	}

	ctx := context.Background()
	start := time.Now()
	if err := sup.Start(ctx); err != nil {
		log.Fatalf("Start: %v", err)
	}
	fmt.Printf("charon up in %s, socket=%s\n", time.Since(start), sup.SocketPath())

	sess, err := sup.Session()
	if err != nil {
		log.Fatalf("Session: %v", err)
	}
	defer sess.Close()

	loadMsg := vici.NewMessage()
	_ = loadMsg.Set("version", "2")
	connMsg := vici.NewMessage()
	_ = connMsg.Set("supervisortest", loadMsg)
	resp, err := sess.Call(ctx, "load-conn", connMsg)
	if err != nil {
		log.Fatalf("load-conn: %v", err)
	}
	fmt.Println("load-conn response:", resp)
	if err := resp.Err(); err != nil {
		log.Fatalf("load-conn rejected: %v", err)
	}

	unloadMsg := vici.NewMessage()
	_ = unloadMsg.Set("name", "supervisortest")
	if resp, err := sess.Call(ctx, "unload-conn", unloadMsg); err != nil {
		log.Printf("unload-conn: %v", err)
	} else {
		fmt.Println("unload-conn response:", resp)
	}

	// Fetch Wait()'s channel *before* Stop, to prove an independent
	// crash-watcher and Stop() both observe the same exit — the bug this
	// test caught was Stop() draining a single-value channel out from under
	// a caller doing exactly this.
	doneCh, err := sup.Wait()
	if err != nil {
		log.Fatalf("Wait: %v", err)
	}

	stopStart := time.Now()
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sup.Stop(stopCtx); err != nil {
		log.Printf("Stop: %v (may just be the process's own exit status)", err)
	}
	fmt.Printf("charon stopped in %s\n", time.Since(stopStart))

	select {
	case <-doneCh:
		fmt.Println("independent Wait() channel observed the exit too: ok, ExitErr =", sup.ExitErr())
	default:
		fmt.Println("BUG: Wait() channel not closed after Stop")
	}

	if _, err := os.Stat(rundir + "/charon.vici"); err == nil {
		fmt.Println("WARNING: vici socket file still present after Stop")
	} else {
		fmt.Println("vici socket cleaned up after Stop: ok")
	}

	// Read only after the process has fully exited: charon's own log
	// buffering isn't guaranteed flushed to disk while it's still running.
	logText, _ := os.ReadFile(rundir + "/charon.log")
	loadedLine := ""
	for _, line := range strings.Split(string(logText), "\n") {
		if strings.Contains(line, "loaded plugins:") {
			loadedLine = line
			break
		}
	}
	fmt.Printf("kernel-libipsec in loaded-plugins summary=%v\n", strings.Contains(loadedLine, "kernel-libipsec"))
}

