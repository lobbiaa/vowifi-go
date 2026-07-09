# SWu ↔ vici control-surface spike: findings

Spike code: `main.go` (SWu-shaped config against a real ePDG FQDN, real network,
no real AKA backend) and `loopback/main.go` (charon-to-itself over PSK, purely
to exercise the event stream for a full up→down lifecycle since no
EAP-AKA test-vector plugin is packaged in this Debian build). Both ran against
strongSwan 5.9.1 (`strongswan-charon` + `strongswan-swanctl` +
`libcharon-extra-plugins`), vici client = `github.com/strongswan/govici` (pure
Go, no cgo — confirmed via `grep -r 'import "C"'` returning nothing, and a
clean `CGO_ENABLED=0 go build`).

**Verdict: control surface is clean and sufficient.** Nothing here required
dropping down to raw vici framing, hand-rolled parsing, or anything charon
couldn't express through swanctl-shaped config. Three real gaps surfaced (see
"Open items"), all closeable without revisiting the overall architecture.

## 1. charon/plugin config (daemon-level, not per-connection)

```
# /etc/strongswan.d/charon/kernel-libipsec.conf
kernel-libipsec {
    load = 2       # higher priority than kernel-netlink's IPsec feature
}
# kernel-netlink stays load = yes — still needed for routing/interface info,
# just loses the KERNEL_IPSEC feature race to kernel-libipsec.
```

Confirmed via log: `feature CUSTOM:kernel-ipsec in plugin 'kernel-netlink'
failed to load` (i.e. it backed off) and `plugin 'kernel-libipsec': loaded
successfully`. No kernel XFRM/`ip xfrm` involvement at any point.

`eap-aka` and `vici` plugins load by default in this build; no extra config
needed for either. **`eap-simaka-file` (static test vectors) is not packaged**
for Debian — only `libsimaka.so` (the framework) + `eap-aka` itself ship. This
is why the loopback plumbing test uses PSK instead of EAP-AKA: there's no
stock way to complete a real EAP-AKA exchange without either the future C
card-backend bridge or a from-source strongSwan build.

## 2. SWu Session → vici connection config

`load-conn` takes one message: `{"<conn-name>": {...}}`. Field names are
identical to swanctl.conf keys (verified against the annotated template at
`/etc/swanctl/swanctl.conf`).

| engine/swu.Config field | vici field | Notes |
|---|---|---|
| `DeviceID` | connection name (map key to `load-conn`) | Also passed as both `ike` and `child` args to `initiate`/`terminate` — always pass both explicitly, don't rely on child-name-only lookup, since multiple devices' children could collide by name. |
| `EPDGAddr` | `remote_addrs` | Confirmed: a bare 3GPP-default FQDN (`epdg.epc.mnc010.mcc234.pub.3gppnetwork.org`) resolves over public DNS and charon correctly sent a real IKE_SA_INIT to the resolved address. Resolution happens inside charon itself — engine/swu doesn't need its own resolver. |
| `Identity` (root NAI or IMPI) | `local-1.eap_id`, with `local-1.auth = "eap-aka"` (not generic `"eap"` — force the method, don't negotiate it) | |
| `AKA` (the `sim.AKAProvider`) | **not a vici field at all** | Bridged out-of-band through the future C plugin + Unix socket. The bridge needs a way to route a live RAND/AUTN request to the right `AKAProvider` — keying that lookup by `Identity` (the same string as `eap_id`) is the natural choice, since that's what charon's simaka framework has on hand when it calls the card backend. **Action for the supervisor phase:** register `Identity → AKA` in the bridge's table before `Dial`, deregister on `Close`. |
| `DataplaneMode` | **not per-connection** | It's the daemon-level `kernel-libipsec`/`kernel-netlink` priority shown above, set once when the supervisor starts charon. Recommend engine/swu.Config keep the field for documentation/consistency, but treat it as an assertion checked once at supervisor startup, not something `Dial` can change per-session. |
| `EnableMOBIKE` | `mobike` (`"yes"`/`"no"`) | Confirmed present in `tasks-active`/`tasks-passive` as `IKE_MOBIKE` once enabled. |
| — | `vips = ["0.0.0.0"]` | Always request one IPv4 vip. Fixed, not derived from Config — every SWu session needs exactly this. |
| — | `remote-1.auth = "pubkey"`, `remote-1.cacerts = [...]` | **Missing from the original Config design** — the ePDG authenticates with a server cert chained to a CA (operator's own, or a public one), never EAP/PSK. `engine/swu.Config` needs a `CACerts []string` (paths) field; the spike ran with none, which is fine for *loading* the config but would fail cert validation against any real ePDG. |
| — | `children.ims { esp_proposals: ["default"], local_ts: ["dynamic"], remote_ts: ["0.0.0.0/0","::/0"], mode: "tunnel", start_action: "none" }` | Fixed shape, not derived from Config. `start_action = none` is deliberate: engine/swu always drives `initiate`/`terminate` explicitly rather than letting charon auto-start or trap-and-acquire. |

## 3. Event stream → SWu.SessionState

Subscribed: `ike-updown`, `child-updown` (didn't get to exercise
`ike-rekey`/`child-rekey` this round — same event shape per strongSwan docs,
follow up when rekey timers are in scope). Confirmed via the loopback test's
full up→down cycle:

| Observed event | SWu.SessionState | Notes |
|---|---|---|
| `child-updown`, top-level `up = yes`, nested `child-sas.<name>.state = "INSTALLED"` | `SessionUp` | **This, not `ike-updown`, is the real "tunnel ready" signal.** `ike-updown up=yes` only means the IKE_SA (control channel) is up — the CHILD_SA (actual ESP tunnel) can still fail separately, and did in the loopback test (see below). |
| `ike-updown`, `up = yes`, no matching `child-updown` yet | `SessionConnecting` | IKE_SA established, CHILD_SA still pending — a real intermediate state, don't collapse it into `SessionUp`. |
| `child-updown`, no `up` key (absent, not `false`), `child-sas.<name>.state = "DELETED"` | `SessionDown` | |
| `ike-updown`, no `up` key, `state = "DELETING"` | `SessionDown` (or a distinct `SessionClosing` if the state machine wants to distinguish "tearing down" from "gone") | |
| the `initiate` `CallStreaming` call itself returning a Go error (e.g. `"CHILD_SA 'ims' not established after 6000ms"`, or `"establishing CHILD_SA 'lo' failed"`) | **not authoritative by itself** | The loopback test hit exactly this: `initiate` returned an error, but the event stream had *already* shown a real `up=yes`/`INSTALLED` moments earlier before the (self-connection-artifact) failure. **The event stream is the source of truth for Session state; the command call's return value is only an initial ack/nack**, not a substitute for watching events. Same lesson from `terminate` returning `"not all matching SAs could be terminated"` while the teardown events fired correctly anyway. |
| `list-sas` → `<conn>.local-vips` (on the entry where `initiator = yes`) | `Session.LocalIP()` | Confirmed field name empirically (not from docs): `local-vips = 10.99.0.1` on the initiator-side IKE_SA. (`remote-vips` is the *peer's* assigned vip on the responder-side entry — irrelevant to us, since engine/swu is always the initiator/UE side.) |

## Open items for the next phases (not blocking; none reopen the architecture)

1. **`InterfaceName()` needs rethinking.** kernel-libipsec creates exactly
   **one TUN device for the whole daemon** (`ipsec0` by default — created at
   plugin *load* time, confirmed in the charon log, not per-CHILD_SA). Every
   concurrent device's tunnel traffic shares that one interface; the kernel
   only tells them apart by selector (source address vs. each CHILD_SA's
   `local_ts`). So `SO_BINDTODEVICE(ipsec0)` — the pattern vohive's SOCKS5
   engine already uses per-modem NIC — **does not disambiguate between
   multiple concurrent SWu sessions.** The correct mechanism is binding each
   session's SIP/RTP sockets to its own `LocalIP()` (the assigned vip), not
   to a distinct device. `Session.InterfaceName()` may still be worth keeping
   (it's still `ipsec0`, useful for diagnostics/logging), but it must not be
   the thing callers use to select a tunnel.
2. Never got a real EAP-AKA exchange to complete (no test-vector plugin
   packaged here) — the C card-backend bridge phase is exactly what closes
   this, and is already the planned next-but-one step.
3. Didn't exercise `ike-rekey`/`child-rekey` or MOBIKE address updates this
   round; same event-shape pattern is documented, worth a quick confirming
   pass once the supervisor exists and there's a long-lived session to rekey.
