package main

// This mirrors the swanctl.conf "connections" schema (identical keys to the
// vici load-conn message body) as documented in /etc/swanctl/swanctl.conf on
// a Debian strongswan-swanctl install. Struct tags are the vici field names.

// LocalAuth is the local ("local-1") authentication round: the UE side,
// which for SWu always authenticates via EAP-AKA using the NAI (USIM) or
// IMPI (ISIM) as the client EAP identity.
type LocalAuth struct {
	Auth  string `vici:"auth"`   // "eap-aka" — force the AKA method, don't let it be negotiated
	EAPID string `vici:"eap_id"` // identity.PreparedSession.IMSIdentity: root NAI or IMPI
}

// RemoteAuth is the remote ("remote-1") authentication round: the ePDG,
// which authenticates with a server certificate chained to the operator's
// (or a public) CA — never EAP, never PSK.
type RemoteAuth struct {
	Auth    string   `vici:"auth"`    // "pubkey"
	ID      string   `vici:"id"`      // expected ePDG identity, %any if unconstrained
	CACerts []string `vici:"cacerts"` // trusted root(s) for the ePDG's cert chain
}

// ChildSA is one CHILD_SA ("children.<name>") under the connection: the
// actual ESP tunnel carrying IMS traffic.
type ChildSA struct {
	ESPProposals []string `vici:"esp_proposals"`
	LocalTS      []string `vici:"local_ts"`  // "dynamic" = the negotiated virtual IP
	RemoteTS     []string `vici:"remote_ts"` // 0.0.0.0/0,::/0 — full tunnel
	Mode         string   `vici:"mode"`      // "tunnel"
	StartAction  string   `vici:"start_action"`
}

// Conn is one "connections.<name>" entry: the whole IKE_SA + CHILD_SA config
// for one device's SWu tunnel, as sent to charon via load-conn.
type Conn struct {
	Version     string             `vici:"version"` // "2" — IKEv2 only, SWu has no v1
	RemoteAddrs []string           `vici:"remote_addrs"`
	Proposals   []string           `vici:"proposals"`
	Vips        []string           `vici:"vips"` // "0.0.0.0" requests an IKEv2 CFG_REQUEST for an IPv4 vIP
	Encap       string             `vici:"encap"`
	Mobike      string             `vici:"mobike"`
	DPDDelay    string             `vici:"dpd_delay"`
	Local1      LocalAuth          `vici:"local-1"`
	Remote1     RemoteAuth         `vici:"remote-1"`
	Children    map[string]ChildSA `vici:"children"`
}

// BuildConn maps an engine/swu.Config (deviceID, ePDG address, IKE identity)
// onto the vici connection shape above. cacerts is the operator/public CA
// bundle used to validate the ePDG's certificate; the spike allows it empty
// to observe charon's own behavior when a config load happens without one.
func BuildConn(epdgAddr, identity string, cacerts []string, enableMOBIKE bool) *Conn {
	mobike := "no"
	if enableMOBIKE {
		mobike = "yes"
	}
	return &Conn{
		Version:     "2",
		RemoteAddrs: []string{epdgAddr},
		Proposals:   []string{"default"},
		Vips:        []string{"0.0.0.0"},
		Encap:       "yes", // force UDP/4500 encapsulation; most UEs are behind NAT anyway
		Mobike:      mobike,
		DPDDelay:    "30s",
		Local1: LocalAuth{
			Auth:  "eap-aka",
			EAPID: identity,
		},
		Remote1: RemoteAuth{
			Auth:    "pubkey",
			ID:      "%any",
			CACerts: cacerts,
		},
		Children: map[string]ChildSA{
			"ims": {
				ESPProposals: []string{"default"},
				LocalTS:      []string{"dynamic"},
				RemoteTS:     []string{"0.0.0.0/0", "::/0"},
				Mode:         "tunnel",
				StartAction:  "none", // we drive initiate/terminate explicitly, no auto-start
			},
		},
	}
}
