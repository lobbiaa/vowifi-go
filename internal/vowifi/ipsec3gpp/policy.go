package ipsec3gpp

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"

	"github.com/1239t/vowifi-go/internal/vowifi/xfrm"
)

// Flow describes one direction of a 3GPP ipsec-3gpp security association.
type Flow struct {
	OutboundSPI uint32
	InboundSPI  uint32
	LocalPort   int
	RemotePort  int
	AuthAlg     string
	EncAlg      string
	CK          []byte
	IK          []byte
}

// Policy captures the negotiated ipsec-3gpp parameters for SIP-over-TCP ESP.
type Policy struct {
	LocalIP     []byte
	RemoteIP    []byte
	LocalPortC  int
	LocalPortS  int
	RemotePortC int
	RemotePortS int
	FlowC       Flow
	FlowS       Flow
}

// ReplayStats tracks anti-replay decisions.
type ReplayStats struct {
	Accepted  uint64
	Duplicate uint64
	TooOld    uint64
}

// TransportStats aggregates userspace ESP transform counters.
type TransportStats struct {
	OutboundPackets    uint64
	InboundPackets     uint64
	PassthroughPackets uint64
	TransformErrors    uint64
	Replay             ReplayStats
}

// PolicyInput is the minimum set of inputs required to build a Policy.
type PolicyInput struct {
	LocalIP    net.IP
	RemoteIP   net.IP
	Mech       SecurityMechanism
	CK         []byte
	IK         []byte
	AuthAlg    string
	EncAlg     string
	LocalPortC int    // UE's local port-c (announced in Security-Client)
	LocalPortS int    // UE's local port-s (announced in Security-Client)
	LocalSPIC  uint32 // UE's local spi-c (announced in Security-Client) - used for inbound decryption
	LocalSPIS  uint32 // UE's local spi-s (announced in Security-Client) - used for inbound decryption
}

// NewPolicy builds a Policy from negotiated Security-Server parameters and AKA keys.
func NewPolicy(in PolicyInput) (Policy, error) {
	localIP, err := normalizeIP(in.LocalIP)
	if err != nil {
		return Policy{}, fmt.Errorf("ipsec3gpp: local IP %w", err)
	}
	remoteIP, err := normalizeIP(in.RemoteIP)
	if err != nil {
		return Policy{}, fmt.Errorf("ipsec3gpp: remote IP %w", err)
	}
	if len(in.CK) == 0 || len(in.IK) == 0 {
		return Policy{}, errors.New("ipsec3gpp: CK and IK are required")
	}

	authAlg := canonicalAuthAlg(coalesce(in.AuthAlg, in.Mech.Alg))
	encAlg := canonicalEncAlg(coalesce(in.EncAlg, in.Mech.EAlg))
	if authAlg == "" || encAlg == "" {
		return Policy{}, errors.New("ipsec3gpp: authentication and encryption algorithms are required")
	}
	if in.Mech.SPIc == 0 || in.Mech.SPIs == 0 {
		return Policy{}, errors.New("ipsec3gpp: spi-c and spi-s are required")
	}

	ports := fillPorts(in.Mech, in.LocalPortC, in.LocalPortS)
	ck := append([]byte(nil), in.CK...)
	ik := append([]byte(nil), in.IK...)

	// [CRITICAL FIX] Correct SPI mapping per RFC 3GPP 33.203:
	// - OutboundSPI: Use remote SPIs from Security-Server (what P-CSCF expects)
	// - InboundSPI: Use local SPIs that UE announced in Security-Client (what P-CSCF will use to encrypt back to UE)
	// Previously we incorrectly used Security-Server SPIs for both directions, causing decryption failures
	flowC := Flow{
		OutboundSPI: in.Mech.SPIc,  // Use P-CSCF's spi-c for outbound (UE→P-CSCF)
		InboundSPI:  in.LocalSPIC,  // Use UE's own spi-c for inbound (P-CSCF→UE)
		LocalPort:   ports.localC,
		RemotePort:  ports.remoteC,
		AuthAlg:     authAlg,
		EncAlg:      encAlg,
		CK:          ck,
		IK:          ik,
	}
	flowS := Flow{
		OutboundSPI: in.Mech.SPIs,  // Use P-CSCF's spi-s for outbound (UE→P-CSCF)
		InboundSPI:  in.LocalSPIS,  // Use UE's own spi-s for inbound (P-CSCF→UE)
		LocalPort:   ports.localS,
		RemotePort:  ports.remoteS,
		AuthAlg:     authAlg,
		EncAlg:      encAlg,
		CK:          ck,
		IK:          ik,
	}

	return Policy{
		LocalIP:     localIP,
		RemoteIP:    remoteIP,
		LocalPortC:  ports.localC,
		LocalPortS:  ports.localS,
		RemotePortC: ports.remoteC,
		RemotePortS: ports.remoteS,
		FlowC:       flowC,
		FlowS:       flowS,
	}, nil
}

type portPair struct {
	localC, localS, remoteC, remoteS int
}

func fillPorts(mech SecurityMechanism, localPortC, localPortS int) portPair {
	// mech.PortC/PortS come from Security-Server (P-CSCF's announced ports).
	// These are the REMOTE ports the UE will connect to.
	remoteC, remoteS := mech.PortC, mech.PortS
	if remoteC == 0 {
		remoteC = 5060
	}
	if remoteS == 0 {
		remoteS = remoteC
	}

	// Local ports: passed from register_session which allocates random high ports.
	// Use defaults only if not provided (backward compatibility).
	localC := localPortC
	localS := localPortS
	if localC <= 0 {
		localC = 5064
	}
	if localS <= 0 {
		localS = 5063
	}

	return portPair{
		localC:  localC,
		localS:  localS,
		remoteC: remoteC,
		remoteS: remoteS,
	}
}

func normalizeIP(ip net.IP) ([]byte, error) {
	if ip == nil {
		return nil, errors.New("must not be nil")
	}
	if v4 := ip.To4(); v4 != nil {
		return append([]byte(nil), v4...), nil
	}
	if v6 := ip.To16(); v6 != nil && ip.To4() == nil {
		return append([]byte(nil), v6...), nil
	}
	return nil, fmt.Errorf("invalid address %q", ip.String())
}

func normalizeIPPair(a, b []byte) (local, remote []byte, err error) {
	if len(a) == 0 || len(b) == 0 {
		return nil, nil, errors.New("ipsec3gpp: local/remote IP must not be nil")
	}
	if (len(a) == 4) != (len(b) == 4) {
		return nil, nil, errors.New("ipsec3gpp: local/remote IP family mismatch")
	}
	return append([]byte(nil), a...), append([]byte(nil), b...), nil
}

func coalesce(values ...string) string {
	for _, v := range values {
		if s := trimToken(v); s != "" {
			return s
		}
	}
	return ""
}

func ipEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// InstallXFRMDualFlow installs 4 XFRM SAs and 4 policies for IMS ESP dual-flow architecture
// Flow 1: UE port-c → P-CSCF port-s (client flow)
// Flow 2: UE port-s → P-CSCF port-c (server flow)
// Reference: vowifi-sms ipsec.go AddDualConnectionSA()
func InstallXFRMDualFlow(policy Policy) (*xfrm.IMSESPManager, error) {
	mgr := xfrm.NewIMSESPManager()

	localIP := net.IP(policy.LocalIP)
	remoteIP := net.IP(policy.RemoteIP)

	// Clean up any existing SAs with the same SPIs to avoid "File exists" errors
	// This handles retry scenarios where partial installation occurred
	mgr.CleanupSPI(policy.FlowS.OutboundSPI, localIP, remoteIP)
	mgr.CleanupSPI(policy.FlowC.InboundSPI, remoteIP, localIP)
	mgr.CleanupSPI(policy.FlowC.OutboundSPI, localIP, remoteIP)
	mgr.CleanupSPI(policy.FlowS.InboundSPI, remoteIP, localIP)

	// Prepare authentication key (IK) - pad to 20 bytes for HMAC-SHA1-96
	ikKey := padKey(policy.FlowS.IK, 20)

	// Prepare encryption key (CK) - use as-is for AES-128-CBC (16 bytes)
	ckKey := append([]byte(nil), policy.FlowS.CK...)

	// Map algorithm names to XFRM format
	authAlg := mapAuthAlg(policy.FlowS.AuthAlg)
	encAlg := mapEncAlg(policy.FlowS.EncAlg)

	// Flow 1: UE port-c → P-CSCF port-s (client flow)
	// OUT SA: local:port-c → remote:port-s (use remote SPI-S)
	if err := mgr.AddSA(xfrm.SAConfig{
		Src:     localIP,
		Dst:     remoteIP,
		SrcPort: policy.LocalPortC,
		DstPort: policy.RemotePortS,
		SPI:     policy.FlowS.OutboundSPI, // remote SPI-S
		AuthAlg: authAlg,
		AuthKey: ikKey,
		EncAlg:  encAlg,
		EncKey:  ckKey,
		ReqID:   int(policy.FlowS.OutboundSPI),
	}); err != nil {
		mgr.Cleanup()
		return nil, fmt.Errorf("failed to add Flow1 OUT SA: %w", err)
	}

	// IN SA: remote:port-s → local:port-c (use local SPI-C)
	if err := mgr.AddSA(xfrm.SAConfig{
		Src:     remoteIP,
		Dst:     localIP,
		SrcPort: policy.RemotePortS,
		DstPort: policy.LocalPortC,
		SPI:     policy.FlowC.InboundSPI, // local SPI-C
		AuthAlg: authAlg,
		AuthKey: ikKey,
		EncAlg:  encAlg,
		EncKey:  ckKey,
		ReqID:   int(policy.FlowC.InboundSPI),
	}); err != nil {
		mgr.Cleanup()
		return nil, fmt.Errorf("failed to add Flow1 IN SA: %w", err)
	}

	// OUT policy: local:port-c → remote:port-s
	if err := mgr.AddPolicy(xfrm.PolicyConfig{
		Src:       localIP,
		Dst:       remoteIP,
		SrcPort:   policy.LocalPortC,
		DstPort:   policy.RemotePortS,
		Direction: "out",
		TmplSrc:   localIP,
		TmplDst:   remoteIP,
		TmplSPI:   int(policy.FlowS.OutboundSPI),
		ReqID:     int(policy.FlowS.OutboundSPI),
		Priority:  2342,
	}); err != nil {
		mgr.Cleanup()
		return nil, fmt.Errorf("failed to add Flow1 OUT policy: %w", err)
	}

	// IN policy: remote:port-s → local:port-c
	if err := mgr.AddPolicy(xfrm.PolicyConfig{
		Src:       remoteIP,
		Dst:       localIP,
		SrcPort:   policy.RemotePortS,
		DstPort:   policy.LocalPortC,
		Direction: "in",
		TmplSrc:   remoteIP,
		TmplDst:   localIP,
		TmplSPI:   int(policy.FlowC.InboundSPI),
		ReqID:     int(policy.FlowC.InboundSPI),
		Priority:  2342,
	}); err != nil {
		mgr.Cleanup()
		return nil, fmt.Errorf("failed to add Flow1 IN policy: %w", err)
	}

	// Flow 2: UE port-s → P-CSCF port-c (server flow)
	// OUT SA: local:port-s → remote:port-c (use remote SPI-C)
	if err := mgr.AddSA(xfrm.SAConfig{
		Src:     localIP,
		Dst:     remoteIP,
		SrcPort: policy.LocalPortS,
		DstPort: policy.RemotePortC,
		SPI:     policy.FlowC.OutboundSPI, // remote SPI-C
		AuthAlg: authAlg,
		AuthKey: ikKey,
		EncAlg:  encAlg,
		EncKey:  ckKey,
		ReqID:   int(policy.FlowC.OutboundSPI),
	}); err != nil {
		mgr.Cleanup()
		return nil, fmt.Errorf("failed to add Flow2 OUT SA: %w", err)
	}

	// IN SA: remote:port-c → local:port-s (use local SPI-S)
	if err := mgr.AddSA(xfrm.SAConfig{
		Src:     remoteIP,
		Dst:     localIP,
		SrcPort: policy.RemotePortC,
		DstPort: policy.LocalPortS,
		SPI:     policy.FlowS.InboundSPI, // local SPI-S
		AuthAlg: authAlg,
		AuthKey: ikKey,
		EncAlg:  encAlg,
		EncKey:  ckKey,
		ReqID:   int(policy.FlowS.InboundSPI),
	}); err != nil {
		mgr.Cleanup()
		return nil, fmt.Errorf("failed to add Flow2 IN SA: %w", err)
	}

	// OUT policy: local:port-s → remote:port-c
	if err := mgr.AddPolicy(xfrm.PolicyConfig{
		Src:       localIP,
		Dst:       remoteIP,
		SrcPort:   policy.LocalPortS,
		DstPort:   policy.RemotePortC,
		Direction: "out",
		TmplSrc:   localIP,
		TmplDst:   remoteIP,
		TmplSPI:   int(policy.FlowC.OutboundSPI),
		ReqID:     int(policy.FlowC.OutboundSPI),
		Priority:  2342,
	}); err != nil {
		mgr.Cleanup()
		return nil, fmt.Errorf("failed to add Flow2 OUT policy: %w", err)
	}

	// IN policy: remote:port-c → local:port-s
	if err := mgr.AddPolicy(xfrm.PolicyConfig{
		Src:       remoteIP,
		Dst:       localIP,
		SrcPort:   policy.RemotePortC,
		DstPort:   policy.LocalPortS,
		Direction: "in",
		TmplSrc:   remoteIP,
		TmplDst:   localIP,
		TmplSPI:   int(policy.FlowS.InboundSPI),
		ReqID:     int(policy.FlowS.InboundSPI),
		Priority:  2342,
	}); err != nil {
		mgr.Cleanup()
		return nil, fmt.Errorf("failed to add Flow2 IN policy: %w", err)
	}

	return mgr, nil
}

// padKey pads a key to the specified length with zeros
func padKey(key []byte, length int) []byte {
	if len(key) >= length {
		return key[:length]
	}
	padded := make([]byte, length)
	copy(padded, key)
	return padded
}

// mapAuthAlg converts ipsec3gpp auth algorithm to XFRM format
func mapAuthAlg(alg string) string {
	switch alg {
	case "hmac-sha-1-96":
		return "hmac(sha1)"
	case "hmac-md5-96":
		return "hmac(md5)"
	default:
		return "hmac(sha1)" // Default to SHA1
	}
}

// mapEncAlg converts ipsec3gpp encryption algorithm to XFRM format
func mapEncAlg(alg string) string {
	switch alg {
	case "aes-cbc":
		return "cbc(aes)"
	case "des-ede3-cbc":
		return "cbc(des3_ede)"
	case "null", "cipher_null":
		return "cipher_null"
	default:
		return "cipher_null" // Default to null encryption
	}
}

// DumpXFRMDebug logs XFRM SA and policy details for debugging
func DumpXFRMDebug(policy Policy) string {
	var buf []byte
	buf = append(buf, fmt.Sprintf("IMS ESP XFRM Configuration:\n")...)
	buf = append(buf, fmt.Sprintf("  Local:  %s\n", net.IP(policy.LocalIP))...)
	buf = append(buf, fmt.Sprintf("  Remote: %s\n", net.IP(policy.RemoteIP))...)
	buf = append(buf, fmt.Sprintf("  Flow1 (C→s): %s:%d → %s:%d (OUT SPI=0x%x IN SPI=0x%x)\n",
		net.IP(policy.LocalIP), policy.LocalPortC,
		net.IP(policy.RemoteIP), policy.RemotePortS,
		policy.FlowS.OutboundSPI, policy.FlowC.InboundSPI)...)
	buf = append(buf, fmt.Sprintf("  Flow2 (S→c): %s:%d → %s:%d (OUT SPI=0x%x IN SPI=0x%x)\n",
		net.IP(policy.LocalIP), policy.LocalPortS,
		net.IP(policy.RemoteIP), policy.RemotePortC,
		policy.FlowC.OutboundSPI, policy.FlowS.InboundSPI)...)
	buf = append(buf, fmt.Sprintf("  Auth: %s, Enc: %s\n", policy.FlowS.AuthAlg, policy.FlowS.EncAlg)...)
	buf = append(buf, fmt.Sprintf("  IK: %s\n", hex.EncodeToString(policy.FlowS.IK))...)
	buf = append(buf, fmt.Sprintf("  CK: %s\n", hex.EncodeToString(policy.FlowS.CK))...)
	return string(buf)
}