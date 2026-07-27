package xfrm

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

// IMSESPManager manages XFRM SA and policies for IMS ESP layer using ip xfrm commands
// This is separate from the ePDG IPsec tunnel (handled by swu-go)
// Implementation follows vowifi-sms proven approach using shell commands
type IMSESPManager struct {
	localIP  string
	remoteIP string
	cleanups []func() error
}

// NewIMSESPManager creates a new IMS ESP XFRM manager
func NewIMSESPManager() *IMSESPManager {
	return &IMSESPManager{
		cleanups: make([]func() error, 0),
	}
}

// SAConfig represents XFRM Security Association configuration for IMS ESP
type SAConfig struct {
	Src       net.IP
	Dst       net.IP
	SrcPort   int
	DstPort   int
	SPI       uint32
	AuthAlg   string // e.g., "hmac(sha1)", "hmac(md5)"
	AuthKey   []byte
	EncAlg    string // e.g., "cbc(aes)", "cipher_null"
	EncKey    []byte
	ReqID     int // Request ID for policy matching
}

// PolicyConfig represents XFRM Security Policy configuration for IMS ESP
type PolicyConfig struct {
	Src       net.IP
	Dst       net.IP
	SrcPort   int
	DstPort   int
	Direction string // "out" or "in"
	TmplSrc   net.IP
	TmplDst   net.IP
	TmplSPI   int
	ReqID     int
	Priority  int
}

// AddSA installs an XFRM SA with port selector for IMS ESP using ip xfrm command
// Reference: vowifi-sms ipsec.go:197-264
func (m *IMSESPManager) AddSA(cfg SAConfig) error {
	m.localIP = cfg.Src.String()
	m.remoteIP = cfg.Dst.String()

	// Determine address family
	fam := "-6"
	if cfg.Src.To4() != nil {
		fam = "-4"
	}

	// Prepare keys with 0x prefix
	authKey := "0x" + hex.EncodeToString(cfg.AuthKey)
	encKey := ""
	if cfg.EncAlg != "cipher_null" && len(cfg.EncKey) > 0 {
		encKey = "0x" + hex.EncodeToString(cfg.EncKey)
	}

	// Build command: ip -6 xfrm state add src SRC dst DST proto esp spi SPI
	//                reqid REQID mode transport replay-window 32
	//                auth ALG KEY enc EALG EKEY
	// NOTE: Port selectors are NOT supported in SA (state), only in SP (policy)
	// The policy will handle port matching using sel sport/dport
	args := []string{fam, "xfrm", "state", "add",
		"src", cfg.Src.String(),
		"dst", cfg.Dst.String(),
		"proto", "esp",
		"spi", fmt.Sprintf("0x%x", cfg.SPI),
		"reqid", strconv.Itoa(cfg.ReqID),
		"mode", "transport",
		"replay-window", "32"}

	// Add authentication
	args = append(args, "auth", cfg.AuthAlg, authKey)

	// Add encryption
	if cfg.EncAlg == "cipher_null" || encKey == "" {
		args = append(args, "enc", "cipher_null", "")
	} else {
		args = append(args, "enc", cfg.EncAlg, encKey)
	}

	// Debug: print the actual command
	cmdStr := "ip " + strings.Join(args, " ")
	log.Printf("[XFRM] Adding SA: %s", cmdStr)

	cmd := exec.Command("ip", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to add XFRM SA (spi=0x%x src=%v dst=%v): %v, output: %s",
			cfg.SPI, cfg.Src, cfg.Dst, err, output)
	}

	// Register cleanup
	m.cleanups = append(m.cleanups, func() error {
		return m.delSA(cfg.SPI, cfg.Src, cfg.Dst, fam)
	})

	return nil
}

// CleanupSPI removes an XFRM SA by SPI if it exists (idempotent)
// Used to clean up stale SAs before installation to avoid "File exists" errors
func (m *IMSESPManager) CleanupSPI(spi uint32, src, dst net.IP) {
	fam := "-6"
	if src.To4() != nil {
		fam = "-4"
	}
	_ = m.delSA(spi, src, dst, fam) // Ignore errors (SA might not exist)
}

// delSA removes an XFRM SA
func (m *IMSESPManager) delSA(spi uint32, src, dst net.IP, fam string) error {
	cmd := exec.Command("ip", fam, "xfrm", "state", "del",
		"src", src.String(),
		"dst", dst.String(),
		"proto", "esp",
		"spi", fmt.Sprintf("0x%x", spi))
	_ = cmd.Run() // Ignore errors (SA might not exist)
	return nil
}

// AddPolicy installs an XFRM policy with port selector for IMS ESP
// Reference: vowifi-sms ipsec.go:232-258
func (m *IMSESPManager) AddPolicy(cfg PolicyConfig) error {
	// Determine address family
	fam := "-6"
	if cfg.Src.To4() != nil {
		fam = "-4"
	}

	// Build command: ip -6 xfrm policy add src SRC dst DST
	//                sport SPORT dport DPORT dir DIR priority PRI
	//                tmpl src TSRC dst TDST proto esp reqid REQID mode transport
	args := []string{fam, "xfrm", "policy", "add",
		"src", cfg.Src.String(),
		"dst", cfg.Dst.String()}

	// Add ports
	if cfg.SrcPort > 0 {
		args = append(args, "sport", strconv.Itoa(cfg.SrcPort))
	}
	if cfg.DstPort > 0 {
		args = append(args, "dport", strconv.Itoa(cfg.DstPort))
	}

	args = append(args,
		"dir", cfg.Direction,
		"priority", strconv.Itoa(cfg.Priority),
		"tmpl",
		"src", cfg.TmplSrc.String(),
		"dst", cfg.TmplDst.String(),
		"proto", "esp",
		"reqid", strconv.Itoa(cfg.ReqID),
		"mode", "transport")

	cmd := exec.Command("ip", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to add XFRM policy (dir=%v src=%v:%d dst=%v:%d): %v, output: %s",
			cfg.Direction, cfg.Src, cfg.SrcPort, cfg.Dst, cfg.DstPort, err, output)
	}

	// Register cleanup
	m.cleanups = append(m.cleanups, func() error {
		return m.delPolicy(cfg, fam)
	})

	return nil
}

// delPolicy removes an XFRM policy
func (m *IMSESPManager) delPolicy(cfg PolicyConfig, fam string) error {
	args := []string{fam, "xfrm", "policy", "del",
		"src", cfg.Src.String(),
		"dst", cfg.Dst.String()}

	if cfg.SrcPort > 0 {
		args = append(args, "sport", strconv.Itoa(cfg.SrcPort))
	}
	if cfg.DstPort > 0 {
		args = append(args, "dport", strconv.Itoa(cfg.DstPort))
	}

	args = append(args, "dir", cfg.Direction)

	cmd := exec.Command("ip", args...)
	_ = cmd.Run() // Ignore errors (policy might not exist)
	return nil
}

// Cleanup removes all installed SAs and policies in reverse order
func (m *IMSESPManager) Cleanup() {
	for i := len(m.cleanups) - 1; i >= 0; i-- {
		_ = m.cleanups[i]()
	}
	m.cleanups = nil
}

// FlushAll clears all XFRM states and policies (use with caution)
func FlushAll() error {
	// Flush IPv6 XFRM
	exec.Command("ip", "-6", "xfrm", "state", "flush").Run()
	exec.Command("ip", "-6", "xfrm", "policy", "flush").Run()

	// Flush IPv4 XFRM
	exec.Command("ip", "-4", "xfrm", "state", "flush").Run()
	exec.Command("ip", "-4", "xfrm", "policy", "flush").Run()

	return nil
}

// FlushRemoteIP removes all XFRM states and policies for a specific remote IP
// This is used to clean up stale SAs from previous failed registration attempts
func FlushRemoteIP(remoteIP net.IP) error {
	ipStr := remoteIP.String()
	ipFamily := "-6"
	if remoteIP.To4() != nil {
		ipFamily = "-4"
	}

	log.Printf("[XFRM] Flushing all states and policies for remote IP: %s", ipStr)

	// Use xfrm state deleteall with src or dst filter
	// Note: deleteall is safer than manual parsing as it's atomic
	exec.Command("sh", "-c", fmt.Sprintf("ip %s xfrm state | grep -B2 'src %s\\|dst %s' | grep -oP 'src \\S+ dst \\S+ proto esp spi 0x\\S+' | while read line; do ip %s xfrm state delete $line; done 2>/dev/null || true", ipFamily, ipStr, ipStr, ipFamily)).Run()

	exec.Command("sh", "-c", fmt.Sprintf("ip %s xfrm policy | grep -B2 'src %s\\|dst %s' | grep -oP 'src \\S+/\\d+ dst \\S+/\\d+ sport \\d+ dport \\d+ dir (in|out)' | while read line; do ip %s xfrm policy delete $line priority 2342; done 2>/dev/null || true", ipFamily, ipStr, ipStr, ipFamily)).Run()

	return nil
}

