package imscore

import (
	"context"
	cryptorand "crypto/rand"
	// "encoding/base64" // retained for commented-out decodeChallengeNonce
	// "encoding/hex"    // retained for commented-out decodeChallengeNonce
	"fmt"
	"math/big"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/icholy/digest"
	"github.com/1239t/swu-go/pkg/logger"

	"github.com/1239t/vowifi-go/internal/vowifi/imsheaders"
	"github.com/1239t/vowifi-go/internal/vowifi/ipsec3gpp"
	"github.com/1239t/vowifi-go/internal/vowifi/policy"
	"github.com/1239t/vowifi-go/engine/sim"
	"github.com/1239t/vowifi-go/runtimehost/simauth"
	"github.com/1239t/vowifi-go/runtimehost/voiceclient"
)

const (
	registerTransactionTimeout = 12 * time.Second
	registerCandidateTimeout   = 15 * time.Second
	registerDialTimeout        = 90 * time.Second
	maxChallengeRounds         = 2
)

type registerState struct {
	spiC  uint32
	spiS  uint32
	portC int
	portS int

	ck []byte
	ik []byte

	sipInstance   string
	selectedOffer *imsheaders.SecurityOffer
	ipsecPolicy   ipsec3gpp.Policy
	transport     *ipsec3gpp.Transport
	secureConn    *ipsec3gpp.SecureChannelConn
	xfrmManager   interface{ Cleanup() } // XFRM manager for IMS ESP cleanup

	expiresSeconds int
	verifyHeader   string

	// cachedAuthHeader stores the Authorization header computed during the
	// initial 401 handling, so buildAuthenticatedRegister can reuse it instead
	// of recomputing AKA (which would trigger AUTS sync failure on the SIM).
	cachedAuthHeader string
}

type registerResult struct {
	pcscfAddr      string
	expiresSeconds int
	verifyHeader   string
	secureConn     *ipsec3gpp.SecureChannelConn
	ipsecPolicy    ipsec3gpp.Policy
	transport      *ipsec3gpp.Transport
}

type initialRegisterVariant struct {
	initialAuth       string
	includePANI       bool
	includeCellular   bool
}

func initialRejectFallbackEnabled(cfg Config) bool {
	if cfg.Template.EnableInitialRejectFallback {
		return true
	}
	return strings.TrimSpace(os.Getenv("VOHIVE_IMS_INITIAL_REJECT_FALLBACK")) == "1"
}

func initialRegisterVariants(cfg Config) []initialRegisterVariant {
	base := initialRegisterVariant{
		initialAuth:     "",
		includePANI:     cfg.Template.IncludePANIAuthenticated,
		includeCellular: true,
	}
	if !initialRejectFallbackEnabled(cfg) {
		return []initialRegisterVariant{base}
	}
	return []initialRegisterVariant{
		base,
		{initialAuth: "aka_empty_uri_first", includePANI: true, includeCellular: true},
		{initialAuth: "aka_empty", includePANI: true, includeCellular: true},
		{initialAuth: "aka_zero_response_uri_first", includePANI: true, includeCellular: true},
		{initialAuth: "none", includePANI: false, includeCellular: false},
	}
}

func shouldRetryInitialRegisterForStatus(cfg Config, statusCode int) bool {
	if !initialRejectFallbackEnabled(cfg) {
		return false
	}
	if statusCode == sip.StatusForbidden {
		return true
	}
	for _, code := range cfg.Template.RegisterPolicy.InitialRejectFallbackStatusCodes {
		if code == statusCode {
			return true
		}
	}
	return false
}

func runSecureAuthenticatedRegister(ctx context.Context, cfg Config, swuTCP voiceclient.SWUTCPDialer, state *registerState, lastReq *sip.Request, lastRes *sip.Response) (*registerResult, error) {
	secureConn, err := dialSecureRegisterConn(ctx, cfg, swuTCP, *state)
	if err != nil {
		return nil, fmt.Errorf("secure channel dial: %w", err)
	}

	ua, secureClient, err := newSecureRegisterSIPStack(cfg, secureConn)
	if err != nil {
		_ = secureConn.Close()
		return nil, err
	}
	defer ua.Close()
	defer secureClient.Close()

	logger.Info("runSecureAuthenticatedRegister: SIP stack created",
		logger.String("trace_id", strings.TrimSpace(cfg.TraceID)),
		logger.String("secure_conn_local", secureConn.LocalAddr().String()),
		logger.String("secure_conn_remote", secureConn.RemoteAddr().String()))

	authRes, _, err := buildAuthenticatedRegister(cfg, *state, lastReq, lastRes)
	if err != nil {
		_ = secureConn.Close()
		return nil, err
	}

	logger.Info("runSecureAuthenticatedRegister: sending authenticated REGISTER",
		logger.String("trace_id", strings.TrimSpace(cfg.TraceID)),
		logger.String("request_uri", authRes.Recipient.String()),
		logger.String("destination", authRes.Destination()),
		logger.String("transport", authRes.Transport()),
		logger.String("route_header", func() string {
			if h := authRes.GetHeader("Route"); h != nil {
				return h.Value()
			}
			return "<nil>"
		}()))

	finalRes, err := doRegisterTransaction(ctx, secureClient, authRes)
	if err != nil {
		_ = secureConn.Close()
		return nil, fmt.Errorf("authenticated REGISTER: %w", err)
	}
	if finalRes.StatusCode != sip.StatusOK {
		_ = secureConn.Close()
		return nil, fmt.Errorf("authenticated REGISTER failed: %d %s", finalRes.StatusCode, finalRes.Reason)
	}

	state.secureConn = secureConn
	return finalizeRegisterSuccess(cfg, *state, finalRes)
}

func installIPSecFromChallenge(cfg Config, state *registerState, res *sip.Response) error {
	secServer := res.GetHeader("Security-Server")
	if secServer == nil {
		return fmt.Errorf("missing Security-Server on %d", res.StatusCode)
	}
	verify, selected, err := buildSecurityVerifyFromChallenge(cfg, res)
	if err != nil {
		return err
	}
	state.selectedOffer = selected
	state.verifyHeader = verify

	rip := effectiveIPSecRemoteIP(cfg)
	if rip == nil {
		return fmt.Errorf("invalid IPSec remote for registrar %q transport %q", cfg.PCSCFAddr, effectiveTransportAddr(cfg))
	}

	mech := ipsec3gpp.SecurityMechanism{
		Alg:   selected.Alg,
		EAlg:  selected.EAlg,
		Prot:  selected.Prot,
		Mode:  selected.Mode,
		SPIc:  selected.SPIC,
		SPIs:  selected.SPIS,
		PortC: selected.PortC,
		PortS: selected.PortS,
	}
	pol, err := ipsec3gpp.NewPolicy(ipsec3gpp.PolicyInput{
		LocalIP:    cfg.LocalIP,
		RemoteIP:   rip,
		Mech:       mech,
		CK:         state.ck,
		IK:         state.ik,
		LocalPortC: state.portC,
		LocalPortS: state.portS,
		LocalSPIC:  state.spiC, // UE's own spi-c announced in Security-Client
		LocalSPIS:  state.spiS, // UE's own spi-s announced in Security-Client
	})
	if err != nil {
		return err
	}

	// [CRITICAL FIX] Update state SPIs to match what P-CSCF assigned
	// The initial Security-Client used randomly generated SPIs, but after 401
	// we MUST use the SPIs from Security-Server response for XFRM SA installation
	// and for the next Security-Client header in authenticated REGISTER.
	// However, DO NOT update ports - UE continues using its own announced ports
	// as local binding addresses. Security-Server ports are P-CSCF's remote ports.
	state.spiC = selected.SPIC
	state.spiS = selected.SPIS
	// Keep state.portC and state.portS unchanged - they are UE's local binding ports

	transport, err := ipsec3gpp.NewTransport(pol)
	if err != nil {
		return err
	}
	state.ipsecPolicy = pol
	state.transport = transport

	// Install IMS ESP using kernel XFRM (replaces user-space ESP)
	logger.Info("Installing IMS ESP via kernel XFRM",
		logger.String("trace_id", strings.TrimSpace(cfg.TraceID)),
		logger.String("local_ip", cfg.LocalIP.String()),
		logger.String("remote_ip", rip.String()),
		logger.Int("local_port_c", state.portC),
		logger.Int("local_port_s", state.portS),
		logger.Int("remote_port_c", selected.PortC),
		logger.Int("remote_port_s", selected.PortS),
		logger.Uint32("local_spi_c", pol.FlowC.InboundSPI),
		logger.Uint32("local_spi_s", pol.FlowS.InboundSPI),
		logger.Uint32("remote_spi_c", selected.SPIC),
		logger.Uint32("remote_spi_s", selected.SPIS))

	xfrmMgr, err := ipsec3gpp.InstallXFRMDualFlow(pol)
	if err != nil {
		return fmt.Errorf("failed to install XFRM IMS ESP: %w", err)
	}
	state.xfrmManager = xfrmMgr

	logger.Info("IMS ESP XFRM policies installed successfully",
		logger.String("trace_id", strings.TrimSpace(cfg.TraceID)),
		logger.String("debug_info", ipsec3gpp.DumpXFRMDebug(pol)))

	return nil
}

func dialSecureRegisterConn(ctx context.Context, cfg Config, swuTCP voiceclient.SWUTCPDialer, state registerState) (*ipsec3gpp.SecureChannelConn, error) {
	transportAddr := effectiveIPSecGatewayAddr(cfg)
	remoteIP, remotePortStr, err := net.SplitHostPort(transportAddr)
	if err != nil {
		return nil, err
	}
	remotePort, err := strconv.Atoi(remotePortStr)
	if err != nil {
		return nil, err
	}
	rip := net.ParseIP(remoteIP)
	if rip == nil {
		return nil, fmt.Errorf("invalid transport P-CSCF %q", transportAddr)
	}
	// UE sends protected REGISTER from its port_uc (LocalPortC) to P-CSCF's
	// port_ps (RemotePortS per 3GPP TS 33.203). Use RemotePortS, not RemotePortC.
	remotePortS := state.ipsecPolicy.RemotePortS
	if remotePortS <= 0 && state.selectedOffer != nil {
		remotePortS = state.selectedOffer.PortS
	}
	if remotePortS <= 0 {
		remotePortS = remotePort
	}
	// IMPORTANT: The TCP source port MUST match port-c declared in Security-Client
	// header. P-CSCF verifies this as part of IMS ESP integrity check.
	// Use port-c as the local port for all TCP connections (both netstack and kernel).
	localPort := state.ipsecPolicy.LocalPortC
	if localPort <= 0 {
		localPort = state.portC
	}
	if localPort <= 0 {
		return nil, fmt.Errorf("dialSecureRegisterConn: port-c not available in state")
	}

	logger.Info("dialSecureRegisterConn attempting secure dial",
		logger.String("local_ip", cfg.LocalIP.String()),
		logger.Int("local_port", localPort),
		logger.String("remote_ip", rip.String()),
		logger.Int("remote_port_s", remotePortS),
		logger.Bool("has_swutcp", swuTCP != nil))

	logger.Info("dialSecureRegisterConn checking state",
		logger.String("trace_id", cfg.TraceID),
		logger.Bool("transport_nil", state.transport == nil),
		logger.Bool("policy_local_ip_nil", state.ipsecPolicy.LocalIP == nil))

	var rawConn net.Conn
	if swuTCP != nil {
		rawConn, err = swuTCP.DialContextTCP(ctx, cfg.LocalIP, localPort, rip, remotePortS)
		if err != nil {
			logger.Warn("secure dial via swuTCP failed",
				logger.String("trace_id", cfg.TraceID),
				logger.String("local_ip", cfg.LocalIP.String()),
				logger.Int("local_port", localPort),
				logger.String("remote_ip", rip.String()),
				logger.Int("remote_port", remotePortS),
				logger.String("error", err.Error()))
		}
	} else {
		// Use tcp6 for IPv6 addresses to ensure proper XFRM matching
		network := "tcp"
		if cfg.LocalIP.To4() == nil {
			network = "tcp6"
		}

		d := net.Dialer{
			LocalAddr: &net.TCPAddr{IP: cfg.LocalIP, Port: localPort},
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}
		target := net.JoinHostPort(rip.String(), strconv.Itoa(remotePortS))
		logger.Info("secure dial using net.Dialer with XFRM IMS ESP",
			logger.String("trace_id", cfg.TraceID),
			logger.String("network", network),
			logger.String("local_addr", d.LocalAddr.String()),
			logger.String("target", target),
			logger.String("note", "XFRM kernel will apply ESP to matching traffic"))
		rawConn, err = d.DialContext(ctx, network, target)
		if err != nil {
			logger.Warn("secure dial via net.Dialer failed",
				logger.String("trace_id", cfg.TraceID),
				logger.String("local_addr", d.LocalAddr.String()),
				logger.String("target", target),
				logger.String("error", err.Error()))
		}
	}
	if err != nil {
		logger.Warn("dialSecureRegisterConn failed",
			logger.String("trace_id", cfg.TraceID),
			logger.Err(err))
		return nil, err
	}
	logger.Info("dialSecureRegisterConn TCP connection established",
		logger.String("trace_id", cfg.TraceID),
		logger.String("local_addr", rawConn.LocalAddr().String()),
		logger.String("remote_addr", rawConn.RemoteAddr().String()),
		logger.String("note", "XFRM handles ESP transparently, returning raw TCP connection"))

	// [CRITICAL FIX] With kernel XFRM, use passthrough wrapper WITHOUT userspace ESP
	// WrapSecureChannel does userspace ESP encryption which creates fake IP/TCP headers
	// and conflicts with kernel XFRM. Kernel handles ESP automatically, so we just need
	// a passthrough wrapper that directly reads/writes to the raw TCP connection.
	return ipsec3gpp.WrapSecureChannelPassthrough(rawConn), nil
}

func buildAuthenticatedRegister(cfg Config, state registerState, prevReq *sip.Request, prevRes *sip.Response) (*sip.Request, *sip.Request, error) {
	if prevReq == nil {
		return nil, nil, fmt.Errorf("missing previous REGISTER request")
	}
	var authHeader string
	if state.cachedAuthHeader != "" {
		// Reuse the Authorization computed during 401 handling to avoid
		// recomputing AKA (which triggers AUTS sync failure on the SIM).
		authHeader = state.cachedAuthHeader
	} else {
		chal, err := selectDigestChallenge(cfg, prevRes)
		if err != nil {
			return nil, nil, err
		}
		_, h, err := computeAKAAuth(cfg, chal, prevReq)
		if err != nil {
			return nil, nil, err
		}
		authHeader = h
	}

	req := prevReq.Clone()
	req.RemoveHeader("Via")
	req.RemoveHeader("Authorization")
	req.RemoveHeader("Security-Verify")

	// [CRITICAL FIX] Update Contact header to use UE's port-s (UE server port)
	// After IMS ESP is installed, P-CSCF must be able to reach UE on UE's port-s
	// The initial REGISTER used port 5060, but authenticated REGISTER must use state.portS
	req.RemoveHeader("Contact")
	secureContactPort := state.portS
	if secureContactPort <= 0 {
		secureContactPort = 5060 // fallback to default UE port-s
	}
	req.AppendHeader(sip.NewHeader("Contact", buildIMSCoreContact(cfg, state, secureContactPort)))

	// [CRITICAL FIX] Update Route header to use port-s (6060) instead of 5060
	// After IMS ESP is installed, authenticated REGISTER must be sent to the secure port
	oldRoute := req.GetHeader("Route")
	oldRouteValue := ""
	if oldRoute != nil {
		oldRouteValue = oldRoute.Value()
	}
	req.RemoveHeader("Route")
	remoteIP := effectiveIPSecRemoteIP(cfg)
	secureRouteAddr := net.JoinHostPort(remoteIP.String(), fmt.Sprintf("%d", state.selectedOffer.PortS))
	req.AppendHeader(sip.NewHeader("Route", "<sip:"+secureRouteAddr+";lr>"))

	// [CRITICAL FIX] Override SetDestination to use port-s (6060)
	// This is what sipgo actually uses to route the TCP connection, not the Route header
	req.SetDestination(secureRouteAddr)
	req.SetTransport("TCP")

	logger.Info("buildAuthenticatedRegister Route header and destination updated",
		logger.String("trace_id", strings.TrimSpace(cfg.TraceID)),
		logger.String("old_route", oldRouteValue),
		logger.String("new_route", "<sip:"+secureRouteAddr+";lr>"),
		logger.String("destination", secureRouteAddr),
		logger.String("remote_ip", remoteIP.String()),
		logger.Int("port_s", state.selectedOffer.PortS))

	req.AppendHeader(sip.NewHeader("Authorization", authHeader))
	if state.verifyHeader != "" {
		req.AppendHeader(sip.NewHeader("Security-Verify", state.verifyHeader))
	}
	return req, prevReq, nil
}

func buildRegisterRequest(cfg Config, state registerState, initial bool, variant initialRegisterVariant) (*sip.Request, error) {
	recipient := sip.Uri{}
	rawURI := "sip:" + strings.TrimSpace(cfg.HomeDomain)
	if err := sip.ParseUri(rawURI, &recipient); err != nil {
		return nil, err
	}
	req := sip.NewRequest(sip.REGISTER, recipient)
	req.AppendHeader(sip.NewHeader("From", "<"+cfg.PublicURI+">;tag="+sip.GenerateTagN(16)))
	req.AppendHeader(sip.NewHeader("To", "<"+cfg.PublicURI+">"))
	req.AppendHeader(sip.NewHeader("Contact", buildIMSCoreContact(cfg, state, registerSIPLocalPort(cfg))))
	if initial {
		if auth := buildInitialAuthorization(cfg, variant.initialAuth); auth != "" {
			req.AppendHeader(sip.NewHeader("Authorization", auth))
		}
	}
	req.AppendHeader(sip.NewHeader("Route", "<sip:"+effectiveRouteAddr(cfg)+";lr>"))
	expires := cfg.RegisterExpirySeconds
	if expires <= 0 {
		expires = 3600
	}
	req.AppendHeader(sip.NewHeader("Expires", strconv.Itoa(expires)))

	// Add Require header if specified in template
	if requireHeader := strings.TrimSpace(cfg.Template.RequireHeader); requireHeader != "" {
		req.AppendHeader(sip.NewHeader("Require", requireHeader))
	}

	// Add Proxy-Require header if specified in template
	if proxyRequireHeader := strings.TrimSpace(cfg.Template.ProxyRequireHeader); proxyRequireHeader != "" {
		req.AppendHeader(sip.NewHeader("Proxy-Require", proxyRequireHeader))
	}

	// Add Supported header (use template or default)
	supportedHeader := strings.TrimSpace(cfg.Template.SupportedHeader)
	if supportedHeader == "" {
		supportedHeader = "path,sec-agree,gruu"
	}
	req.AppendHeader(sip.NewHeader("Supported", supportedHeader))

	req.AppendHeader(sip.NewHeader("Allow", "INVITE,ACK,CANCEL,BYE,UPDATE,PRACK,MESSAGE,REFER,NOTIFY,INFO,OPTIONS"))
	req.AppendHeader(sip.NewHeader("P-Preferred-Identity", "<"+cfg.PublicURI+">"))
	req.AppendHeader(sip.NewHeader("P-Visited-Network-ID", "\""+cfg.HomeDomain+"\""))
	includePANI := cfg.Template.IncludePANIAuthenticated
	includeCellular := true
	if initial {
		includePANI = variant.includePANI
		includeCellular = variant.includeCellular
	}
	if includePANI {
		req.AppendHeader(sip.NewHeader("P-Access-Network-Info", "IEEE-802.11;i-wlan-node-id=000000000000;network-provided"))
	}
	if includeCellular {
		req.AppendHeader(sip.NewHeader("Cellular-Network-Info", buildCellularNetworkInfo(cfg)))
	}
	req.AppendHeader(sip.NewHeader("Accept-Contact", "*;+g.3gpp.smsip"))
	req.AppendHeader(sip.NewHeader("Accept-Contact", "*;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel\""))
	var secClient string
	if initial {
		secClient = buildTemplateSecurityClient(cfg.Template, state.spiC, state.spiS, state.portC, state.portS)
	} else if state.verifyHeader != "" {
		secClient = buildFullSecurityClient(cfg.Template, state.spiC, state.spiS, state.portC, state.portS)
	} else {
		secClient = buildTemplateSecurityClient(cfg.Template, state.spiC, state.spiS, state.portC, state.portS)
	}
	req.AppendHeader(sip.NewHeader("Security-Client", secClient))
	req.AppendHeader(sip.NewHeader("User-Agent", cfg.UserAgent))
	req.SetDestination(effectiveTransportAddr(cfg))
	req.SetTransport("TCP")
	logRegisterRouting(cfg, req)
	return req, nil
}

func finalizeRegisterSuccess(cfg Config, state registerState, res *sip.Response) (*registerResult, error) {
	expires := 3600
	if h := res.GetHeader("Expires"); h != nil {
		if v, err := strconv.Atoi(strings.TrimSpace(h.Value())); err == nil && v > 0 {
			expires = v
		}
	}
	logger.Info(fmt.Sprintf("[%s] IMS REGISTER 成功", strings.TrimSpace(cfg.DeviceID)),
		logger.String("trace_id", strings.TrimSpace(cfg.TraceID)),
		logger.Int("code", res.StatusCode),
		logger.Int("expires_seconds", expires),
		logger.String("sip_security_mode", "ipsec3gpp"),
		logger.String("verify", state.verifyHeader))
	return &registerResult{
		pcscfAddr:      cfg.PCSCFAddr,
		expiresSeconds: expires,
		verifyHeader:   state.verifyHeader,
		secureConn:     state.secureConn,
		ipsecPolicy:    state.ipsecPolicy,
		transport:      state.transport,
	}, nil
}

func doRegisterTransaction(ctx context.Context, client *sipgo.Client, req *sip.Request, opts ...sipgo.ClientRequestOption) (*sip.Response, error) {
	txCtx, cancel := context.WithTimeout(ctx, registerTransactionTimeout)
	defer cancel()
	tx, err := client.TransactionRequest(txCtx, req, opts...)
	if err != nil {
		return nil, err
	}
	defer tx.Terminate()
	select {
	case <-tx.Done():
		if err := tx.Err(); err != nil {
			return nil, fmt.Errorf("transaction ended: %w", err)
		}
		return nil, fmt.Errorf("transaction ended without a response")
	case res := <-tx.Responses():
		return res, nil
	case <-txCtx.Done():
		return nil, txCtx.Err()
	}
}

func buildInitialAuthorization(cfg Config, mode string) string {
	authMode := strings.ToLower(strings.TrimSpace(mode))
	if authMode == "" {
		if strings.EqualFold(strings.TrimSpace(cfg.Template.SecAgreeMode), "auto") {
			authMode = "aka_empty_uri_first"
		} else if !cfg.Template.UsePlainDigestPlaceholder {
			authMode = "none"
		} else {
			authMode = "aka_empty_uri_first"
		}
	}
	requestURI := "sip:" + strings.TrimSpace(cfg.HomeDomain)
	username := authorizationUsername(cfg)
	realm := quoteSipParam(strings.TrimSpace(cfg.Realm))
	switch authMode {
	case "none":
		return ""
	case "aka_empty":
		return fmt.Sprintf(
			`Digest username="%s",realm="%s",nonce="",uri="%s",response="",algorithm=AKAv1-MD5`,
			quoteSipParam(username),
			realm,
			quoteSipParam(requestURI),
		)
	case "aka_zero_response_uri_first":
		return fmt.Sprintf(
			`Digest uri="%s",username="%s",algorithm=AKAv1-MD5,response="00000000000000000000000000000000",realm="%s",nonce=""`,
			quoteSipParam(requestURI),
			quoteSipParam(username),
			realm,
		)
	default:
		// aka_empty_uri_first - matches iniwex format: NO algorithm field in initial REGISTER
		return fmt.Sprintf(
			`Digest uri="%s",username="%s",response="",realm="%s",nonce=""`,
			quoteSipParam(requestURI),
			quoteSipParam(username),
			realm,
		)
	}
}

func authorizationUsername(cfg Config) string {
	// Always rebuild username using imsi_home_domain shape for Authorization header
	// Do NOT use cfg.PrivateID directly as it may be EPC NAI format (0IMSI@nai.epc...)
	// Authorization header needs IMS format: IMSI@ims domain
	imsi := strings.TrimSpace(cfg.IMSI)
	realm := strings.TrimSpace(cfg.Realm)
	domain := strings.TrimSpace(cfg.HomeDomain)
	if imsi != "" && realm != "" && domain != "" {
		// Use "imsi_home_domain" shape: IMSI@realm (no "0" prefix)
		// This matches iniwex/vohive: 262036013159494@ims.mnc003.mcc262.3gppnetwork.org
		if privateID, _ := voiceclient.BuildIMSIdentity(imsi, realm, domain, "imsi_home_domain"); privateID != "" {
			return privateID
		}
	}

	// Fallback to PrivateID only if BuildIMSIdentity fails
	if v := strings.TrimSpace(cfg.PrivateID); v != "" {
		return v
	}
	return ""
}

func buildIMSCoreContact(cfg Config, state registerState, localPort int) string {
	sipInstance := strings.TrimSpace(state.sipInstance)
	if sipInstance == "" {
		sipInstance = strings.TrimSpace(cfg.SIPInstanceURN)
	}
	if sipInstance == "" {
		sipInstance = voiceclient.NewSIPInstanceURN()
	}
	return policy.BuildIMSContactHeader(cfg.Template, policy.ContactBuildInput{
		IMSI:               cfg.IMSI,
		PublicURI:          cfg.PublicURI,
		LocalIP:            cfg.LocalIP,
		LocalPort:          localPort,
		SIPInstanceURN:     sipInstance,
		RegisterExpirySecs: cfg.RegisterExpirySeconds,
	})
}

func buildCellularNetworkInfo(cfg Config) string {
	// [CRITICAL FIX] PLMN must be exactly 6 digits: MCC (3 digits) + MNC (3 digits)
	// DO NOT strip leading zeros from MNC - "003" must stay "003", not "3"
	// Example: MCC=262, MNC=003 → PLMN=262003 (not 2623)
	mcc := strings.TrimSpace(cfg.MCC)
	mnc := strings.TrimSpace(cfg.MNC)

	// Pad MCC to 3 digits if needed
	if len(mcc) < 3 {
		mcc = fmt.Sprintf("%03s", mcc)
	}
	// Pad MNC to 3 digits if needed (keep leading zeros!)
	if len(mnc) < 3 {
		mnc = fmt.Sprintf("%03s", mnc)
	}

	plmn := mcc + mnc
	if plmn == "" || plmn == "000000" {
		plmn = "000000"
	}

	cell := strings.TrimSpace(cfg.CellID)
	if cell == "" {
		// [FIX] O2 Germany requires realistic random cell-id after PLMN
		// Format: PLMN (6 digits) + random hex (10 digits)
		// Example: 26200307D0F294E0 = 262003 + 07D0F294E0
		cell = fmt.Sprintf("%08X%02X", rand.Uint32(), rand.Intn(256))
	}

	// [FIX] O2 Germany requires realistic cell-info-age, not 0
	// Use random value between 10000-50000 milliseconds
	cellInfoAge := 10000 + rand.Intn(40000)

	return fmt.Sprintf("3GPP-E-UTRAN-TDD;utran-cell-id-3gpp=%s%s;cell-info-age=%d", plmn, cell, cellInfoAge)
}

func computeAKAAuth(cfg Config, chal *digest.Challenge, req *sip.Request) (sim.AKAResult, string, error) {
	// ComputeDigest performs the single AKA computation against the SIM and
	// returns both the Authorization header and the full AKA result (RES/CK/IK).
	// We must NOT call CalculateAKA a second time for the same RAND/AUTN: the
	// USIM's SQN replay protection would reject it with a sync failure and yield
	// no CK/IK. Reuse result.AKA instead.

	// [FIX] O2 Germany requires username to be IMSI@ims.mnc003.mcc262.3gppnetwork.org
	// Extract IMSI from cfg.IMSI (not PrivateID which may have 0 prefix and wrong domain)
	imsi := strings.TrimSpace(cfg.IMSI)
	// Remove leading 0 if present
	imsi = strings.TrimPrefix(imsi, "0")
	username := imsi + "@" + cfg.HomeDomain

	result, err := simauth.ComputeDigest(cfg.AKA, chal, digest.Options{
		Method:   req.Method.String(),
		URI:      "sip:" + cfg.HomeDomain,  // Use full SIP URI
		Username: username,                  // Use IMSI@HomeDomain format (e.g. 262036013159494@ims.mnc003.mcc262.3gppnetwork.org)
	})
	if err != nil {
		return sim.AKAResult{}, "", err
	}
	return result.AKA, result.Header, nil
}

// akaResultFromChallenge is retained (commented out) for reference. It performed
// a SECOND CalculateAKA for the same RAND/AUTN just to obtain CK/IK, which the
// USIM rejects with a sync failure (SQN replay protection). computeAKAAuth now
// reuses simauth.ComputeDigest's result.AKA instead, so this is no longer used.
//
// func akaResultFromChallenge(provider sim.AKAProvider, chal *digest.Challenge) (sim.AKAResult, error) {
// 	if provider == nil {
// 		return sim.AKAResult{}, fmt.Errorf("AKA provider required")
// 	}
// 	rawNonce, err := decodeChallengeNonce(chal.Nonce)
// 	if err != nil {
// 		return sim.AKAResult{}, err
// 	}
// 	if len(rawNonce) < 32 {
// 		return sim.AKAResult{}, fmt.Errorf("nonce too short for RAND||AUTN")
// 	}
// 	return provider.CalculateAKA(rawNonce[:16], rawNonce[16:32])
// }
//
// decodeChallengeNonce is retained (commented out) alongside akaResultFromChallenge.
// simauth.decodeNonceBytes performs the equivalent hex/base64 decoding used by the
// live path.
//
// func decodeChallengeNonce(nonce string) ([]byte, error) {
// 	trimmed := strings.TrimSpace(nonce)
// 	if trimmed == "" {
// 		return nil, fmt.Errorf("empty nonce")
// 	}
//
// 	// Try hex first (most common)
// 	if len(trimmed)%2 == 0 {
// 		if raw, err := hex.DecodeString(trimmed); err == nil {
// 			return raw, nil
// 		}
// 	}
//
// 	// Try base64 (O2 Germany uses this)
// 	if raw, err := base64.StdEncoding.DecodeString(trimmed); err == nil {
// 		return raw, nil
// 	}
//
// 	// Try base64 with padding
// 	padded := trimmed
// 	for len(padded)%4 != 0 {
// 		padded += "="
// 	}
// 	if raw, err := base64.StdEncoding.DecodeString(padded); err == nil {
// 		return raw, nil
// 	}
//
// 	return nil, fmt.Errorf("unsupported nonce encoding")
// }

func selectDigestChallenge(cfg Config, res *sip.Response) (*digest.Challenge, error) {
	headers := res.GetHeaders("WWW-Authenticate")
	if len(headers) == 0 && res.StatusCode == sip.StatusProxyAuthRequired {
		headers = res.GetHeaders("Proxy-Authenticate")
	}
	if len(headers) == 0 {
		return nil, fmt.Errorf("%d response with no authenticate header", res.StatusCode)
	}
	for _, header := range headers {
		chal, err := digest.ParseChallenge(header.Value())
		if err == nil {
			return chal, nil
		}
	}
	return nil, fmt.Errorf("parse challenge failed")
}

func quoteSipParam(value string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value)
}

func registerSIPLocalPort(cfg Config) int {
	return registerAttemptLocalPort(cfg, 0)
}

func registerAttemptLocalPort(cfg Config, attemptIndex int) int {
	if attemptIndex > 0 || !registrarHostEqualsLocalIP(cfg.PCSCFAddr, cfg.LocalIP) {
		return randomEphemeralSIPPort()
	}
	return 5060
}

func randomEphemeralSIPPort() int {
	for {
		n, err := cryptorand.Int(cryptorand.Reader, big.NewInt(50000))
		if err != nil {
			return 5062
		}
		port := 10000 + int(n.Int64())
		if port != 5060 && port != 5061 {
			return port
		}
	}
}

func randomNonZeroUint32() uint32 {
	for {
		n, err := cryptorand.Int(cryptorand.Reader, big.NewInt(1<<32-1))
		if err != nil {
			return 0xc0ffee01
		}
		if v := uint32(n.Int64()) + 1; v != 0 {
			return v
		}
	}
}