package imscore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
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

	expiresSeconds int
	verifyHeader   string
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

	authRes, _, err := buildAuthenticatedRegister(cfg, *state, lastReq, lastRes)
	if err != nil {
		_ = secureConn.Close()
		return nil, err
	}

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
		LocalIP:  cfg.LocalIP,
		RemoteIP: rip,
		Mech:     mech,
		CK:       state.ck,
		IK:       state.ik,
	})
	if err != nil {
		return err
	}
	state.portC = pol.LocalPortC
	state.portS = pol.LocalPortS
	transport, err := ipsec3gpp.NewTransport(pol)
	if err != nil {
		return err
	}
	state.ipsecPolicy = pol
	state.transport = transport
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
	portC := state.ipsecPolicy.RemotePortC
	if portC <= 0 && state.selectedOffer != nil {
		portC = state.selectedOffer.PortC
	}
	if portC <= 0 {
		portC = remotePort
	}
	localPort := state.ipsecPolicy.LocalPortC
	if localPort <= 0 {
		localPort = state.portC
	}

	var rawConn net.Conn
	if swuTCP != nil {
		rawConn, err = swuTCP.DialContextTCP(ctx, cfg.LocalIP, localPort, rip, portC)
	} else {
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: cfg.LocalIP, Port: localPort}}
		rawConn, err = d.DialContext(ctx, "tcp", net.JoinHostPort(rip.String(), strconv.Itoa(portC)))
	}
	if err != nil {
		return nil, err
	}
	return ipsec3gpp.WrapSecureChannel(rawConn, state.transport, state.ipsecPolicy), nil
}

func buildAuthenticatedRegister(cfg Config, state registerState, prevReq *sip.Request, prevRes *sip.Response) (*sip.Request, *sip.Request, error) {
	if prevReq == nil {
		return nil, nil, fmt.Errorf("missing previous REGISTER request")
	}
	chal, err := selectDigestChallenge(cfg, prevRes)
	if err != nil {
		return nil, nil, err
	}
	_, authHeader, err := computeAKAAuth(cfg, chal, prevReq)
	if err != nil {
		return nil, nil, err
	}

	req := prevReq.Clone()
	req.RemoveHeader("Via")
	req.RemoveHeader("Authorization")
	req.RemoveHeader("Security-Verify")
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
	if v := strings.TrimSpace(cfg.PrivateID); v != "" {
		return v
	}
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
	plmn := strings.TrimSpace(cfg.MCC) + strings.TrimLeft(strings.TrimSpace(cfg.MNC), "0")
	if plmn == "" {
		plmn = "00000"
	}
	cell := strings.TrimSpace(cfg.CellID)
	if cell == "" {
		cell = "0000000"
	}
	return fmt.Sprintf("3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=%s%s;cell-info-age=0", plmn, cell)
}

func computeAKAAuth(cfg Config, chal *digest.Challenge, req *sip.Request) (sim.AKAResult, string, error) {
	result, err := simauth.ComputeDigest(cfg.AKA, chal, digest.Options{
		Method:   req.Method.String(),
		URI:      req.Recipient.Host,
		Username: cfg.PrivateID,
	})
	if err != nil {
		return sim.AKAResult{}, "", err
	}
	akaResult, err := akaResultFromChallenge(cfg.AKA, chal)
	if err != nil {
		return sim.AKAResult{}, "", err
	}
	return akaResult, result.Header, nil
}

func akaResultFromChallenge(provider sim.AKAProvider, chal *digest.Challenge) (sim.AKAResult, error) {
	if provider == nil {
		return sim.AKAResult{}, fmt.Errorf("AKA provider required")
	}
	rawNonce, err := decodeChallengeNonce(chal.Nonce)
	if err != nil {
		return sim.AKAResult{}, err
	}
	if len(rawNonce) < 32 {
		return sim.AKAResult{}, fmt.Errorf("nonce too short for RAND||AUTN")
	}
	return provider.CalculateAKA(rawNonce[:16], rawNonce[16:32])
}

func decodeChallengeNonce(nonce string) ([]byte, error) {
	trimmed := strings.TrimSpace(nonce)
	if trimmed == "" {
		return nil, fmt.Errorf("empty nonce")
	}
	if len(trimmed)%2 == 0 {
		if raw, err := hex.DecodeString(trimmed); err == nil {
			return raw, nil
		}
	}
	return nil, fmt.Errorf("unsupported nonce encoding")
}

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
		n, err := rand.Int(rand.Reader, big.NewInt(50000))
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
		n, err := rand.Int(rand.Reader, big.NewInt(1<<32-1))
		if err != nil {
			return 0xc0ffee01
		}
		if v := uint32(n.Int64()) + 1; v != 0 {
			return v
		}
	}
}