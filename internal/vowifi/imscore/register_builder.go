package imscore

import (
	"strings"

	"github.com/1239t/vowifi-go/internal/vowifi/policy"
)

// buildTemplateSecurityClient renders all Security-Client mechanisms
// for the initial REGISTER, matching iniwex format with multiple mechanisms.
func buildTemplateSecurityClient(template policy.IMSRegisterTemplate, spiC, spiS uint32, portC, portS int) string {
	// Send ALL mechanisms, not just one preferred
	// This matches iniwex which sends 6 mechanisms comma-separated
	return policy.BuildSecurityClientHeader(template, spiC, spiS, portC, portS)
}

// buildFullSecurityClient renders all template mechanisms for sec-agree verify
// rounds that require the full client capability set.
func buildFullSecurityClient(template policy.IMSRegisterTemplate, spiC, spiS uint32, portC, portS int) string {
	return policy.BuildSecurityClientHeader(template, spiC, spiS, portC, portS)
}

func preferredSecurityClientMechanism(template policy.IMSRegisterTemplate) policy.IPSec3GPPSecurityMechanism {
	mechanisms := supportedSecurityClientMechanisms(template)
	for i := len(mechanisms) - 1; i >= 0; i-- {
		m := mechanisms[i]
		if strings.EqualFold(strings.TrimSpace(m.Alg), "hmac-sha-1-96") &&
			strings.EqualFold(canonicalTemplateEAlg(m.EAlg), "aes-cbc") {
			return policy.IPSec3GPPSecurityMechanism{
				Alg:  m.Alg,
				EAlg: m.EAlg,
				Prot: "esp",
				Mode: "trans",
			}
		}
	}
	if len(mechanisms) > 0 {
		m := mechanisms[len(mechanisms)-1]
		if strings.TrimSpace(m.Prot) == "" {
			m.Prot = "esp"
		}
		if strings.TrimSpace(m.Mode) == "" {
			m.Mode = "trans"
		}
		return m
	}
	return policy.IPSec3GPPSecurityMechanism{
		Alg:  "hmac-sha-1-96",
		EAlg: "aes-cbc",
		Prot: "esp",
		Mode: "trans",
	}
}

func supportedSecurityClientMechanisms(template policy.IMSRegisterTemplate) []policy.IPSec3GPPSecurityMechanism {
	if len(template.SecurityClientMechanisms) > 0 {
		return template.SecurityClientMechanisms
	}
	return policy.DefaultSecurityClientMechanisms()
}

func securityClientMechanismCount(template policy.IMSRegisterTemplate) int {
	return len(supportedSecurityClientMechanisms(template))
}

func canonicalTemplateEAlg(ealg string) string {
	ealg = strings.TrimSpace(strings.ToLower(ealg))
	if ealg == "" || ealg == "null" {
		return "null"
	}
	return ealg
}

func secAgreeEnabled(template policy.IMSRegisterTemplate) bool {
	mode := strings.ToLower(strings.TrimSpace(template.SecAgreeMode))
	return mode == "" || mode == "auto" || mode == "on" || mode == "true"
}