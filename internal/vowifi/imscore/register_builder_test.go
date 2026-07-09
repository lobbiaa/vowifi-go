package imscore

import (
	"strings"
	"testing"

	"github.com/1239t/vowifi-go/internal/vowifi/policy"
)

func TestBuildTemplateSecurityClientSingleMechanism(t *testing.T) {
	got := buildTemplateSecurityClient(policy.DefaultGiffgaffTemplate(), 1, 2, 5064, 5063)
	if strings.Count(got, "ipsec-3gpp") != 1 {
		t.Fatalf("expected single mechanism, got %q", got)
	}
	for _, want := range []string{
		"alg=hmac-sha-1-96",
		"ealg=aes-cbc",
		"prot=esp",
		"mod=trans",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("header %q missing %q", got, want)
		}
	}
}

func TestResolveStableSIPInstanceUsesConfig(t *testing.T) {
	cfg := Config{SIPInstanceURN: "urn:uuid:fixed-id"}
	if got := resolveStableSIPInstance(cfg); got != "urn:uuid:fixed-id" {
		t.Fatalf("got %q", got)
	}
}