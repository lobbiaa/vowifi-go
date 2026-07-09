package policy

import "testing"

func TestDefaultGiffgaffTemplate(t *testing.T) {
	tmpl := DefaultGiffgaffTemplate()

	if tmpl.ID != "giffgaff" {
		t.Fatalf("id = %q, want giffgaff", tmpl.ID)
	}
	if !tmpl.IncludePANIAuthenticated {
		t.Fatal("expected include_pani_authenticated=true")
	}
	if !tmpl.StrictSecurityServerOffer {
		t.Fatal("expected strict_security_server_offer=true")
	}
	if tmpl.EnableInitialRejectFallback {
		t.Fatal("expected enable_initial_reject_fallback=false")
	}
	if tmpl.SecAgreeMode != "auto" {
		t.Fatalf("sec_agree_mode = %q, want auto", tmpl.SecAgreeMode)
	}

	wantOrder := []string{
		"access_type",
		"audio",
		"smsip",
		"icsi_ref",
		"sip_instance",
	}
	if len(tmpl.ContactParamOrder) != len(wantOrder) {
		t.Fatalf("contact_param_order = %#v", tmpl.ContactParamOrder)
	}
	for i, want := range wantOrder {
		if tmpl.ContactParamOrder[i] != want {
			t.Fatalf("contact_param_order[%d] = %q, want %q", i, tmpl.ContactParamOrder[i], want)
		}
	}

	if len(tmpl.SecurityClientMechanisms) != 6 {
		t.Fatalf("mechanisms = %d, want 6", len(tmpl.SecurityClientMechanisms))
	}
	wantMechs := []struct{ alg, ealg string }{
		{"hmac-md5-96", "des-ede3-cbc"},
		{"hmac-md5-96", "aes-cbc"},
		{"hmac-md5-96", "null"},
		{"hmac-sha-1-96", "des-ede3-cbc"},
		{"hmac-sha-1-96", "aes-cbc"},
		{"hmac-sha-1-96", "null"},
	}
	for i, want := range wantMechs {
		got := tmpl.SecurityClientMechanisms[i]
		if got.Alg != want.alg || got.EAlg != want.ealg {
			t.Fatalf("mechanism[%d] = %+v, want %s/%s", i, got, want.alg, want.ealg)
		}
	}
}