package policy

// DefaultSecurityClientMechanisms returns the standard 6-mechanism phone-style
// Security-Client set used when a carrier preset does not override mechanisms.
func DefaultSecurityClientMechanisms() []IPSec3GPPSecurityMechanism {
	return []IPSec3GPPSecurityMechanism{
		{Alg: "hmac-md5-96", EAlg: "des-ede3-cbc"},
		{Alg: "hmac-md5-96", EAlg: "aes-cbc"},
		{Alg: "hmac-md5-96", EAlg: "null"},
		{Alg: "hmac-sha-1-96", EAlg: "des-ede3-cbc"},
		{Alg: "hmac-sha-1-96", EAlg: "aes-cbc"},
		{Alg: "hmac-sha-1-96", EAlg: "null"},
	}
}

// DefaultGiffgaffTemplate matches extracted preset giffgaff_23410.yaml and the
// embedded author binary carrier registry.
func DefaultGiffgaffTemplate() IMSRegisterTemplate {
	mechanisms := DefaultSecurityClientMechanisms()
	return IMSRegisterTemplate{
		ID:                       "giffgaff",
		SecAgreeMode:             "auto",
		IncludePANIAuthenticated: true,
		StrictSecurityServerOffer: true,
		EnableInitialRejectFallback: false,
		ContactParamOrder: []string{
			"access_type",
			"audio",
			"smsip",
			"icsi_ref",
			"sip_instance",
		},
		SecurityClientMechanisms: mechanisms,
	}
}

// DefaultO2GermanyTemplate returns the O2 Germany (26203) IMS register template
// matching the successful iniwex/vohive configuration.
func DefaultO2GermanyTemplate() IMSRegisterTemplate {
	mechanisms := DefaultSecurityClientMechanisms()
	return IMSRegisterTemplate{
		ID:                          "O2_de_26203_ios",
		SecAgreeMode:                "auto",
		UsePlainDigestPlaceholder:   false,
		SupportedHeader:             "path,sec-agree,gruu",
		IncludePANIAuthenticated:    true,
		StrictSecurityServerOffer:   true,
		EnableInitialRejectFallback: false,
		ContactParamOrder: []string{
			"access_type",
			"audio",
			"smsip",
			"icsi_ref",
			"sip_instance",
		},
		SecurityClientMechanisms: mechanisms,
		RegisterPolicy: IMSRegisterPolicy{
			ID:                               "default",
			TemporaryStatusCodes:             []int{408, 429, 500, 502, 503, 504},
			ForbiddenStatusCodes:             []int{403},
			InitialRejectFallbackStatusCodes: []int{400, 403, 500},
			TemporaryRetrySeconds:            60,
		},
	}
}