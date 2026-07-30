package main

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/icholy/digest"
	"github.com/1239t/vowifi-go/engine/sim"
	"github.com/1239t/vowifi-go/runtimehost/simauth"
)

// MockAKAProvider for testing
type MockAKAProvider struct {
	RES []byte
}

func (m *MockAKAProvider) CalculateAKA(rand, autn []byte) (sim.AKAResult, error) {
	return sim.AKAResult{
		RES:  m.RES,
		CK:   make([]byte, 16),
		IK:   make([]byte, 16),
		AUTS: nil,
	}, nil
}

func main() {
	// Test parameters from closed-source v0.8.3
	nonceB64 := "k8ftfd3xgpGDj9YlGJNvvgPf3LDRIwAAWwvdSjjP5qM="
	realm := "epc.mnc007.mcc262.3gppnetwork.org"
	username := "262036013159494@ims.mnc003.mcc262.3gppnetwork.org"
	uri := "sip:ims.mnc003.mcc262.3gppnetwork.org"
	resHex := "7af52aa75750c993"
	expectedResponse := "9a92745f3a332b2e07375658900f383b"

	fmt.Println("=== Testing VoHive's simauth.ComputeDigest ===")
	fmt.Println()

	// Decode RES
	resBytes, err := hex.DecodeString(resHex)
	if err != nil {
		fmt.Printf("ERROR: Failed to decode RES: %v\n", err)
		os.Exit(1)
	}

	// Create mock provider
	provider := &MockAKAProvider{RES: resBytes}

	// Create challenge
	chal := &digest.Challenge{
		Realm:     realm,
		Nonce:     nonceB64,
		Algorithm: "AKAv1-MD5",
	}

	// Create options
	opts := digest.Options{
		Method:   "REGISTER",
		URI:      uri,
		Username: username,
	}

	// Compute digest using VoHive's simauth
	result, err := simauth.ComputeDigest(provider, chal, opts)
	if err != nil {
		fmt.Printf("ERROR: ComputeDigest failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Input:\n")
	fmt.Printf("  Nonce:    %s\n", nonceB64)
	fmt.Printf("  Realm:    %s\n", realm)
	fmt.Printf("  Username: %s\n", username)
	fmt.Printf("  URI:      %s\n", uri)
	fmt.Printf("  RES:      %s\n", resHex)
	fmt.Println()

	fmt.Printf("Authorization Header:\n")
	fmt.Printf("  %s\n", result.Header)
	fmt.Println()

	// Extract response from header
	authHeader := result.Header
	responseStart := -1
	for i := 0; i < len(authHeader)-9; i++ {
		if authHeader[i:i+9] == "response=" {
			responseStart = i + 10 // skip 'response="'
			break
		}
	}

	if responseStart == -1 {
		fmt.Println("ERROR: Could not find response field")
		os.Exit(1)
	}

	responseEnd := responseStart
	for responseEnd < len(authHeader) && authHeader[responseEnd] != '"' {
		responseEnd++
	}

	actualResponse := authHeader[responseStart:responseEnd]

	// Also manually calculate to compare
	fmt.Printf("Manual Calculation:\n")
	ha1Input := fmt.Sprintf("%s:%s:%s", username, realm, resHex)
	ha1Hash := md5.Sum([]byte(ha1Input))
	ha1 := hex.EncodeToString(ha1Hash[:])
	fmt.Printf("  HA1 = MD5(%s)\n", ha1Input)
	fmt.Printf("      = %s\n", ha1)
	fmt.Println()

	ha2Input := fmt.Sprintf("%s:%s", "REGISTER", uri)
	ha2Hash := md5.Sum([]byte(ha2Input))
	ha2 := hex.EncodeToString(ha2Hash[:])
	fmt.Printf("  HA2 = MD5(%s)\n", ha2Input)
	fmt.Printf("      = %s\n", ha2)
	fmt.Println()

	responseInput := fmt.Sprintf("%s:%s:%s", ha1, nonceB64, ha2)
	responseHash := md5.Sum([]byte(responseInput))
	manualResponse := hex.EncodeToString(responseHash[:])
	fmt.Printf("  Response = MD5(%s)\n", responseInput)
	fmt.Printf("           = %s\n", manualResponse)
	fmt.Println()

	fmt.Printf("=== COMPARISON ===\n")
	fmt.Printf("  Expected (closed-source): %s\n", expectedResponse)
	fmt.Printf("  Actual (simauth):         %s\n", actualResponse)
	fmt.Printf("  Manual calculation:       %s\n", manualResponse)
	fmt.Println()

	if actualResponse == expectedResponse {
		fmt.Println("✅ SUCCESS: simauth.ComputeDigest produces correct response!")
		os.Exit(0)
	} else {
		fmt.Println("❌ FAILURE: Response mismatch")

		// Try with different nonce encoding
		fmt.Println()
		fmt.Println("Debugging: Check nonce decoding")
		nonceBytes, _ := base64.StdEncoding.DecodeString(nonceB64)
		fmt.Printf("  Nonce bytes (hex): %s\n", hex.EncodeToString(nonceBytes))
		fmt.Printf("  Nonce length: %d bytes\n", len(nonceBytes))

		os.Exit(1)
	}
}
