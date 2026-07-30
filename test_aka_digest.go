package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/icholy/digest"
	"github.com/1239t/vowifi-go/engine/sim"
	"github.com/1239t/vowifi-go/runtimehost/simauth"
)

// MockAKAProvider simulates SIM card responses for testing
type MockAKAProvider struct {
	RES  []byte
	CK   []byte
	IK   []byte
	AUTS []byte
	Err  error
}

func (m *MockAKAProvider) CalculateAKA(rand, autn []byte) (sim.AKAResult, error) {
	if m.Err != nil {
		return sim.AKAResult{AUTS: m.AUTS}, m.Err
	}
	return sim.AKAResult{
		RES: m.RES,
		CK:  m.CK,
		IK:  m.IK,
	}, nil
}

func main() {
	// Data from closed-source successful registration
	nonceB64 := "3vYSA3o/MbFLnmWFtH7rs/gpeCCPegAAR7N89zv8cfs="
	realm := "epc.mnc007.mcc262.3gppnetwork.org"
	username := "262036013159494@ims.mnc003.mcc262.3gppnetwork.org"
	uri := "sip:ims.mnc003.mcc262.3gppnetwork.org"
	expectedResponse := "36ce6a7052042105d1958364acf36e94"

	// Decode nonce to extract RAND and AUTN
	nonceBytes, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		log.Fatalf("Failed to decode nonce: %v", err)
	}

	fmt.Printf("Nonce (base64): %s\n", nonceB64)
	fmt.Printf("Nonce (hex):    %s\n", hex.EncodeToString(nonceBytes))
	fmt.Printf("Nonce length:   %d bytes\n\n", len(nonceBytes))

	if len(nonceBytes) < 32 {
		log.Fatalf("Nonce too short: %d bytes (need 32)", len(nonceBytes))
	}

	rand16 := nonceBytes[:16]
	autn16 := nonceBytes[16:32]

	fmt.Printf("RAND (hex): %s\n", hex.EncodeToString(rand16))
	fmt.Printf("AUTN (hex): %s\n\n", hex.EncodeToString(autn16))

	// We need actual RES from the real SIM card for this test
	// Since we can't access the SIM card directly in this test,
	// we'll demonstrate the algorithm structure

	fmt.Println("=== Test Scenario 1: Demonstrate algorithm structure ===")
	fmt.Println("To properly test, we need the actual RES value from SIM card")
	fmt.Println("Let's try with a mock RES and show the calculation:")

	// Mock RES (8 bytes) - this would come from real SIM
	mockRES := []byte{0x10, 0x59, 0x74, 0x67, 0x94, 0xc1, 0xe3, 0x34}

	mockProvider := &MockAKAProvider{
		RES: mockRES,
		CK:  make([]byte, 16), // Not needed for digest calculation
		IK:  make([]byte, 16),
	}

	chal := &digest.Challenge{
		Realm:     realm,
		Nonce:     nonceB64,
		Algorithm: "AKAv1-MD5",
	}

	opts := digest.Options{
		Method:   "REGISTER",
		URI:      uri,
		Username: username,
	}

	result, err := simauth.ComputeDigest(mockProvider, chal, opts)
	if err != nil {
		log.Fatalf("ComputeDigest failed: %v", err)
	}

	fmt.Printf("\nMock RES (hex): %s\n", hex.EncodeToString(mockRES))
	fmt.Printf("Authorization header:\n%s\n\n", result.Header)

	// Extract response value from Authorization header
	// Format: Digest username="...", realm="...", nonce="...", uri="...", response="...", algorithm=AKAv1-MD5
	fmt.Println("=== Algorithm Breakdown ===")
	fmt.Printf("Step 1 - HA1 = MD5(%s:%s:%s)\n", username, realm, hex.EncodeToString(mockRES))
	fmt.Printf("Step 2 - HA2 = MD5(%s:%s)\n", "REGISTER", uri)
	fmt.Printf("Step 3 - response = MD5(HA1:%s:HA2)\n\n", nonceB64)

	fmt.Println("=== Comparison ===")
	fmt.Printf("Expected response: %s\n", expectedResponse)
	fmt.Printf("Mock response:     (extracted from Authorization header above)\n\n")

	fmt.Println("=== To Complete This Test ===")
	fmt.Println("1. Run VoHive with the same RAND/AUTN from closed-source test")
	fmt.Println("2. Capture the RES value from SIM card (already logged)")
	fmt.Println("3. Use that RES value here to compute the exact response")
	fmt.Println("4. Compare with closed-source expected response")
}
