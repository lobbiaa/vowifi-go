package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/icholy/digest"
	"github.com/1239t/vowifi-go/engine/sim"
	"github.com/1239t/vowifi-go/runtimehost/simauth"
)

func main() {
	// Data from closed-source successful registration (Frame 34)
	nonceB64 := "3vYSA3o/MbFLnmWFtH7rs/gpeCCPegAAR7N89zv8cfs="
	realm := "epc.mnc007.mcc262.3gppnetwork.org"
	username := "262036013159494@ims.mnc003.mcc262.3gppnetwork.org"
	uri := "sip:ims.mnc003.mcc262.3gppnetwork.org"
	expectedResponse := "36ce6a7052042105d1958364acf36e94"

	fmt.Println("=== AKA Digest Authentication Test ===")
	fmt.Println()
	fmt.Println("Testing VoHive's AKA algorithm against closed-source successful registration")
	fmt.Println()

	// Decode nonce to extract RAND and AUTN
	nonceBytes, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		fmt.Printf("ERROR: Failed to decode nonce: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Input Parameters:\n")
	fmt.Printf("  Nonce (base64): %s\n", nonceB64)
	fmt.Printf("  Nonce (hex):    %s\n", hex.EncodeToString(nonceBytes))
	fmt.Printf("  Realm:          %s\n", realm)
	fmt.Printf("  Username:       %s\n", username)
	fmt.Printf("  URI:            %s\n", uri)
	fmt.Printf("  Expected:       %s\n", expectedResponse)
	fmt.Println()

	if len(nonceBytes) < 32 {
		fmt.Printf("ERROR: Nonce too short: %d bytes (need at least 32)\n", len(nonceBytes))
		os.Exit(1)
	}

	rand16 := nonceBytes[:16]
	autn16 := nonceBytes[16:32]

	fmt.Printf("Extracted RAND/AUTN:\n")
	fmt.Printf("  RAND: %s\n", hex.EncodeToString(rand16))
	fmt.Printf("  AUTN: %s\n", hex.EncodeToString(autn16))
	fmt.Println()

	// Try to connect to real SIM card
	fmt.Println("Attempting to connect to SIM card via /dev/ttyUSB2...")

	simProvider := sim.NewATModem("/dev/ttyUSB2")
	if simProvider == nil {
		fmt.Println("ERROR: Failed to create SIM provider")
		fmt.Println()
		fmt.Println("MANUAL TEST INSTRUCTIONS:")
		fmt.Println("1. Ensure modem is connected and /dev/ttyUSB2 is accessible")
		fmt.Println("2. Or manually extract RES from VoHive logs when it processes this RAND/AUTN:")
		fmt.Printf("   RAND: %s\n", hex.EncodeToString(rand16))
		fmt.Printf("   AUTN: %s\n", hex.EncodeToString(autn16))
		fmt.Println("3. Then run: go run cmd/test-aka-manual/main.go <RES_hex>")
		os.Exit(1)
	}

	fmt.Println("SIM provider created, calculating AKA...")

	// Calculate AKA using real SIM
	akaResult, err := simProvider.CalculateAKA(rand16, autn16)
	if err != nil {
		if err == sim.ErrSyncFailure {
			fmt.Printf("ERROR: SIM returned sync failure (AUTS)\n")
			fmt.Printf("  AUTS: %s\n", hex.EncodeToString(akaResult.AUTS))
			fmt.Println()
			fmt.Println("This means the SIM's sequence number is out of sync.")
			fmt.Println("The RAND/AUTN from the test may be too old or already used.")
		} else {
			fmt.Printf("ERROR: CalculateAKA failed: %v\n", err)
		}
		os.Exit(1)
	}

	fmt.Printf("AKA Result from SIM:\n")
	fmt.Printf("  RES: %s\n", hex.EncodeToString(akaResult.RES))
	fmt.Printf("  CK:  %s\n", hex.EncodeToString(akaResult.CK))
	fmt.Printf("  IK:  %s\n", hex.EncodeToString(akaResult.IK))
	fmt.Println()

	// Now compute the digest response
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

	result, err := simauth.ComputeDigest(simProvider, chal, opts)
	if err != nil {
		fmt.Printf("ERROR: ComputeDigest failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Digest Calculation:\n")
	fmt.Printf("  Authorization header:\n")
	fmt.Printf("    %s\n", result.Header)
	fmt.Println()

	// Extract response value
	authHeader := result.Header
	responseStart := strings.Index(authHeader, `response="`)
	if responseStart == -1 {
		fmt.Println("ERROR: Could not find response field in Authorization header")
		os.Exit(1)
	}
	responseStart += len(`response="`)
	responseEnd := strings.Index(authHeader[responseStart:], `"`)
	if responseEnd == -1 {
		fmt.Println("ERROR: Could not parse response field")
		os.Exit(1)
	}
	actualResponse := authHeader[responseStart : responseStart+responseEnd]

	fmt.Printf("=== COMPARISON ===\n")
	fmt.Printf("  Expected: %s\n", expectedResponse)
	fmt.Printf("  Actual:   %s\n", actualResponse)
	fmt.Println()

	if strings.EqualFold(actualResponse, expectedResponse) {
		fmt.Println("✅ SUCCESS: Responses match! AKA algorithm is correct.")
		os.Exit(0)
	} else {
		fmt.Println("❌ FAILURE: Responses do NOT match!")
		fmt.Println()
		fmt.Println("This indicates either:")
		fmt.Println("1. Different SIM card (different K key)")
		fmt.Println("2. Bug in AKA algorithm implementation")
		fmt.Println("3. Bug in digest calculation")
		fmt.Println()
		fmt.Println("Debugging info:")
		fmt.Printf("  RES used: %s\n", hex.EncodeToString(akaResult.RES))
		fmt.Printf("  Password (hex RES): %s\n", hex.EncodeToString(akaResult.RES))
		os.Exit(1)
	}
}
