package main

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run test-aka-manual.go <RES_hex>")
		fmt.Println()
		fmt.Println("Extract RES from VoHive logs when it processes the test RAND/AUTN:")
		fmt.Println("  RAND: def6120377a3f31b9e6585b47eebbf")
		fmt.Println("  AUTN: b297982f8ea776000047b37cf73bfc71")
		fmt.Println()
		fmt.Println("Look for log line like:")
		fmt.Println(`  [DJ3] USIM AKA 成功响应已解析 {"res": "...", ...}`)
		fmt.Println()
		fmt.Println("Then run: go run test-aka-manual.go <res_value>")
		os.Exit(1)
	}

	resHex := os.Args[1]

	// Data from closed-source successful registration
	nonceB64 := "k8ftfd3xgpGDj9YlGJNvvgPf3LDRIwAAWwvdSjjP5qM="
	realm := "epc.mnc007.mcc262.3gppnetwork.org"
	username := "262036013159494@ims.mnc003.mcc262.3gppnetwork.org"
	uri := "sip:ims.mnc003.mcc262.3gppnetwork.org"
	method := "REGISTER"
	expectedResponse := "9a92745f3a332b2e07375658900f383b"

	fmt.Println("=== AKA Digest Authentication Manual Test ===")
	fmt.Println()

	// Decode nonce
	nonceBytes, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		fmt.Printf("ERROR: Failed to decode nonce: %v\n", err)
		os.Exit(1)
	}

	rand16 := nonceBytes[:16]
	autn16 := nonceBytes[16:32]

	fmt.Printf("Input Parameters:\n")
	fmt.Printf("  RAND:     %s\n", hex.EncodeToString(rand16))
	fmt.Printf("  AUTN:     %s\n", hex.EncodeToString(autn16))
	fmt.Printf("  RES:      %s (from your input)\n", resHex)
	fmt.Printf("  Username: %s\n", username)
	fmt.Printf("  Realm:    %s\n", realm)
	fmt.Printf("  URI:      %s\n", uri)
	fmt.Printf("  Method:   %s\n", method)
	fmt.Println()

	// Calculate digest response using RFC 3310 algorithm
	// HA1 = MD5(username:realm:hex(RES))
	ha1Input := fmt.Sprintf("%s:%s:%s", username, realm, resHex)
	ha1Hash := md5.Sum([]byte(ha1Input))
	ha1 := hex.EncodeToString(ha1Hash[:])

	// HA2 = MD5(method:uri)
	ha2Input := fmt.Sprintf("%s:%s", method, uri)
	ha2Hash := md5.Sum([]byte(ha2Input))
	ha2 := hex.EncodeToString(ha2Hash[:])

	// response = MD5(HA1:nonce:HA2)
	responseInput := fmt.Sprintf("%s:%s:%s", ha1, nonceB64, ha2)
	responseHash := md5.Sum([]byte(responseInput))
	actualResponse := hex.EncodeToString(responseHash[:])

	fmt.Printf("Digest Calculation (RFC 3310):\n")
	fmt.Printf("  HA1 = MD5(%s)\n", ha1Input)
	fmt.Printf("      = %s\n", ha1)
	fmt.Println()
	fmt.Printf("  HA2 = MD5(%s)\n", ha2Input)
	fmt.Printf("      = %s\n", ha2)
	fmt.Println()
	fmt.Printf("  Response = MD5(%s:%s:%s)\n", ha1, nonceB64, ha2)
	fmt.Printf("           = %s\n", actualResponse)
	fmt.Println()

	fmt.Printf("=== COMPARISON ===\n")
	fmt.Printf("  Expected: %s (from closed-source)\n", expectedResponse)
	fmt.Printf("  Actual:   %s (calculated)\n", actualResponse)
	fmt.Println()

	if strings.EqualFold(actualResponse, expectedResponse) {
		fmt.Println("✅ SUCCESS: Responses match!")
		fmt.Println("This means:")
		fmt.Println("  - VoHive's AKA algorithm is CORRECT")
		fmt.Println("  - VoHive's digest calculation is CORRECT")
		fmt.Println("  - The 403 error is NOT caused by incorrect authentication")
		os.Exit(0)
	} else {
		fmt.Println("❌ FAILURE: Responses do NOT match!")
		fmt.Println()
		fmt.Println("Possible causes:")
		fmt.Println("  1. Different SIM card used (different K key)")
		fmt.Println("  2. Wrong RES value extracted from logs")
		fmt.Println("  3. Bug in digest calculation")
		os.Exit(1)
	}
}
