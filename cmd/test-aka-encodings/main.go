package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strings"
)

func main() {
	nonceB64 := "k8ftfd3xgpGDj9YlGJNvvgPf3LDRIwAAWwvdSjjP5qM="
	realm := "epc.mnc007.mcc262.3gppnetwork.org"
	username := "262036013159494@ims.mnc003.mcc262.3gppnetwork.org"
	uri := "sip:ims.mnc003.mcc262.3gppnetwork.org"
	method := "REGISTER"
	resHex := "7af52aa75750c993"
	expectedResponse := "9a92745f3a332b2e07375658900f383b"

	fmt.Println("=== Testing different RES encodings ===")
	fmt.Println()

	// Test 1: RES as hex string (current implementation)
	fmt.Println("Test 1: RES as hex string")
	ha1Input := fmt.Sprintf("%s:%s:%s", username, realm, resHex)
	ha1Hash := md5.Sum([]byte(ha1Input))
	ha1 := hex.EncodeToString(ha1Hash[:])

	ha2Input := fmt.Sprintf("%s:%s", method, uri)
	ha2Hash := md5.Sum([]byte(ha2Input))
	ha2 := hex.EncodeToString(ha2Hash[:])

	responseInput := fmt.Sprintf("%s:%s:%s", ha1, nonceB64, ha2)
	responseHash := md5.Sum([]byte(responseInput))
	response1 := hex.EncodeToString(responseHash[:])

	fmt.Printf("  HA1 input: %s\n", ha1Input)
	fmt.Printf("  Response: %s\n", response1)
	fmt.Printf("  Match: %v\n", response1 == expectedResponse)
	fmt.Println()

	// Test 2: RES as uppercase hex string
	fmt.Println("Test 2: RES as uppercase hex string")
	resHexUpper := strings.ToUpper(resHex)
	ha1Input2 := fmt.Sprintf("%s:%s:%s", username, realm, resHexUpper)
	ha1Hash2 := md5.Sum([]byte(ha1Input2))
	ha12 := hex.EncodeToString(ha1Hash2[:])

	responseInput2 := fmt.Sprintf("%s:%s:%s", ha12, nonceB64, ha2)
	responseHash2 := md5.Sum([]byte(responseInput2))
	response2 := hex.EncodeToString(responseHash2[:])

	fmt.Printf("  HA1 input: %s\n", ha1Input2)
	fmt.Printf("  Response: %s\n", response2)
	fmt.Printf("  Match: %v\n", response2 == expectedResponse)
	fmt.Println()

	// Test 3: RES as raw bytes
	fmt.Println("Test 3: RES as raw bytes (binary)")
	resBytes, _ := hex.DecodeString(resHex)
	ha1Input3 := username + ":" + realm + ":" + string(resBytes)
	ha1Hash3 := md5.Sum([]byte(ha1Input3))
	ha13 := hex.EncodeToString(ha1Hash3[:])

	responseInput3 := fmt.Sprintf("%s:%s:%s", ha13, nonceB64, ha2)
	responseHash3 := md5.Sum([]byte(responseInput3))
	response3 := hex.EncodeToString(responseHash3[:])

	fmt.Printf("  HA1 input: %s (bytes as string)\n", "username:realm:<binary_res>")
	fmt.Printf("  Response: %s\n", response3)
	fmt.Printf("  Match: %v\n", response3 == expectedResponse)
	fmt.Println()

	// Test 4: Different realm or username
	fmt.Println("Test 4: Check if realm is different")
	realm2 := "ims.mnc003.mcc262.3gppnetwork.org" // Different realm
	ha1Input4 := fmt.Sprintf("%s:%s:%s", username, realm2, resHex)
	ha1Hash4 := md5.Sum([]byte(ha1Input4))
	ha14 := hex.EncodeToString(ha1Hash4[:])

	responseInput4 := fmt.Sprintf("%s:%s:%s", ha14, nonceB64, ha2)
	responseHash4 := md5.Sum([]byte(responseInput4))
	response4 := hex.EncodeToString(responseHash4[:])

	fmt.Printf("  HA1 input: %s:%s:%s\n", username, realm2, resHex)
	fmt.Printf("  Response: %s\n", response4)
	fmt.Printf("  Match: %v\n", response4 == expectedResponse)
	fmt.Println()

	fmt.Println("=== Summary ===")
	fmt.Printf("Expected: %s\n", expectedResponse)
	fmt.Printf("Test 1 (hex lowercase): %s - %v\n", response1, response1 == expectedResponse)
	fmt.Printf("Test 2 (hex uppercase): %s - %v\n", response2, response2 == expectedResponse)
	fmt.Printf("Test 3 (binary RES): %s - %v\n", response3, response3 == expectedResponse)
	fmt.Printf("Test 4 (different realm): %s - %v\n", response4, response4 == expectedResponse)
}
