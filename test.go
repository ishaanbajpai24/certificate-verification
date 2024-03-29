package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func main() {
	// OID descriptions
	oids := map[string]string{
		"1.3.6.1.4.1.57264.1":    "Fulcio",
		"1.3.6.1.4.1.57264.1.1":  "Issuer (deprecated)",
		"1.3.6.1.4.1.57264.1.2":  "GitHub Workflow Trigger (deprecated)",
		"1.3.6.1.4.1.57264.1.3":  "GitHub Workflow SHA (deprecated)",
		"1.3.6.1.4.1.57264.1.4":  "GitHub Workflow Name (deprecated)",
		"1.3.6.1.4.1.57264.1.5":  "GitHub Workflow Repository (deprecated)",
		"1.3.6.1.4.1.57264.1.6":  "GitHub Workflow Ref (deprecated)",
		"1.3.6.1.4.1.57264.1.7":  "OtherName SAN",
		"1.3.6.1.4.1.57264.1.8":  "Issuer (V2)",
		"1.3.6.1.4.1.57264.1.9":  "Build Signer URI",
		"1.3.6.1.4.1.57264.1.10": "Build Signer Digest",
		"1.3.6.1.4.1.57264.1.11": "Runner Environment",
		"1.3.6.1.4.1.57264.1.12": "Source Repository URI",
		"1.3.6.1.4.1.57264.1.13": "Source Repository Digest",
		"1.3.6.1.4.1.57264.1.14": "Source Repository Ref",
		"1.3.6.1.4.1.57264.1.15": "Source Repository Identifier",
		"1.3.6.1.4.1.57264.1.16": "Source Repository Owner URI",
		"1.3.6.1.4.1.57264.1.17": "Source Repository Owner Identifier",
		"1.3.6.1.4.1.57264.1.18": "Build Config URI",
		"1.3.6.1.4.1.57264.1.19": "Build Config Digest",
		"1.3.6.1.4.1.57264.1.20": "Build Trigger",
		"1.3.6.1.4.1.57264.1.21": "Run Invocation URI",
		"1.3.6.1.4.1.57264.1.22": "Source Repository Visibility At Signing",
		"1.3.6.1.4.1.57264.2":    "Policy OID for Sigstore Timestamp Authority",
	}

	// Sample target byte values for each enumerated OID
	targetByteValues := map[string][]byte{
		"1.3.6.1.4.1.57264.1":    []byte{1, 2, 3},
		"1.3.6.1.4.1.57264.1.1":  []byte{4, 5, 6},
		"1.3.6.1.4.1.57264.1.2":  []byte{7, 8, 9},
		"1.3.6.1.4.1.57264.1.3":  []byte{10, 11, 12},
		"1.3.6.1.4.1.57264.1.4":  []byte{13, 14, 15},
		"1.3.6.1.4.1.57264.1.5":  []byte{16, 17, 18},
		"1.3.6.1.4.1.57264.1.6":  []byte{19, 20, 21},
		"1.3.6.1.4.1.57264.1.7":  []byte{22, 23, 24},
		"1.3.6.1.4.1.57264.1.8":  []byte{25, 26, 27},
		"1.3.6.1.4.1.57264.1.9":  []byte{28, 29, 30},
		"1.3.6.1.4.1.57264.1.10": []byte{31, 32, 33},
		"1.3.6.1.4.1.57264.1.11": []byte{34, 35, 36},
		"1.3.6.1.4.1.57264.1.12": []byte{37, 38, 39},
		"1.3.6.1.4.1.57264.1.13": []byte{40, 41, 42},
		"1.3.6.1.4.1.57264.1.14": []byte{43, 44, 45},
		"1.3.6.1.4.1.57264.1.15": []byte{46, 47, 48},
		"1.3.6.1.4.1.57264.1.16": []byte{49, 50, 51},
		"1.3.6.1.4.1.57264.1.17": []byte{52, 53, 54},
		"1.3.6.1.4.1.57264.1.18": []byte{55, 56, 57},
		"1.3.6.1.4.1.57264.1.19": []byte{58, 59, 60},
		"1.3.6.1.4.1.57264.1.20": []byte{61, 62, 63},
		"1.3.6.1.4.1.57264.1.21": []byte{64, 65, 66},
		"1.3.6.1.4.1.57264.1.22": []byte{67, 68, 69},
		"1.3.6.1.4.1.57264.2":    []byte{70, 71, 72},
	}

	data, err := os.ReadFile("./certs/github.com.cer")
	if err == nil {
		block, _ := pem.Decode(data)
		certificate, _ := x509.ParseCertificate(block.Bytes)

		// Collect OIDs and their values
		oidValues := make(map[string][]byte)
		for _, ext := range certificate.Extensions {
			oidValues[ext.Id.String()] = ext.Value
		}

		// Check if OIDs match and compare values
		for oid, desc := range oids {
			value, ok := oidValues[oid]
			fmt.Printf("OID: %s (%s)\n", oid, desc)
			if ok {
				// Compare value with sample target byte value
				targetValue, found := targetByteValues[oid]
				if found {
					fmt.Printf("Match determination: %t\n", compareValue(value, targetValue))
				} else {
					fmt.Println("No sample target byte value found for this OID.")
				}
			} else {
				fmt.Println("OID not present in the certificate.")
			}
			fmt.Println()
		}
	}

	if err != nil {
		fmt.Println(err)
	}
}

// compareValue compares two byte arrays for equality
func compareValue(value []byte, target []byte) bool {
	if len(value) != len(target) {
		return false
	}
	for i := range value {
		if value[i] != target[i] {
			return false
		}
	}
	return true
}
