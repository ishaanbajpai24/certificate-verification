package main

import (
	"testing"
	"fmt"
)
// Correctly structured test data
var mockOIDsExist = getOIDs("./certs/github.com.cer")

// Correct descriptions for OIDs
var oids = map[string]string{
	"2.5.29.17": "Subject Alternative Name", // Use real descriptions as needed
}

// Target byte values for OIDs
var targetByteValues = map[string][]byte{
	"2.5.29.17": []byte{48, 28, 130, 10, 103, 105, 116, 104, 117, 98, 46, 99, 111, 109, 130, 14, 119, 119, 119, 46, 103, 105, 116, 104, 117, 98, 46, 99, 111, 109}, // Assuming this is the correct byte array for this OID
}

var wrongTargetByteValues = map[string][]byte{
	"2.5.29.17": []byte{4, 5, 6}, // Wrong value to trigger an error in test
}

func TestSomething(t *testing.T) {
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
	oidValues := getOIDs("./certs/github.com.cer")
	err := ApplyPolicy(oidValues, oids, targetByteValues)

	if err != nil {
		fmt.Println(err)
	}
}

func TestAnotherCert(t *testing.T) {
	oids := map[string]string{
		"2.5.29.17": "Subject Alternative Name",
	}
	// Sample target byte values for each enumerated OID
	targetByteValues := map[string][]byte{
		"2.5.29.17": []byte{70, 71, 72},
	}
	oidValues := getOIDs("./certs/github.com.cer")
	err := ApplyPolicy(oidValues, oids, targetByteValues)

	if err != nil {
		fmt.Println(err)
	}

}



func TestOIDExists(t *testing.T) {
	
	err := ApplyPolicy(mockOIDsExist, oids, targetByteValues)
	if err != nil {
		t.Errorf("OID exists: Expected no error for existing OID with correct value, got: %s", err)
	}
}

func TestOIDExistsWithWrongValue(t *testing.T) {
	err := ApplyPolicy(mockOIDsExist, oids, wrongTargetByteValues)
	if err == nil {
		t.Error("OID exists with wrong value: Expected an error for existing OID with wrong value, got none")
	}
}

func TestOIDDoesNotExist(t *testing.T) {
	
	mockOIDsMissing := map[string][]byte{
		"2.5.29.14": []byte{1, 2, 3}, // Present
	}
	missingOIDs := map[string]string{
		"1.3.6.1.4.1.99999": "Nonexistent OID", // This OID is intended to not exist in 'mockOIDsMissing'
	}

	err := ApplyPolicy(mockOIDsMissing, missingOIDs, targetByteValues) // Using 'targetByteValues' for simplicity
	if err == nil {
		t.Error("OID does not exist: Expected an error for non-existent OID, got none")
	}
}

