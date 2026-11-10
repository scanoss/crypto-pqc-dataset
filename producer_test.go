package pqcdataset

import "testing"

// The metadata maps detection rules emit, whole. Each field resolves right on
// its own; what this pins is how Classify reads them together.
func TestClassifyProducerMetadata(t *testing.T) {
	cases := []struct {
		name     string
		metadata map[string]string
		family   string
		status   Status
	}{
		// Hybrid TLS key-exchange groups: the post-quantum half as the family,
		// the pair as the name, the classical half on its own.
		{"X25519MLKEM768 group", map[string]string{"algorithmFamily": "ML-KEM", "algorithmName": "X25519MLKEM768", "classicalAlgorithm": "X25519"}, "X25519MLKEM768", Hybrid},
		{"SecP256r1MLKEM768 group", map[string]string{"algorithmFamily": "ML-KEM", "algorithmName": "SecP256r1MLKEM768", "classicalAlgorithm": "SecP256r1"}, "SecP256r1MLKEM768", Hybrid},
		{"SecP384r1MLKEM1024 group", map[string]string{"algorithmFamily": "ML-KEM", "algorithmName": "SecP384r1MLKEM1024", "classicalAlgorithm": "SecP384r1"}, "SecP384r1MLKEM1024", Hybrid},
		{"hybrid group, no classical key", map[string]string{"algorithmFamily": "ML-KEM", "algorithmName": "X25519MLKEM768"}, "X25519MLKEM768", Hybrid},
		{"hybrid group, OpenSSL spelling", map[string]string{"algorithmFamily": "ML-KEM", "algorithmName": "X25519_MLKEM768"}, "X25519MLKEM768", Hybrid},
		{"hybrid group, draft name", map[string]string{"algorithmFamily": "ML-KEM", "algorithmName": "X25519Kyber768Draft00"}, "X25519MLKEM768", Hybrid},
		{"unnamed pair, classical key only", map[string]string{"algorithmFamily": "ML-KEM", "algorithmName": "MLKEM768", "classicalAlgorithm": "X25519"}, hybridFamily, Hybrid},

		// Pure post-quantum stays safe.
		{"pure ML-KEM group", map[string]string{"algorithmFamily": "ML-KEM", "algorithmName": "MLKEM768"}, "ML-KEM", Safe},
		{"pure ML-KEM parameter set", map[string]string{"algorithmFamily": "ML-KEM", "algorithmName": "ML-KEM-768"}, "ML-KEM", Safe},
		{"ML-DSA signature", map[string]string{"algorithmFamily": "ML-DSA", "algorithmName": "ML-DSA-65"}, "ML-DSA", Safe},
		{"classical key that is not a public-key algorithm", map[string]string{"algorithmFamily": "ML-KEM", "algorithmName": "ML-KEM-768", "classicalAlgorithm": "SHA-256"}, "ML-KEM", Safe},

		// Composite KEMs named without a family.
		{"X-Wing", map[string]string{"algorithmName": "X-Wing"}, "X-Wing", Hybrid},
		{"composite ML-KEM over P-256", map[string]string{"algorithmName": "ML-KEM-768-P256"}, "Composite-ML-KEM", Hybrid},
		{"KitchenSink composite", map[string]string{"algorithmName": "KitchenSink-ML-KEM-768-X25519"}, "Composite-ML-KEM", Hybrid},

		// Classical findings keep their verdict.
		{"RSA encryption scheme", map[string]string{"algorithmFamily": "RSAES-OAEP", "algorithmName": "RSA-OAEP"}, "RSA", Vulnerable},
		{"X25519 key agreement", map[string]string{"algorithmFamily": "ECDH", "algorithmName": "X25519"}, "ECDH", Vulnerable},
		{"key material", map[string]string{"materialAlgorithm": "RSA"}, "RSA", Vulnerable},
		{"certificate signature", map[string]string{"certificateAlgorithm": "sha256WithRSAEncryption"}, "RSA", Vulnerable},
		{"symmetric cipher", map[string]string{"algorithmFamily": "AES", "algorithmName": "AES-256-GCM"}, "AES", NotApplicable},
		{"hash", map[string]string{"algorithmFamily": "SHA-2", "algorithmName": "SHA-256"}, "SHA-2", NotApplicable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, ok := Classify(tc.metadata)
			if !ok {
				t.Fatalf("Classify(%v) is unassessed, want %s %s", tc.metadata, tc.family, tc.status)
			}
			if f.Name != tc.family || f.PQCStatus != tc.status {
				t.Errorf("Classify(%v) = %s %s, want %s %s", tc.metadata, f.Name, f.PQCStatus, tc.family, tc.status)
			}
		})
	}
}
