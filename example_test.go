// Copyright (c) 2026 SCANOSS
// SPDX-License-Identifier: MIT

package pqcdataset_test

import (
	"fmt"

	pqcdataset "github.com/scanoss/crypto-pqc-dataset"
)

func ExampleClassify() {
	family, ok := pqcdataset.Classify(map[string]string{"algorithmFamily": "RSAES-OAEP"})
	if !ok {
		return
	}
	nist, _ := family.Deadline(pqcdataset.SourceNISTIR8547)
	earliest, _ := family.EarliestDeadline()
	fmt.Println(family.Name, family.PQCStatus, nist.DeprecatedAfter, nist.DisallowedAfter, earliest)
	// Output: RSA vulnerable 2030 2035 2030
}

func ExampleClassify_algorithmName() {
	// CycloneDX has no RSA family, so a finding may only name the algorithm.
	family, _ := pqcdataset.Classify(map[string]string{"algorithmName": "RSA-PKCS1v15-SHA256"})
	fmt.Println(family.Name, family.PQCStatus)
	// Output: RSA vulnerable
}

func ExampleStatusOf() {
	for _, spelling := range []string{"ECDSA", "ML-KEM-768", "SLH-DSA", "X-Wing", "HMAC", "HPKE"} {
		fmt.Println(spelling, pqcdataset.StatusOf(spelling))
	}
	// Output:
	// ECDSA vulnerable
	// ML-KEM-768 safe
	// SLH-DSA safe
	// X-Wing hybrid
	// HMAC not_applicable
	// HPKE unassessed
}

func ExampleResolve() {
	for _, spelling := range []string{"rsassa_pss", "RSA-2048", "RIPEMD-128"} {
		family, parameter, ok := pqcdataset.Resolve(spelling)
		fmt.Println(spelling, family.Name, parameter, ok)
	}
	// Output:
	// rsassa_pss RSA 0 true
	// RSA-2048 RSA 2048 true
	// RIPEMD-128  0 false
}
