// Copyright (c) 2026 SCANOSS
// SPDX-License-Identifier: MIT

package pqcdataset

import (
	"reflect"
	"strings"
	"testing"
)

// A caller that changes a returned family must not change what later calls see.
func TestReturnedFamiliesDoNotShareTheDataset(t *testing.T) {
	mutate := func(f Family) {
		f.Aliases[0] = "CHANGED"
		f.Deadlines[0].MigrateBy = 1
	}
	f, _, _ := Resolve("RSA")
	mutate(f)
	g, _ := Classify(map[string]string{"algorithmFamily": "RSA"})
	mutate(g)
	for _, h := range Families() {
		if h.Name == "RSA" {
			mutate(h)
		}
	}

	got, _, _ := Resolve("RSA")
	if got.Aliases[0] == "CHANGED" || got.Deadlines[0].MigrateBy != 2030 {
		t.Errorf("RSA was changed through a returned value: %+v %v", got.Deadlines, got.Aliases)
	}
}

// Family exposes resolved values, not the file's keys, so dataset.yaml can
// change how rows reference deadlines without breaking callers.
func TestFamilyHidesTheFileFormat(t *testing.T) {
	typ := reflect.TypeFor[Family]()
	for i := range typ.NumField() {
		field := typ.Field(i)
		if field.Tag.Get("yaml") != "" {
			t.Errorf("Family.%s carries a yaml tag", field.Name)
		}
		if strings.HasSuffix(field.Name, "Key") || strings.HasSuffix(field.Name, "Keys") {
			t.Errorf("Family.%s is a file-format key", field.Name)
		}
	}
}
