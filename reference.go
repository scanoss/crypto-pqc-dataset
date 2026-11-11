// Copyright (c) 2026 SCANOSS
// SPDX-License-Identifier: MIT

package pqcdataset

import (
	_ "embed"
	"fmt"
	"sync"

	"go.yaml.in/yaml/v3"
)

// Path is the effort of moving one quantum-vulnerable use to ML-KEM / ML-DSA.
type Path string

// Migration paths, cheapest first.
const (
	Upgrade  Path = "upgrade"
	Swap     Path = "swap"
	Redesign Path = "redesign"
	Blocked  Path = "blocked"
)

// effort orders the paths, cheapest first.
var effort = map[Path]int{Upgrade: 1, Swap: 2, Redesign: 3, Blocked: 4}

// Size is one cited key, ciphertext or signature size.
type Size struct {
	Algorithm string `yaml:"algorithm"`
	Item      string `yaml:"item"`
	Bytes     int    `yaml:"bytes"`
	Citation  string `yaml:"citation"`
}

type pathRule struct {
	Primitive  string   `yaml:"primitive"`
	Operations []string `yaml:"operations"`
	Path       Path     `yaml:"path"`
	Reason     string   `yaml:"reason"`
	Citation   string   `yaml:"citation"`
}

type jwtLibrary struct {
	Library  string   `yaml:"library"`
	Purls    []string `yaml:"purls"`
	Citation string   `yaml:"citation"`
}

type reference struct {
	Paths        []pathRule   `yaml:"paths"`
	Sizes        []Size       `yaml:"sizes"`
	JWTLibraries []jwtLibrary `yaml:"jwt_libraries"`
}

//go:embed migration.yaml
var migrationYAML []byte

var loadReference = sync.OnceValues(func() (*reference, error) { return parseReference(migrationYAML) })

func parseReference(data []byte) (*reference, error) {
	var r reference
	if err := yaml.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("pqcdataset: migration.yaml: %w", err)
	}
	for _, p := range r.Paths {
		if p.Primitive == "" || p.Reason == "" || p.Citation == "" || effort[p.Path] == 0 {
			return nil, fmt.Errorf("pqcdataset: migration.yaml: incomplete path rule %+v", p)
		}
	}
	for _, s := range r.Sizes {
		if s.Algorithm == "" || s.Item == "" || s.Bytes <= 0 || s.Citation == "" {
			return nil, fmt.Errorf("pqcdataset: migration.yaml: incomplete size %+v", s)
		}
	}
	for _, l := range r.JWTLibraries {
		if l.Library == "" || l.Citation == "" {
			return nil, fmt.Errorf("pqcdataset: migration.yaml: incomplete JWT library %+v", l)
		}
	}
	return &r, nil
}

func mustReference() *reference {
	r, err := loadReference()
	if err != nil {
		panic(err) // the data is embedded; a parse failure is a build defect
	}
	return r
}

// Sizes returns the cited key, ciphertext and signature sizes.
func Sizes() []Size {
	return append([]Size(nil), mustReference().Sizes...)
}
