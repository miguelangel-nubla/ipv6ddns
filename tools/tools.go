//go:build tools

// Package main keeps in go.mod the modules that generated code uses: the generated files are not
// committed, so go mod tidy, which Dependabot runs, would drop them otherwise.
package main

import (
	// The generator of ddns/gravity/client.gen.go.
	_ "github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen"
	// What ddns/gravity/client.gen.go imports.
	_ "github.com/oapi-codegen/runtime"
)
