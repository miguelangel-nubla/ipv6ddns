//go:build tools

// Package main keeps in go.mod the generator of the generated code, which nothing else imports:
// go mod tidy, which Dependabot runs, would drop it otherwise.
package main

import (
	// The generator of ddns/gravity/client.gen.go.
	_ "github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen"
	// What ddns/gravity/client.gen.go imports.
	_ "github.com/oapi-codegen/runtime"
)
