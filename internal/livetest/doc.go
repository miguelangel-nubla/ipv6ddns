// Package livetest is what the live tests share: those that need a real link, between network
// namespaces, and Home Assistant's own libraries at the other end of it. They are built with the
// integration tag, on Linux, and need root and iproute2: tools/live-test.sh runs them from any
// system with Docker.
package livetest
