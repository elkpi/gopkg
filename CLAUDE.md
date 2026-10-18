# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

`gopkg` (`github.com/elkpi/gopkg`) is a high-performance, low-dependency Go infrastructure library designed for network penetration, high-performance gateways, security redaction, and low-level Linux systems programming.

## Common Development Commands

### Building and Testing

```bash
# Run all tests across the repository without cache
go test -v -count=1 ./...

# Run tests in a specific package
go test -v -count=1 ./net/portmapper/...

# Run a specific test function
go test -v -run TestPortMapper_PCP_Priority ./net/portmapper

# Run Go static analysis
go vet ./...

# Format all Go source files according to standard idiom
gofmt -s -w .
```

*Note on race detection:* On this environment (Linux ARM64 Android kernel with 39-bit VMA), ThreadSanitizer does not support 39-bit VMA and requires 48-bit VMA. Use `go test -v -count=1 ./...` for local test regression.

## Architecture and Core Principles

### Core Design Constraints
1. **Zero Large External Dependencies**: Rely strictly on the Go standard library (with `golang.org/x/sys` permitted for raw Linux syscalls). Never introduce heavy third-party packages.
2. **Minimal Memory Allocations**: Hot paths (QoS packet calculation, underlay socket I/O, secret redaction regex compilation) must minimize heap allocations.
3. **Strict RFC Compliance**: Every protocol implementation strictly conforms to corresponding RFCs with typed error mapping and boundary validation.
4. **Cross-Platform Compilability**: Linux-specific features (such as `SO_MARK`, `IP_TTL` OOB injection, `/proc/net/route` parsing) must be guarded with `//go:build linux`. Corresponding non-Linux fallbacks or stubs (`//go:build !linux`) must be provided to ensure the repository cleanly compiles across all platforms.

### Foundational Pillars

- **`net/qos` (RFC 6298-style & RFC 3550-style Network Telemetry)**:
  - High-precision sliding window quality accumulator.
  - Computes EWMA smoothed RTT (RFC 6298-style, deliberately tuned α=0.2 instead of the RFC's 1/8), mean deviation jitter (RFC 3550-style), and real-time packet loss rates (`LossRate`). Thread-safe with low allocation overhead.

- **`net/underlay` (Linux Low-Level Socket Manipulation)**:
  - Linux `SO_MARK` socket isolation factory for policy-based routing.
  - Per-packet OOB TTL injection (`SendUDPWithTTL`) using ancillary control messages (`IP_TTL` / `IPV6_UNICAST_HOPS`) on a single UDP socket without altering global socket options.
  - Destination safety prefix checking to prevent overlay address loopbacks.

- **`net/portmapper` (Gateway Port Mapping Suite)**:
  - Comprehensive NAT-PMP (RFC 6886, UDP 5351 unicast), PCP (RFC 6887, UDP 5351 unicast with IPv4-mapped IPv6 and 12-byte nonces), and UPnP IGD (SSDP multicast + SOAP XML control point).
  - High-level orchestration API (`Discover`, `DiscoverProtocol`) with automatic Linux route table (`/proc/net/route`) gateway detection.
  - Tiered concurrent probing mechanism (PCP/PMP unicast prioritized for millisecond response, UPnP as fallback).
  - Background automatic lease renewal (`AutoRenew`) and explicit teardown (`Release`, `ReleaseAll`).
  - Standalone mock gateway test suite (`MockGateway`) for hermetic offline regression.

- **`security/securelog` (Recursive Secret Redaction Engine)**:
  - Standard library recursive secret scrubber.
  - Automatically derives all standard encodings (raw, Base64, RawBase64, Hex, JSON-escaped, URL-query/path escaped) from sensitive tokens or byte slices and sanitizes matches to `[REDACTED]`.

## Git Commit & Engineering Conventions

- **Fine-Grained Commits**: Keep commits atomic and isolated by component so they can be cleanly cherry-picked across branches. Do not mix unrelated refactoring with feature or bugfix changes.
- **Symlink Contract**: Every update or generation of `CLAUDE.md` must maintain a root symbolic link `AGENTS.md -> CLAUDE.md`.
