// Copyright 2025 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"testing"

	"github.com/gopacket/gopacket"
)

// TestLinuxSLLOversizedAddress verifies that LinkFlow() gracefully handles
// packets with hardware addresses exceeding MaxEndpointSize (16 bytes).
// Note: To test with the actual pcap file (testdata/linux_sll_oversized_addr.pcapng),
// use an integration test in a separate package to avoid import cycles.

// TestLinuxSLLLinkFlowTruncation directly tests the truncation logic
func TestLinuxSLLLinkFlowTruncation(t *testing.T) {
	tests := []struct {
		name        string
		addrLen     int
		expectPanic bool
	}{
		{"Normal 6-byte MAC", 6, false},
		{"Normal 8-byte addr", 8, false},
		{"Max size 16 bytes", 16, false},
		{"Oversized 20 bytes", 20, false}, // Should NOT panic with fix
		{"Oversized 32 bytes", 32, false}, // Should NOT panic with fix
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a LinuxSLL with an address of the specified length
			sll := &LinuxSLL{
				Addr: make([]byte, tt.addrLen),
			}

			// This should not panic
			defer func() {
				if r := recover(); r != nil {
					if !tt.expectPanic {
						t.Errorf("Unexpected panic: %v", r)
					}
				} else if tt.expectPanic {
					t.Error("Expected panic but none occurred")
				}
			}()

			flow := sll.LinkFlow()

			// Verify endpoints are within limits
			src, dst := flow.Endpoints()
			if len(src.Raw()) > gopacket.MaxEndpointSize {
				t.Errorf("Source endpoint exceeds MaxEndpointSize: %d > %d",
					len(src.Raw()), gopacket.MaxEndpointSize)
			}
			if len(dst.Raw()) > gopacket.MaxEndpointSize {
				t.Errorf("Destination endpoint exceeds MaxEndpointSize: %d > %d",
					len(dst.Raw()), gopacket.MaxEndpointSize)
			}
		})
	}
}

// TestLinuxSLL2LinkFlowTruncation tests LinuxSLL2 truncation logic
func TestLinuxSLL2LinkFlowTruncation(t *testing.T) {
	tests := []struct {
		name        string
		addrLen     int
		expectPanic bool
	}{
		{"Normal 6-byte MAC", 6, false},
		{"Normal 8-byte addr", 8, false},
		{"Max size 16 bytes", 16, false},
		{"Oversized 20 bytes", 20, false}, // Should NOT panic with fix
		{"Oversized 32 bytes", 32, false}, // Should NOT panic with fix
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a LinuxSLL2 with an address of the specified length
			sll := &LinuxSLL2{
				Addr: make([]byte, tt.addrLen),
			}

			// This should not panic
			defer func() {
				if r := recover(); r != nil {
					if !tt.expectPanic {
						t.Errorf("Unexpected panic: %v", r)
					}
				} else if tt.expectPanic {
					t.Error("Expected panic but none occurred")
				}
			}()

			flow := sll.LinkFlow()

			// Verify endpoints are within limits
			src, dst := flow.Endpoints()
			if len(src.Raw()) > gopacket.MaxEndpointSize {
				t.Errorf("Source endpoint exceeds MaxEndpointSize: %d > %d",
					len(src.Raw()), gopacket.MaxEndpointSize)
			}
			if len(dst.Raw()) > gopacket.MaxEndpointSize {
				t.Errorf("Destination endpoint exceeds MaxEndpointSize: %d > %d",
					len(dst.Raw()), gopacket.MaxEndpointSize)
			}
		})
	}
}
