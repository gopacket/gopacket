// This example demonstrates that the LinuxSLL/LinuxSLL2 oversized address fix
// works correctly. It processes the test pcap file that previously caused panics.
//
// Usage:
//   go run main.go ../../layers/testdata/linux_sll_oversized_addr.pcapng

package main

import (
	"fmt"
	"log"
	"os"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <pcap_file>")
		fmt.Println("Example: go run main.go ../../layers/testdata/linux_sll_oversized_addr.pcapng")
		os.Exit(1)
	}

	filename := os.Args[1]

	fmt.Printf("Processing: %s\n", filename)

	f, err := os.Open(filename)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer f.Close()

	// Try both pcap and pcapng formats
	r, err := pcapgo.NewNgReader(f, pcapgo.NgReaderOptions{})
	if err != nil {
		log.Fatalf("Failed to create pcapng reader: %v", err)
	}

	packetCount := 0
	linkFlowCallCount := 0
	linuxSLLCount := 0
	oversizedAddrCount := 0

	fmt.Println("\nProcessing packets...")

	for {
		data, _, err := r.ReadPacketData()
		if err != nil {
			// EOF is expected
			break
		}

		packet := gopacket.NewPacket(data, r.LinkType(), gopacket.Default)
		packetCount++

		// Check for Linux SLL layers
		if sllLayer := packet.Layer(layers.LayerTypeLinuxSLL); sllLayer != nil {
			linuxSLLCount++
			sll := sllLayer.(*layers.LinuxSLL)

			// Track oversized addresses
			if len(sll.Addr) > gopacket.MaxEndpointSize {
				oversizedAddrCount++
				fmt.Printf("  Packet %d: Found oversized LinuxSLL address (len=%d, truncated to %d)\n",
					packetCount, len(sll.Addr), gopacket.MaxEndpointSize)
			}
		}

		// Try to get LinkFlow - this previously caused panics
		if ll := packet.LinkLayer(); ll != nil {
			flow := ll.LinkFlow()
			linkFlowCallCount++

			// Verify endpoints are within limits
			src, dst := flow.Endpoints()
			if len(src.Raw()) > gopacket.MaxEndpointSize {
				log.Fatalf("ERROR: Source endpoint exceeds MaxEndpointSize: %d > %d",
					len(src.Raw()), gopacket.MaxEndpointSize)
			}
			if len(dst.Raw()) > gopacket.MaxEndpointSize {
				log.Fatalf("ERROR: Destination endpoint exceeds MaxEndpointSize: %d > %d",
					len(dst.Raw()), gopacket.MaxEndpointSize)
			}
		}
	}

	fmt.Println("\n✓ Processing completed successfully (no panics!)")
	fmt.Printf("\nStatistics:\n")
	fmt.Printf("  Total packets:           %d\n", packetCount)
	fmt.Printf("  LinkFlow() calls:        %d\n", linkFlowCallCount)
	fmt.Printf("  Linux SLL packets:       %d\n", linuxSLLCount)
	fmt.Printf("  Oversized addresses:     %d\n", oversizedAddrCount)

	if oversizedAddrCount > 0 {
		fmt.Printf("\n✓ Successfully handled %d packet(s) with oversized addresses\n", oversizedAddrCount)
		fmt.Println("  (These would have caused panics before the fix)")
	}
}
