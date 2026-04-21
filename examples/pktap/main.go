// pktapdemo is a pure Go implementation of pktap metadata extraction,
// equivalent to the C demo pktap_meta_demo.c.
// It demonstrates parsing pktap v1 and v2 headers from DLT_PKTAP captures.
//
// Usage:
//
//	pktapdemo -i <interface>   live capture (macOS: uses pktap mode automatically)
//	pktapdemo -c <count>       max packet count (default 5)
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

const (
	pthFlagDirIn  uint32 = 0x00000001
	pthFlagDirOut uint32 = 0x00000002
)

// =============================================================================
// Utility functions
// =============================================================================

func readLE16(b []byte) uint16 {
	return uint16(b[0]) | (uint16(b[1]) << 8)
}

func readLE32(b []byte) uint32 {
	return uint32(b[0]) | (uint32(b[1]) << 8) | (uint32(b[2]) << 16) | (uint32(b[3]) << 24)
}

func svcToString(svc uint32) string {
	switch svc {
	case 0:
		return "BK_SYS"
	case 1:
		return "BK"
	case 2:
		return "BE"
	case 3:
		return "RD"
	case 4:
		return "OAM"
	case 5:
		return "AV"
	case 6:
		return "RV"
	case 7:
		return "VI"
	case 8:
		return "VO"
	case 9:
		return "CTL"
	default:
		return "UNK"
	}
}

// =============================================================================
// Print pktap v1 metadata (raw byte parsing, platform-independent)
// =============================================================================

func printPktapV1(data []byte, caplen int) {
	if caplen < 156 {
		fmt.Fprintf(os.Stderr, "  [too short for v1 header: %d < 156]\n", caplen)
		return
	}

	hdrlen := readLE32(data[0:4])
	fmt.Println(hdrlen)
	if int(hdrlen) > caplen || hdrlen < 156 {
		fmt.Fprintf(os.Stderr, "  [invalid pkt_len: %d]\n", hdrlen)
		return
	}
	pth_type_next := readLE32(data[4:8])
	fmt.Println(pth_type_next)

	flags := readLE32(data[0x24:0x28])
	innerDLT := int(readLE32(data[0x08:0x0c]))
	pid := readLE32(data[0x34:0x38])
	epid := readLE32(data[0x54:0x58])
	svc := readLE32(data[0x4c:0x50])
	iftype := readLE16(data[0x50:0x52])
	ifunit := readLE16(data[0x52:0x54])

	var ifname, cmdname, ecmdname string
	if idx := bytes.IndexByte(data[0x0c:0x24], 0); idx >= 0 {
		ifname = string(data[0x0c : 0x0c+idx])
	}
	if idx := bytes.IndexByte(data[0x38:0x4c], 0); idx >= 0 {
		cmdname = string(data[0x38 : 0x38+idx])
	}
	if idx := bytes.IndexByte(data[0x58:0x6c], 0); idx >= 0 {
		ecmdname = string(data[0x58 : 0x58+idx])
	}

	fmt.Printf("(")
	fmt.Printf("%s %d %d", ifname, iftype, ifunit)
	fmt.Printf(", proc %s:%d", cmdname, pid)
	fmt.Printf(", eproc %s:%d", ecmdname, epid)
	fmt.Printf(", svc %s", svcToString(svc))

	if flags&pthFlagDirIn != 0 {
		fmt.Printf(", in")
	} else if flags&pthFlagDirOut != 0 {
		fmt.Printf(", out")
	}

	if flags&^3 != 0 {
		fmt.Printf(", flags 0x%08x", flags)
	}

	fmt.Printf(", inner_DLT %d) ", innerDLT)

	innerLen := caplen - int(hdrlen)
	fmt.Printf("[inner %d bytes]\n", innerLen)
}

// =============================================================================
// printPacket prints decoded layers from a gopacket.Packet
// =============================================================================

func printPacket(packet gopacket.Packet) {
	if pktapLayer := packet.Layer(layers.LayerTypePktap); pktapLayer != nil {
		pt := pktapLayer.(*layers.PktapV1)
		fmt.Printf("[PKTAP] Interface: %s | PID: %d | App: %s | Inner_DLT: %d\n",
			pt.InterfaceName, pt.PID, pt.CommandName, pt.DLT)
	}

	if eth := packet.Layer(layers.LayerTypeEthernet); eth != nil {
		layer, _ := eth.(*layers.Ethernet)
		fmt.Printf("[Ethernet] Client MAC: %s | Server MAC: %s\n", layer.SrcMAC, layer.DstMAC)
	}

	if tplayer := packet.Layer(layers.LayerTypeTCP); tplayer != nil {
		layer, _ := tplayer.(*layers.TCP)
		fmt.Printf("[TCP] Client Port: %d | Server Port: %d\n", layer.SrcPort, layer.DstPort)
	}

	if iplayer := packet.Layer(layers.LayerTypeIPv4); iplayer != nil {
		layer, _ := iplayer.(*layers.IPv4)
		fmt.Printf("[IP] Client IP: %s | Server IP: %s\n", layer.SrcIP, layer.DstIP)
	}
}

// =============================================================================
// Main
// =============================================================================

func main() {
	var device string
	var maxCount int = 5

	flag.StringVar(&device, "i", "any", "interface (use 'any' or 'pktap' on macOS)")
	flag.IntVar(&maxCount, "c", 5, "max packet count")
	flag.Parse()

	// On macOS, normalise device name to "pktap" so the kernel wraps
	// packets with pktap v1 metadata (process info, direction, etc.).
	deviceArg := device
	if runtime.GOOS == "darwin" {
		if device == "any" || device == "all" || strings.HasPrefix(device, "pktap") {
			deviceArg = "pktap"
		}
	}

	inactive, err := pcap.NewInactiveHandle(deviceArg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pcap.NewInactiveHandle(%s): %v\n", deviceArg, err)
		os.Exit(1)
	}
	defer inactive.CleanUp()

	if err := inactive.SetSnapLen(1514); err != nil {
		fmt.Fprintf(os.Stderr, "SetSnapLen: %v\n", err)
		os.Exit(1)
	}
	if err := inactive.SetPromisc(false); err != nil {
		fmt.Fprintf(os.Stderr, "SetPromisc: %v\n", err)
		os.Exit(1)
	}
	if err := inactive.SetTimeout(time.Second); err != nil {
		fmt.Fprintf(os.Stderr, "SetTimeout: %v\n", err)
		os.Exit(1)
	}

	// SetWantPktap requests pktap v1 metadata headers on macOS.
	// On other platforms the method is a no-op provided by pcap_notdarwin.go.
	if err := inactive.SetWantPktap(true); err != nil {
		fmt.Fprintf(os.Stderr, "SetWantPktap: %v\n", err)
		os.Exit(1)
	}

	handle, err := inactive.Activate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Activate: %v\n", err)
		os.Exit(1)
	}
	defer handle.Close()

	dlt := handle.LinkType()
	fmt.Printf("DLT: %d (%s)\n", int(dlt), pcap.DatalinkValToName(int(dlt)))
	fmt.Printf("listening on %s, link-type %s (%s), capture size %d bytes\n\n",
		device, pcap.DatalinkValToName(int(dlt)), pcap.DatalinkValToName(int(dlt)), handle.SnapLen())

	count := 0
	for count < maxCount {
		data, ci, err := handle.ReadPacketData()
		if err != nil {
			fmt.Fprintf(os.Stderr, "ReadPacketData: %v\n", err)
			break
		}

		ts := ci.Timestamp
		fmt.Printf("%02d:%02d:%02d.%06d ", ts.Hour(), ts.Minute(), ts.Second(), ts.Nanosecond()/1000)

		if dlt == layers.LinkTypeApplePKTAP {
			printPktapV1(data, len(data))
		} else {
			fmt.Printf("[DLT: %s (%d), %d bytes]\n", pcap.DatalinkValToName(int(dlt)), int(dlt), len(data))
		}

		count++
	}

	fmt.Printf("\n%d packets captured\n", count)

	//count := 0
	//packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	//for packet := range packetSource.Packets() {
	//	printPacket(packet)
	//	count++
	//	if maxCount > 0 && count >= maxCount {
	//		break
	//	}
	//}
}
