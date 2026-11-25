package layers_test

import (
	"os"
	"slices"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestDHCPv4CaptivePortalPcap(t *testing.T) {
	// Frames 2 and 4 from MikroTik Dojo's published Ethernet capture.
	// https://mikrotikdojo.com/wp-content/uploads/2026/10/hotspot-ssl-opt114.pcap
	capture, err := os.Open("testdata/dhcpv4-captive-portal.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	defer capture.Close()

	reader, err := pcapgo.NewNgReader(capture, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		t.Fatal(err)
	}

	const wantURI = "https://hotspot.mikrotikdojo.com/api"
	for _, wantMessage := range []layers.DHCPMsgType{layers.DHCPMsgTypeOffer, layers.DHCPMsgTypeAck} {
		data, _, err := reader.ReadPacketData()
		if err != nil {
			t.Fatalf("read DHCP %s packet: %v", wantMessage, err)
		}
		packet := gopacket.NewPacket(data, reader.LinkType(), gopacket.Default)
		if errLayer := packet.ErrorLayer(); errLayer != nil {
			t.Fatalf("decode DHCP %s packet: %v", wantMessage, errLayer.Error())
		}
		dhcp, ok := packet.Layer(layers.LayerTypeDHCPv4).(*layers.DHCPv4)
		if !ok {
			t.Fatalf("expected DHCP %s layer in captured packet", wantMessage)
		}
		if !slices.ContainsFunc(dhcp.Options, func(option layers.DHCPOption) bool {
			return option.Type == layers.DHCPOptMessageType && len(option.Data) == 1 &&
				layers.DHCPMsgType(option.Data[0]) == wantMessage
		}) {
			t.Errorf("expected DHCP %s message, got options %v", wantMessage, dhcp.Options)
		}
		index := slices.IndexFunc(dhcp.Options, func(option layers.DHCPOption) bool {
			return option.Type == layers.DHCPOptCaptivePortal
		})
		if index < 0 {
			t.Errorf("DHCP %s has no Captive Portal option", wantMessage)
			continue
		}
		if got := string(dhcp.Options[index].Data); got != wantURI {
			t.Errorf("DHCP %s Captive Portal URI = %q, want %q", wantMessage, got, wantURI)
		}
	}
}
