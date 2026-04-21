package layers

import (
	"encoding/hex"
	"net"
	"testing"

	"github.com/gopacket/gopacket"
)

func TestPktapV1_ethernet(t *testing.T) {
	// en10 Google Chrome He:2227 -> 123.117.132.38:443 SYN-ACK (in)
	// Flags=0x00021001 DLT=1(Ethernet) inner=74 bytes
	var raw = "9c0000000100000001000000656e3130000000000000000000000000000000000000000001100200020000000e00000000000000b3080000476f6f676c65204368726f6d65204865000600000000000006000a00b3080000476f6f676c65204368726f6d6520486500000000083d0dbe0000000000000000000000004c4c443655553144a1189540bad5b0580000000000000000000000000000000004d9c809f0168465692d4a8f08004500003c0000400032068ced7b758426ac12102101bbd3d640f76ce1fb022591a012ffff1d0e0000020405840402080a317f0b7c1d22712501030309"
	pr, err := hex.DecodeString(raw)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}

	p := gopacket.NewPacket(pr, LayerTypePktap, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Fatalf("decode error: %v", p.ErrorLayer().Error())
	}

	// --- pktap header ---
	pktapLayer := p.Layer(LayerTypePktap)
	if pktapLayer == nil {
		t.Fatal("LayerTypePktap not found")
	}
	pt := pktapLayer.(*PktapV1)

	if pt.InterfaceName != "en10" {
		t.Errorf("InterfaceName: got %q, want %q", pt.InterfaceName, "en10")
	}
	if pt.DLT != 1 {
		t.Errorf("DLT: got %d, want 1 (Ethernet)", pt.DLT)
	}
	if pt.PID != 2227 {
		t.Errorf("PID: got %d, want 2227", pt.PID)
	}
	if pt.CommandName != "Google Chrome He" {
		t.Errorf("CommandName: got %q, want %q", pt.CommandName, "Google Chrome He")
	}
	if pt.EffectivePID != 2227 {
		t.Errorf("EffectivePID: got %d, want 2227", pt.EffectivePID)
	}
	if pt.EffectiveCommandName != "Google Chrome He" {
		t.Errorf("EffectiveCommandName: got %q, want %q", pt.EffectiveCommandName, "Google Chrome He")
	}
	if pt.Flags != 0x00021001 {
		t.Errorf("Flags: got 0x%08x, want 0x00021001", pt.Flags)
	}
	if pt.Direction() != PTHFlagDirIn {
		t.Errorf("Direction: got %v, want in", pt.Direction())
	}

	// --- Ethernet ---
	ethLayer := p.Layer(LayerTypeEthernet)
	if ethLayer == nil {
		t.Fatal("LayerTypeEthernet not found")
	}
	eth := ethLayer.(*Ethernet)
	if eth.EthernetType != EthernetTypeIPv4 {
		t.Errorf("EthernetType: got %v, want IPv4", eth.EthernetType)
	}

	// --- IPv4 ---
	ipLayer := p.Layer(LayerTypeIPv4)
	if ipLayer == nil {
		t.Fatal("LayerTypeIPv4 not found")
	}
	ip := ipLayer.(*IPv4)
	if !ip.SrcIP.Equal(net.ParseIP("123.117.132.38")) {
		t.Errorf("SrcIP: got %s, want 123.117.132.38", ip.SrcIP)
	}
	if !ip.DstIP.Equal(net.ParseIP("172.18.16.33")) {
		t.Errorf("DstIP: got %s, want 172.18.16.33", ip.DstIP)
	}

	// --- TCP ---
	tcpLayer := p.Layer(LayerTypeTCP)
	if tcpLayer == nil {
		t.Fatal("LayerTypeTCP not found")
	}
	tcp := tcpLayer.(*TCP)
	if tcp.SrcPort != 443 {
		t.Errorf("SrcPort: got %d, want 443", tcp.SrcPort)
	}
	if tcp.DstPort != 54230 {
		t.Errorf("DstPort: got %d, want 54230", tcp.DstPort)
	}
	if !tcp.SYN || !tcp.ACK {
		t.Errorf("TCP flags: got SYN=%v ACK=%v, want SYN=true ACK=true", tcp.SYN, tcp.ACK)
	}
}

func TestPktapV1_utun(t *testing.T) {
	//utun4 Spotify Helper:794
	//11.11.11.11:5228->15.251.130.147:64356
	var testPktapPacketHex = "9c00000001000000000000007574756e3400000000000000000000000000000000000000010002000200000004000000000000001a03000053706f746966792048656c7065720000000000000000000001000400ffffffff000000000000000000000000000000000000000000000000000000000000000000000000d73db7bdb5cc3293a7642307c8beb82f00000000000000000000000000000000020000004500003ca5ac0000400633e50b0b0b0b0ffb8293146cfb6452a1b86d4e2060d0a012720001690000020405b40402080adb52d790a46a123f01030305"
	pr, err := hex.DecodeString(testPktapPacketHex)
	if err != nil {
		t.Errorf("Error decoding hex packet: %v", err)
	}

	p := gopacket.NewPacket(pr, LayerTypePktap, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Errorf("LayerTypePktap: %v", p.ErrorLayer().Error())
	}
	pktapLayer := p.Layer(LayerTypePktap)
	if pktapLayer == nil {
		t.Errorf("LayerTypePktap layer not found")
	}
	pt := pktapLayer.(*PktapV1)
	if pt.InterfaceName != "utun4" {
		t.Errorf("InterfaceName mismatch: got %s", pt.InterfaceName)
	}

	tplayer := p.Layer(LayerTypeTCP)
	if tplayer == nil {
		t.Errorf("LayerTypeTCP layer not found")
	}
	tlayer := tplayer.(*TCP)
	if tlayer.SrcPort != 5228 || tlayer.DstPort != 64356 {
		t.Errorf("TCP port mismatch: got %d, %d", tlayer.SrcPort, tlayer.DstPort)
	}

	iplayer := p.Layer(LayerTypeIPv4)
	if iplayer == nil {
		t.Errorf("LayerTypeIPv4 layer not found")
	}
	ilayer := iplayer.(*IPv4)
	if ilayer.SrcIP.String() != "11.11.11.11" {
		t.Errorf("SrcIP mismatch: got %s", ilayer.SrcIP.String())
	}
}
