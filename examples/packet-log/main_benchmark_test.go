package main_test

import (
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
)

func BenchmarkSlog_UDP(b *testing.B) {
	handle, err := pcap.OpenOffline("../../pcap/test_dns.pcap")
	if err != nil {
		b.Fatal(err)
	}
	defer handle.Close()

	// Loop through packets in file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	packet, err := packetSource.NextPacket()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		packet.LogValue()
	}
}

func BenchmarkRawString_UDP(b *testing.B) {
	handle, err := pcap.OpenOffline("../../pcap/test_dns.pcap")
	if err != nil {
		b.Fatal(err)
	}
	defer handle.Close()

	// Loop through packets in file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	packet, err := packetSource.NextPacket()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		packet.String()
	}
}

func BenchmarkSlog_TCP(b *testing.B) {
	handle, err := pcap.OpenOffline("../../pcap/test_ethernet.pcap")
	if err != nil {
		b.Fatal(err)
	}
	defer handle.Close()

	// Loop through packets in file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	packet, err := packetSource.NextPacket()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		packet.LogValue()
	}
}

func BenchmarkRawString_TCP(b *testing.B) {
	handle, err := pcap.OpenOffline("../../pcap/test_ethernet.pcap")
	if err != nil {
		b.Fatal(err)
	}
	defer handle.Close()

	// Loop through packets in file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	packet, err := packetSource.NextPacket()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		packet.String()
	}
}
