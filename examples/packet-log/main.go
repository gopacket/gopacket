package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
)

func main() {
	var iFace = flag.String("iface", "", "(required) interface to listen on")
	var bpf = flag.String("bpf", "", "(optional) bpf to apply")
	var format = flag.String("format", "json", "one of (text|json)")

	flag.Parse()

	logger := func(format string) *slog.Logger {
		switch format {
		case "text":
			return slog.New(slog.NewTextHandler(os.Stdout, nil))
		case "json":
			return slog.New(slog.NewJSONHandler(os.Stdout, nil))
		default:
			fmt.Printf("Unknown format: %s\nSee flags\n", format)
			flag.PrintDefaults()
			os.Exit(1)
			return nil
		}
	}(*format)

	if *iFace == "" {
		fmt.Println("Interface must be specified, see flags:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	logger.Info("Starting", slog.Group("config", slog.String("interface", *iFace)),
		slog.String("format", *format),
		slog.String("bpf", *bpf))

	handle, err := pcap.OpenLive(*iFace, 1500, true, 30*time.Second)
	if err != nil {
		logger.Error("could not open interface", slog.String("interface", *iFace), slog.String("err", err.Error()))
		os.Exit(1)
	}
	defer handle.Close()
	if *bpf != "" {
		if err := handle.SetBPFFilter(*bpf); err != nil {
			logger.Error("could not set BPF filter", slog.String("err", err.Error()))
			os.Exit(1)
		}
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		logger.Info("New Packet", slog.Any("packetData", packet))
	}
}
