package pcap

import (
	"context"
	"io"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// Native crashes and blocked Close calls must not kill or hang the test runner.
func TestCloseLifecycle(t *testing.T) {
	if os.Getenv("GOPACKET_CLOSE_CHILD") == "1" {
		t.Log(Version())
		for i := 0; i < 100; i++ {
			bpf, err := NewBPF(layers.LinkTypeEthernet, 65535, "ether proto 0x0800")
			if err != nil {
				t.Fatal(err)
			}
			packet := make([]byte, 60)
			packet[12] = 8
			ci := gopacket.CaptureInfo{CaptureLength: len(packet), Length: len(packet)}
			if !bpf.Matches(ci, packet) {
				t.Fatal("IPv4 packet did not match")
			}
			packet[13] = 6
			if bpf.Matches(ci, packet) {
				t.Fatal("ARP packet matched IPv4")
			}
			if _, err := CompileBPFFilter(layers.LinkTypeEthernet, 65535, "ip"); err != nil {
				t.Fatal(err)
			}
			if _, err := NewBPF(layers.LinkTypeEthernet, 65535, "invalid filter ("); err == nil {
				t.Fatal("invalid filter accepted")
			}
			h, err := pcapOpenDead(layers.LinkTypeEthernet, 65535)
			if err != nil {
				t.Fatal(err)
			}
			closeConcurrently(h)
		}
		f, err := os.CreateTemp(t.TempDir(), "offline-*.pcap")
		if err != nil {
			t.Fatal(err)
		}
		w := pcapgo.NewWriter(f)
		if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		h, err := OpenOffline(f.Name())
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := h.ReadPacketData(); err != io.EOF {
			t.Fatalf("read = %v, want EOF", err)
		}
		closeConcurrently(h)
		if _, _, err := h.ReadPacketData(); err != io.EOF {
			t.Fatalf("closed read = %v, want EOF", err)
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCloseLifecycle$", "-test.v")
	cmd.Env = append(os.Environ(), "GOPACKET_CLOSE_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("lifecycle subprocess: %v\n%s", err, out)
	}
	t.Log(string(out))
}

func closeConcurrently(h *Handle) {
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); h.Close() }()
	}
	wg.Wait()
	h.Close()
}
