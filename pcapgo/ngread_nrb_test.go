package pcapgo

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
)

func TestNgReaderNRBRecordBounds(t *testing.T) {
	block := func(body []byte) []byte {
		length := uint32(8 + len(body) + 4)
		out := binary.LittleEndian.AppendUint32(nil, uint32(ngBlockTypeNameResolution))
		out = binary.LittleEndian.AppendUint32(out, length)
		out = append(out, body...)
		return binary.LittleEndian.AppendUint32(out, length)
	}

	for _, tc := range []struct {
		name    string
		value   []byte
		wantErr bool
	}{
		{"short address", nil, true},
		{"unterminated name", []byte{192, 0, 2, 1, 'n', 'a', 'm', 'e'}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := getBasicOnePacketPcap(t).Bytes()
			epbLength := binary.LittleEndian.Uint32(buf[len(buf)-4:])
			epbStart := len(buf) - int(epbLength)

			record := binary.LittleEndian.AppendUint16(nil, uint16(ngNameRecordIPv4))
			record = binary.LittleEndian.AppendUint16(record, uint16(len(tc.value)))
			record = append(record, tc.value...)
			record = append(record, 0, 0, 0, 0) // end of records
			capture := append(bytes.Clone(buf[:epbStart]), block(record)...)
			capture = append(capture, buf[epbStart:]...)

			r, err := NewNgReader(bytes.NewReader(capture), DefaultNgReaderOptions)
			if err != nil {
				t.Fatal(err)
			}
			packet, _, err := r.ReadPacketData()
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "too short for its address") {
					t.Fatalf("wanted short address error, got %v", err)
				}
				return
			}
			if err != nil || len(packet) == 0 {
				t.Fatalf("packet after NRB was lost: %v", err)
			}
		})
	}
}

func readNgNRB(t *testing.T, name string) (*NgReader, error) {

	testf, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer testf.Close()

	options := DefaultNgReaderOptions
	options.SkipUnknownVersion = true

	var r *NgReader
	r, err = NewNgReader(testf, options)
	if err != nil {
		return nil, err
		// t.Fatal("Couldn't read start of file:", err)
	}

	var ii int
	var found int
	for {
		_, _, err := r.ReadPacketData()
		if len(r.nameRecords) > found {
			found = len(r.nameRecords)
			t.Log("Name Resolution Block found, index block:", ii)
		}
		if err == io.EOF {
			t.Log("ReadPacketData returned EOF")
			break
		} else if err != nil {
			t.Log("Error:", err)
		}
		ii++
	}

	return r, nil
}

// TestNgReadDSB tests the readDecryptionSecretsBlock function.
func TestNgReaderNRB(t *testing.T) {

	pcapngFile := "tests/le/test016.pcapng"
	r, err := readNgNRB(t, pcapngFile)
	if err != nil {
		t.Fatal("Couldn't open file:", err)
	}

	t.Log("test file:", pcapngFile)
	t.Log("nameRecords:", len(r.nameRecords))
	i := 0
	for _, record := range r.nameRecords {
		t.Log(fmt.Sprintf("Addr:%v, Names:%v", record.Addr, record.Names))
		i++
	}
	if i != 10 {
		t.Fatalf("Expected %d name record(s) but found %d", 10, i)
	}
	if nr, ok := r.nameRecords[2].Addr.(*NgIPAddress); !ok {
		t.Fatalf("Expected an IP address")
	} else {
		addr, _ := netip.ParseAddr("10.1.2.3")
		if nr.Addr != addr {
			t.Fatalf("Expected '10.1.2.3' but found '%s'", r.nameRecords[2].Addr)
		}
	}
	if r.nameRecords[6].Names[0] != "qux.example.com" {
		t.Fatalf("Expected 'qux.example.com' but found '%s'", r.nameRecords[6].Names[0])
	}

	pcapngFile = "tests/le/test102.pcapng"
	r, err = readNgNRB(t, pcapngFile)
	if err != nil {
		t.Fatal("Couldn't open file:", err)
	}

	t.Log("test file:", pcapngFile)
	t.Log("nameRecords:", len(r.nameRecords))
	i = 0
	for _, record := range r.nameRecords {
		t.Log(fmt.Sprintf("Addr:%s, Names:%v", record.Addr, record.Names))
		i++
	}
	if i != 11 {
		t.Fatalf("Expected %d name record(s) but found %d", 11, i)
	}
	if nr, ok := r.nameRecords[3].Addr.(*NgIPAddress); !ok {
		t.Fatalf("Expected an IP address")
	} else {
		addr, _ := netip.ParseAddr("fc01:dead::beef")
		if nr.Addr != addr {
			t.Fatalf("Expected 'fc01:dead::beef' but found '%s'", nr.Addr)
		}
	}
	if r.nameRecords[8].Names[0] != "bar.example.net" {
		t.Fatalf("Expected 'bar.example.net' but found '%s'", r.nameRecords[8].Names[0])
	}
}

// TestNgReaderNRBEUI checks that EUI-48 and EUI-64 name records are decoded
// with their names, and that the reader stays in sync with the block
// boundaries so the packet following the NRB is still returned.
func TestNgReaderNRBEUI(t *testing.T) {
	data := []byte{
		0x0A, 0x0D, 0x0D, 0x0A, // Section Header
		0, 0, 0, 28, // block total length
		0x1A, 0x2B, 0x3C, 0x4D, // BOM
		0, 1, 0, 0, // Version
		0, 0, 0, 0, // Section length
		0, 0, 0, 0, // Section length
		0, 0, 0, 28, // block total length

		0, 0, 0, 1, // IDB
		0, 0, 0, 20, // block total length
		0, 1, 0, 0, // Ethernet
		0, 0, 0, 0, // Snap length
		0, 0, 0, 20, // block total length

		0, 0, 0, 4, // NRB
		0, 0, 0, 52, // block total length
		0, 3, 0, 12, // nrb_record_eui48, length 12
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // address
		'm', 'a', 'c', '4', '8', 0, // name
		0, 4, 0, 14, // nrb_record_eui64, length 14
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, // address
		'm', 'a', 'c', '6', '4', 0, // name
		0, 0, // padding
		0, 0, 0, 0, // nrb_record_end
		0, 0, 0, 52, // block total length

		0, 0, 0, 6, // EPB
		0, 0, 0, 40, // block total length
		0, 0, 0, 0, // interface ID
		0, 0, 0, 0, // time (high)
		0, 0, 0, 0, // time (low)
		0, 0, 0, 8, // capture packet length
		0, 0, 0, 8, // original packet length
		8, 7, 6, 5,
		4, 3, 2, 1,
		0, 0, 0, 40, // block total length
	}

	r, err := NewNgReader(bytes.NewReader(data), DefaultNgReaderOptions)
	if err != nil {
		t.Fatal("Couldn't read header + IDB:", err)
	}
	packet, _, err := r.ReadPacketData()
	if err != nil {
		t.Fatal("Couldn't read packet after NRB:", err)
	}
	if !bytes.Equal(packet, []byte{8, 7, 6, 5, 4, 3, 2, 1}) {
		t.Fatalf("Unexpected packet data: %v", packet)
	}
	if _, _, err = r.ReadPacketData(); err != io.EOF {
		t.Fatal("Expected io.EOF, got:", err)
	}

	if len(r.nameRecords) != 2 {
		t.Fatalf("Expected %d name record(s) but found %d", 2, len(r.nameRecords))
	}
	want := []struct {
		addr net.HardwareAddr
		name string
	}{
		{net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, "mac48"},
		{net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77}, "mac64"},
	}
	for i, record := range r.nameRecords {
		nr, ok := record.Addr.(*NgEUIAddress)
		if !ok {
			t.Fatalf("Expected an EUI address in record %d", i)
		}
		if !bytes.Equal(nr.Addr, want[i].addr) {
			t.Fatalf("Expected '%s' but found '%s'", want[i].addr, nr.Addr)
		}
		if len(record.Names) != 1 || record.Names[0] != want[i].name {
			t.Fatalf("Expected names [%s] but found %v", want[i].name, record.Names)
		}
	}
}
