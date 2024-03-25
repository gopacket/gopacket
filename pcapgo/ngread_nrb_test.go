package pcapgo

import (
	"fmt"
	"io"
	"net/netip"
	"os"
	"testing"
)

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
