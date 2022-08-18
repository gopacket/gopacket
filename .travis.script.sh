#!/bin/bash

set -ev

go test github.com/google/gopacket
go test github.com/google/gopacket/layers
go test github.com/google/gopacket/tcpassembly
go test github.com/google/gopacket/reassembly
go test github.com/google/gopacket/pcap
sudo $(which go) test github.com/google/gopacket/pcapgo
sudo $(which go) test github.com/google/gopacket/routing
