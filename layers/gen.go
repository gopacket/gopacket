// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

//go:build ignore
// +build ignore

// This binary pulls known ports from IANA, and uses them to populate
// iana_ports.go's TCPPortNames and UDPPortNames maps.
//
//	go run gen.go | gofmt > iana_ports.go
package main

import (
	"bytes"
	"encoding/xml"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"time"
)

const fmtString = `// Copyright 2012 Google, Inc. All rights reserved.

package layers

// Created by gen.go, don't edit manually
// Generated at %s
// Fetched from %q

// TCPPortNames contains the port names for all TCP ports.
func TCPPortNames(port TCPPort) (string, bool) {
	switch port {
	%s
	}

	return "", false
}

// UDPPortNames contains the port names for all UDP ports.
func UDPPortNames(port UDPPort) (string, bool) {
	switch port {
	%s
	}

	return "", false
}

// SCTPPortNames contains the port names for all SCTP ports.
func SCTPPortNames(port SCTPPort) (string, bool) {
	switch port {
	%s
	}

	return "", false
}
`

var url = flag.String("url", "http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xml", "URL to grab port numbers from")

func main() {
	fmt.Fprintf(os.Stderr, "Fetching ports from %q\n", *url)
	resp, err := http.Get(*url)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	fmt.Fprintln(os.Stderr, "Parsing XML")
	var registry struct {
		Records []struct {
			Protocol string `xml:"protocol"`
			Number   string `xml:"number"`
			Name     string `xml:"name"`
		} `xml:"record"`
	}
	xml.Unmarshal(body, &registry)
	var tcpPorts bytes.Buffer
	var udpPorts bytes.Buffer
	var sctpPorts bytes.Buffer
	done := map[string]map[int]bool{
		"tcp":  {},
		"udp":  {},
		"sctp": {},
	}
	for _, r := range registry.Records {
		port, err := strconv.Atoi(r.Number)
		if err != nil {
			continue
		}
		if r.Name == "" {
			continue
		}
		var b *bytes.Buffer
		switch r.Protocol {
		case "tcp":
			b = &tcpPorts
		case "udp":
			b = &udpPorts
		case "sctp":
			b = &sctpPorts
		default:
			continue
		}
		if done[r.Protocol][port] {
			continue
		}
		done[r.Protocol][port] = true
		fmt.Fprintf(b, "\tcase %d: return %q, true\n", port, r.Name)
	}
	fmt.Fprintln(os.Stderr, "Writing results to stdout")
	fmt.Printf(fmtString, time.Now(), *url, tcpPorts.String(), udpPorts.String(), sctpPorts.String())
}
