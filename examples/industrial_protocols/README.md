# Industrial Protocols Monitor

A live packet capture tool for monitoring ENIP, CIP, and Modbus TCP industrial protocols.

## Features

- Live capture from network interfaces
- Real-time decoding of industrial protocols:
  - **ENIP** (EtherNet/IP) - port 44818
  - **CIP** (Common Industrial Protocol) - port 2222
  - **Modbus TCP** - port 502
- Display protocol constants and status codes
- Detailed packet information with human-readable constant names

## Building

```bash
go build
```

## Usage

### Show Available Network Interfaces

```bash
./industrial_protocols
```

This will list all available network interfaces on your system.

### Display Protocol Constants

```bash
./industrial_protocols -show-constants
```

This displays all protocol constants, including:
- ENIP commands and status codes
- CIP services and status codes
- Modbus function codes and exception codes

### Live Capture

```bash
./industrial_protocols -i <interface>
```

Example:
```bash
./industrial_protocols -i en0
```

### Options

- `-i <interface>` - Network interface to capture from (required for live capture)
- `-show-constants` - Display protocol constants and exit
- `-snaplen <bytes>` - Snapshot length for packet capture (default: 65536)
- `-promisc` - Enable promiscuous mode (default: true)
- `-timeout <duration>` - Read timeout (default: 30s)
- `-filter <bpf>` - BPF filter (default: "tcp port 502 or tcp port 44818 or tcp port 2222")

## Examples

### Monitor all industrial protocols on interface en0:
```bash
./industrial_protocols -i en0
```

### Monitor only Modbus TCP traffic:
```bash
./industrial_protocols -i en0 -filter "tcp port 502"
```

### Monitor ENIP traffic only:
```bash
./industrial_protocols -i en0 -filter "tcp port 44818"
```

### Capture with custom BPF filter and specific host:
```bash
./industrial_protocols -i en0 -filter "tcp port 502 and host 192.168.1.100"
```

## Output Format

The tool displays detailed information for each captured packet:

### ENIP Packets
- Command type and code
- Session handle
- Status (with success/error indicators)
- Embedded CIP data if present

### CIP Packets
- Request/Response type
- Service code
- Class, Instance, and Attribute IDs (for requests)
- Status codes (for responses)

### Modbus TCP Packets
- MBAP header (Transaction ID, Protocol ID, Unit ID)
- Function code
- Exception information (if exception response)
- Data details (address, quantity for read/write operations)

## Requirements

- Root/Administrator privileges may be required for packet capture on some systems
- libpcap must be installed

## Notes

- Press `Ctrl+C` to stop the capture
- The tool automatically applies filters for common industrial protocol ports
- All numeric values are displayed in hexadecimal with human-readable names

