# Linux SLL Oversized Address Test Example

This example demonstrates the fix for oversized Linux SLL hardware addresses that previously caused panics.

## Usage

```bash
go run main.go <pcap_file>
```

## Example

Process the test pcap file that contains an oversized address:

```bash
go run main.go ../../layers/testdata/linux_sll_oversized_addr.pcapng
```

## What It Tests

1. Graceful Handling: Verifies that packets with oversized addresses don't cause panics
2. Endpoint Validation: Ensures all flow endpoints are within MaxEndpointSize limits
3. Truncation: Confirms that oversized addresses are correctly truncated
4. Statistics: Provides detailed information about packet processing

## Test Data

The included test pcap (linux_sll_oversized_addr.pcapng) contains:
- 209 total packets
- 204 Linux SLL packets
- 1 packet with a 22-byte hardware address (packet 91)
