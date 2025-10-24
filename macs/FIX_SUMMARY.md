# Fix: MAC Prefixes Generator

## Problem
The `gen.go` script was producing empty output when run, making it impossible to update the MAC address prefixes database.

## Root Causes
1. **HTTP to HTTPS redirect**: The IEEE OUI database URL (`http://standards-oui.ieee.org/oui/oui.txt`) now redirects to HTTPS, but Go's `http.Get()` wasn't following the redirect properly.

2. **Bot blocking**: The IEEE server returns HTTP 418 ("I'm a teapot") when it detects Go's default User-Agent, effectively blocking automated requests.

## Changes Made

### `gen.go`
- Updated the default URL from `http://` to `https://standards-oui.ieee.org/oui/oui.txt`
- Modified HTTP request to use a custom User-Agent header: `Mozilla/5.0 (compatible; gopacket-macs-generator/1.0)`
- Changed from simple `http.Get()` to creating a custom request with `http.NewRequest()` and `client.Do()`

### `valid_mac_prefixes.go`
- Regenerated with fresh data from IEEE (38,264 lines)
- Updated generation timestamp
- Now contains current MAC address prefix mappings

## Testing
```bash
# Command now works correctly:
go run gen.go | gofmt > valid_mac_prefixes.go

# Output: ~38,000+ lines of MAC prefix mappings
```

## Impact
- MAC address prefix lookups will now have up-to-date vendor information
- Future regeneration of the MAC database will work without issues

