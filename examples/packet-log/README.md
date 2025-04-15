# packet-log

This example shows how you can log packets using Go's built in [slog](https://pkg.go.dev/log/slog) logger.

Logging using `slog` over printing the packet using `packet.String()` has two benefits:
- Structured Logs over unstructured, see the [Go Blog for more details.](https://go.dev/blog/slog)
- Performance, see the below benchmarks of calling `String` vs `LogValue` on a `Packet`.


## Benchmarks
```
goos: darwin
goarch: arm64
pkg: github.com/gopacket/gopacket/examples/packet-log
BenchmarkSlog_UDP
BenchmarkSlog_UDP-10         	  788236	      1403 ns/op	    2928 B/op	      35 allocs/op
BenchmarkRawString_UDP
BenchmarkRawString_UDP-10    	   46135	     26229 ns/op	   23573 B/op	     657 allocs/op
BenchmarkSlog_TCP
BenchmarkSlog_TCP-10         	  484540	      2341 ns/op	    5952 B/op	      56 allocs/op
BenchmarkRawString_TCP
BenchmarkRawString_TCP-10    	   89091	     13429 ns/op	   10700 B/op	     352 allocs/op
PASS
```