package routing

import (
	"net"
	"sort"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Pulled from https://learn.microsoft.com/zh-cn/windows/win32/winsock/sockaddr-2
type inAddr [4]byte
type sockaddrIN struct {
	SinFamily int16
	SinPort   uint16
	SinAddr   inAddr
	SinZero   [8]int8
}

// Pulled from https://learn.microsoft.com/zh-cn/windows/win32/winsock/sockaddr-2
type in6Addr [16]byte
type sockaddrIN6 struct {
	SinFamily   int16
	SinPort     uint16
	SinFlowInfo uint32
	Sin6Addr    in6Addr
	Sin6ScopeId uint32
}

// Pulled from https://learn.microsoft.com/zh-cn/windows/win32/api/netioapi/ns-netioapi-ip_address_prefix
type sockaddrINet [28]byte
type ipAddressPrefix struct {
	Prefix       sockaddrINet
	PrefixLength uint8
}

// Pulled from https://learn.microsoft.com/zh-cn/windows/win32/api/netioapi/ns-netioapi-mib_ipforward_row2
type mibIPForwardRow2 struct {
    InterfaceLuid        uint64
    InterfaceIndex       uint32
    DestinationPrefix    ipAddressPrefix
	_                    [3]byte // To fix the problem caused by memory alignment
    NextHop              sockaddrINet
    SitePrefixLength     uint8
    ValidLifetime        uint32
    PreferredLifetime    uint32
    Metric               uint32
    Protocol             uint32
    Loopback             bool
    AutoconfigureAddress bool
    Publish              bool
    Immortal             bool
    Age                  bool
    Origin               uint32
}

// Pulled from https://learn.microsoft.com/zh-cn/windows/win32/api/netioapi/nf-netioapi-getipforwardtable2
type mibIPForwardRowTable2 struct {
	NumEntries uint32
	Table      [1]mibIPForwardRow2 // It is [NumEntries]mibIPForwardRow2 in fact
}

func (r *router) setupRouteTable() error {
	modIPhelperAPI := windows.NewLazySystemDLL("iphlpapi.dll")
	procGetIpForwardTable2 := modIPhelperAPI.NewProc("GetIpForwardTable2")
	procFreeMibTable := modIPhelperAPI.NewProc("FreeMibTable")

	var table *mibIPForwardRowTable2
	result, _, err := procGetIpForwardTable2.Call(windows.AF_INET, uintptr(unsafe.Pointer(&table)))
	if errno, ok := err.(syscall.Errno); ok && errno != 0 || !ok {
		return err
	}
	if result != windows.NO_ERROR {
		return syscall.Errno(result)
	}
	defer procFreeMibTable.Call(uintptr(unsafe.Pointer(table)))

	if table.NumEntries > 0 {
		pFirstRow := unsafe.Pointer(&table.Table[0])
		rowSize := unsafe.Sizeof(table.Table[0])

		for i := uint32(0); i < table.NumEntries; i++ {
			row := (*mibIPForwardRow2)(unsafe.Pointer(uintptr(pFirstRow) + rowSize * uintptr(i)))
			routeInfo := rtInfo{
				Src: net.IPNet{
					IP: make([]byte, 4),
					Mask: make([]byte, 4),
				},
			}

			dstAddr := make([]byte, 4)
			copy(dstAddr, ((*sockaddrIN)(unsafe.Pointer(&row.DestinationPrefix.Prefix[0]))).SinAddr[:])
			routeInfo.Dst = net.IPNet{
				IP:   dstAddr,
				Mask: net.CIDRMask(int(row.DestinationPrefix.PrefixLength), 32),
			}

			routeInfo.OutputIface = int64(row.InterfaceIndex)

			gatewayAddr := make([]byte, 4)
			copy(gatewayAddr, ((*sockaddrIN)(unsafe.Pointer(&row.NextHop[0]))).SinAddr[:])
			routeInfo.Gateway = gatewayAddr

			routeInfo.Metrics = int64(row.Metric)

			r.v4 = append(r.v4, routeInfo)
		}
	}

	result, _, err = procGetIpForwardTable2.Call(windows.AF_INET6, uintptr(unsafe.Pointer(&table)))
	if errno, ok := err.(syscall.Errno); ok && errno != 0 || !ok {
		return err
	}
	if result != windows.NO_ERROR {
		return syscall.Errno(result)
	}
	defer procFreeMibTable.Call(uintptr(unsafe.Pointer(table)))

	if table.NumEntries > 0 {
		pFirstRow := unsafe.Pointer(&table.Table[0])
		rowSize := unsafe.Sizeof(table.Table[0])

		for i := uint32(0); i < table.NumEntries; i++ {
			row := (*mibIPForwardRow2)(unsafe.Pointer(uintptr(pFirstRow) + rowSize * uintptr(i)))
			routeInfo := rtInfo{
				Src: net.IPNet{
					IP: make([]byte, 16),
					Mask: make([]byte, 16),
				},
			}

			dstAddr := make([]byte, 16)
			copy(dstAddr, ((*sockaddrIN6)(unsafe.Pointer(&row.DestinationPrefix.Prefix[0]))).Sin6Addr[:])
			routeInfo.Dst = net.IPNet{
				IP:   dstAddr,
				Mask: net.CIDRMask(int(row.DestinationPrefix.PrefixLength), 128),
			}

			routeInfo.OutputIface = int64(row.InterfaceIndex)

			gatewayAddr := make([]byte, 16)
			copy(gatewayAddr, ((*sockaddrIN6)(unsafe.Pointer(&row.NextHop[0]))).Sin6Addr[:])
			routeInfo.Gateway = gatewayAddr

			routeInfo.Metrics = int64(row.Metric)

			r.v6 = append(r.v6, routeInfo)
		}
	}

	sort.Sort(r.v4)
	sort.Sort(r.v6)
	return nil
}
