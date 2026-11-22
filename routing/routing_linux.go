// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package routing

import (
	"net"
	"sort"
	"syscall"
	"unsafe"
)

// Pulled from http://man7.org/linux/man-pages/man7/rtnetlink.7.html
// See the section on RTM_NEWROUTE, specifically 'struct rtmsg'.
type routeInfoInMemory struct {
	Family byte
	DstLen byte
	SrcLen byte
	TOS    byte

	Table    byte
	Protocol byte
	Scope    byte
	Type     byte

	Flags uint32
}

func (r *router) setupRouteTable() error {
	tab, err := syscall.NetlinkRIB(syscall.RTM_GETROUTE, syscall.AF_UNSPEC)
	if err != nil {
		return err
	}
	msgs, err := syscall.ParseNetlinkMessage(tab)
	if err != nil {
		return err
	}
loop:
	for _, m := range msgs {
		switch m.Header.Type {
		case syscall.NLMSG_DONE:
			break loop
		case syscall.RTM_NEWROUTE:
			rt := (*routeInfoInMemory)(unsafe.Pointer(&m.Data[0]))
			routeInfo := rtInfo{}
			attrs, err := syscall.ParseNetlinkRouteAttr(&m)
			if err != nil {
				return err
			}
			if rt.Family != syscall.AF_INET && rt.Family != syscall.AF_INET6 {
				continue loop
			}
			if rt.Family == syscall.AF_INET {
				routeInfo.Src = net.IPNet{
					IP: make([]byte, 4),
					Mask: make([]byte, 4),
				}
				routeInfo.Dst = net.IPNet{
					IP: make([]byte, 4),
					Mask: make([]byte, 4),
				}
			} else {
				routeInfo.Src = net.IPNet{
					IP: make([]byte, 16),
					Mask: make([]byte, 16),
				}
				routeInfo.Dst = net.IPNet{
					IP: make([]byte, 16),
					Mask: make([]byte, 16),
				}
			}
			for _, attr := range attrs {
				switch attr.Attr.Type {
				case syscall.RTA_DST:
					routeInfo.Dst = net.IPNet{
						IP:   net.IP(attr.Value),
						Mask: net.CIDRMask(int(rt.DstLen), len(attr.Value)*8),
					}
				case syscall.RTA_SRC:
					routeInfo.Src = net.IPNet{
						IP:   net.IP(attr.Value),
						Mask: net.CIDRMask(int(rt.SrcLen), len(attr.Value)*8),
					}
				case syscall.RTA_IIF:
					routeInfo.InputIface = int64(*(*int32)(unsafe.Pointer(&attr.Value[0])))
				case syscall.RTA_OIF:
					routeInfo.OutputIface = int64(*(*int32)(unsafe.Pointer(&attr.Value[0])))
				case syscall.RTA_GATEWAY:
					routeInfo.Gateway = net.IP(attr.Value)
				case syscall.RTA_PRIORITY:
					routeInfo.Priority = *(*int32)(unsafe.Pointer(&attr.Value[0]))
				case syscall.RTA_PREFSRC:
					routeInfo.PrefSrc = net.IP(attr.Value)
				case syscall.RTA_METRICS:
					routeInfo.Metrics = int64(*(*int32)(unsafe.Pointer(&attr.Value[0])))
				}
			}
			if rt.Family == syscall.AF_INET {
				r.v4 = append(r.v4, routeInfo)
			} else {
				r.v6 = append(r.v6, routeInfo)
			}
		}
	}
	sort.Sort(r.v4)
	sort.Sort(r.v6)
	return nil
}
