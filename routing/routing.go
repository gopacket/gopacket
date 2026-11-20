// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// Package routing provides a very basic but mostly functional implementation of
// a routing table for IPv4/IPv6 addresses.  It uses a routing table pulled from
// the kernel to find the correct interface, gateway, and preferred source IP
// address for packets destined to a particular location.
//
// The routing package is meant to be used with applications that are sending
// raw packet data, which don't have the benefit of having the kernel route
// packets for them.
package routing

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"
)

// rtInfo contains information on a single route.
type rtInfo struct {
	Dst, Src net.IPNet
	InputIface, OutputIface int64
	Gateway  net.IP
	Priority int32
	PrefSrc  net.IP
	Metrics  int64
}

func countMaskOnes(mask net.IPMask) (cnt int) {
	for _, each := range mask {
		for each != 0 {
			each &= (each - 1)
			cnt++
		}
	}
	return
}

type routeSlice []rtInfo

// routeSlice implements sort.Interface to sort.
func (r routeSlice) Len() int {
	return len(r)
}
func (r routeSlice) Less(i, j int) bool {
	var onesI, onesJ int
	onesI = countMaskOnes(r[i].Dst.Mask)
	onesJ = countMaskOnes(r[j].Dst.Mask)
	if onesI == onesJ {
		if r[i].Priority == r[j].Priority {
			return r[i].Metrics < r[j].Metrics
		}
		return r[i].Priority < r[j].Priority
	}
	return onesI > onesJ
}
func (r routeSlice) Swap(i, j int) {
	r[i], r[j] = r[j], r[i]
}

type router struct {
	ifaces map[int64]*net.Interface
	addrs  map[int64]ipAddrs
	v4, v6 routeSlice
}

func (r *router) String() string {
	strs := []string{"ROUTER", "--- V4 ---"}
	for _, route := range r.v4 {
		strs = append(strs, fmt.Sprintf("%+v", route))
	}
	strs = append(strs, "--- V6 ---")
	for _, route := range r.v6 {
		strs = append(strs, fmt.Sprintf("%+v", route))
	}
	return strings.Join(strs, "\n")
}

type ipAddrs struct {
	v4, v6 []net.IPNet
}

func (r *router) Route(dst net.IP) (iface *net.Interface, gateway, preferredSrc net.IP, err error) {
	return r.RouteWithSrc(nil, nil, dst)
}

func (r *router) RouteWithSrc(input net.HardwareAddr, src, dst net.IP) (iface *net.Interface, gateway, preferredSrc net.IP, err error) {
	var inputIndex int64
	if input != nil {
		inputIndex = -1
		for i, iface := range r.ifaces {
			if bytes.Equal(input, iface.HardwareAddr) {
				inputIndex = i
				break
			}
		}
	}
	
	var ifaceIndex int64
	switch {
	case dst.To4() != nil:
		ifaceIndex, gateway, preferredSrc, err = r.route(inputIndex, src, dst, false)
	case dst.To16() != nil:
		ifaceIndex, gateway, preferredSrc, err = r.route(inputIndex, src, dst, true)
	default:
		err = errors.New("IP is not valid as IPv4 or IPv6")
	}
	if err != nil {
		return
	}

	iface = r.ifaces[ifaceIndex]
	return
}

func (r *router) route(input int64, src, dst net.IP, ipv6 bool) (iface int64, gateway, preferredSrc net.IP, err error) {
	var rs routeSlice
	if ipv6 {
		rs = r.v6
	} else {
		rs = r.v4
	}
	var matchedRtInfo *rtInfo
	for _, rt := range rs {
		if !rt.Dst.Contains(dst) {
			continue
		}
		if src != nil && !rt.Src.Contains(src) {
			continue
		}
		if rt.InputIface != 0 && input != 0 && rt.InputIface != input {
			continue
		}
		matchedRtInfo = &rt
		break
	}
	if matchedRtInfo == nil {
		err = fmt.Errorf("no route found for %v", dst)
		return
	}

	if matchedRtInfo.Gateway == nil || matchedRtInfo.Gateway.IsUnspecified(){
		gateway = dst
	} else {
		gateway = matchedRtInfo.Gateway
	}
	if matchedRtInfo.OutputIface == 0 {
		if matchedRtInfo.PrefSrc != nil {
			for i, ifaceAddrs := range r.addrs {
				var addrs []net.IPNet
				if ipv6 {
					addrs = ifaceAddrs.v6
				} else {
					addrs = ifaceAddrs.v4
				}
				for _, each := range addrs {
					if each.Contains(gateway) && each.IP.Equal(matchedRtInfo.PrefSrc) {
						iface = i
						preferredSrc = each.IP
					}
				}
			}
		}
		if preferredSrc == nil {
			for i, ifaceAddrs := range r.addrs {
				var addrs []net.IPNet
				if ipv6 {
					addrs = ifaceAddrs.v6
				} else {
					addrs = ifaceAddrs.v4
				}
				for _, each := range addrs {
					if each.Contains(gateway) {
						iface = i
						preferredSrc = each.IP
					}
				}
			}
		}
	} else {
		iface = matchedRtInfo.OutputIface
		ifaceAddrs, ok := r.addrs[iface]
		if !ok {
			err = fmt.Errorf("no output interface found for %v", dst)
			return
		}
		var addrs []net.IPNet
		if ipv6 {
			addrs = ifaceAddrs.v6
		} else {
			addrs = ifaceAddrs.v4
		}
		if matchedRtInfo.PrefSrc != nil {
			for _, each := range addrs {
				if each.Contains(gateway) && each.IP.Equal(matchedRtInfo.PrefSrc) {
					preferredSrc = each.IP
				}
			}
		}
		if preferredSrc == nil {
			for _, each := range addrs {
				if each.Contains(gateway) {
					preferredSrc = each.IP
				}
			}
		}
	}
	if preferredSrc == nil {
		err = fmt.Errorf("no src found for %v", dst)
		return
	}
	return
}

// New creates a new router object.  The router returned by New currently does
// not update its routes after construction... care should be taken for
// long-running programs to call New() regularly to take into account any
// changes to the routing table which have occurred since the last New() call.
func New() (Router, error) {
	rtr := &router{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	rtr.ifaces = make(map[int64]*net.Interface)
	rtr.addrs = make(map[int64]ipAddrs)
	for i, _ := range ifaces {
		iface := &ifaces[i]
		if duplicated_iface, ok := rtr.ifaces[int64(iface.Index)]; ok {
			return nil, fmt.Errorf("duplicated index iface %v = %v = %v", iface.Index, iface, duplicated_iface)
		}
		rtr.ifaces[int64(iface.Index)] = iface
		var addrs ipAddrs
		ifaceAddrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range ifaceAddrs {
			if inet, ok := addr.(*net.IPNet); ok {
				if v4 := inet.IP.To4(); v4 != nil {
					addrs.v4 = append(addrs.v4, net.IPNet{
						IP: v4,
						Mask: inet.Mask,
					})
				} else {
					addrs.v6 = append(addrs.v6, *inet)
				}
			}
		}
		rtr.addrs[int64(iface.Index)] = addrs
	}

	err = rtr.setupRouteTable()
	if err != nil {
		return nil, err
	}
	return rtr, nil
}