// +build linux

package main

import (
	"syscall"
)

func GetMreq(fd, level, opt int) ([16]byte, error) {
	addr, err2 := syscall.GetsockoptIPv6Mreq(fd, syscall.IPPROTO_IP, SO_ORIGINAL_DST)
	if err2 != nil {
		return [16]byte{}, err2
	} else {
		return addr.Multiaddr, nil
	}
}
