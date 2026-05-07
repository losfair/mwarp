package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func restrictCurrentThreadCaps(mask uint64) error {
	for cap := 0; cap <= kernelLastCap(); cap++ {
		if capInMask(mask, cap) {
			continue
		}
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(cap), 0, 0, 0); err != nil {
			if errors.Is(err, unix.EINVAL) {
				continue
			}
			return fmt.Errorf("drop bounding cap %d: %w", cap, err)
		}
	}

	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		if !errors.Is(err, unix.EINVAL) {
			return fmt.Errorf("clear ambient caps: %w", err)
		}
	}

	data := [2]unix.CapUserData{
		{
			Effective:   uint32(mask),
			Permitted:   uint32(mask),
			Inheritable: uint32(mask),
		},
		{
			Effective:   uint32(mask >> 32),
			Permitted:   uint32(mask >> 32),
			Inheritable: uint32(mask >> 32),
		},
	}
	hdr := unix.CapUserHeader{
		Version: unix.LINUX_CAPABILITY_VERSION_3,
		Pid:     0,
	}
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("set caps mask 0x%x: %w", mask, err)
	}
	return nil
}

func capInMask(mask uint64, cap int) bool {
	return cap >= 0 && cap < 64 && mask&(uint64(1)<<uint(cap)) != 0
}

func capMask(caps ...int) uint64 {
	var mask uint64
	for _, cap := range caps {
		if cap >= 0 && cap < 64 {
			mask |= uint64(1) << uint(cap)
		}
	}
	return mask
}

func kernelLastCap() int {
	b, err := os.ReadFile("/proc/sys/kernel/cap_last_cap")
	if err != nil {
		return unix.CAP_LAST_CAP
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || n < 0 {
		return unix.CAP_LAST_CAP
	}
	return n
}
