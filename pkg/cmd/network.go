package cmd

import (
	"fmt"
	"net"
	"strings"
)

// GetInterfaceNames get ethernet interface names,include "lo"
func GetInterfaceNames() ([]string, error) {
	is, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0)
	for _, nif := range is {
		if strings.ToLower(nif.Name) == "lo" {
			continue
		}
		names = append(names, nif.Name)
	}
	return names, nil
}

// GetInterfaceIPAddress get ethernet interface ip address
// from ethernet name prefix
func GetInterfaceIPAddress(prefix string) ([]string, error) {
	is, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	ips := make([]string, 0)
	for _, nif := range is {
		if strings.ToLower(nif.Name) == "lo" {
			continue
		}
		if prefix != "" && !strings.HasPrefix(nif.Name, prefix) {
			continue
		}
		addrs, err := nif.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			if strings.Contains(addr.String(), ":") {
				continue
			}
			ips = append(ips, strings.Split(addr.String(), "/")[0])
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf(
			"ethernet interface name prefix [%s] not found ip info", prefix)
	}
	return ips, nil
}

// GetIPsWithCidr scan ip form cidr
func GetIPsWithCidr(cidrs []string) ([]string, error) {
	var ips []string
	for _, cidr := range cidrs {
		ip, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
			if ip.IsLoopback() || ip.IsMulticast() ||
				ip.To4()[3] == 0xff ||
				ip.To4()[3] == 0x00 {
				continue
			}
			ips = append(ips, ip.String())
		}
	}
	return ips, nil
}

// ScanPortStatus scan port status
type ScanPortStatus struct {
	Addr  string
	Error error
}

// ScanActivePortMachines scan active port machines
func ScanActivePortMachines(cidrs []string, f func(aip string) *ScanPortStatus) ([]*ScanPortStatus, error) {
	ips, err := GetIPsWithCidr(cidrs)
	if err != nil {
		return nil, err
	}
	ipParts := make([][]string, 0)
	ipTmp := make([]string, 0)
	for _, ip := range ips {
		if len(ipTmp) < 50 {
			ipTmp = append(ipTmp, ip)
			continue
		}
		aTmp := ipTmp
		ipParts = append(ipParts, aTmp)
		ipTmp = make([]string, 0)
		ipTmp = append(ipTmp, ip)
	}
	if len(ipTmp) > 0 {
		aTmp := ipTmp
		ipParts = append(ipParts, aTmp)
	}
	status := make(chan []*ScanPortStatus)
	for _, fip := range ipParts {
		go func(_ip []string) {
			var sps []*ScanPortStatus
			for _, aip := range _ip {
				if f == nil {
					continue
				}
				as := f(aip)
				sps = append(sps, as)
			}
			status <- sps
		}(fip)
	}
	st := make([]*ScanPortStatus, 0)
	idx := 0
	for as := range status {
		st = append(st, as...)
		idx++
		if idx == len(ipParts) {
			break
		}
	}
	return st, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
