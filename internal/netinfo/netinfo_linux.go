//go:build linux

package netinfo

import "os"

// defaultGateway reads the default route from /proc/net/route.
func defaultGateway() (string, error) {
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "", err
	}
	return parseProcNetRoute(string(b))
}

// systemDNS reads nameserver entries from /etc/resolv.conf.
func systemDNS() ([]string, error) {
	b, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	return parseResolvConf(string(b)), nil
}
