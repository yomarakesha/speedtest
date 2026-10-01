//go:build darwin

package netinfo

import (
	"fmt"
	"os"
	"os/exec"
)

// defaultGateway shells out to `route -n get default`.
func defaultGateway() (string, error) {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return "", err
	}
	gw := parseDarwinRouteGet(string(out))
	if gw == "" {
		return "", fmt.Errorf("шлюз не найден в выводе route")
	}
	return gw, nil
}

// systemDNS reads nameserver entries from /etc/resolv.conf.
func systemDNS() ([]string, error) {
	b, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	return parseResolvConf(string(b)), nil
}
