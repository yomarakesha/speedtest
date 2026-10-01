//go:build windows

package netinfo

import (
	"fmt"
	"os/exec"
)

// defaultGateway shells out to `route print -4`.
func defaultGateway() (string, error) {
	out, err := exec.Command("route", "print", "-4").Output()
	if err != nil {
		return "", err
	}
	gw := parseWindowsRoutePrint(string(out))
	if gw == "" {
		return "", fmt.Errorf("шлюз не найден в выводе route print")
	}
	return gw, nil
}

// systemDNS shells out to `ipconfig /all`.
func systemDNS() ([]string, error) {
	out, err := exec.Command("ipconfig", "/all").Output()
	if err != nil {
		return nil, err
	}
	dns := parseWindowsDNS(string(out))
	if len(dns) == 0 {
		return nil, fmt.Errorf("DNS-серверы не найдены в выводе ipconfig")
	}
	return dns, nil
}
