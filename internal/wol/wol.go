// Package wol sends Wake-on-LAN magic packets to power on a sleeping device
// that supports WoL, over UDP broadcast — no agent needed on the target.
package wol

import (
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"strings"

	"speedtest/internal/util"
)

// DefaultBroadcastIP is used when --ip is not given.
const DefaultBroadcastIP = "255.255.255.255"

// DefaultPort is the conventional WoL UDP port.
const DefaultPort = 9

// ParseMAC parses a MAC address in colon, dash, or bare-hex form
// (aa:bb:cc:dd:ee:ff, aa-bb-cc-dd-ee-ff, aabbccddeeff), case-insensitive.
func ParseMAC(s string) ([6]byte, error) {
	var mac [6]byte
	clean := strings.NewReplacer(":", "", "-", "", ".", "").Replace(s)
	if len(clean) != 12 {
		return mac, fmt.Errorf("некорректный MAC-адрес %q (нужно 12 hex-цифр)", s)
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return mac, fmt.Errorf("некорректный MAC-адрес %q: %w", s, err)
	}
	copy(mac[:], b)
	return mac, nil
}

// BuildPacket builds the 102-byte WoL magic packet for mac: six 0xFF bytes
// followed by the 6-byte MAC address repeated 16 times.
func BuildPacket(macStr string) ([]byte, error) {
	mac, err := ParseMAC(macStr)
	if err != nil {
		return nil, err
	}
	packet := make([]byte, 0, 102)
	for i := 0; i < 6; i++ {
		packet = append(packet, 0xFF)
	}
	for i := 0; i < 16; i++ {
		packet = append(packet, mac[:]...)
	}
	return packet, nil
}

// RunWOL is the CLI entry point for `speedtest wol <mac>`.
func RunWOL(args []string) error {
	fs := flag.NewFlagSet("wol", flag.ContinueOnError)
	ip := fs.String("ip", DefaultBroadcastIP, "broadcast IP to send to")
	port := fs.Int("port", DefaultPort, "UDP port to send to")
	pos, err := util.ParseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return fmt.Errorf("использование: speedtest wol <mac> [--ip 255.255.255.255] [--port 9]")
	}

	packet, err := BuildPacket(pos[0])
	if err != nil {
		return err
	}

	dst := fmt.Sprintf("%s:%d", *ip, *port)
	addr, err := net.ResolveUDPAddr("udp4", dst)
	if err != nil {
		return fmt.Errorf("адрес %s: %w", dst, err)
	}
	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return fmt.Errorf("подключение: %w", err)
	}
	defer conn.Close()

	if _, err := conn.Write(packet); err != nil {
		return fmt.Errorf("отправка: %w", err)
	}

	fmt.Printf("Magic-пакет отправлен на %s (MAC %s)\n", dst, pos[0])
	return nil
}
