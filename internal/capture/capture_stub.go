//go:build !pcap

package capture

import "context"

// Available reports whether a capture backend is compiled in. The default build
// has none.
func Available() bool { return false }

// Devices lists capture-capable interfaces. Unavailable without -tags pcap.
func Devices() ([]Device, error) { return nil, ErrUnavailable }

// TopTalkers streams the highest-volume peers. Unavailable without -tags pcap.
func TopTalkers(ctx context.Context, opt Options, cb func([]Talker)) error {
	return ErrUnavailable
}
