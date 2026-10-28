//go:build windows && pcap

// Windows port->PID and PID->process-name attribution for TopProcesses, via
// iphlpapi.dll (GetExtendedTcpTable/GetExtendedUdpTable) and
// CreateToolhelp32Snapshot. Neither call requires administrator rights.
//
// Scope: IPv4 (AF_INET) connections only. IPv6 rows use a different, larger
// MIB_TCP6ROW_OWNER_PID/MIB_UDP6ROW_OWNER_PID layout (16-byte address + scope
// id) not implemented here — IPv6 traffic simply falls through to the
// unattributed "Система/неизвестно" bucket, same as any other lookup miss.
package capture

import (
	"encoding/binary"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	afInet              = 2
	tcpTableOwnerPIDAll = 5
	udpTableOwnerPID    = 1
	th32csSnapProcess   = 0x00000002
	maxPath             = 260
)

var (
	modIphlpapi = syscall.NewLazyDLL("iphlpapi.dll")
	modKernel32 = syscall.NewLazyDLL("kernel32.dll")

	procGetExtendedTCPTable  = modIphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUDPTable  = modIphlpapi.NewProc("GetExtendedUdpTable")
	procCreateToolhelp32Snap = modKernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW      = modKernel32.NewProc("Process32FirstW")
	procProcess32NextW       = modKernel32.NewProc("Process32NextW")
	procCloseHandle          = modKernel32.NewProc("CloseHandle")
)

// mibTCPRowOwnerPID mirrors Win32's MIB_TCPROW_OWNER_PID (six DWORDs).
type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

// mibUDPRowOwnerPID mirrors Win32's MIB_UDPROW_OWNER_PID (three DWORDs).
type mibUDPRowOwnerPID struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPid uint32
}

// processEntry32W mirrors Win32's PROCESSENTRY32W.
type processEntry32W struct {
	Size            uint32
	CntUsage        uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	CntThreads      uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [maxPath]uint16
}

type portKey struct {
	proto string
	port  uint16
}

const pidMapTTL = 2 * time.Second

var (
	pidMapMu sync.Mutex
	pidMap   = map[portKey]int{}
	nameMap  = map[int]string{}
	pidMapAt time.Time
)

func init() {
	pidLookup = windowsPortPID
	procName = windowsProcessName
}

// windowsPortPID is TopProcesses' pidLookup hook: the PID owning localPort
// for proto ("tcp"/"udp"), refreshing the underlying snapshot at most once
// every pidMapTTL.
func windowsPortPID(proto string, port uint16) (int, bool) {
	pidMapMu.Lock()
	defer pidMapMu.Unlock()
	if time.Since(pidMapAt) > pidMapTTL {
		refreshLocked()
	}
	pid, ok := pidMap[portKey{proto, port}]
	return pid, ok
}

// windowsProcessName is TopProcesses' procName hook, reading the same cached
// snapshot windowsPortPID refreshes.
func windowsProcessName(pid int) string {
	pidMapMu.Lock()
	defer pidMapMu.Unlock()
	if time.Since(pidMapAt) > pidMapTTL {
		refreshLocked()
	}
	return nameMap[pid]
}

// refreshLocked rebuilds pidMap/nameMap. Caller must hold pidMapMu.
func refreshLocked() {
	m := make(map[portKey]int, len(pidMap))
	for _, row := range readTCPTable() {
		m[portKey{"tcp", ntohsPort(row.LocalPort)}] = int(row.OwningPid)
	}
	for _, row := range readUDPTable() {
		m[portKey{"udp", ntohsPort(row.LocalPort)}] = int(row.OwningPid)
	}
	pidMap = m
	nameMap = snapshotProcessNames()
	pidMapAt = time.Now()
}

// ntohsPort extracts the 16-bit port number from a MIB_*ROW_OWNER_PID's
// LocalPort field, which Windows stores in network (big-endian) byte order
// in the low word of the DWORD.
func ntohsPort(v uint32) uint16 {
	return binary.BigEndian.Uint16([]byte{byte(v), byte(v >> 8)})
}

// readTCPTable returns the current IPv4 TCP table via
// GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL). Returns nil on any failure —
// callers treat "no table" the same as "nothing known yet".
func readTCPTable() []mibTCPRowOwnerPID {
	var size uint32
	procGetExtendedTCPTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, afInet, tcpTableOwnerPIDAll, 0)
	if size == 0 {
		return nil
	}
	buf := make([]byte, size)
	ret, _, _ := procGetExtendedTCPTable.Call(
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, afInet, tcpTableOwnerPIDAll, 0)
	if ret != 0 {
		return nil
	}
	return parseTCPRows(buf)
}

func parseTCPRows(buf []byte) []mibTCPRowOwnerPID {
	if len(buf) < 4 {
		return nil
	}
	n := binary.LittleEndian.Uint32(buf[:4])
	const rowSize = int(unsafe.Sizeof(mibTCPRowOwnerPID{}))
	rows := make([]mibTCPRowOwnerPID, 0, n)
	for i := uint32(0); i < n; i++ {
		off := 4 + int(i)*rowSize
		if off+rowSize > len(buf) {
			break
		}
		rows = append(rows, *(*mibTCPRowOwnerPID)(unsafe.Pointer(&buf[off])))
	}
	return rows
}

// readUDPTable returns the current IPv4 UDP table via
// GetExtendedUdpTable(UDP_TABLE_OWNER_PID).
func readUDPTable() []mibUDPRowOwnerPID {
	var size uint32
	procGetExtendedUDPTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, afInet, udpTableOwnerPID, 0)
	if size == 0 {
		return nil
	}
	buf := make([]byte, size)
	ret, _, _ := procGetExtendedUDPTable.Call(
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, afInet, udpTableOwnerPID, 0)
	if ret != 0 {
		return nil
	}
	return parseUDPRows(buf)
}

func parseUDPRows(buf []byte) []mibUDPRowOwnerPID {
	if len(buf) < 4 {
		return nil
	}
	n := binary.LittleEndian.Uint32(buf[:4])
	const rowSize = int(unsafe.Sizeof(mibUDPRowOwnerPID{}))
	rows := make([]mibUDPRowOwnerPID, 0, n)
	for i := uint32(0); i < n; i++ {
		off := 4 + int(i)*rowSize
		if off+rowSize > len(buf) {
			break
		}
		rows = append(rows, *(*mibUDPRowOwnerPID)(unsafe.Pointer(&buf[off])))
	}
	return rows
}

// snapshotProcessNames returns every running PID's executable filename via
// CreateToolhelp32Snapshot — no administrator rights required.
func snapshotProcessNames() map[int]string {
	h, _, _ := procCreateToolhelp32Snap.Call(uintptr(th32csSnapProcess), 0)
	if h == 0 || h == ^uintptr(0) {
		return map[int]string{}
	}
	defer procCloseHandle.Call(h)

	out := map[int]string{}
	var entry processEntry32W
	entry.Size = uint32(unsafe.Sizeof(entry))
	ret, _, _ := procProcess32FirstW.Call(h, uintptr(unsafe.Pointer(&entry)))
	for ret != 0 {
		out[int(entry.ProcessID)] = syscall.UTF16ToString(entry.ExeFile[:])
		entry = processEntry32W{Size: uint32(unsafe.Sizeof(entry))}
		ret, _, _ = procProcess32NextW.Call(h, uintptr(unsafe.Pointer(&entry)))
	}
	return out
}
