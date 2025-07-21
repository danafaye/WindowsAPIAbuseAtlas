package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	modPsapi           = syscall.NewLazyDLL("psapi.dll")
	procEnumProcesses  = modPsapi.NewProc("EnumProcesses")
)

func main() {
	const maxPids = 1024
	var processIds [maxPids]uint32
	var bytesReturned uint32

	ret, _, err := procEnumProcesses.Call(
		uintptr(unsafe.Pointer(&processIds[0])),               // Process IDs buffer
		uintptr(len(processIds)*4),                            // Size of buffer in bytes
		uintptr(unsafe.Pointer(&bytesReturned)),               // Bytes returned
	)

	if ret == 0 {
		fmt.Printf("EnumProcesses failed: %v\n", err)
		return
	}

	numProcs := bytesReturned / 4
	fmt.Printf("Found %d running processes:\n", numProcs)
	for i := 0; i < int(numProcs); i++ {
		fmt.Printf("PID: %d\n", processIds[i])
	}
}
