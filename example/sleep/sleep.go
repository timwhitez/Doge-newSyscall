package main

import (
	"crypto/sha1"
	"fmt"
	"github.com/timwhitez/Doge-newSyscall/pkg/newsyscall"
	"syscall"
	"unsafe"
)

func main() {
	//NtDelayExecution HellsGate
	sleep1, e := newsyscall.MemHgate("84804f99e2c7ab8aee611d256a085cf4879c4be8", str2sha1)
	if e != nil {
		panic(e)
	}

	fmt.Printf("%s: %x\n", "NtDelayExecution Sysid", sleep1)
	times := -(5000 * 10000)

	ptr := newsyscall.PrepareSyscall(sleep1)

	r, _, _ := syscall.Syscall(ptr, 2, 0, uintptr(unsafe.Pointer(&times)), 0)
	fmt.Println(r)

}

func str2sha1(s string) string {
	h := sha1.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs)
}
