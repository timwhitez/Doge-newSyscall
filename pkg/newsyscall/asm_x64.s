
//func prepareSyscall()
TEXT ·prepareSyscall(SB),$0-0
    BYTE $0x65
    BYTE $0x67
    BYTE $0x67
    BYTE $0x63
    BYTE $0x61
    BYTE $0x6c
    BYTE $0x6c

    BYTE $0x90            //NOP

    //xor r15, r15
    BYTE $0x4d
    BYTE $0x31
    BYTE $0xff

    BYTE $0x90            //NOP

    //xor r12, r12
    BYTE $0x4d
    BYTE $0x31
    BYTE $0xe4

    BYTE $0x90            //NOP

    //r15存储sysid
    //mov r15, rcx
    BYTE $0x49
    BYTE $0x89
    BYTE $0xcf

    BYTE $0x90            //NOP

    //r12存储syscall;ret地址
    //mov r12, rdx
    BYTE $0x49
    BYTE $0x89
    BYTE $0xd4

    BYTE $0x90            //NOP

    //ret
    BYTE $0xc3


    //nop
    BYTE $0x90

    //xor rax,rax
    BYTE $0x48
    BYTE $0x31
    BYTE $0xc0

    //nop
    BYTE $0x90

    //mov rax, rcx
    BYTE $0x48
    BYTE $0x89
    BYTE $0xc8

    //nop
    BYTE $0x90

    //mov r10, rax
    BYTE $0x49
    BYTE $0x89
    BYTE $0xc2

    //nop
    BYTE $0x90


    //sysid
    //mov eax, r15d
    BYTE $0x44
    BYTE $0x89
    BYTE $0xf8


    //nop
    BYTE $0x90

    //跳转代替syscall
    //jmp r12
    BYTE $0x41
    BYTE $0xff
    BYTE $0xe4

    BYTE $0x90            //NOP

    BYTE $0xc3



//func getModuleLoadedOrder(i int) (start uintptr, size uintptr)
TEXT ·getMLO(SB), $0-32
    //All operations push values into AX
    //PEB
    MOVQ 0x60(GS), AX
    BYTE $0x90            //NOP
    //PEB->LDR
    MOVQ 0x18(AX),AX
    BYTE $0x90            //NOP

    //LDR->InMemoryOrderModuleList
    MOVQ 0x20(AX),AX
    BYTE $0x90            //NOP

    //loop things
    XORQ R10,R10
startloop:
    CMPQ R10,i+0(FP)
    BYTE $0x90            //NOP
    JE endloop
    BYTE $0x90            //NOP
    //Flink (get next element)
    MOVQ (AX),AX
    BYTE $0x90            //NOP
    INCQ R10
    JMP startloop
endloop:
    //Flink - 0x10 -> _LDR_DATA_TABLE_ENTRY
    //_LDR_DATA_TABLE_ENTRY->DllBase (offset 0x30)

    MOVQ 0x30(AX),CX
    BYTE $0x90            //NOP
    MOVQ CX, size+16(FP)
    BYTE $0x90            //NOP


    MOVQ 0x20(AX),CX
    BYTE $0x90            //NOP
    MOVQ CX, start+8(FP)
    BYTE $0x90            //NOP


    MOVQ AX,CX
    BYTE $0x90            //NOP
    ADDQ $0x38,CX
    BYTE $0x90            //NOP
    MOVQ CX, modulepath+24(FP)
    //SYSCALL
    RET

