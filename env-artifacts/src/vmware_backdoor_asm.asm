; vmware_backdoor_asm.asm
; Windows x64 MASM helper for the VMware I/O backdoor probe.
;
; Executes:  IN EAX, DX
;   with EAX = 564D5868h ("VMXh"), ECX = 0, EDX = 5658h ("VX")
;
; VMware intercepts this instruction and writes 564D5868h into EBX.
; On bare metal the IN causes a GPF; the C caller wraps this in __try/__except.
;
; Prototype (C linkage):
;   uint32_t vmware_backdoor_probe(void);
; Returns: value of EBX after the IN instruction (via EAX/RAX per Win64 ABI).
;
; Calling convention: Microsoft x64 (no args; return in RAX).
; Non-volatile registers used: RBX — saved/restored around the probe.

.code

vmware_backdoor_probe PROC
    push    rbx                 ; RBX is non-volatile in the Win64 ABI

    mov     eax, 0564D5868h     ; EAX = "VMXh" magic
    xor     ebx, ebx            ; EBX = 0  (cleared so we can detect the magic response)
    xor     ecx, ecx            ; ECX = 0x0  (command, as per spec)
    mov     edx, 05658h         ; EDX = 0x5658  ("VX" port)

    in      eax, dx             ; VMware traps this; bare metal triggers a GPF

    mov     eax, ebx            ; return EBX value in RAX (Win64 return register)
    pop     rbx                 ; restore non-volatile RBX
    ret
vmware_backdoor_probe ENDP

END
