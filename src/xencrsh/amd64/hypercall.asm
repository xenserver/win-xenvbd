                page    ,132
                title   Hypercall Gates

                .code

                extrn   Hypercall:qword

                ; uintptr_t __stdcall asm___hypercall2(uint32_t ord, uintptr_t arg1, uintptr_t arg2);
                public asm___hypercall2
asm___hypercall2 proc
	        push rdi
	        push rsi
	        mov rdi, rdx                            ; arg1
	        mov rax, qword ptr [Hypercall]
	        shl rcx, 5                              ; ord
	        add rax, rcx
	        mov rsi, r8                             ; arg2
	        call rax
	        pop rsi
	        pop rdi
	        ret
asm___hypercall2 endp

                ; uintptr_t __stdcall asm___hypercall3(uint32_t ord, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3);
                public asm___hypercall3
asm___hypercall3 proc
	        push rdi
	        push rsi
	        mov rdi, rdx                            ; arg1
	        mov rax, qword ptr [Hypercall]
	        shl rcx, 5                              ; ord
	        add rax, rcx
	        mov rsi, r8                             ; arg2
	        mov rdx, r9                             ; arg3
	        call rax
	        pop rsi
	        pop rdi
	        ret
asm___hypercall3 endp

                end


