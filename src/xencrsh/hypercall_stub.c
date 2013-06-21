/* Copyright (c) Citrix Systems Inc.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, 
 * with or without modification, are permitted provided 
 * that the following conditions are met:
 * 
 * *   Redistributions of source code must retain the above 
 *     copyright notice, this list of conditions and the 
 *     following disclaimer.
 * *   Redistributions in binary form must reproduce the above 
 *     copyright notice, this list of conditions and the 
 *     following disclaimer in the documentation and/or other 
 *     materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND 
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR 
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING 
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE.
 */ 

#include <wdm.h>
#include <xenvbd-storport.h>


#include <xen-version.h>
#include <xen\xen-compat.h>
         
#include <xen-types.h>

#include "hypercall.h"

extern uintptr_t __stdcall asm___hypercall2(uint32_t ord, uintptr_t arg1, uintptr_t arg2);

ULONG_PTR
___Hypercall2(
    ULONG       Ordinal,
    ULONG_PTR   Argument1,
    ULONG_PTR   Argument2
    )
{
    return asm___hypercall2(Ordinal, Argument1, Argument2);
}

extern uintptr_t __stdcall asm___hypercall3(uint32_t ord, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3);

ULONG_PTR
___Hypercall3(
    ULONG       Ordinal,
    ULONG_PTR   Argument1,
    ULONG_PTR   Argument2,
    ULONG_PTR   Argument3
    )
{
    return asm___hypercall3(Ordinal, Argument1, Argument2, Argument3);
}
