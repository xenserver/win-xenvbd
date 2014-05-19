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

#ifndef _DEBUG_H
#define _DEBUG_H

#include <ntddk.h>
#include <stdarg.h>

#ifdef  _SDV_
#define __MODULE__ ""
#endif

// DEBUG_FILTER_MASKs
// Set these to see relevant output
// ERROR        0x00000001
// WARNING      0x00000002
// TRACE        0x00000004
// INFO         0x00000008

#pragma warning(disable:4127)   // conditional expression is constant

//
// Debug Output and Logging
//
static __inline VOID
__DebugMessage(
    __in    ULONG       Level,
    __in __nullterminated const CHAR  *Prefix,
    __in __nullterminated const CHAR  *Format,
    ...
    )
{
    va_list         Arguments;

    va_start(Arguments, Format);

#pragma prefast(suppress:6001) // Using uninitialized memory
    vDbgPrintExWithPrefix(Prefix,
                          DPFLTR_IHVDRIVER_ID,
                          Level,
                          Format,
                          Arguments);
    va_end(Arguments);
}

#define Error(...)  \
        __DebugMessage(DPFLTR_ERROR_LEVEL, __MODULE__ "|" __FUNCTION__ ":", __VA_ARGS__)

#define Warning(...)  \
        __DebugMessage(DPFLTR_WARNING_LEVEL, __MODULE__ "|" __FUNCTION__ ":", __VA_ARGS__)

#if DBG
#define Trace(...)  \
        __DebugMessage(DPFLTR_TRACE_LEVEL, __MODULE__ "|" __FUNCTION__ ":", __VA_ARGS__)
#else   // DBG
#define Trace(...) \
        (VOID)(__VA_ARGS__)
#endif  // DBG

#define Verbose(...) \
        __DebugMessage(DPFLTR_INFO_LEVEL, __MODULE__ "|" __FUNCTION__ ":", __VA_ARGS__)

#include "assert.h"

#endif  // _DEBUG_H
