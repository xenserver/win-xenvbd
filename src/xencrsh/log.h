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

#ifndef _XENCRSH_LOG_H
#define _XENCRSH_LOG_H

#include <ntddk.h>
#include <stdarg.h>

#pragma warning(disable:4127)   // conditional expression is constant

extern void
__LogMessage(
    IN  ULONG       Level,
    IN  const char* Func,
    IN  const char* Format,
    ...
    );

#define LogError(...)   __LogMessage(DPFLTR_ERROR_LEVEL,   __FUNCTION__, __VA_ARGS__)
#define LogWarning(...) __LogMessage(DPFLTR_WARNING_LEVEL, __FUNCTION__, __VA_ARGS__)
#define LogVerbose(...) __LogMessage(DPFLTR_INFO_LEVEL,    __FUNCTION__, __VA_ARGS__)

#if DBG
#define LogTrace(...)   __LogMessage(DPFLTR_TRACE_LEVEL,   __FUNCTION__, __VA_ARGS__)
#else
#define LogTrace(...)   (void)(__VA_ARGS__)
#endif

#endif  // _XENCRSH_LOG_H
