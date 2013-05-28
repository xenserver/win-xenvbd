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

#ifndef _XENVBD_BUFFER_H
#define _XENVBD_BUFFER_H

#include <wdm.h>
#include "..\..\include\xenvbd-storport.h"
#include "..\..\include\debug_interface.h"

extern VOID
BufferInitialize(
    );

extern VOID
BufferTerminate(
    );

__checkReturn
extern BOOLEAN
BufferGet(
    __in  PVOID             Context,
    __out PVOID*            BufferId,
    __out PFN_NUMBER*       Pfn
    );

extern VOID
BufferPut(
    __in  PVOID             BufferId
    );

extern VOID
BufferCopyIn(
    __in  PVOID             BufferId,
    __in  PVOID             Input,
    __in  ULONG             Length
    );

extern VOID
BufferCopyOut(
    __in  PVOID             BufferId,
    __in  PVOID             Output,
    __in  ULONG             Length
    );

extern VOID 
BufferDebugCallback(
    __in PXENBUS_DEBUG_INTERFACE DebugInterface,
    __in PXENBUS_DEBUG_CALLBACK  DebugCallback
    );

   
#endif // _XENVBD_BUFFER_H
