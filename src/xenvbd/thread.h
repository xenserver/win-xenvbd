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

#ifndef _XENVBD_THREAD_H
#define _XENVBD_THREAD_H

#include <ntddk.h>

typedef struct _XENVBD_THREAD XENVBD_THREAD, *PXENVBD_THREAD;

typedef NTSTATUS (*XENVBD_THREAD_FUNCTION)(PXENVBD_THREAD, PVOID);

__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
extern NTSTATUS
_ThreadCreate(
    __in  PCHAR                   Name,
    __in  XENVBD_THREAD_FUNCTION  Function,
    __in_opt PVOID                Context,
    __out PXENVBD_THREAD          *Thread
    );

#define ThreadCreate(_f, _c, _t)    \
            _ThreadCreate(#_f, _f, _c, _t)

extern PKEVENT
ThreadGetEvent(
    __in PXENVBD_THREAD  Self
    );

__checkReturn
extern BOOLEAN
ThreadIsAlerted(
    __in PXENVBD_THREAD  Self
    );

extern VOID
ThreadWake(
    __in PXENVBD_THREAD  Thread
    );

extern VOID
ThreadAlert(
    __in PXENVBD_THREAD  Thread
    );

__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
extern BOOLEAN
ThreadWait(
    __in PXENVBD_THREAD  Thread
    );

__drv_maxIRQL(PASSIVE_LEVEL)
extern VOID
ThreadJoin(
    __in PXENVBD_THREAD  Thread
    );

#endif  // _XENVBD_THREAD_H

