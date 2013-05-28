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

#ifndef _XENVBD_QUEUE_H
#define _XENVBD_QUEUE_H

#include <wdm.h>
#include "..\..\include\xenvbd-storport.h"
#include "..\..\include\debug_interface.h"

typedef struct _SRB_QUEUE {
    KSPIN_LOCK          Lock;
    LIST_ENTRY          List;
    ULONG               Count;
    ULONG               MaxCount;
} SRB_QUEUE, *PSRB_QUEUE;

extern VOID
QueueInit(
    __in PSRB_QUEUE          Queue
    );

extern ULONG
QueueCount(
    __in PSRB_QUEUE          Queue
    );

__checkReturn
extern PSCSI_REQUEST_BLOCK
QueuePeek(
    __in PSRB_QUEUE          Queue
    );

__checkReturn
extern PSCSI_REQUEST_BLOCK
QueuePop(
    __in PSRB_QUEUE          Queue
    );

__checkReturn
extern PSCSI_REQUEST_BLOCK
QueueRemoveTail(
    __in PSRB_QUEUE          Queue
    );

extern VOID
QueueInsertHead(
    __in PSRB_QUEUE          Queue,
    __in PSCSI_REQUEST_BLOCK Srb
    );

extern VOID
QueueInsertTail(
    __in PSRB_QUEUE          Queue,
    __in PSCSI_REQUEST_BLOCK Srb
    );

extern VOID
QueueRemove(
    __in PSRB_QUEUE          Queue,
    __in PSCSI_REQUEST_BLOCK Srb
    );

extern VOID
QueueDebugCallback(
    __in PSRB_QUEUE          Queue,
    __in __nullterminated const CHAR *Name,
    __in PXENBUS_DEBUG_INTERFACE Debug,
    __in PXENBUS_DEBUG_CALLBACK  Callback
    );

#endif // _XENVBD_QUEUE_H
