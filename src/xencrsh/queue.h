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
#include <xenvbd-storport.h>

//typedef struct _XENVBD_SRBEXT {
//    PVOID               QueueHead;  // Pointer to Queue (or NULL)
//    PVOID               QueueNext;  // Next SRB in chain (or NULL)
//    PVOID               QueuePrev;  // Prev SRB in chain (or NULL)
//    ...
typedef struct _SRB_QUEUE {
    PSCSI_REQUEST_BLOCK Head;
    PSCSI_REQUEST_BLOCK Tail;
    LONG                Count;
    LONG                MaxCount;
} SRB_QUEUE, *PSRB_QUEUE;

PSCSI_REQUEST_BLOCK
QueuePeek(
    IN  PSRB_QUEUE          Queue
    );

PSCSI_REQUEST_BLOCK
QueuePop(
    IN  PSRB_QUEUE          Queue
    );

VOID
QueueInsertHead(
    IN  PSRB_QUEUE          Queue,
    IN  PSCSI_REQUEST_BLOCK Srb
    );

VOID
QueueInsertTail(
    IN  PSRB_QUEUE          Queue,
    IN  PSCSI_REQUEST_BLOCK Srb
    );

VOID
QueueRemove(
    IN  PSRB_QUEUE          Queue,
    IN  PSCSI_REQUEST_BLOCK Srb
    );

VOID
QueueDebugCallback(
    IN  PSRB_QUEUE          Queue,
    IN  PCHAR               Name
    );

#endif // _XENVBD_QUEUE_H
