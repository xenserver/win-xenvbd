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

#include "queue.h"
#include "srbext.h"

#include "log.h"
#include "assert.h"

static FORCEINLINE BOOLEAN
__QueueValid(
    IN  PSRB_QUEUE          Queue
    )
{
    if (( Queue->Count == 0 && (Queue->Head != NULL || Queue->Tail != NULL) ) ||
        ( Queue->Count != 0 && (Queue->Head == NULL || Queue->Tail == NULL) ) ||
        ( Queue->Count < 0) ) {
        LogError("Queue(%p): Count = %d, Head = %p, Tail = %p\n", Queue, Queue->Count, Queue->Head, Queue->Tail);
        return FALSE;
    }
    return TRUE;
}
static VOID
__QueueRemoveLocked(
    IN  PSRB_QUEUE          Queue,
    IN  PSCSI_REQUEST_BLOCK Srb
    )
{
    PXENVBD_SRBEXT  SrbExt = GetSrbExt(Srb);

    ASSERT3P(SrbExt->QueueHead, ==, Queue);

    if (SrbExt->QueueNext) {
        PXENVBD_SRBEXT Next = GetSrbExt(SrbExt->QueueNext);
        Next->QueuePrev = SrbExt->QueuePrev;
    } else {
        ASSERT3P(Queue->Tail, ==, Srb);
        Queue->Tail = SrbExt->QueuePrev;
    }
    if (SrbExt->QueuePrev) {
        PXENVBD_SRBEXT Prev = GetSrbExt(SrbExt->QueuePrev);
        Prev->QueueNext = SrbExt->QueueNext;
    } else {
        ASSERT3P(Queue->Head, ==, Srb);
        Queue->Head = SrbExt->QueueNext;
    }

    ASSERT3U(Queue->Count, >, 0);
    InterlockedDecrement(&Queue->Count);
    ASSERT3U(Queue->Count, >=, 0);
    ASSERT(__QueueValid(Queue));

    SrbExt->QueueHead = NULL;
    SrbExt->QueueNext = NULL;
    SrbExt->QueuePrev = NULL;
}

static FORCEINLINE VOID
__QueueInsertHeadLocked(
    IN  PSRB_QUEUE          Queue,
    IN  PSCSI_REQUEST_BLOCK Srb
    )
{
    PXENVBD_SRBEXT  SrbExt = GetSrbExt(Srb);

    ASSERT3P(SrbExt->QueueHead, ==, NULL);

    SrbExt->QueuePrev = NULL;
    SrbExt->QueueNext = Queue->Head;
    if (Queue->Head) {
        PXENVBD_SRBEXT Head = GetSrbExt(Queue->Head);
        Head->QueuePrev = Srb;
    }
    Queue->Head = Srb;
    if (!Queue->Tail) {
        Queue->Tail = Srb;
    }

    InterlockedIncrement(&Queue->Count);
    ASSERT3U(Queue->Count, >, 0);
    if (Queue->Count > Queue->MaxCount)
        Queue->MaxCount = Queue->Count;

    ASSERT(__QueueValid(Queue));

    SrbExt->QueueHead = Queue;
}

static FORCEINLINE VOID
__QueueInsertTailLocked(
    IN  PSRB_QUEUE          Queue,
    IN  PSCSI_REQUEST_BLOCK Srb
    )
{
    PXENVBD_SRBEXT  SrbExt = GetSrbExt(Srb);

    ASSERT3P(SrbExt->QueueHead, ==, NULL);

    SrbExt->QueueNext = NULL;
    SrbExt->QueuePrev = Queue->Tail;
    if (Queue->Tail) {
        PXENVBD_SRBEXT Tail = GetSrbExt(Queue->Tail);
        Tail->QueueNext = Srb;
    }
    Queue->Tail = Srb;
    if (!Queue->Head) {
        Queue->Head = Srb;
    }

    InterlockedIncrement(&Queue->Count);
    ASSERT3U(Queue->Count, >, 0);
    if (Queue->Count > Queue->MaxCount)
        Queue->MaxCount = Queue->Count;

    ASSERT(__QueueValid(Queue));

    SrbExt->QueueHead = Queue;
}

PSCSI_REQUEST_BLOCK
QueuePeek(
    IN  PSRB_QUEUE          Queue
    )
{
    ASSERT(__QueueValid(Queue));
    return Queue->Head;
}

PSCSI_REQUEST_BLOCK
QueuePop(
    IN  PSRB_QUEUE          Queue
    )
{
    PSCSI_REQUEST_BLOCK Srb = NULL;

    Srb = Queue->Head;
    if (Srb)
        __QueueRemoveLocked(Queue, Srb);
    return Srb;
}

VOID
QueueInsertHead(
    IN  PSRB_QUEUE          Queue,
    IN  PSCSI_REQUEST_BLOCK Srb
    )
{
    __QueueInsertHeadLocked(Queue, Srb);
}

VOID
QueueInsertTail(
    IN  PSRB_QUEUE          Queue,
    IN  PSCSI_REQUEST_BLOCK Srb
    )
{
    __QueueInsertTailLocked(Queue, Srb);
}

VOID
QueueRemove(
    IN  PSRB_QUEUE          Queue,
    IN  PSCSI_REQUEST_BLOCK Srb
    )
{
    __QueueRemoveLocked(Queue, Srb);
}

VOID
QueueDebugCallback(
    IN  PSRB_QUEUE          Queue,
    IN  PCHAR               Name
    )
{
    LogTrace("=====> %s\n", Name);
    LogTrace("== Head          : 0x%p\n", Queue->Head);
    LogTrace("== Tail          : 0x%p\n", Queue->Tail);
    LogTrace("== Count         : %d\n", Queue->Count);
    LogTrace("== MaxCount      : %d\n", Queue->MaxCount);
    LogTrace("<===== %s\n", Name);

    Queue->MaxCount = Queue->Count;
}

