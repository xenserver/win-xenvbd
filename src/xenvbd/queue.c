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
#include "debug.h"
#include "assert.h"
#include <xencdb.h>

__drv_requiresIRQL(DISPATCH_LEVEL)
static VOID
__QueueRemoveLocked(
    __in PSRB_QUEUE          Queue,
    __in PSCSI_REQUEST_BLOCK Srb
    )
{
    PXENVBD_SRBEXT  SrbExt = GetSrbExt(Srb);

    ASSERT3P(SrbExt, !=, NULL);
    ASSERT3P(SrbExt->QueueHead, ==, Queue);
    ASSERT3P(SrbExt->QueueEntry.Flink, !=, NULL);
    ASSERT3P(SrbExt->QueueEntry.Blink, !=, NULL);

    RemoveEntryList(&SrbExt->QueueEntry);
    ASSERT3U(Queue->Count, !=, 0);
    --Queue->Count;

    SrbExt->QueueHead = NULL;
    SrbExt->QueueEntry.Flink = SrbExt->QueueEntry.Blink = NULL;
}

__drv_requiresIRQL(DISPATCH_LEVEL)
static FORCEINLINE VOID
__QueueInsertHeadLocked(
    __in PSRB_QUEUE          Queue,
    __in PSCSI_REQUEST_BLOCK Srb
    )
{
    PXENVBD_SRBEXT  SrbExt = GetSrbExt(Srb);

    ASSERT3P(SrbExt, !=, NULL);
    ASSERT3P(SrbExt->QueueHead, ==, NULL);
    ASSERT3P(SrbExt->QueueEntry.Flink, ==, NULL);
    ASSERT3P(SrbExt->QueueEntry.Blink, ==, NULL);

    InsertHeadList(&Queue->List, &SrbExt->QueueEntry);
    ++Queue->Count;
    if (Queue->Count > Queue->MaxCount)
        Queue->MaxCount = Queue->Count;

    SrbExt->QueueHead = Queue;
}

__drv_requiresIRQL(DISPATCH_LEVEL)
static FORCEINLINE VOID
__QueueInsertTailLocked(
    __in PSRB_QUEUE          Queue,
    __in PSCSI_REQUEST_BLOCK Srb
    )
{
    PXENVBD_SRBEXT  SrbExt = GetSrbExt(Srb);

    ASSERT3P(SrbExt, !=, NULL);
    ASSERT3P(SrbExt->QueueHead, ==, NULL);
    ASSERT3P(SrbExt->QueueEntry.Flink, ==, NULL);
    ASSERT3P(SrbExt->QueueEntry.Blink, ==, NULL);

    InsertTailList(&Queue->List, &SrbExt->QueueEntry);
    ++Queue->Count;
    if (Queue->Count > Queue->MaxCount)
        Queue->MaxCount = Queue->Count;

    SrbExt->QueueHead = Queue;
}

VOID
QueueInit(
    __in PSRB_QUEUE          Queue
    )
{
    KeInitializeSpinLock(&Queue->Lock);
    InitializeListHead(&Queue->List);
}

ULONG
QueueCount(
    __in PSRB_QUEUE          Queue
    )
{
    KIRQL               Irql;
    ULONG               Count;

    KeAcquireSpinLock(&Queue->Lock, &Irql);
    
    Count = Queue->Count;
    
    KeReleaseSpinLock(&Queue->Lock, Irql);

    return Count;
}

__checkReturn
PSCSI_REQUEST_BLOCK
QueuePeek(
    __in PSRB_QUEUE          Queue
    )
{
    KIRQL               Irql;
    PSCSI_REQUEST_BLOCK Srb = NULL;

    KeAcquireSpinLock(&Queue->Lock, &Irql);
    
    if (!IsListEmpty(&Queue->List)) {
        PXENVBD_SRBEXT  SrbExt = CONTAINING_RECORD(Queue->List.Flink, XENVBD_SRBEXT, QueueEntry);
        Srb = SrbExt->Srb;
    }
    
    KeReleaseSpinLock(&Queue->Lock, Irql);

    return Srb;
}

__checkReturn
PSCSI_REQUEST_BLOCK
QueuePop(
    __in PSRB_QUEUE          Queue
    )
{
    KIRQL               Irql;
    PSCSI_REQUEST_BLOCK Srb = NULL;

    KeAcquireSpinLock(&Queue->Lock, &Irql);

    if (!IsListEmpty(&Queue->List)) {
        PXENVBD_SRBEXT  SrbExt = CONTAINING_RECORD(Queue->List.Flink, XENVBD_SRBEXT, QueueEntry);
        Srb = SrbExt->Srb;
        __QueueRemoveLocked(Queue, Srb);
    }

    KeReleaseSpinLock(&Queue->Lock, Irql);

    return Srb;
}

__checkReturn
PSCSI_REQUEST_BLOCK
QueueRemoveTail(
    __in PSRB_QUEUE          Queue
    )
{
    KIRQL               Irql;
    PSCSI_REQUEST_BLOCK Srb = NULL;

    KeAcquireSpinLock(&Queue->Lock, &Irql);

    if (!IsListEmpty(&Queue->List)) {
        PXENVBD_SRBEXT  SrbExt = CONTAINING_RECORD(Queue->List.Blink, XENVBD_SRBEXT, QueueEntry);
        Srb = SrbExt->Srb;
        __QueueRemoveLocked(Queue, Srb);
    }

    KeReleaseSpinLock(&Queue->Lock, Irql);

    return Srb;
}

VOID
QueueInsertHead(
    __in PSRB_QUEUE          Queue,
    __in PSCSI_REQUEST_BLOCK Srb
    )
{
    KIRQL               Irql;

    KeAcquireSpinLock(&Queue->Lock, &Irql);
    
    __QueueInsertHeadLocked(Queue, Srb);
    
    KeReleaseSpinLock(&Queue->Lock, Irql);
}

VOID
QueueInsertTail(
    __in PSRB_QUEUE          Queue,
    __in PSCSI_REQUEST_BLOCK Srb
    )
{
    KIRQL               Irql;

    KeAcquireSpinLock(&Queue->Lock, &Irql);
    
    __QueueInsertTailLocked(Queue, Srb);
    
    KeReleaseSpinLock(&Queue->Lock, Irql);
}

VOID
QueueRemove(
    __in PSRB_QUEUE          Queue,
    __in PSCSI_REQUEST_BLOCK Srb
    )
{
    KIRQL               Irql;

    KeAcquireSpinLock(&Queue->Lock, &Irql);

    __QueueRemoveLocked(Queue, Srb);
    
    KeReleaseSpinLock(&Queue->Lock, Irql);
}

VOID
QueueDebugCallback(
    __in PSRB_QUEUE          Queue,
    __in __nullterminated const CHAR *Name,
    __in PXENBUS_DEBUG_INTERFACE Debug,
    __in PXENBUS_DEBUG_CALLBACK  Callback
    )
{
    PLIST_ENTRY     Entry;
    ULONG           Index;

    for (Entry = Queue->List.Flink, Index = 0;
            Entry != &Queue->List;
            Entry = Entry->Flink, ++Index) {

        PXENVBD_SRBEXT  SrbExt = CONTAINING_RECORD(Entry, XENVBD_SRBEXT, QueueEntry);
        PSCSI_REQUEST_BLOCK Srb = SrbExt->Srb;

        DEBUG(Printf, Debug, Callback,
                "QUEUE: %10s : [%-3d] : { 0x%p %s (%d) }\n",
                Name, Index, Srb, Cdb_OperationName(Srb->Cdb[0]), 
                SrbExt->RequestSize);
    }

    DEBUG(Printf, Debug, Callback,
            "QUEUE: %10s : Count    : %d\n", 
            Name, Queue->Count);
    DEBUG(Printf, Debug, Callback,
            "QUEUE: %10s : MaxCount : %d\n", 
            Name, Queue->MaxCount);

    Queue->MaxCount = Queue->Count;
}

