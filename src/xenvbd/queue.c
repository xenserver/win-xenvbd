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
#include "debug.h"
#include "assert.h"

VOID
QueueInit(
    __in PXENVBD_QUEUE      Queue
    )
{
    RtlZeroMemory(Queue, sizeof(XENVBD_QUEUE));
    KeInitializeSpinLock(&Queue->Lock);
    InitializeListHead(&Queue->List);
}

ULONG
QueueCount(
    __in PXENVBD_QUEUE      Queue
    )
{
    return Queue->Current;
}

__checkReturn
PLIST_ENTRY
QueuePop(
    __in PXENVBD_QUEUE      Queue
    )
{
    KIRQL       Irql;
    PLIST_ENTRY Entry = NULL;

    KeAcquireSpinLock(&Queue->Lock, &Irql);

    if (!IsListEmpty(&Queue->List)) {
        Entry = RemoveHeadList(&Queue->List);
        ASSERT3P(Entry, !=, &Queue->List);
        --Queue->Current;
    }

    KeReleaseSpinLock(&Queue->Lock, Irql);

    return Entry;
}

VOID
QueueUnPop(
    __in PXENVBD_QUEUE      Queue,
    __in PLIST_ENTRY        Entry
    )
{
    KIRQL               Irql;

    KeAcquireSpinLock(&Queue->Lock, &Irql);
    
    InsertHeadList(&Queue->List, Entry);
    if (++Queue->Current > Queue->Maximum)
        Queue->Maximum = Queue->Current;
    
    KeReleaseSpinLock(&Queue->Lock, Irql);
}

VOID
QueueAppend(
    __in PXENVBD_QUEUE      Queue,
    __in PLIST_ENTRY        Entry
    )
{
    KIRQL               Irql;

    KeAcquireSpinLock(&Queue->Lock, &Irql);
    
    InsertTailList(&Queue->List, Entry);
    if (++Queue->Current > Queue->Maximum)
        Queue->Maximum = Queue->Current;
    
    KeReleaseSpinLock(&Queue->Lock, Irql);
}

VOID
QueueRemove(
    __in PXENVBD_QUEUE      Queue,
    __in PLIST_ENTRY        Entry
    )
{
    KIRQL               Irql;

    KeAcquireSpinLock(&Queue->Lock, &Irql);

    RemoveEntryList(Entry);
    --Queue->Current;
    
    KeReleaseSpinLock(&Queue->Lock, Irql);
}

VOID
QueueDebugCallback(
    __in PXENVBD_QUEUE                  Queue,
    __in __nullterminated const CHAR*   Name,
    __in PXENBUS_DEBUG_INTERFACE        Debug,
    __in PXENBUS_DEBUG_CALLBACK         Callback
    )
{
    DEBUG(Printf, Debug, Callback,
            "QUEUE: %s : %u / %u\n",
            Name, Queue->Current, Queue->Maximum);

    Queue->Maximum = Queue->Current;
}

