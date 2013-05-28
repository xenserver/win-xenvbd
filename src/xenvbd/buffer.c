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

#include "buffer.h"
#include "thread.h"
#include "debug.h"
#include "assert.h"
#include "util.h"

#define BUFFER_POOL_TAG 'fuBX'

#define BUFFER_MIN_COUNT         32

extern PHYSICAL_ADDRESS MmGetPhysicalAddress(PVOID BaseAddress);

typedef struct _XENVBD_BUFFER {
    LIST_ENTRY          Entry;
    PMDL                Mdl;
    PVOID               VAddr;
    PFN_NUMBER          Pfn;
    PVOID               Context;
} XENVBD_BUFFER, *PXENVBD_BUFFER;

typedef struct _XENVBD_BOUNCE_BUFFER {
    LIST_ENTRY          FreeList;
    LIST_ENTRY          UsedList;
    ULONG               FreeSize;
    ULONG               UsedSize;
    ULONG               FreeMaxSize;
    ULONG               UsedMaxSize;
    KSPIN_LOCK          Lock;
    PXENVBD_THREAD      Thread;
    ULONG               ReapThreadCount;
    ULONG               Reaped;
    ULONG               Allocated;
    ULONG               Freed;
} XENVBD_BOUNCE_BUFFER, *PXENVBD_BOUNCE_BUFFER;

static XENVBD_BOUNCE_BUFFER __Buffer;

#define TIME_US(_us)        ((_us) * 10)
#define TIME_MS(_ms)        (TIME_US((_ms) * 1000))
#define TIME_S(_s)          (TIME_MS((_s) * 1000))
#define TIME_RELATIVE(_t)   (-(_t))

static DECLSPEC_NOINLINE PXENVBD_BUFFER
__BufferAlloc()
{
    PXENVBD_BUFFER  BufferId;

    BufferId = (PXENVBD_BUFFER)__AllocateNonPagedPoolWithTag(__FUNCTION__, __LINE__, sizeof(XENVBD_BUFFER), BUFFER_POOL_TAG);
    if (BufferId == NULL)
        goto fail1;

    RtlZeroMemory(BufferId, sizeof(XENVBD_BUFFER));
    
    BufferId->VAddr = __AllocPages(PAGE_SIZE, &BufferId->Mdl);
    if (BufferId->VAddr == NULL)
        goto fail2;

    BufferId->Pfn = (PFN_NUMBER)(MmGetPhysicalAddress(BufferId->VAddr).QuadPart >> PAGE_SHIFT);
    
    ++__Buffer.Allocated;
    return BufferId;

fail2:
    __FreePoolWithTag(BufferId, BUFFER_POOL_TAG);
fail1:
    return NULL;
}
static DECLSPEC_NOINLINE VOID
__BufferFree(
    IN PXENVBD_BUFFER           BufferId
    )
{
    if (BufferId == NULL)
        return;

    __FreePages(BufferId->VAddr, BufferId->Mdl);
    __FreePoolWithTag((PVOID)BufferId, BUFFER_POOL_TAG);

    ++__Buffer.Freed;
}
static DECLSPEC_NOINLINE BOOLEAN
__IsOnList(
    IN  PLIST_ENTRY             ListHead,
    IN  PLIST_ENTRY             ListItem
    )
{
    PLIST_ENTRY Entry;

    for (Entry = ListHead->Flink; Entry != ListHead; Entry = Entry->Flink) {
        if (Entry == ListItem) {
            return TRUE;
        }
    }
    return FALSE;
}

#ifdef DBG
#define IsOnList(a, b)  __IsOnList(a, b)
#else
#define IsOnList(a, b)  (TRUE)
#endif

static DECLSPEC_NOINLINE VOID
__BufferPushFreeList(
    IN PXENVBD_BUFFER           BufferId
    )
{
    ASSERT3P(BufferId->Entry.Flink, ==, NULL);
    ASSERT3P(BufferId->Entry.Blink, ==, NULL);

    InsertHeadList(&__Buffer.FreeList, &BufferId->Entry);
    ++__Buffer.FreeSize;
    if (__Buffer.FreeSize > __Buffer.FreeMaxSize)
        __Buffer.FreeMaxSize = __Buffer.FreeSize;
}
static DECLSPEC_NOINLINE PXENVBD_BUFFER
__BufferPopFreeList(
)
{
    PLIST_ENTRY     Entry;

    Entry = RemoveHeadList(&__Buffer.FreeList);
    if (Entry && Entry != &__Buffer.FreeList) {
        PXENVBD_BUFFER BufferId = CONTAINING_RECORD(Entry, XENVBD_BUFFER, Entry);
        BufferId->Entry.Flink = NULL;
        BufferId->Entry.Blink = NULL;
        --__Buffer.FreeSize;
        return BufferId;
    }

    return NULL;
}
static DECLSPEC_NOINLINE VOID
__BufferPushUsedList(
    IN PXENVBD_BUFFER           BufferId
)
{
    ASSERT3P(BufferId->Entry.Flink, ==, NULL);
    ASSERT3P(BufferId->Entry.Blink, ==, NULL);

    InsertHeadList(&__Buffer.UsedList, &BufferId->Entry);
    ++__Buffer.UsedSize;
    if (__Buffer.UsedSize > __Buffer.UsedMaxSize)
        __Buffer.UsedMaxSize = __Buffer.UsedSize;
}
static DECLSPEC_NOINLINE PXENVBD_BUFFER
__BufferPopUsedList(
)
{
    PLIST_ENTRY     Entry;

    Entry = RemoveHeadList(&__Buffer.UsedList);
    if (Entry && Entry != &__Buffer.UsedList) {
        PXENVBD_BUFFER BufferId = CONTAINING_RECORD(Entry, XENVBD_BUFFER, Entry);
        BufferId->Entry.Flink = NULL;
        BufferId->Entry.Blink = NULL;
        --__Buffer.UsedSize;
        return BufferId;
    }

    return NULL;
}
static DECLSPEC_NOINLINE VOID
__BufferRemoveUsedList(
    IN PXENVBD_BUFFER           BufferId
    )
{
    ASSERT3P(BufferId->Entry.Flink, !=, NULL);
    ASSERT3P(BufferId->Entry.Blink, !=, NULL);
    ASSERT(IsOnList(&__Buffer.UsedList, &BufferId->Entry));

    RemoveEntryList(&BufferId->Entry);
    BufferId->Entry.Flink = NULL;
    BufferId->Entry.Blink = NULL;
    --__Buffer.UsedSize;
}
static DECLSPEC_NOINLINE NTSTATUS
__BufferReaperThread(
    IN PXENVBD_THREAD           Thread,
    IN PVOID                    Context
    )
{
    KIRQL           Irql;
    PKEVENT         Event;
    LARGE_INTEGER   Timeout;
    PXENVBD_BUFFER  BufferId;

    UNREFERENCED_PARAMETER(Context);
    
    Timeout.QuadPart = TIME_RELATIVE(TIME_S(1)); // 1 Second
    Event = ThreadGetEvent(Thread);

    while (TRUE) {
        KeWaitForSingleObject(Event, Executive, KernelMode, FALSE, &Timeout);
        if (ThreadIsAlerted(Thread))
            break;

        KeAcquireSpinLock(&__Buffer.Lock, &Irql);
        if (__Buffer.FreeSize > BUFFER_MIN_COUNT) {
            Verbose("Reaping Buffers (%d > %d)\n", __Buffer.FreeSize, BUFFER_MIN_COUNT);
            ++__Buffer.ReapThreadCount;
        }
        while (__Buffer.FreeSize > BUFFER_MIN_COUNT) {
            BufferId = __BufferPopFreeList();
            if (BufferId) {
                ++__Buffer.Reaped;
                __BufferFree(BufferId);
            }
        }
        KeReleaseSpinLock(&__Buffer.Lock, Irql);
    }

    return STATUS_SUCCESS;
}

VOID
BufferInitialize(
    )
{
    ULONG           i;
    PXENVBD_BUFFER  BufferId;

    RtlZeroMemory(&__Buffer, sizeof(XENVBD_BOUNCE_BUFFER));
    KeInitializeSpinLock(&__Buffer.Lock);
    InitializeListHead(&__Buffer.FreeList);
    InitializeListHead(&__Buffer.UsedList);

    for (i = 0; i < BUFFER_MIN_COUNT; ++i) {
        BufferId = __BufferAlloc();
        if (BufferId) {
            __BufferPushFreeList(BufferId);
        }
    }

    if (__Buffer.Thread == NULL) {
        (VOID) ThreadCreate(__BufferReaperThread, NULL, &__Buffer.Thread);
    }
}

VOID
BufferTerminate(
    )
{
    PXENVBD_BUFFER  BufferId;

    if (__Buffer.Thread) {
        ThreadAlert(__Buffer.Thread);
        ThreadJoin(__Buffer.Thread);
        __Buffer.Thread = NULL;
    }

    while ((BufferId = __BufferPopUsedList()) != NULL) {
        Warning("Potentially leaking buffer @ 0x%p\n", BufferId->VAddr);
        __BufferPushFreeList(BufferId);
    }
    while ((BufferId = __BufferPopFreeList()) != NULL) {
        __BufferFree(BufferId);
    }
}

__checkReturn
BOOLEAN
BufferGet(
    __in  PVOID             _Context,
    __out PVOID*            _BufferId,
    __out PFN_NUMBER*       Pfn
    )
{
    PXENVBD_BUFFER  BufferId;
    KIRQL           Irql;
    BOOLEAN         Result = FALSE;

	*_BufferId = NULL;
	*Pfn = 0;

    KeAcquireSpinLock(&__Buffer.Lock, &Irql);
    BufferId = __BufferPopFreeList();
    if (BufferId == NULL) {
        BufferId = __BufferAlloc();
    }
    if (BufferId) {
        __BufferPushUsedList(BufferId);

        BufferId->Context = _Context;
        *_BufferId = BufferId;
        *Pfn = BufferId->Pfn; 
        Result = TRUE;
    } 
    KeReleaseSpinLock(&__Buffer.Lock, Irql);
    
    return Result;
}

VOID
BufferPut(
    __in PVOID              _BufferId
    )
{
    KIRQL           Irql;
    PXENVBD_BUFFER  BufferId = (PXENVBD_BUFFER)_BufferId;

    KeAcquireSpinLock(&__Buffer.Lock, &Irql);
    __BufferRemoveUsedList(BufferId);
    BufferId->Context = NULL;
    __BufferPushFreeList(BufferId);
    KeReleaseSpinLock(&__Buffer.Lock, Irql);
}

VOID
BufferCopyIn(
    __in PVOID              _BufferId,
    __in PVOID              Input,
    __in ULONG              Length
    )
{
    PXENVBD_BUFFER  BufferId = (PXENVBD_BUFFER)_BufferId;

    ASSERT3P(BufferId, !=, NULL);
    ASSERT3P(Input, !=, NULL);
    ASSERT3U(Length, <=, PAGE_SIZE);

    ASSERT3P(BufferId->VAddr, !=, NULL);
    ASSERT(IsOnList(&__Buffer.UsedList, &BufferId->Entry));
    RtlCopyMemory(BufferId->VAddr, Input, Length);
}

VOID
BufferCopyOut(
    __in PVOID              _BufferId,
    __in PVOID              Output,
    __in ULONG              Length
    )
{
    PXENVBD_BUFFER  BufferId = (PXENVBD_BUFFER)_BufferId;

    ASSERT3P(BufferId, !=, NULL);
    ASSERT3P(Output, !=, NULL);
    ASSERT3U(Length, <=, PAGE_SIZE);

    ASSERT3P(BufferId->VAddr, !=, NULL);
    ASSERT(IsOnList(&__Buffer.UsedList, &BufferId->Entry));
    RtlCopyMemory(Output, BufferId->VAddr, Length);
}

VOID 
BufferDebugCallback(
    __in PXENBUS_DEBUG_INTERFACE DebugInterface,
    __in PXENBUS_DEBUG_CALLBACK  DebugCallback
    )
{
    PLIST_ENTRY Entry;

    DEBUG(Printf, DebugInterface, DebugCallback,
            "BUFFER: Allocated/Freed : %d / %d\n",
            __Buffer.Allocated, __Buffer.Freed);
    DEBUG(Printf, DebugInterface, DebugCallback,
            "BUFFER: Free (Cur/Max)  : %d / %d\n",
            __Buffer.FreeSize, __Buffer.FreeMaxSize);
    DEBUG(Printf, DebugInterface, DebugCallback,
            "BUFFER: Used (Cur/Max)  : %d / %d\n",
            __Buffer.UsedSize, __Buffer.UsedMaxSize);

    for (Entry = __Buffer.UsedList.Flink; Entry != &__Buffer.UsedList; Entry = Entry->Flink) {
        PXENVBD_BUFFER BufferId = CONTAINING_RECORD(Entry, XENVBD_BUFFER, Entry);

        DEBUG(Printf, DebugInterface, DebugCallback,
                "BUFFER: (Used)          : VADDR:0x%p PFN:%p (SRB 0x%p)\n",
                BufferId->VAddr, (void*)BufferId->Pfn, BufferId->Context);
    }

    DEBUG(Printf, DebugInterface, DebugCallback,
            "BUFFER: Reaped          : %d / %d\n", 
            __Buffer.Reaped, __Buffer.ReapThreadCount);
}
