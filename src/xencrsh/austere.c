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

#pragma section(".austere_section", nopage,read,write)
#include "austere.h"
#include "driver.h"

#include "log.h"
#include "assert.h"

#define AUSTERE_TAG     'MEMX'
/* Each vbd needs three pages (two for the TARGET_INFO and one for the
   ring), plus we need at least one bounce buffer, and we need one
   more for other allocations.  We need to support at least 4 disks,
   so we need 4*4=16 pages.  Add an extra couple of pages just to be
   safe, since running out of memory in the austere heap usually leads
   to a crash. */
#define AUSTERE_HEAP_PAGES 23
#define AUSTERE_MAX_ALLOC_SIZE  (8*PAGE_SIZE)
//
// Cause the emergency heap to be allocated in its own section with
// read/write/execute attributes, default is with no execute. On crash
// hibernate, the hypercall page is allocated from this heap and needs
// to be executable.
//

__declspec(allocate(".austere_section"))
static UCHAR __AustereSection[(AUSTERE_HEAP_PAGES + 1) * PAGE_SIZE];

#define SUBHEAP_SIZE (PAGE_SIZE - sizeof(PVOID) * 2 - sizeof(ULONG))

typedef struct _XENCRSH_SUBHEAP {
    struct _XENCRSH_SUBHEAP*    Next;
    struct _XENCRSH_SUBHEAP*    Prev;
    ULONG                       Free;
    UCHAR                       Heap[SUBHEAP_SIZE];
} XENCRSH_SUBHEAP, *PXENCRSH_SUBHEAP;

typedef struct _XENCRSH_HEAP {
    PUCHAR              BigHeapStart;
    ULONG               HeapBlockSizes[AUSTERE_HEAP_PAGES];
    ULONG               BigHeapCursor;
    ULONG               NumHeapPages;
    PXENCRSH_SUBHEAP    HeadSubHeap;
} XENCRSH_HEAP, *PXENCRSH_HEAP;

static XENCRSH_HEAP AustereHeap;

#define FREE_CHUNK      0x80000000

static FORCEINLINE BOOLEAN
__CompactBigHeap()
{
    ULONG   i;
    ULONG   Size;
    BOOLEAN Ret = FALSE;

    for (i = 0; i < AustereHeap.NumHeapPages; ) {
        Size = AustereHeap.HeapBlockSizes[i] & ~FREE_CHUNK;
        if ((AustereHeap.HeapBlockSizes[i] & FREE_CHUNK) &&
            (i + Size < AustereHeap.NumHeapPages)        &&
            (AustereHeap.HeapBlockSizes[i + Size] & FREE_CHUNK)) {
            AustereHeap.HeapBlockSizes[i] = Size + AustereHeap.HeapBlockSizes[i + Size];
            Ret = TRUE;
            continue;
        }
        i += Size;
    }
    return Ret;
}
static PVOID
__AllocBig(
    IN  PCHAR   Caller,
    IN  ULONG   Size
    )
{
    ULONG   NumPages;
    ULONG   i, n;
    PVOID   Res;
    BOOLEAN repeat = FALSE;
    
    NumPages = (ULONG)((Size + PAGE_SIZE - 1) / (PAGE_SIZE));

retry:
    i = AustereHeap.BigHeapCursor % AustereHeap.NumHeapPages;
    for (;;) {
        n = AustereHeap.HeapBlockSizes[i] & ~FREE_CHUNK;
        if (n >= NumPages && AustereHeap.HeapBlockSizes[i] & FREE_CHUNK)
            break;
        i = (i + n) % AustereHeap.NumHeapPages;
        if (i == AustereHeap.BigHeapCursor) {
            if (!repeat && NumPages > 1) {
                if (__CompactBigHeap()) {
                    repeat = TRUE;
                    goto retry;
                }
            }
            LogError("Failed to alloc big (%d bytes) %s\n", Size, Caller);
            return NULL;
        }
    }

    Res = (PVOID)(AustereHeap.BigHeapStart + i * PAGE_SIZE);
    if (AustereHeap.HeapBlockSizes[i] != (NumPages | FREE_CHUNK)) {
        if (i + NumPages <= AUSTERE_HEAP_PAGES)
            AustereHeap.HeapBlockSizes[i + NumPages] = AustereHeap.HeapBlockSizes[i] - NumPages;
    }
    AustereHeap.HeapBlockSizes[i] = NumPages;
    AustereHeap.BigHeapCursor = (i + NumPages) % AustereHeap.NumHeapPages;
    return Res;
}
static VOID
__FreeBig(
    IN  PVOID   Buffer
    )
{
    int   StartNr;
    StartNr = (int)(((PUCHAR)Buffer - AustereHeap.BigHeapStart) / PAGE_SIZE);
    if (StartNr < 0 || (ULONG)StartNr >= AustereHeap.NumHeapPages)
        return;

    if (AustereHeap.HeapBlockSizes[StartNr] & FREE_CHUNK)
        return;

    AustereHeap.HeapBlockSizes[StartNr] |= FREE_CHUNK;
    AustereHeap.BigHeapCursor = (ULONG)StartNr;
}
static PVOID
__TrySmall(
    IN  PXENCRSH_SUBHEAP    SubHeap,
    IN  ULONG               Size
    )
{
    PUCHAR      Ptr;
    ULONG       ThisSize;
    
    if (SubHeap->Free < Size)
        return NULL;

    ThisSize = 0xF001DEAD;
    for (Ptr = SubHeap->Heap; Ptr < (PUCHAR)(SubHeap + 1); Ptr += ThisSize) {
        ULONG   Head;
        ULONG   Tail;

        Head = *(PULONG)Ptr;
        if (Head == 0)
            LogError("Heap Corruption @ 0x%p\n", Ptr);
        if (Head & FREE_CHUNK) {
            ThisSize = Head & ~FREE_CHUNK;
            if (ThisSize >= Size)
                break;
        } else {
            ThisSize = Head;
        }

        Tail = *(PULONG)(Ptr + ThisSize - sizeof(ULONG));
        if (Tail != ThisSize)
            LogError("Heap Chain Corruption @ 0x%p (%d != %d)\n", Ptr, Head, Tail);
    }

    if (Ptr == (PUCHAR)(SubHeap + 1))
        return NULL;

    if (Ptr > (PUCHAR)(SubHeap + 1))
        return NULL;

    if (ThisSize > Size + 64) {
        *(PULONG)Ptr = (ULONG)Size;
        *(PULONG)(Ptr + Size - sizeof(ULONG)) = Size;

        *(PULONG)(Ptr + Size) = (ThisSize - Size) | FREE_CHUNK;
        *(PULONG)(Ptr + ThisSize - sizeof(ULONG)) = ThisSize - Size;
        
        SubHeap->Free -= Size;
    } else {
        *(PULONG)Ptr = ThisSize;
        SubHeap->Free -= ThisSize;
    }

    return (PVOID)(Ptr + sizeof(ULONG));
}
static FORCEINLINE PXENCRSH_SUBHEAP
__NewSubHeap(
    )
{
    PXENCRSH_SUBHEAP    SubHeap;

    SubHeap = __AllocBig(__FUNCTION__, sizeof(XENCRSH_SUBHEAP));
    if (!SubHeap)
        return NULL;

    SubHeap->Free = SUBHEAP_SIZE;
    SubHeap->Next = SubHeap->Prev = NULL;
    *(PULONG)SubHeap->Heap = SUBHEAP_SIZE | FREE_CHUNK;
    *(PULONG)(SubHeap->Heap + SUBHEAP_SIZE - sizeof(ULONG)) = SUBHEAP_SIZE;
    return SubHeap;
}
static PVOID
__AllocSmall(
    IN  PCHAR   Caller,
    IN  ULONG   Size
    )
{
    PXENCRSH_SUBHEAP    SubHeap;
    PVOID               Res = NULL;

    Size = (Size + 3) & ~3;
    Size += sizeof(ULONG) * 2;

    for (SubHeap = AustereHeap.HeadSubHeap; SubHeap; SubHeap = SubHeap->Next) {
        if (SubHeap->Free > Size) {
            Res = __TrySmall(SubHeap, Size);
            if (Res)
                break;
        }
    }
    if (!Res) {
        SubHeap = __NewSubHeap();
        if (SubHeap) {
            Res = __TrySmall(SubHeap, Size);
        } else {
            LogError("Failed to allocate sub-heap %s\n", Caller);
        }
    }
    if (!Res) {
        LogError("Failed to allocate small (%d bytes) %s\n", Size, Caller);
        return NULL;
    }

    if (SubHeap != AustereHeap.HeadSubHeap) {
        if (SubHeap->Prev)
            SubHeap->Prev->Next = SubHeap->Next;
        if (SubHeap->Next)
            SubHeap->Next->Prev = SubHeap->Prev;
        SubHeap->Prev = NULL;
        SubHeap->Next = AustereHeap.HeadSubHeap;
        AustereHeap.HeadSubHeap = SubHeap;
    }
    return Res;
}
static VOID
__FreeSmall(
    IN  PVOID   Buffer
    )
{
    PXENCRSH_SUBHEAP    SubHeap;
    PUCHAR              Ptr = Buffer;
    ULONG               Size;

    SubHeap = (PXENCRSH_SUBHEAP)((ULONG_PTR)Buffer & ~(PAGE_SIZE - 1));

    Ptr -= sizeof(ULONG);
    Size = *(PULONG)Ptr;

    if (Size & FREE_CHUNK)
        return;

    SubHeap->Free += Size;

    if (SubHeap->Free == SUBHEAP_SIZE) {
        if (SubHeap->Next)
            SubHeap->Next->Prev = SubHeap->Prev;
        if (SubHeap->Prev)
            SubHeap->Prev->Next = SubHeap->Next;
        if (SubHeap == AustereHeap.HeadSubHeap)
            AustereHeap.HeadSubHeap = SubHeap->Next;
        __FreeBig(SubHeap);
        return;
    }

    if (Ptr + Size < (PUCHAR)(SubHeap + 1) && 
        *(PULONG)(Ptr + Size) & FREE_CHUNK) {
        Size += *(PULONG)(Ptr + Size);
        Size &= ~ FREE_CHUNK;
        *(PULONG)Ptr = Size;
        *(PULONG)(Ptr + Size - sizeof(ULONG)) = Size;
    }

    if (Ptr > SubHeap->Heap) {
        ULONG   LSize;
        PUCHAR  LPtr;

        LSize = *(PULONG)(Ptr - sizeof(ULONG));
        LPtr = Ptr - LSize;
        if (*(PULONG)LPtr & FREE_CHUNK) {
            LSize += Size;
            *(PULONG)LPtr = LSize;
            *(PULONG)(LPtr + LSize - sizeof(ULONG)) = LSize;
            Ptr = LPtr;
        }
    }

    *(PULONG)Ptr |= FREE_CHUNK;

    if (SubHeap != AustereHeap.HeadSubHeap) {
        if (SubHeap->Prev)
            SubHeap->Prev->Next = SubHeap->Next;
        if (SubHeap->Next)
            SubHeap->Next->Prev = SubHeap->Prev;
        SubHeap->Prev = NULL;
        SubHeap->Next = AustereHeap.HeadSubHeap;
        AustereHeap.HeadSubHeap = SubHeap;
    }
}

static FORCEINLINE PVOID
__Round(
    IN  PVOID               Buffer,
    IN  ULONG               RoundTo
    )
{
    // round buffer to (normally PAGE_SIZE) boundary
    ULONG_PTR   Mask = (ULONG_PTR)RoundTo - 1;
    return (PVOID)(((ULONG_PTR)Buffer + Mask) & ~Mask);
}
NTSTATUS
AustereInitialize()
{
    RtlZeroMemory(&AustereHeap, sizeof(XENCRSH_HEAP));

    AustereHeap.BigHeapStart = __AustereSection;
    AustereHeap.NumHeapPages = AUSTERE_HEAP_PAGES;

    // ensure big heap is page aligned
    if ( ((ULONG_PTR)AustereHeap.BigHeapStart & (PAGE_SIZE - 1)) ) {
        AustereHeap.BigHeapStart = __Round(AustereHeap.BigHeapStart, PAGE_SIZE);
        --AustereHeap.NumHeapPages;
    }
    
    LogVerbose("HEAP: [%p - %p) (%d pages)\n", AustereHeap.BigHeapStart, AustereHeap.BigHeapStart + (AustereHeap.NumHeapPages * PAGE_SIZE), AustereHeap.NumHeapPages);

    AustereHeap.BigHeapCursor = 0;
    AustereHeap.HeapBlockSizes[0] = AustereHeap.NumHeapPages | FREE_CHUNK;
    AustereHeap.HeadSubHeap = NULL;

    return STATUS_SUCCESS;
}

static FORCEINLINE ULONG
__SubHeapSize()
{
    return (ULONG)(SUBHEAP_SIZE - (sizeof(ULONG) * 2));
}
PVOID
__AustereAllocate(
    IN  PCHAR   Caller,
    IN  ULONG   Size
    )
{
    PVOID   Res;

    if (Size > AUSTERE_MAX_ALLOC_SIZE) {
        LogError("%s failing alloc of %d bytes (%d maximum)\n", Caller, Size, AUSTERE_MAX_ALLOC_SIZE);
        return NULL;
    }

    if (Size < __SubHeapSize())
        Res = __AllocSmall(Caller, Size);
    else
        Res = __AllocBig(Caller, Size);
    if (Res == NULL) {
        LogError("%s failed to Allocate %d bytes (%d maximum)\n", Caller, Size, AUSTERE_MAX_ALLOC_SIZE);
        return NULL;
    }

    RtlZeroMemory(Res, Size);

    return Res;
}

VOID
__AustereFree(
    IN  PCHAR   Caller,
    IN  PVOID   Buffer
    )
{   
    const ULONG_PTR AustereHeapStart = (ULONG_PTR)AustereHeap.BigHeapStart;
    const ULONG_PTR AustereHeapEnd = (ULONG_PTR)AustereHeap.BigHeapStart + AustereHeap.NumHeapPages * PAGE_SIZE;
    
    if (!Buffer)
        return;

    UNREFERENCED_PARAMETER(Caller);

    if ((ULONG_PTR)Buffer < AustereHeapStart ||
        (ULONG_PTR)Buffer > AustereHeapEnd) {
        // I didnt allocate this!
        LogError("Attempt to free unknown memory 0x%p [0x%p-0x%p]\n", Buffer, (PVOID)AustereHeapStart, (PVOID)AustereHeapEnd);
    } else {
        if ((ULONG_PTR)Buffer & (PAGE_SIZE - 1)) {
            __FreeSmall(Buffer);
        } else {
            __FreeBig(Buffer);
        }
    }
}
