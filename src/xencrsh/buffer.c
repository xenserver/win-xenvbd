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

#include "driver.h"
#include "austere.h"

#include "log.h"
#include "assert.h"

#define NUM_BUFFERS 8

extern PHYSICAL_ADDRESS MmGetPhysicalAddress(PVOID BaseAddress);

typedef struct _XENVBD_BUFFER {
    ULONG               Next;                   // 1 based index into array (0 is invalid)
    PVOID               VAddr;
    PHYSICAL_ADDRESS    PAddr;
} XENVBD_BUFFER, *PXENVBD_BUFFER;

typedef struct _XENVBD_BOUNCE_BUFFER {
    XENVBD_BUFFER       Buffers[NUM_BUFFERS];   // 0 based array
    ULONG               Next;                   // 1 based index into array (0 is invalid)
    ULONG               Free;
    ULONG               MinFree;
} XENVBD_BOUNCE_BUFFER, *PXENVBD_BOUNCE_BUFFER;

static XENVBD_BOUNCE_BUFFER __Buffer;

VOID
BufferInitialize(
    )
{
    ULONG i;

    RtlZeroMemory(&__Buffer, sizeof(XENVBD_BOUNCE_BUFFER));

    for (i = 0; i < NUM_BUFFERS; ++i) {
        if (!__Buffer.Buffers[i].VAddr) {
            __Buffer.Buffers[i].VAddr = AustereAllocate(PAGE_SIZE);
        }
        if (!__Buffer.Buffers[i].VAddr) {
            continue;
        }
        __Buffer.Buffers[i].PAddr = MmGetPhysicalAddress(__Buffer.Buffers[i].VAddr);

        // thread to free list
        __Buffer.Buffers[i].Next = __Buffer.Next;
        __Buffer.Next = i + 1;
        
        ++__Buffer.Free;
    }
    __Buffer.MinFree = __Buffer.Free;

    ASSERT3U(__Buffer.Next, !=, 0);
}

VOID
BufferTerminate(
    )
{
    ULONG i;

    for (i = 0; i < NUM_BUFFERS; ++i) {
        AustereFree(__Buffer.Buffers[i].VAddr);
    }
    RtlZeroMemory(&__Buffer, sizeof(__Buffer));
    __Buffer.Next = 0;
}

BOOLEAN
BufferGet(
    OUT PULONG      BufferId,
    OUT PFN_NUMBER* Pfn
    )
{
    ULONG           BufId;
    PXENVBD_BUFFER  Buf;

    if (__Buffer.Next == 0) {
        // Warn!
        return FALSE;
    }
    // find a free buffer, copy Buffer@Length into the buffer, return the BufferId and Pfn
    BufId = __Buffer.Next;
    Buf = &__Buffer.Buffers[BufId - 1];
    __Buffer.Next = Buf->Next;
    --__Buffer.Free;
    if (__Buffer.Free < __Buffer.MinFree)
        __Buffer.MinFree = __Buffer.Free;

    ASSERT3U(BufId, !=, 0);
    ASSERT3U(BufId, <=, NUM_BUFFERS);

    *BufferId   = BufId;
    *Pfn = (PFN_NUMBER)(Buf->PAddr.QuadPart >> PAGE_SHIFT);
    RtlZeroMemory(Buf->VAddr, PAGE_SIZE);
    return TRUE;
}

VOID
BufferPut(
    IN  ULONG       BufferId
    )
{
    // copy the Pfn@Length to the Buffer, and release the BufferId to the free list
    ASSERT3U(BufferId, <=, NUM_BUFFERS);
    ASSERT3U(BufferId, !=, 0);
    // PREFAST Warning 6386
    if (BufferId > NUM_BUFFERS)
        return;
    // PREFAST Warning 6385
    if (BufferId == 0)
        return;

    __Buffer.Buffers[BufferId - 1].Next = __Buffer.Next;
    __Buffer.Next = BufferId;
    ++__Buffer.Free;
}

VOID
BufferCopyIn(
    IN  ULONG       BufferId,
    IN  PVOID       Input,
    IN  ULONG       Length
    )
{
    PXENVBD_BUFFER  Buf;

    ASSERT3U(BufferId, <=, NUM_BUFFERS);
    ASSERT3U(BufferId, !=, 0);
    Buf = &__Buffer.Buffers[BufferId - 1];

    ASSERT(Input != NULL);
    ASSERT3U(Length, >, 0);
    ASSERT3U(Length, <=, PAGE_SIZE);
    ASSERT(Buf->VAddr != NULL);
    RtlCopyMemory(Buf->VAddr, Input, Length);
}

VOID
BufferCopyOut(
    IN  ULONG       BufferId,
    IN  PVOID       Output,
    IN  ULONG       Length
    )
{
    PXENVBD_BUFFER  Buf;

    ASSERT3U(BufferId, <=, NUM_BUFFERS);
    ASSERT3U(BufferId, !=, 0);
    Buf = &__Buffer.Buffers[BufferId - 1];

    ASSERT(Output != NULL);
    ASSERT3U(Length, >, 0);
    ASSERT3U(Length, <=, PAGE_SIZE);
    ASSERT(Buf->VAddr != NULL);
    RtlCopyMemory(Output, Buf->VAddr, Length);
}

