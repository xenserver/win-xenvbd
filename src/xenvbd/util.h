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

#ifndef _UTIL_H
#define _UTIL_H

#include <ntddk.h>

#include "assert.h"

static FORCEINLINE ULONG
__min(
    IN  ULONG                   a,
    IN  ULONG                   b
    )
{
    return a < b ? a : b;
}

typedef struct _NON_PAGED_BUFFER_HEADER {
    SIZE_T  Length;
    ULONG   Tag;
} NON_PAGED_BUFFER_HEADER, *PNON_PAGED_BUFFER_HEADER;

typedef struct _NON_PAGED_BUFFER_TRAILER {
    ULONG   Tag;
} NON_PAGED_BUFFER_TRAILER, *PNON_PAGED_BUFFER_TRAILER;

static FORCEINLINE PVOID
__AllocateNonPagedPoolWithTag(
    IN  PCHAR                   Caller,
    IN  ULONG                   Line,
    IN  SIZE_T                  Length,
    IN  ULONG                   Tag
    )
{
    PUCHAR                      Buffer;
    PNON_PAGED_BUFFER_HEADER    Header;
    PNON_PAGED_BUFFER_TRAILER   Trailer;

    ASSERT3S(Length, !=, 0);

    Buffer = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool,
                                   sizeof (NON_PAGED_BUFFER_HEADER) +
                                   Length +
                                   sizeof (NON_PAGED_BUFFER_TRAILER),
                                   Tag);
    if (Buffer == NULL) {
        Warning("%s:%u : AllocFailed %d bytes, %08x tag\n", Caller, Line, Length, Tag);
        goto done;
    }

    RtlZeroMemory(Buffer, 
                  sizeof (NON_PAGED_BUFFER_HEADER) +
                  Length +
                  sizeof (NON_PAGED_BUFFER_TRAILER));

    Header = (PNON_PAGED_BUFFER_HEADER)Buffer;
    Header->Length = Length;
    Header->Tag = Tag;

    Buffer += sizeof (NON_PAGED_BUFFER_HEADER);

    Trailer = (PNON_PAGED_BUFFER_TRAILER)(Buffer + Length);
    Trailer->Tag = Tag;

done:
    return Buffer;
}

static FORCEINLINE VOID
__FreePoolWithTag(
    IN  PVOID                   _Buffer,
    IN  ULONG                   Tag
    )
{
    PUCHAR                      Buffer = (PUCHAR)_Buffer;
    SIZE_T                      Length;
    PNON_PAGED_BUFFER_HEADER    Header;
    PNON_PAGED_BUFFER_TRAILER   Trailer;

    ASSERT3P(Buffer, !=, NULL);

    Buffer -= sizeof (NON_PAGED_BUFFER_HEADER);

    Header = (PNON_PAGED_BUFFER_HEADER)Buffer;
    ASSERT3U(Tag, ==, Header->Tag);
    Length = Header->Length;

    Buffer += sizeof (NON_PAGED_BUFFER_HEADER);

    Trailer = (PNON_PAGED_BUFFER_TRAILER)(Buffer + Length);
    ASSERT3U(Tag, ==, Trailer->Tag);

    Buffer -= sizeof (NON_PAGED_BUFFER_HEADER);

    RtlFillMemory(Buffer, 
                  sizeof (NON_PAGED_BUFFER_HEADER) +
                  Length +
                  sizeof (NON_PAGED_BUFFER_TRAILER),
                  0xAA);

    ExFreePoolWithTag(Buffer, Tag);
}

static FORCEINLINE PMDL
__AllocPagesForMdl(
    IN  SIZE_T          Size
    )
{
    PMDL                Mdl;
    PHYSICAL_ADDRESS    LowAddr;
    PHYSICAL_ADDRESS    HighAddr;
    PHYSICAL_ADDRESS    SkipBytes;

    SkipBytes.QuadPart = 0ull;
    HighAddr.QuadPart = ~0ull;

    // try > 4GB
    LowAddr.QuadPart = 0x100000000ull;
    Mdl = MmAllocatePagesForMdlEx(LowAddr, HighAddr, SkipBytes, Size, MmCached, 0);
    if (Mdl) {
        if (MmGetMdlByteCount(Mdl) == Size) {
            goto done;
        }
        MmFreePagesFromMdl(Mdl);
        ExFreePool(Mdl);
        Mdl = NULL;
    }

    // try > 2GB
    LowAddr.QuadPart = 0x80000000ull;
    Mdl = MmAllocatePagesForMdlEx(LowAddr, HighAddr, SkipBytes, Size, MmCached, 0);
    if (Mdl) {
        if (MmGetMdlByteCount(Mdl) == Size) {
            goto done;
        }
        MmFreePagesFromMdl(Mdl);
        ExFreePool(Mdl);
        Mdl = NULL;
    }

    // try anywhere
    LowAddr.QuadPart = 0ull;
    Mdl = MmAllocatePagesForMdlEx(LowAddr, HighAddr, SkipBytes, Size, MmCached, 0);
    // Mdl byte count gets checked again after this returns

done:
    return Mdl;
}
static FORCEINLINE PVOID
___AllocPages(
    IN  PCHAR           Caller, 
    IN  ULONG           Line,
    IN  SIZE_T          Size,
    OUT PMDL*           Mdl
    )
{
    PVOID               Buffer;

    *Mdl = __AllocPagesForMdl(Size);
    if (*Mdl == NULL) {
        Warning("%s:%u : MmAllocatePagesForMdlEx Failed %d bytes\n", Caller, Line, Size);
        goto fail1;
    }

    if (MmGetMdlByteCount(*Mdl) != Size) {
        Warning("%s:%u : %d bytes != %d bytes requested\n", Caller, Line, MmGetMdlByteCount(*Mdl), Size);
        goto fail2;
    }

    Buffer = MmMapLockedPagesSpecifyCache(*Mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
    if (Buffer == NULL) {
        Warning("%s:%u : MmMapLockedPagesSpecifyCache Failed %d bytes\n", Caller, Line, Size);
        goto fail3;
    }

    return Buffer;

fail3:
fail2:
    MmFreePagesFromMdl(*Mdl);
    ExFreePool(*Mdl);
fail1:
    *Mdl = NULL;
    return NULL;
}
#define __AllocPages(Size, Mdl) ___AllocPages(__FUNCTION__, __LINE__, Size, Mdl)

static FORCEINLINE VOID
__FreePages(
    IN  PVOID           Buffer,
    IN  PMDL            Mdl
    )
{
    if (Buffer && Mdl) {
        MmUnmapLockedPages(Buffer, Mdl);
        MmFreePagesFromMdl(Mdl);
        ExFreePool(Mdl);
    }
}

#endif  // _UTIL_H
