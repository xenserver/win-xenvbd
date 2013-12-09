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

#pragma section(".gnttab_section", nopage,read,write)
#include <wdm.h>
#include <xenvbd-storport.h>


#include <xen-version.h>
#include <xen\xen-compat.h>
         
#include <xen-types.h>
#include <xen-warnings.h>
#include <xen-errno.h>
#include <xen\memory.h>
#include <xen\grant_table.h>

#include "gnttab.h"
#include "hypercall.h"
#include "austere.h"
#include "hvm.h"

#include "log.h"
#include "assert.h"

#define GNTTAB_HEADER_SIGNATURE 'TTNG'

#define GNTTAB_MAXIMUM_FRAME_COUNT  1
#define GNTTAB_ENTRY_PER_FRAME      (PAGE_SIZE / sizeof (grant_entry_v1_t))

#define GNTTAB_RESERVED_ENTRY_COUNT 8

#define GNTTAB_INVALID_REFERENCE    0

#define GNTTAB_IS_INVALID_REFERENCE(_Reference) \
        ((_Reference) < GNTTAB_RESERVED_ENTRY_COUNT)

#define GNTTAB_IS_OUT_OF_RANGE_REFERENCE(_Reference) \
        ((_Reference) > GNTTAB_ENTRY_PER_FRAME)

#define GNTTAB_MAX_DESCRIPTOR   (GNTTAB_MAXIMUM_FRAME_COUNT * GNTTAB_ENTRY_PER_FRAME)

typedef struct _GNTTAB_REFERENCE_DESCRIPTOR {
    ULONG               Next;   // next free entry
    grant_entry_v1_t    Entry;  // local copy of grant entry
} GNTTAB_REFERENCE_DESCRIPTOR, *PGNTTAB_REFERENCE_DESCRIPTOR;

typedef struct _XENBUS_GNTTAB_CONTEXT {
    grant_entry_v1_t*           Entry;  // mapped page
    GNTTAB_REFERENCE_DESCRIPTOR Descriptor[GNTTAB_MAX_DESCRIPTOR]; // free list
    ULONG                       HeadFreeReference; // head free list
    ULONG                       Count;  // number in use
} XENBUS_GNTTAB_CONTEXT, *PXENBUS_GNTTAB_CONTEXT;

static XENBUS_GNTTAB_CONTEXT    GnttabContext;

#define MAXIMUM_GRANT_ENTRY_PAGES   1
// Entry(s), Status(s)
#define MAXIMUM_GRANT_PAGES 1

__declspec(allocate(".gnttab_section"))
static UCHAR __GnttabSection[(MAXIMUM_GRANT_PAGES + 1) * PAGE_SIZE];

extern PHYSICAL_ADDRESS MmGetPhysicalAddress(IN PVOID Buffer);
static FORCEINLINE PFN_NUMBER
__VirtToPfn(
    IN  PVOID                   VirtAddr
    )
{
    PHYSICAL_ADDRESS PhysAddr = MmGetPhysicalAddress(VirtAddr);
    return (PFN_NUMBER)(ULONG_PTR)(PhysAddr.QuadPart >> PAGE_SHIFT);
}

NTSTATUS
GnttabGet(
    OUT PULONG                      Reference
    )
{
    PGNTTAB_REFERENCE_DESCRIPTOR    Descriptor;

    if (GNTTAB_IS_INVALID_REFERENCE(GnttabContext.HeadFreeReference))
        goto gnttab_full;

    ASSERT(!GNTTAB_IS_INVALID_REFERENCE(GnttabContext.HeadFreeReference));
    ASSERT(!GNTTAB_IS_OUT_OF_RANGE_REFERENCE(GnttabContext.HeadFreeReference));

    *Reference = GnttabContext.HeadFreeReference;
    Descriptor = &GnttabContext.Descriptor[*Reference];

    GnttabContext.HeadFreeReference = Descriptor->Next;
    Descriptor->Next = GNTTAB_INVALID_REFERENCE;

    GnttabContext.Count++;

    return STATUS_SUCCESS;

gnttab_full:
    return STATUS_INSUFFICIENT_RESOURCES;
}

VOID
GnttabPut(
    IN  ULONG                       Reference
    )
{
    PGNTTAB_REFERENCE_DESCRIPTOR    Descriptor;

    ASSERT(!GNTTAB_IS_INVALID_REFERENCE(Reference));
    ASSERT(!GNTTAB_IS_OUT_OF_RANGE_REFERENCE(Reference));

    Descriptor = &GnttabContext.Descriptor[Reference];

    ASSERT3U(GnttabContext.Count, !=, 0);
    --GnttabContext.Count;

    ASSERT(GNTTAB_IS_INVALID_REFERENCE(Descriptor->Next));
    Descriptor->Next = GnttabContext.HeadFreeReference;
    GnttabContext.HeadFreeReference = Reference;
}

VOID
GnttabPermitForeignAccess(
    IN  ULONG                       Reference,
    IN  USHORT                      Domain,
    IN  PFN_NUMBER                  Frame,
    IN  BOOLEAN                     ReadOnly
    )
{
    PGNTTAB_REFERENCE_DESCRIPTOR    Descriptor;
    grant_entry_v1_t                *Entry;

    ASSERT(!GNTTAB_IS_INVALID_REFERENCE(Reference));
    ASSERT(!GNTTAB_IS_OUT_OF_RANGE_REFERENCE(Reference));

    Descriptor = &GnttabContext.Descriptor[Reference];

    Descriptor->Entry.domid = Domain;
    Descriptor->Entry.flags = (ReadOnly) ? GTF_readonly : 0;
    Descriptor->Entry.frame = (uint32_t)Frame;

    Entry = &GnttabContext.Entry[Reference];

    *Entry = Descriptor->Entry;
    KeMemoryBarrier();

    Entry->flags |= GTF_permit_access;
    KeMemoryBarrier();
}

VOID
GnttabRevokeForeignAccess(
    IN  ULONG                       Reference
    )
{
    grant_entry_v1_t                *Entry;
    volatile SHORT                  *Flags;
    PGNTTAB_REFERENCE_DESCRIPTOR    Descriptor;
    ULONG                           Attempt;

    Entry = &GnttabContext.Entry[Reference];
    Flags = (volatile SHORT *)&Entry->flags;

    Attempt = 0;
    while (Attempt++ < 100) {
        uint16_t    Old;
        uint16_t    New;

        Old = *Flags;
        Old &= ~(GTF_reading | GTF_writing);

        New = Old & ~GTF_permit_access;

        if (InterlockedCompareExchange16(Flags, New, Old) == Old)
            break;

        _mm_pause();
    }
    if (Attempt == 100)
        LogWarning("Reference %08x is still busy\n");

    RtlZeroMemory(Entry, sizeof(grant_entry_v1_t));

    Descriptor = &GnttabContext.Descriptor[Reference];
    RtlZeroMemory(&Descriptor->Entry, sizeof (grant_entry_v1_t));
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
GnttabInitialize(
    )
{
    PFN_NUMBER              Pfn;
    NTSTATUS                Status;
    ULONG                   Reference;

    LogTrace("===>\n");

    // map __GnttabSection[0] to grant_ref_v1_t's
    GnttabContext.Entry = __Round(&__GnttabSection[0], PAGE_SIZE);
    Pfn = __VirtToPfn(GnttabContext.Entry);
    Status = HvmAddToPhysMap(Pfn,
                             XENMAPSPACE_grant_table,
                             0); // Page0
    if (!NT_SUCCESS(Status))
        goto fail1;
    LogVerbose("grant_entry_v1_t* : %p\n", GnttabContext.Entry);

    // initialize free list
    LogVerbose("adding refrences [%08x - %08x]\n", GNTTAB_RESERVED_ENTRY_COUNT, GNTTAB_ENTRY_PER_FRAME - 1);

    GnttabContext.HeadFreeReference = GNTTAB_INVALID_REFERENCE;
    GnttabContext.Count = 0;
    for (Reference = GNTTAB_ENTRY_PER_FRAME - 1; Reference >= GNTTAB_RESERVED_ENTRY_COUNT; --Reference) {
        PGNTTAB_REFERENCE_DESCRIPTOR    Descriptor = &GnttabContext.Descriptor[Reference];

        ASSERT(GNTTAB_IS_INVALID_REFERENCE(Descriptor->Next));
        Descriptor->Next = GnttabContext.HeadFreeReference;
        GnttabContext.HeadFreeReference = Reference;
    }

    LogTrace("<===\n");
    return STATUS_SUCCESS;

fail1:
    LogError("Fail1 (%08x)\n", Status);
    return Status;
}

VOID
GnttabTerminate(
    )
{
    ASSERT3U(GnttabContext.Count, ==, 0);
}
