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
#define GNTTAB_ENTRY_PER_FRAME      (PAGE_SIZE / sizeof (grant_entry_v2_t))
#define GNTTAB_STATUS_PER_FRAME     (PAGE_SIZE / sizeof (grant_status_t))

#define GNTTAB_RESERVED_ENTRY_COUNT 8

#define GNTTAB_INVALID_REFERENCE    0

#define GNTTAB_IS_INVALID_REFERENCE(_Reference) \
        ((_Reference) < GNTTAB_RESERVED_ENTRY_COUNT)

#define GNTTAB_IS_OUT_OF_RANGE_REFERENCE(_Reference) \
        ((_Reference) > GNTTAB_ENTRY_PER_FRAME)

#define GNTTAB_MAX_DESCRIPTOR   (GNTTAB_MAXIMUM_FRAME_COUNT * GNTTAB_ENTRY_PER_FRAME)

typedef struct _GNTTAB_REFERENCE_DESCRIPTOR {
    ULONG               Next;   // next free entry
    grant_entry_v2_t    Entry;  // local copy of grant entry
} GNTTAB_REFERENCE_DESCRIPTOR, *PGNTTAB_REFERENCE_DESCRIPTOR;

typedef struct _XENBUS_GNTTAB_CONTEXT {
    grant_entry_v2_t*           Entry;  // mapped page
    grant_status_t*             Status; // mapped page
    GNTTAB_REFERENCE_DESCRIPTOR Descriptor[GNTTAB_MAX_DESCRIPTOR]; // free list
    ULONG                       HeadFreeReference; // head free list
    ULONG                       Count;  // number in use
} XENBUS_GNTTAB_CONTEXT, *PXENBUS_GNTTAB_CONTEXT;

static XENBUS_GNTTAB_CONTEXT    GnttabContext;

#define MAXIMUM_GRANT_ENTRY_PAGES   1
#define MAXIMUM_GRANT_STATUS_PAGES  1
// Entry(s), Status(s)
#define MAXIMUM_GRANT_PAGES (MAXIMUM_GRANT_ENTRY_PAGES + MAXIMUM_GRANT_STATUS_PAGES)

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

static FORCEINLINE LONG_PTR
GrantTableOp(
    IN  ULONG   Command,
    IN  PVOID   Argument,
    IN  ULONG   Count
    )
{
    return Hypercall3(ULONG, grant_table_op, Command, Argument, Count);
}

static FORCEINLINE NTSTATUS
__GetVersion(
    OUT PULONG                  Version
    )
{
    struct gnttab_get_version   op;
    LONG_PTR                    rc;
    NTSTATUS                    status;

    op.dom = DOMID_SELF;

    rc = GrantTableOp(GNTTABOP_get_version, &op, 1);

    if (rc < 0) {
        ERRNO_TO_STATUS(-rc, status);
        goto fail1;
    }

    *Version = op.version;

    return STATUS_SUCCESS;

fail1:
    LogError("fail1 (%08x)\n", status);

    return status;
}
static FORCEINLINE NTSTATUS
__SetVersion(
    IN  ULONG                   Version
    )
{
    struct gnttab_set_version   op;
    LONG_PTR                    rc;
    NTSTATUS                    status;

    op.version = Version;

    rc = GrantTableOp(GNTTABOP_set_version, &op, 1);

    if (rc < 0) {
        ERRNO_TO_STATUS(-rc, status);
        goto fail1;
    }

    return STATUS_SUCCESS;

fail1:
    LogError("fail1 (%08x)\n", status);

    return status;
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
    grant_entry_v2_t                *Entry;

    ASSERT(!GNTTAB_IS_INVALID_REFERENCE(Reference));
    ASSERT(!GNTTAB_IS_OUT_OF_RANGE_REFERENCE(Reference));

    Descriptor = &GnttabContext.Descriptor[Reference];

    Descriptor->Entry.full_page.hdr.domid = Domain;
    Descriptor->Entry.full_page.hdr.flags = (ReadOnly) ? GTF_readonly : 0;
    Descriptor->Entry.full_page.frame = Frame;

    Entry = &GnttabContext.Entry[Reference];

    *Entry = Descriptor->Entry;
    KeMemoryBarrier();

    Entry->hdr.flags |= GTF_permit_access;
    _ReadWriteBarrier();
}

VOID
GnttabRevokeForeignAccess(
    IN  ULONG                       Reference
    )
{
    grant_entry_v2_t                *Entry;
    PGNTTAB_REFERENCE_DESCRIPTOR    Descriptor;
    ULONG                           Attempt;

    Entry = &GnttabContext.Entry[Reference];

    Entry->hdr.flags = 0;
    _ReadWriteBarrier();

    KeMemoryBarrier();

    Attempt = 0;
    while (Attempt++ < 100) {
        grant_status_t  Status;

        Status = GnttabContext.Status[Reference];
        _ReadWriteBarrier();

        if ((Status & (GTF_reading | GTF_writing)) == 0)
            break;

        _mm_pause();
    }
    if (Attempt == 100)
        LogWarning("Reference %08x is still busy\n");

    Descriptor = &GnttabContext.Descriptor[Reference];
    RtlZeroMemory(&Descriptor->Entry, sizeof (grant_entry_v2_t));

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
    ULONG                   Version;
    NTSTATUS                Status;
    ULONG                   Reference;

    LogTrace("===>\n");

    // set grant version to 2
    Version = 2;
    Status = __SetVersion(Version);
    if (!NT_SUCCESS(Status))
        goto fail1;

    //  test grant version (protected, so will fail)
    Status = __GetVersion(&Version);
    if (!NT_SUCCESS(Status))
        LogWarning("Failed to verify grant table version\n");
    else
        ASSERT3U(Version, ==, 2);

    // map __GnttabSection[0] to grant_ref_v2_t's
    GnttabContext.Entry = __Round(&__GnttabSection[0], PAGE_SIZE);
    Pfn = __VirtToPfn(GnttabContext.Entry);
    Status = HvmAddToPhysMap(Pfn,
                             XENMAPSPACE_grant_table,
                             0); // Page0
    if (!NT_SUCCESS(Status))
        goto fail2;
    LogVerbose("grant_entry_v2_t* : %p\n", GnttabContext.Entry);

    // map __GnttabSection[1] to grant_status_t's
    GnttabContext.Status = __Round(&__GnttabSection[1], PAGE_SIZE);
    Pfn = __VirtToPfn(GnttabContext.Status);
    Status = HvmAddToPhysMap(Pfn,
                             XENMAPSPACE_grant_table,
                             0 | XENMAPIDX_grant_table_status); // Page0 (status)
    if (!NT_SUCCESS(Status))
        goto fail3;
    LogVerbose("grant_status_t*   : %p\n", GnttabContext.Status);
    
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

fail3:
    LogError("Fail3\n");
fail2:
    LogError("Fail2\n");
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
