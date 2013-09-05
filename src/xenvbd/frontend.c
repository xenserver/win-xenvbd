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

#include "frontend.h"
#include "driver.h"
#include "fdo.h"
#include "pdo-inquiry.h"
#include "srbext.h"
#include "debug.h"
#include "assert.h"
#include "util.h"
#include "names.h"
#include <store_interface.h>
#include <evtchn_interface.h>
#include <gnttab_interface.h>
#include <suspend_interface.h>

#include <stdlib.h>

struct _XENVBD_FRONTEND {
    // Frontend
    PXENVBD_PDO                 Pdo;
    ULONG                       TargetId;
    ULONG                       DeviceId;
    PCHAR                       FrontendPath;
    PCHAR                       BackendPath;
    PCHAR                       TargetPath;
    USHORT                      BackendId;
    XENVBD_STATE                State;
    KSPIN_LOCK                  StateLock;

    XENVBD_CAPS                 Caps;
    XENVBD_FEATURES             Features;
    XENVBD_DISKINFO             DiskInfo;
    PVOID                       Inquiry;

    // Interfaces to XenBus
    PXENBUS_STORE_INTERFACE     Store;
    PXENBUS_EVTCHN_INTERFACE    Evtchn;
    PXENBUS_GNTTAB_INTERFACE    Gnttab;
    PXENBUS_SUSPEND_INTERFACE   Suspend;

    PXENBUS_SUSPEND_CALLBACK    SuspendLateCallback;

    // Ring
    KSPIN_LOCK                  RingLock;
    PMDL                        Mdl;
    blkif_sring_t*              SharedRing;
    blkif_front_ring_t          FrontRing;
    ULONG                       RingOrder;
    ULONG                       RingGrantRefs[XENVBD_MAX_RING_PAGES];
    ULONG                       RequestsOutstanding;
    ULONG                       RequestsSubmitted;
    ULONG                       ResponsesRecieved;
    // Evtchn
    PXENBUS_EVTCHN_DESCRIPTOR   EvtchnPort;
    ULONG                       EvtchnPortNumber;
    KDPC                        EvtchnDpc;
    ULONG                       NumEvents;
    ULONG                       NumDpcs;

    // Backend State Watch
    BOOLEAN                     Active;
    PKEVENT                     BackendEvent;
    PXENBUS_STORE_WATCH         BackendStateWatch;
    PXENBUS_STORE_WATCH         BackendInfoWatch;
    PXENBUS_STORE_WATCH         BackendSectorSizeWatch;
    PXENBUS_STORE_WATCH         BackendSectorCountWatch;
};

#define XEN_IO_PROTO_ABI_NATIVE     "x86_32-abi"

#define DOMID_INVALID (0x7FF4U)

static const PCHAR
__XenvbdStateName(
    IN  XENVBD_STATE                        State
    )
{
    switch (State) {
    case XENVBD_STATE_INVALID:      return "STATE_INVALID";
    case XENVBD_INITIALIZED:        return "INITIALIZED";
    case XENVBD_CLOSED:             return "CLOSED";
    case XENVBD_PREPARED:           return "PREPARED";
    case XENVBD_CONNECTED:          return "CONNECTED";
    case XENVBD_ENABLED:            return "ENABLED";
    default:                        return "UNKNOWN";
    }
}
//=============================================================================
#define FRONTEND_POOL_TAG            'tnFX'
__checkReturn
__drv_allocatesMem(mem)
__bcount(Size)
static FORCEINLINE PVOID
#pragma warning(suppress: 28195)
___FrontendAlloc(
    __in  PCHAR                   Caller,
    __in  ULONG                   Line,
    __in  ULONG                   Size
    )
{
    return __AllocateNonPagedPoolWithTag(Caller, Line, Size, FRONTEND_POOL_TAG);
}
#define __FrontendAlloc(Size) ___FrontendAlloc(__FUNCTION__, __LINE__, Size)

static FORCEINLINE VOID
#pragma warning(suppress: 28197)
__FrontendFree(
    __in __drv_freesMem(mem) PVOID Buffer
    )
{
    if (Buffer)
        __FreePoolWithTag(Buffer, FRONTEND_POOL_TAG);
}

//=============================================================================
// Accessors
PXENVBD_CAPS
FrontendGetCaps(
    __in  PXENVBD_FRONTEND      Frontend
    )
{
    return &Frontend->Caps;
}
PXENVBD_FEATURES
FrontendGetFeatures(
    __in  PXENVBD_FRONTEND      Frontend
    )
{
    return &Frontend->Features;
}
PXENVBD_DISKINFO
FrontendGetDiskInfo(
    __in  PXENVBD_FRONTEND      Frontend
    )
{
    return &Frontend->DiskInfo;
}
ULONG
FrontendGetTargetId(
    __in  PXENVBD_FRONTEND      Frontend
    )
{
    return Frontend->TargetId;
}
PVOID
FrontendGetInquiry(
    __in  PXENVBD_FRONTEND      Frontend
    )
{
    return Frontend->Inquiry;
}

//=============================================================================
// Interface indirection
NTSTATUS
FrontendGnttabGet(
    __in  PXENVBD_FRONTEND      Frontend,
    __in  PFN_NUMBER            Pfn,
    __in  BOOLEAN               ReadOnly,
    __out PULONG                GrantRef
    )
{
    NTSTATUS    Status;

    Status = GNTTAB(Get, Frontend->Gnttab, GrantRef);
    if (NT_SUCCESS(Status)) {
        GNTTAB(PermitForeignAccess, Frontend->Gnttab, *GrantRef,
                                    Frontend->BackendId, GNTTAB_ENTRY_FULL_PAGE, 
                                    Pfn, ReadOnly);
    }

    return Status;
}
VOID
FrontendGnttabPut(
    __in  PXENVBD_FRONTEND      Frontend,
    __in  ULONG                 GrantRef
    )
{
    GNTTAB(RevokeForeignAccess, Frontend->Gnttab, GrantRef);
    GNTTAB(Put, Frontend->Gnttab, GrantRef);
}
VOID
FrontendEvtchnTrigger(
    __in  PXENVBD_FRONTEND      Frontend
    )
{
    EVTCHN(Trigger, Frontend->Evtchn, Frontend->EvtchnPort);
}
VOID
FrontendEvtchnSend(
    __in  PXENVBD_FRONTEND      Frontend
    )
{
    EVTCHN(Send, Frontend->Evtchn, Frontend->EvtchnPort);
}
NTSTATUS
FrontendStoreWriteFrontend(
    __in  PXENVBD_FRONTEND      Frontend,
    __in  PCHAR                 Name,
    __in  PCHAR                 Value
    )
{
    return STORE(Write, Frontend->Store, NULL, Frontend->FrontendPath, Name, Value);
}
NTSTATUS
FrontendStoreReadBackend(
    __in  PXENVBD_FRONTEND      Frontend,
    __in  PCHAR                 Name,
    __out PCHAR*                Value
    )
{
    NTSTATUS    Status;

    Status = STATUS_INVALID_PARAMETER;
    if (Frontend->Store == NULL) 
        goto fail1;

    if (Frontend->BackendPath == NULL)
        goto fail2;

    Status = STORE(Read, Frontend->Store, NULL, Frontend->BackendPath, Name, Value);
    if (!NT_SUCCESS(Status))
        goto fail3;

    return STATUS_SUCCESS;

fail3:
fail2:
fail1:
    return Status;
}
VOID
FrontendStoreFree(
    __in  PXENVBD_FRONTEND      Frontend,
    __in  PCHAR                 Value
    )
{
    STORE(Free, Frontend->Store, Value);
}

//=============================================================================
static FORCEINLINE VOID
xen_mb()
{
    KeMemoryBarrier();
    _ReadWriteBarrier();
}
static FORCEINLINE VOID
xen_wmb()
{
    KeMemoryBarrier();
    _WriteBarrier();
}
static FORCEINLINE ULONG
__Idx(
    __in  ULONG   Index,
    __in  ULONG   nr_ents
    )
{
    if (nr_ents == 0)
        return Index;
    return Index & (nr_ents - 1);
}

__drv_requiresIRQL(DISPATCH_LEVEL)
static DECLSPEC_NOINLINE VOID
__FrontendCompleteResponses(
    __in  PXENVBD_FRONTEND        Frontend
    )
{
    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);
    KeAcquireSpinLockAtDpcLevel(&Frontend->RingLock);

    // Guard against this locked region being called after the 
    // lock on FrontendSetState
    if (Frontend->SharedRing == NULL)
        goto done;

    for (;;) {
        ULONG   rsp_prod;
        ULONG   rsp_cons;
        int     notify;

        rsp_prod = Frontend->SharedRing->rsp_prod;
        rsp_cons = Frontend->FrontRing.rsp_cons;

        xen_mb();

        while (rsp_cons != rsp_prod) {
            blkif_response_t*   Response;
            PXENVBD_REQUEST     Request;
            SHORT               Status;

            Response = RING_GET_RESPONSE(&Frontend->FrontRing, rsp_cons);
            Status = Response->status;
            Request = (PXENVBD_REQUEST)(ULONG_PTR)(Response->id);

            ++rsp_cons;

            Frontend->ResponsesRecieved++;
            Frontend->RequestsOutstanding--;

            if (Request) {
                PdoCompleteSubmittedRequest(Frontend->Pdo, Request, Status);
            }

            // zero request slot now its read
            RtlZeroMemory(Response, sizeof(blkif_response_t));
        }

        Frontend->FrontRing.rsp_cons = rsp_cons;

        xen_mb();

        RING_FINAL_CHECK_FOR_RESPONSES(&Frontend->FrontRing, notify);
        if (!notify)
            break;
    }

done:
    KeReleaseSpinLockFromDpcLevel(&Frontend->RingLock);
}

__drv_requiresIRQL(DISPATCH_LEVEL)
VOID
FrontendEvtchnCallback(
    __in  PXENVBD_FRONTEND        Frontend
    )
{
    __FrontendCompleteResponses(Frontend);
    PdoPrepareFresh(Frontend->Pdo);
    PdoSubmitPrepared(Frontend->Pdo);
    PdoCompleteShutdown(Frontend->Pdo);
}

KSERVICE_ROUTINE EvtchnInterruptFunc;

BOOLEAN
EvtchnInterruptFunc(
    __in  PKINTERRUPT             Interrupt,
    _In_opt_ PVOID                   Context
    )
{
    PXENVBD_FRONTEND        Frontend = (PXENVBD_FRONTEND)Context;
    
    UNREFERENCED_PARAMETER(Interrupt);

	// PreFast: C28281
	if (Frontend) {
		++Frontend->NumEvents;
		if (Frontend->Caps.Connected) {
			if (KeInsertQueueDpc(&Frontend->EvtchnDpc, NULL, NULL))
				++Frontend->NumDpcs;
		}
	}

    return TRUE;
}

__checkReturn
__drv_requiresIRQL(DISPATCH_LEVEL)
static FORCEINLINE BOOLEAN
__EvtchnPending(
    __in  PXENVBD_FRONTEND        Frontend
    )
{
    BOOLEAN     Pending = FALSE;

    KeAcquireSpinLockAtDpcLevel(&Frontend->RingLock);

    if (Frontend->Evtchn && Frontend->EvtchnPort)
        Pending = EVTCHN(Unmask, Frontend->Evtchn, Frontend->EvtchnPort, FALSE);

    KeReleaseSpinLockFromDpcLevel(&Frontend->RingLock);

    return Pending;
}

KDEFERRED_ROUTINE EvtchnDpcFunc;

VOID 
EvtchnDpcFunc(
    __in  PKDPC                   Dpc,
    __in_opt PVOID                Context,
    __in_opt PVOID                Arg1,
    __in_opt PVOID                Arg2
    )
{
    PXENVBD_FRONTEND    Frontend = (PXENVBD_FRONTEND)Context;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Arg1);
    UNREFERENCED_PARAMETER(Arg2);

    ASSERT(Frontend != NULL);

    if (PdoIsPaused(Frontend->Pdo)) {
        Warning("Target[%d] : Paused, %d outstanding\n",
                    Frontend->TargetId, PdoOutstandingSrbs(Frontend->Pdo));
        if (PdoOutstandingSrbs(Frontend->Pdo) == 0)
            return;
    }

    do {
        if (Frontend->Caps.Connected)
            FrontendEvtchnCallback(Frontend);
    } while (__EvtchnPending(Frontend) && Frontend->Caps.Connected);
}
//=============================================================================
// Ring Slots
static FORCEINLINE BOOLEAN
__FrontendCanSubmitRequest(
    __in  PXENVBD_FRONTEND        Frontend,
    __in  ULONG                   NumRequests
    )
{
    // RING_PROD_SLOTS_AVAIL(...)
    ULONG   Available = Frontend->FrontRing.nr_ents - (Frontend->FrontRing.req_prod_pvt - Frontend->FrontRing.rsp_cons);
    if (Available > NumRequests)
        return TRUE;
    return FALSE;
}

static FORCEINLINE VOID
__FrontendInsertRequestOnRing(
    __in  PXENVBD_FRONTEND        Frontend,
    __in  PXENVBD_REQUEST         Request
    )
{
    ULONG                       Index;
    blkif_request_t*            RingReq;
    blkif_request_discard_t*    Discard;

    RingReq = RING_GET_REQUEST(&Frontend->FrontRing, Frontend->FrontRing.req_prod_pvt);
    
    Frontend->FrontRing.req_prod_pvt++;

    Frontend->RequestsSubmitted++;
    Frontend->RequestsOutstanding++;

    switch (Request->Operation) {
    case BLKIF_OP_DISCARD:
        Discard = (blkif_request_discard_t*)RingReq;
        Discard->operation       = BLKIF_OP_DISCARD;
        Discard->handle          = (USHORT)Frontend->DeviceId;
        Discard->id              = (ULONG64)Request;
        Discard->sector_number   = Request->FirstSector;
        Discard->nr_sectors      = Request->NrSectors;
        break;
    case BLKIF_OP_READ:
    case BLKIF_OP_WRITE:
        RingReq->operation          = Request->Operation;
        RingReq->nr_segments        = Request->NrSegments;
        RingReq->handle             = (USHORT)Frontend->DeviceId;
        RingReq->id                 = (ULONG64)Request;
        RingReq->sector_number      = Request->FirstSector;
        for (Index = 0; Index < Request->NrSegments; ++Index) {
            RingReq->seg[Index].gref       = Request->Segments[Index].GrantRef;
            RingReq->seg[Index].first_sect = Request->Segments[Index].FirstSector;
            RingReq->seg[Index].last_sect  = Request->Segments[Index].LastSector;
        }
        break;
    case BLKIF_OP_WRITE_BARRIER:
        RingReq->operation          = Request->Operation;
        RingReq->nr_segments        = 0;
        RingReq->handle             = (USHORT)Frontend->DeviceId;
        RingReq->id                 = (ULONG64)Request;
        RingReq->sector_number      = Request->FirstSector;
        break;
    default:
        ASSERT(FALSE);
        break;
    }
}

BOOLEAN
FrontendSubmitRequest(
    __in  PXENVBD_FRONTEND          Frontend,
    __in  PSCSI_REQUEST_BLOCK       Srb
    )
{
    KIRQL           Irql;
    PLIST_ENTRY     Entry;
    PXENVBD_SRBEXT  SrbExt = GetSrbExt(Srb);
    BOOLEAN         Success = FALSE;

    ASSERT3P(SrbExt, !=, NULL);

    KeAcquireSpinLock(&Frontend->RingLock, &Irql);

    if (!__FrontendCanSubmitRequest(Frontend, SrbExt->RequestSize)) {
        goto done;
    }

    for (Entry = SrbExt->RequestList.Flink; 
            Entry != &SrbExt->RequestList; 
            Entry = Entry->Flink) {
        PXENVBD_REQUEST Request = CONTAINING_RECORD(Entry, XENVBD_REQUEST, Entry);
        __FrontendInsertRequestOnRing(Frontend, Request);
    }
    Success = TRUE;

done:
    KeReleaseSpinLock(&Frontend->RingLock, Irql);
    return Success;
}

VOID
FrontendPushRequests(
    __in  PXENVBD_FRONTEND        Frontend
    )
{
    int notify;

    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&Frontend->FrontRing, notify);
    if (notify) {
        (VOID) EVTCHN(Send, Frontend->Evtchn, Frontend->EvtchnPort);
    }
}

//=============================================================================
extern PHYSICAL_ADDRESS MmGetPhysicalAddress(IN PVOID Buffer);
static FORCEINLINE PFN_NUMBER
__VirtToPfn(
    __in  PVOID                   VirtAddr
    )
{
    PHYSICAL_ADDRESS PhysAddr = MmGetPhysicalAddress(VirtAddr);
    return (PFN_NUMBER)(ULONG_PTR)(PhysAddr.QuadPart >> 12);
}

//=============================================================================
__drv_requiresIRQL(DISPATCH_LEVEL)
static NTSTATUS
__UpdateBackendPath(
    __in  PXENVBD_FRONTEND        Frontend
    )
{
    NTSTATUS    Status;
    PCHAR       Value;
    ULONG       Length;

    Status = STORE(Read, Frontend->Store, NULL, Frontend->FrontendPath, 
                        "backend-id", &Value);
    if (NT_SUCCESS(Status)) {
        Frontend->BackendId = (USHORT)strtoul(Value, NULL, 10);
        STORE(Free, Frontend->Store, Value);
    } else {
        Frontend->BackendId = 0;
    }

    Status = STORE(Read, Frontend->Store, NULL, Frontend->FrontendPath,
                    "backend", &Value);
    if (NT_SUCCESS(Status)) {
        if (Frontend->BackendPath) {
            Trace("<< %s\n", Frontend->BackendPath);
            __FrontendFree(Frontend->BackendPath);
            Frontend->BackendPath = NULL;
        }

        Length = (ULONG)strlen(Value);
        Frontend->BackendPath = (PCHAR)__FrontendAlloc(Length + 1);

        if (Frontend->BackendPath) {
            RtlCopyMemory(Frontend->BackendPath, Value, Length);
            Trace(">> %s\n", Frontend->BackendPath);
        }

        STORE(Free, Frontend->Store, Value);
    } else {
        Warning("Failed to read \'backend\' from \'%s\' (%08x)\n", 
                    Frontend->FrontendPath, Status);
    }

    return Status;
}
__drv_maxIRQL(DISPATCH_LEVEL)
static NTSTATUS
__ReadState(
    __in  PXENVBD_FRONTEND        Frontend,
    __in_opt PXENBUS_STORE_TRANSACTION Transaction,
    __in  PCHAR                   Path,
    __out XenbusState*            State
    )
{
    NTSTATUS        Status;
    PCHAR           Buffer;

    Status = STORE(Read, Frontend->Store, Transaction, Path, 
                    "state", &Buffer);
    if (!NT_SUCCESS(Status))
        goto fail;
    *State = (XenbusState)strtoul(Buffer, NULL, 10);
    STORE(Free, Frontend->Store, Buffer);

    return STATUS_SUCCESS;

fail:
    *State = XenbusStateUnknown;
    return Status;
}
__drv_requiresIRQL(DISPATCH_LEVEL)
static NTSTATUS
__WaitState(
    __in  PXENVBD_FRONTEND        Frontend,
    __inout  XenbusState*         State
    )
{
    NTSTATUS        Status;
    XenbusState     OldState = *State;
    PXENBUS_STORE_WATCH Watch;
    KEVENT          Event;
    LARGE_INTEGER   Timeout;

    LARGE_INTEGER   StartTime;
    LARGE_INTEGER   CurrentTime;
    ULONG           Count = 0;

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    Timeout.QuadPart = 0;

    ASSERT3P(Frontend->BackendPath, !=, NULL);
    Status = STORE(Watch, Frontend->Store, Frontend->BackendPath, "state", 
                        &Event, &Watch);
    if (!NT_SUCCESS(Status))
        goto fail1;

    KeQuerySystemTime(&StartTime);

    while (OldState == *State) {
        // check event and spin or read
#pragma prefast(suppress:28121)
        if (KeWaitForSingleObject(&Event, Executive, KernelMode, 
                                    FALSE, &Timeout) == STATUS_TIMEOUT) {
            STORE(Poll, Frontend->Store);

            KeQuerySystemTime(&CurrentTime);
            if ((CurrentTime.QuadPart - StartTime.QuadPart) > 10000) {
                Warning("Target[%d] : %d Waited for %d ms\n", Frontend->TargetId, 
                            Count, (ULONG)((CurrentTime.QuadPart - StartTime.QuadPart) / 10));
                StartTime.QuadPart = CurrentTime.QuadPart;
                ++Count;
            }

            continue;
        }

        Status = __ReadState(Frontend, NULL, Frontend->BackendPath, State);
        if (!NT_SUCCESS(Status))
            goto fail2;
    }

    STORE(Unwatch, Frontend->Store, Watch);
    Trace("Target[%d] : BACKEND_STATE  -> %s\n", Frontend->TargetId, XenbusStateName(*State));
    return STATUS_SUCCESS;

fail2:
    Error("Fail2\n");
    STORE(Unwatch, Frontend->Store, Watch);
fail1:
    Error("Fail1 (%08x)\n", Status);
    return Status;
}
__drv_requiresIRQL(DISPATCH_LEVEL)
static NTSTATUS
___SetState(
    __in  PXENVBD_FRONTEND        Frontend,
    __in  XenbusState             State
    )
{
    NTSTATUS    Status;

    Status = STORE(Printf, Frontend->Store, NULL, Frontend->FrontendPath,
                    "state", "%u", State);
    if (NT_SUCCESS(Status)) {
        Trace("Target[%d] : FRONTEND_STATE -> %s\n", Frontend->TargetId, XenbusStateName(State));
    } else {
        Error("Fail (%08x)\n", Status);
    }

    return Status;
}
__drv_requiresIRQL(DISPATCH_LEVEL)
static FORCEINLINE NTSTATUS
__WriteTargetPath(
    __in  PXENVBD_FRONTEND        Frontend
    )
{
    NTSTATUS    Status;

    Status = FrontendWriteUsage(Frontend);
    if (!NT_SUCCESS(Status))
        goto out;

    Status = STORE(Printf, Frontend->Store, NULL, Frontend->TargetPath, 
                        "frontend", "%s", Frontend->FrontendPath);
    if (!NT_SUCCESS(Status))
        goto out;

    Status = STORE(Printf, Frontend->Store, NULL, Frontend->TargetPath, 
                        "device", "%u", Frontend->DeviceId);
    if (!NT_SUCCESS(Status))
        goto out;

out:
    return Status;
}
__drv_requiresIRQL(DISPATCH_LEVEL)
static FORCEINLINE VOID
__ReadFeatures(
    __in  PXENVBD_FRONTEND        Frontend
    )
{
    NTSTATUS    Status;
    PCHAR       Buffer;

    Status = STORE(Read, Frontend->Store, NULL, Frontend->BackendPath, 
                        "removable", &Buffer);
    if (NT_SUCCESS(Status)) {
        Frontend->Caps.Removable = (strtoul(Buffer, NULL, 10) == 1);
        STORE(Free, Frontend->Store, Buffer);
    }

    Status = STORE(Read, Frontend->Store, NULL, Frontend->BackendPath,
                        "max-ring-page-order", &Buffer);
    if (NT_SUCCESS(Status)) {
        Frontend->RingOrder = __min(strtoul(Buffer, NULL, 10),
                                        XENVBD_MAX_RING_PAGE_ORDER);
        STORE(Free, Frontend->Store, Buffer);
    } else {
        Frontend->RingOrder = 0;
    }

    Status = STORE(Read, Frontend->Store, NULL, Frontend->BackendPath,
                        "feature-barrier", &Buffer);
    if (NT_SUCCESS(Status)) {
        Frontend->Features.Barrier = (strtoul(Buffer, NULL, 10) == 1);
        STORE(Free, Frontend->Store, Buffer);
    } else {
        Frontend->Features.Barrier = FALSE;
    }

    Status = STORE(Read, Frontend->Store, NULL, Frontend->BackendPath,
                        "feature-discard", &Buffer);
    if (NT_SUCCESS(Status)) {
        Frontend->Features.Discard = (strtoul(Buffer, NULL, 10) == 1);
        STORE(Free, Frontend->Store, Buffer);
    } else {
        Frontend->Features.Discard = FALSE;
    }

    Status = STORE(Read, Frontend->Store, NULL, Frontend->BackendPath,
                        "feature-flush-cache", &Buffer);
    if (NT_SUCCESS(Status)) {
        Frontend->Features.FlushCache = (strtoul(Buffer, NULL, 10) == 1);
        STORE(Free, Frontend->Store, Buffer);
    } else {
        Frontend->Features.FlushCache = FALSE;
    }
}
__drv_requiresIRQL(DISPATCH_LEVEL)
static BOOLEAN
__ReadDiskInfo(
    __in  PXENVBD_FRONTEND        Frontend
    )
{
    NTSTATUS    Status;
    PCHAR       Buffer;
    BOOLEAN     Updated = FALSE;

    if (Frontend->Store == NULL)
        return FALSE;
    if (Frontend->BackendPath == NULL)
        return FALSE;

    Status = STORE(Read, Frontend->Store, NULL, Frontend->BackendPath, 
                        "info", &Buffer);
    if (NT_SUCCESS(Status)) {
        ULONG   DiskInfo;
        DiskInfo = strtoul(Buffer, NULL, 10);
        STORE(Free, Frontend->Store, Buffer);
        
        if (Frontend->DiskInfo.DiskInfo != DiskInfo) {
            Frontend->DiskInfo.DiskInfo = DiskInfo;
            Frontend->Caps.SurpriseRemovable = (Frontend->DiskInfo.DiskInfo & VDISK_REMOVABLE);
            Updated = TRUE;
            if (Frontend->DiskInfo.DiskInfo & VDISK_READONLY) {
                Warning("Target[%d] : DiskInfo contains VDISK_READONLY flag!\n", Frontend->TargetId);
            }
            if (Frontend->DiskInfo.DiskInfo & VDISK_CDROM) {
                Warning("Target[%d] : DiskInfo contains VDISK_CDROM flag!\n", Frontend->TargetId);
            }
        }
    }

    Status = STORE(Read, Frontend->Store, NULL, Frontend->BackendPath, 
                        "sector-size", &Buffer);
    if (NT_SUCCESS(Status)) {
        ULONG   SectorSize;
        SectorSize = strtoul(Buffer, NULL, 10);
        STORE(Free, Frontend->Store, Buffer);

        if (Frontend->DiskInfo.SectorSize != SectorSize) {
            Frontend->DiskInfo.SectorSize = SectorSize;
            Updated = TRUE;
            if (Frontend->DiskInfo.SectorSize == 0) {
                Error("Target[%d] : Invalid SectorSize!\n", Frontend->TargetId);
            }
        }
    }

    Status = STORE(Read, Frontend->Store, NULL, Frontend->BackendPath, 
                        "sectors", &Buffer);
    if (NT_SUCCESS(Status)) {
        ULONG64 SectorCount;
        SectorCount = _strtoui64(Buffer, NULL, 10);
        STORE(Free, Frontend->Store, Buffer);

        if (Frontend->DiskInfo.SectorCount != SectorCount) {
            Frontend->DiskInfo.SectorCount = SectorCount;
            Updated = TRUE;
            if (Frontend->DiskInfo.SectorCount == 0) {
                Error("Target[%d] : Invalid SectorCount!\n", Frontend->TargetId);
            }
        }
    }

    return Updated;
}
__drv_requiresIRQL(DISPATCH_LEVEL)
static FORCEINLINE NTSTATUS
__AllocRing(
    __in  PXENVBD_FRONTEND        Frontend
    )
{
    NTSTATUS            Status;
    ULONG               Index;
    BOOLEAN             Pending;
    const ULONG         RingPages = (1 << Frontend->RingOrder);

    // SharedRing
    ASSERT3P(Frontend->SharedRing, ==, NULL);
    Frontend->SharedRing = __AllocPages((SIZE_T)RingPages << PAGE_SHIFT, &Frontend->Mdl);

    Status = STATUS_INSUFFICIENT_RESOURCES;
    if (!Frontend->SharedRing)
        goto fail1;

#pragma warning(push)
#pragma warning(disable: 4305)
    SHARED_RING_INIT(Frontend->SharedRing);
    FRONT_RING_INIT(&Frontend->FrontRing, Frontend->SharedRing, PAGE_SIZE << Frontend->RingOrder);
#pragma warning(pop)

    // GNTTAB
    for (Index = 0; Index < RingPages; ++Index) {
        ULONG       RingRef;
        PFN_NUMBER  Pfn = __VirtToPfn((PUCHAR)Frontend->SharedRing + (Index * PAGE_SIZE));

        ASSERT3U(Frontend->RingGrantRefs[Index], ==, 0);

        Status = GNTTAB(Get, Frontend->Gnttab, &RingRef);
        if (!NT_SUCCESS(Status))
            goto fail2;

        GNTTAB(PermitForeignAccess, Frontend->Gnttab, RingRef, Frontend->BackendId, 
                    GNTTAB_ENTRY_FULL_PAGE, Pfn, FALSE);

        Frontend->RingGrantRefs[Index] = RingRef;
    }

    // EVTCHN
    ASSERT3P(Frontend->EvtchnPort, ==, NULL);
    Frontend->EvtchnPort = EVTCHN(Open, Frontend->Evtchn, EVTCHN_UNBOUND, EvtchnInterruptFunc,
                                    Frontend, Frontend->BackendId, TRUE);
    if (Frontend->EvtchnPort == NULL)
        goto fail3;

    Frontend->EvtchnPortNumber = EVTCHN(Port, Frontend->Evtchn, Frontend->EvtchnPort);

    Pending = EVTCHN(Unmask, Frontend->Evtchn, Frontend->EvtchnPort, FALSE);
    if (Pending)
        EVTCHN(Trigger, Frontend->Evtchn, Frontend->EvtchnPort);

    return STATUS_SUCCESS;

fail3:
    Error("Fail3\n");
    for (Index = 0; Index < RingPages; ++Index) {
        if (Frontend->RingGrantRefs[Index] != 0) {
            GNTTAB(RevokeForeignAccess, Frontend->Gnttab, Frontend->RingGrantRefs[Index]);
            GNTTAB(Put, Frontend->Gnttab, Frontend->RingGrantRefs[Index]);
            Frontend->RingGrantRefs[Index] = 0;
        }
    }

fail2:
    Error("Fail2\n");
    RtlZeroMemory(&Frontend->FrontRing, sizeof(Frontend->FrontRing));
    MmFreeContiguousMemory(Frontend->SharedRing);
    Frontend->SharedRing = NULL;

fail1:
    Error("Fail1 (%08x)\n", Status);
    return Status;
}
__drv_requiresIRQL(DISPATCH_LEVEL)
static VOID
__FreeRing(
    __in  PXENVBD_FRONTEND        Frontend
    )
{
    ULONG   Index;

    // EVTCHN
    if (Frontend->EvtchnPort) {
        EVTCHN(Close, Frontend->Evtchn, Frontend->EvtchnPort);
        Frontend->EvtchnPort = NULL;
        Frontend->EvtchnPortNumber = 0;
    }

    // GNTTAB
    for (Index = 0; Index < XENVBD_MAX_RING_PAGES; ++Index) {
        if (Frontend->RingGrantRefs[Index] != 0) {
            GNTTAB(RevokeForeignAccess, Frontend->Gnttab, Frontend->RingGrantRefs[Index]);
            GNTTAB(Put, Frontend->Gnttab, Frontend->RingGrantRefs[Index]);
            Frontend->RingGrantRefs[Index] = 0;
        }
    }

    // SharedRing
    RtlZeroMemory(&Frontend->FrontRing, sizeof(Frontend->FrontRing));
    __FreePages(Frontend->SharedRing, Frontend->Mdl);
    Frontend->SharedRing = NULL;
    Frontend->Mdl = NULL;
}
__drv_requiresIRQL(DISPATCH_LEVEL)
static FORCEINLINE NTSTATUS
__WriteRing(
    __in  PXENVBD_FRONTEND        Frontend
    )
{
    NTSTATUS    Status;
    const ULONG RingPages = (1 << Frontend->RingOrder);
    
    for (;;) {
        PXENBUS_STORE_TRANSACTION   Transaction;
        ULONG                       Index;

        Status = STORE(TransactionStart, Frontend->Store, &Transaction);
        if (!NT_SUCCESS(Status))
            break;

        Status = STORE(Printf, Frontend->Store, Transaction, Frontend->FrontendPath, 
                        "event-channel", "%u", Frontend->EvtchnPortNumber);
        if (!NT_SUCCESS(Status))
            goto abort;

        if (Frontend->RingOrder == 0) {
            Status = STORE(Printf, Frontend->Store, Transaction, Frontend->FrontendPath,
                            "ring-ref", "%u", Frontend->RingGrantRefs[0]);
            if (!NT_SUCCESS(Status))
                goto abort;
        } else {
            Status = STORE(Printf, Frontend->Store, Transaction, Frontend->FrontendPath, 
                            "ring-page-order", "%u", Frontend->RingOrder);
            if (!NT_SUCCESS(Status))
                goto abort;

            for (Index = 0; Index < RingPages; ++Index) {
                PCHAR   RingRefName = DriverFormat("ring-ref%d", Index);
                Status = STATUS_INSUFFICIENT_RESOURCES;
                if (RingRefName == NULL)
                    goto abort;

                Status = STORE(Printf, Frontend->Store, Transaction, Frontend->FrontendPath,
                                RingRefName, "%u", Frontend->RingGrantRefs[Index]);
                DriverFormatFree(RingRefName);
                if (!NT_SUCCESS(Status))
                    goto abort;
            }
        }

        Status = STORE(Printf, Frontend->Store, Transaction, Frontend->FrontendPath,
                        "target-id", "%u", Frontend->TargetId);
        if (!NT_SUCCESS(Status))
            goto abort;

        Status = STORE(Write, Frontend->Store, Transaction, Frontend->FrontendPath,
                        "protocol", XEN_IO_PROTO_ABI_NATIVE);
        if (!NT_SUCCESS(Status))
            goto abort;

        Status = STORE(Write, Frontend->Store, Transaction, Frontend->FrontendPath,
                        "feature-surprise-remove", "1");
        if (!NT_SUCCESS(Status))
            goto abort;

        Status = STORE(Write, Frontend->Store, Transaction, Frontend->FrontendPath,
                        "feature-online-resize", "1");
        if (!NT_SUCCESS(Status))
            goto abort;

        Status = STORE(TransactionEnd, Frontend->Store, Transaction, TRUE);
        if (Status == STATUS_RETRY)
            continue;

        return Status;

abort:
        (VOID) STORE(TransactionEnd, Frontend->Store, Transaction, FALSE);
        break;
    }

    return Status;
}
__drv_requiresIRQL(DISPATCH_LEVEL)
static FORCEINLINE VOID
__CheckBackendForEject(
    __in  PXENVBD_FRONTEND        Frontend
    )
{
    XenbusState     FrontendState;
    XenbusState     BackendState;
    BOOLEAN         Online;
    ULONG           Attempt;
    NTSTATUS        Status;

    if (Frontend->Store == NULL)
        return;
    if (Frontend->FrontendPath == NULL)
        return;
    if (Frontend->BackendPath == NULL)
        return;

    // get FrontendState, BackendState and Online
    Attempt         = 0;
    FrontendState   = XenbusStateUnknown;
    BackendState    = XenbusStateUnknown;
    Online          = TRUE;
    for (;;) {
        PXENBUS_STORE_TRANSACTION   Transaction;
        PCHAR                       Buffer;

        Status = STORE(TransactionStart, Frontend->Store, &Transaction);
        if (!NT_SUCCESS(Status))
            break;

        Status = __ReadState(Frontend, Transaction, Frontend->FrontendPath, &FrontendState);
        if (!NT_SUCCESS(Status))
            goto abort;

        Status = __ReadState(Frontend, Transaction, Frontend->BackendPath, &BackendState);
        if (!NT_SUCCESS(Status))
            goto abort;

        Status = STORE(Read, Frontend->Store, Transaction, Frontend->BackendPath, 
                        "online", &Buffer);
        if (!NT_SUCCESS(Status))
            goto abort;

        Online = (BOOLEAN)strtol(Buffer, NULL, 2);
        STORE(Free, Frontend->Store, Buffer);

        Status = STORE(TransactionEnd, Frontend->Store, Transaction, TRUE);
        if (Status != STATUS_RETRY || ++Attempt > 10)
            break;

        continue;

abort:
        (VOID) STORE(TransactionEnd, Frontend->Store, Transaction, FALSE);
        break;
    }
    if (!NT_SUCCESS(Status))
        return;

    // check to see eject required
    if (!Online && BackendState == XenbusStateClosing) {
        Trace("Target[%d] : BackendState(%s) FrontendState(%s)\n", 
                Frontend->TargetId, XenbusStateName(BackendState), XenbusStateName(FrontendState));

        PdoIssueDeviceEject(Frontend->Pdo, XenbusStateName(BackendState));
    }    
}
//=============================================================================
__drv_requiresIRQL(DISPATCH_LEVEL)
static NTSTATUS
FrontendClose(
    __in  PXENVBD_FRONTEND        Frontend
    )
{
    NTSTATUS        Status;
    XenbusState     BackendState;

    // dont try to queue the DPC when the lock is dropped
    KeRemoveQueueDpc(&Frontend->EvtchnDpc);

    // unwatch backend
    if (Frontend->BackendStateWatch) {
        STORE(Unwatch, Frontend->Store, Frontend->BackendStateWatch);
        Frontend->BackendStateWatch = NULL;
    }
    if (Frontend->BackendInfoWatch) {
        STORE(Unwatch, Frontend->Store, Frontend->BackendInfoWatch);
        Frontend->BackendInfoWatch = NULL;
    }
    if (Frontend->BackendSectorSizeWatch) {
        STORE(Unwatch, Frontend->Store, Frontend->BackendSectorSizeWatch);
        Frontend->BackendSectorSizeWatch = NULL;
    }
    if (Frontend->BackendSectorCountWatch) {
        STORE(Unwatch, Frontend->Store, Frontend->BackendSectorCountWatch);
        Frontend->BackendSectorCountWatch = NULL;
    }

    Frontend->BackendId = DOMID_INVALID;

    // get/update backend path
    Status = __UpdateBackendPath(Frontend);
    if (!NT_SUCCESS(Status))
        goto fail1;

    // Backend : -> !INITIALIZING
    BackendState = XenbusStateUnknown;
    do {
        Status = __WaitState(Frontend, &BackendState);
        if (!NT_SUCCESS(Status))
            goto fail2;
    } while (BackendState == XenbusStateInitialising);

    // Frontend: -> CLOSING 
    // Backend : -> CLOSING 
    while (BackendState != XenbusStateClosing &&
           BackendState != XenbusStateClosed) {
        Status = ___SetState(Frontend, XenbusStateClosing);
        if (!NT_SUCCESS(Status))
            goto fail3;
        Status = __WaitState(Frontend, &BackendState);
        if (!NT_SUCCESS(Status))
            goto fail4;
    }

    // Frontend: -> CLOSED
    // Backend : -> CLOSED
    while (BackendState != XenbusStateClosed) {
        Status = ___SetState(Frontend, XenbusStateClosed);
        if (!NT_SUCCESS(Status))
            goto fail5;
        Status = __WaitState(Frontend, &BackendState);
        if (!NT_SUCCESS(Status))
            goto fail6;
    }

    return STATUS_SUCCESS;

fail6:
fail5:
fail4:
fail3:
fail2:
fail1:
    return Status;
}
__drv_requiresIRQL(DISPATCH_LEVEL)
static NTSTATUS
FrontendPrepare(
    __in  PXENVBD_FRONTEND        Frontend
    )
{
    NTSTATUS        Status;
    XenbusState    BackendState;

    // get/update backend path
    Status = __UpdateBackendPath(Frontend);
    if (!NT_SUCCESS(Status))
        goto fail1;

    // watch backend (4 paths needed)
    if (Frontend->BackendStateWatch == NULL) {
        Status = STORE(Watch, Frontend->Store, Frontend->BackendPath, "state",
                        Frontend->BackendEvent, &Frontend->BackendStateWatch);
        if (!NT_SUCCESS(Status))
            goto fail1;
    }
    if (Frontend->BackendInfoWatch == NULL) {
        Status = STORE(Watch, Frontend->Store, Frontend->BackendPath, "info",
                        Frontend->BackendEvent, &Frontend->BackendInfoWatch);
        if (!NT_SUCCESS(Status))
            goto fail1;
    }
    if (Frontend->BackendSectorSizeWatch == NULL) {
        Status = STORE(Watch, Frontend->Store, Frontend->BackendPath, "sector-size",
                        Frontend->BackendEvent, &Frontend->BackendSectorSizeWatch);
        if (!NT_SUCCESS(Status))
            goto fail1;
    }
    if (Frontend->BackendSectorCountWatch == NULL) {
        Status = STORE(Watch, Frontend->Store, Frontend->BackendPath, "sectors",
                        Frontend->BackendEvent, &Frontend->BackendSectorCountWatch);
        if (!NT_SUCCESS(Status))
            goto fail1;
    }

    // write targetpath
    Status = __WriteTargetPath(Frontend);
    if (!NT_SUCCESS(Status))
        goto fail2;

    // Frontend: -> INITIALIZING
    Status = ___SetState(Frontend, XenbusStateInitialising);
    if (!NT_SUCCESS(Status))
        goto fail3;

    // Backend : -> INITWAIT
    BackendState = XenbusStateUnknown;
    do {
        Status = __WaitState(Frontend, &BackendState);
        if (!NT_SUCCESS(Status))
            goto fail4;
    } while (BackendState == XenbusStateClosed || 
             BackendState == XenbusStateInitialising);
    Status = STATUS_UNSUCCESSFUL;
    if (BackendState != XenbusStateInitWait)
        goto fail5;

    // read inquiry data
    if (Frontend->Inquiry == NULL)
        PdoReadInquiryData(Frontend, &Frontend->Inquiry);
    PdoUpdateInquiryData(Frontend, Frontend->Inquiry);

    // read features and caps (removable, ring-order, ...)
    __ReadFeatures(Frontend);
    Verbose("Target[%d] : BackendId=%d, RingOrder=%d, %s %s %s %s\n", 
                Frontend->TargetId, Frontend->BackendId, Frontend->RingOrder, 
                Frontend->Caps.Removable ? "REMOVABLE" : "NOT_REMOVABLE",
                Frontend->Features.Barrier ? "BARRIER" : "NOT_BARRIER",
                Frontend->Features.Discard ? "DISCARD" : "NOT_DISCARD",
                Frontend->Features.FlushCache ?  "FLUSH" : "NOT_FLUSH");
    
    return STATUS_SUCCESS;

fail5:
    Error("Fail5\n");
fail4:
    Error("Fail4\n");
fail3:
    Error("Fail3\n");
fail2:
    Error("Fail2\n");
fail1:
    Error("Fail1 (%08x)\n", Status);

    if (Frontend->BackendStateWatch) {
        (VOID) STORE(Unwatch, Frontend->Store, Frontend->BackendStateWatch);
        Frontend->BackendStateWatch = NULL;
    }
    if (Frontend->BackendInfoWatch) {
        (VOID) STORE(Unwatch, Frontend->Store, Frontend->BackendInfoWatch);
        Frontend->BackendInfoWatch = NULL;
    }
    if (Frontend->BackendSectorSizeWatch) {
        (VOID) STORE(Unwatch, Frontend->Store, Frontend->BackendSectorSizeWatch);
        Frontend->BackendSectorSizeWatch = NULL;
    }
    if (Frontend->BackendSectorCountWatch) {
        (VOID) STORE(Unwatch, Frontend->Store, Frontend->BackendSectorCountWatch);
        Frontend->BackendSectorCountWatch = NULL;
    }
    return Status;
}
__drv_requiresIRQL(DISPATCH_LEVEL)
static NTSTATUS
FrontendConnect(
    __in  PXENVBD_FRONTEND        Frontend
    )
{
    NTSTATUS        Status;
    XenbusState     BackendState;

    // Alloc Ring, Create Evtchn, Gnttab map
    Status = __AllocRing(Frontend);
    if (!NT_SUCCESS(Status))
        goto fail1;

    // write evtchn/gnttab details in xenstore
    Status = __WriteRing(Frontend);
    if (!NT_SUCCESS(Status))
        goto fail2;

    // Frontend: -> INITIALIZED
    Status = ___SetState(Frontend, XenbusStateInitialised);
    if (!NT_SUCCESS(Status))
        goto fail3;

    // Backend : -> CONNECTED
    BackendState = XenbusStateUnknown;
    do {
        Status = __WaitState(Frontend, &BackendState);
        if (!NT_SUCCESS(Status))
            goto fail4;
    } while (BackendState == XenbusStateInitWait ||
             BackendState == XenbusStateInitialising ||
             BackendState == XenbusStateInitialised);
    Status = STATUS_UNSUCCESSFUL;
    if (BackendState != XenbusStateConnected)
        goto fail5;

    // Frontend: -> CONNECTED
    Status = ___SetState(Frontend, XenbusStateConnected);
    if (!NT_SUCCESS(Status))
        goto fail6;

    // read disk info
    __ReadDiskInfo(Frontend);
    Verbose("Target[%d] : %lld sectors of %d bytes (%lld MB), Info %08x %s\n", Frontend->TargetId,
                Frontend->DiskInfo.SectorCount, Frontend->DiskInfo.SectorSize,
                (Frontend->DiskInfo.SectorSize * Frontend->DiskInfo.SectorCount) / (1024 * 1024),
                Frontend->DiskInfo.DiskInfo, Frontend->Caps.SurpriseRemovable ? "SURPRISE_REMOVABLE" : "");
    
    return STATUS_SUCCESS;

fail6:
    Error("Fail6\n");
fail5:
    Error("Fail5\n");
fail4:
    Error("Fail4\n");
fail3:
    Error("Fail3\n");
fail2:
    Error("Fail2\n");
    __FreeRing(Frontend);
fail1:
    Error("Fail1 (%08x)\n", Status);
    return Status;
}
__drv_requiresIRQL(DISPATCH_LEVEL)
static FORCEINLINE VOID
FrontendDisconnect(
    __in  PXENVBD_FRONTEND        Frontend
    )
{
    __FreeRing(Frontend);
}
__drv_requiresIRQL(DISPATCH_LEVEL)
static FORCEINLINE VOID
FrontendEnable(
    __in  PXENVBD_FRONTEND        Frontend
    )
{
    Frontend->Caps.Connected = TRUE;
    KeMemoryBarrier();

    EVTCHN(Trigger, Frontend->Evtchn, Frontend->EvtchnPort);
}
__drv_requiresIRQL(DISPATCH_LEVEL)
static FORCEINLINE VOID
FrontendDisable(
    __in  PXENVBD_FRONTEND        Frontend
    )
{
    Frontend->Caps.Connected = FALSE;
}

//=============================================================================
static DECLSPEC_NOINLINE NTSTATUS
__FrontendSetState(
    __in  PXENVBD_FRONTEND        Frontend,
    __in  XENVBD_STATE            State
    );

__drv_requiresIRQL(DISPATCH_LEVEL)
static VOID
FrontendSuspendLateCallback(
    __in  PVOID                   Argument
    )
{
    NTSTATUS            Status;
    XENVBD_STATE        State;
    PXENVBD_FRONTEND    Frontend = (PXENVBD_FRONTEND)Argument;

    Verbose("Target[%d] : ===> from %s\n", Frontend->TargetId, __XenvbdStateName(Frontend->State));
    State = Frontend->State;

    PdoPreResume(Frontend->Pdo);

    // dont acquire state lock - called at DISPATCH on 1 vCPU with interrupts enabled
    Status = __FrontendSetState(Frontend, XENVBD_CLOSED);
    if (!NT_SUCCESS(Status)) {
        Error("Target[%d] : SetState CLOSED (%08x)\n", Frontend->TargetId, Status);
        ASSERT(FALSE);
    }

    // reset some stats - previous values are just not relevant any more
    Verbose("Target[%d] : ResetFrom: %d NumEvents, %d NumDpcs\n", 
                Frontend->TargetId, Frontend->NumEvents, Frontend->NumDpcs);
    Verbose("Target[%d] : ResetFrom: %d Outstanding, %d Submitted, %d Recieved\n", 
                Frontend->TargetId, Frontend->RequestsOutstanding, 
                Frontend->RequestsSubmitted, Frontend->ResponsesRecieved);

    Frontend->NumEvents = Frontend->NumDpcs = 0;
    Frontend->RequestsOutstanding = Frontend->RequestsSubmitted = Frontend->ResponsesRecieved = 0;

    // dont acquire state lock - called at DISPATCH on 1 vCPU with interrupts enabled
    Status = __FrontendSetState(Frontend, State);
    if (!NT_SUCCESS(Status)) {
        Error("Target[%d] : SetState %s (%08x)\n", Frontend->TargetId, __XenvbdStateName(State), Status);
        ASSERT(FALSE);
    }

    PdoPostResume(Frontend->Pdo);
    EVTCHN(Trigger, Frontend->Evtchn, Frontend->EvtchnPort);

    Verbose("Target[%d] : <=== restored %s\n", Frontend->TargetId, __XenvbdStateName(Frontend->State));
}
//=============================================================================
// Init/Term
__checkReturn
NTSTATUS
FrontendCreate(
    __in  PXENVBD_PDO             Pdo,
    __in  PCHAR                   DeviceId, 
    __in  ULONG                   TargetId, 
    __in  PKEVENT                 Event,
    __out PXENVBD_FRONTEND*       _Frontend
    )
{
    NTSTATUS            Status;
    PXENVBD_FRONTEND    Frontend;

    Trace("Target[%d] @ (%d) =====>\n", TargetId, KeGetCurrentIrql());

    Frontend = __FrontendAlloc(sizeof(XENVBD_FRONTEND));

    Status = STATUS_NO_MEMORY;
    if (Frontend == NULL)
        goto fail1;

    // populate members
    Frontend->Pdo = Pdo;
    Frontend->TargetId = TargetId;
    Frontend->DeviceId = strtoul(DeviceId, NULL, 10);
    Frontend->State = XENVBD_INITIALIZED;
    Frontend->DiskInfo.SectorSize = 512; // default sector size
    Frontend->BackendId = DOMID_INVALID;
    Frontend->BackendEvent = Event;
    
    Status = STATUS_INSUFFICIENT_RESOURCES;
    Frontend->FrontendPath = DriverFormat("device/%s/%s", FdoEnum(PdoGetFdo(Pdo)), DeviceId);
    if (Frontend->FrontendPath == NULL) 
        goto fail2;

    Frontend->TargetPath = DriverFormat("data/scsi/target/%d", TargetId);
    if (Frontend->TargetPath == NULL)
        goto fail3;

    // kernel objects
    KeInitializeSpinLock(&Frontend->StateLock);
    KeInitializeSpinLock(&Frontend->RingLock);
    KeInitializeDpc(&Frontend->EvtchnDpc, EvtchnDpcFunc, Frontend);

    Trace("Target[%d] @ (%d) <===== (STATUS_SUCCESS)\n", Frontend->TargetId, KeGetCurrentIrql());
    *_Frontend = Frontend;
    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");
    DriverFormatFree(Frontend->FrontendPath);
    Frontend->FrontendPath = NULL;
fail2:
    Error("Fail2\n");
    __FrontendFree(Frontend);
fail1:
    Error("Fail1 (%08x)\n", Status);
    *_Frontend = NULL;
    return Status;
}

VOID
FrontendDestroy(
    __in  PXENVBD_FRONTEND        Frontend
    )
{
    const ULONG TargetId = Frontend->TargetId;

    Trace("Target[%d] @ (%d) =====>\n", TargetId, KeGetCurrentIrql());

    PdoFreeInquiryData(Frontend->Inquiry);
    Frontend->Inquiry = NULL;

    DriverFormatFree(Frontend->TargetPath);
    Frontend->TargetPath = NULL;

    DriverFormatFree(Frontend->FrontendPath);
    Frontend->FrontendPath = NULL;

    ASSERT3P(Frontend->BackendPath, ==, NULL);
    ASSERT3P(Frontend->Inquiry, ==, NULL);
    ASSERT3P(Frontend->SuspendLateCallback, ==, NULL);
    ASSERT3P(Frontend->SharedRing, ==, NULL);
    ASSERT3U(Frontend->RingGrantRefs[0], ==, 0); // only ASSERTing on 1st entry
    ASSERT3P(Frontend->EvtchnPort, ==, NULL);
    ASSERT3P(Frontend->BackendStateWatch, ==, NULL);
    ASSERT3P(Frontend->BackendInfoWatch, ==, NULL);
    ASSERT3P(Frontend->BackendSectorSizeWatch, ==, NULL);
    ASSERT3P(Frontend->BackendSectorCountWatch, ==, NULL);

    __FrontendFree(Frontend);
    Trace("Target[%d] @ (%d) <=====\n", TargetId, KeGetCurrentIrql());
}

__checkReturn
__drv_maxIRQL(DISPATCH_LEVEL)
NTSTATUS
FrontendD3ToD0(
    __in  PXENVBD_FRONTEND        Frontend
    )
{
    NTSTATUS    Status;
    KIRQL       Irql;

    KeAcquireSpinLock(&Frontend->StateLock, &Irql);

    // acquire interfaces
    Frontend->Store   = FdoAcquireStore(PdoGetFdo(Frontend->Pdo));
    Frontend->Evtchn  = FdoAcquireEvtchn(PdoGetFdo(Frontend->Pdo));
    Frontend->Gnttab  = FdoAcquireGnttab(PdoGetFdo(Frontend->Pdo));
    Frontend->Suspend = FdoAcquireSuspend(PdoGetFdo(Frontend->Pdo));

    // register suspend callback
    ASSERT3P(Frontend->SuspendLateCallback, ==, NULL);
    Status = SUSPEND(Register, Frontend->Suspend, SUSPEND_CALLBACK_LATE,
                    FrontendSuspendLateCallback, Frontend, &Frontend->SuspendLateCallback);
    if (!NT_SUCCESS(Status))
        goto fail1;

    // update state
    Frontend->Active = TRUE;

    KeReleaseSpinLock(&Frontend->StateLock, Irql);
    return STATUS_SUCCESS;

fail1:
    Error("Fail1 (%08x)\n", Status);

    SUSPEND(Release, Frontend->Suspend);
    Frontend->Suspend = NULL;
    
    GNTTAB(Release, Frontend->Gnttab);
    Frontend->Gnttab = NULL;
    
    EVTCHN(Release, Frontend->Evtchn);
    Frontend->Evtchn = NULL;
    
    STORE(Release, Frontend->Store);
    Frontend->Store = NULL;

    KeReleaseSpinLock(&Frontend->StateLock, Irql);
    return Status;
}

__drv_maxIRQL(DISPATCH_LEVEL)
VOID
FrontendD0ToD3(
    __in  PXENVBD_FRONTEND        Frontend
    )
{
    KIRQL       Irql;

    KeAcquireSpinLock(&Frontend->StateLock, &Irql);

    // update state
    Frontend->Active = FALSE;

    // deregister suspend callback
    if (Frontend->SuspendLateCallback != NULL) {
        SUSPEND(Deregister, Frontend->Suspend, Frontend->SuspendLateCallback);
        Frontend->SuspendLateCallback = NULL;
    }
    // Free backend path before dropping store interface
    if (Frontend->BackendPath) {
        __FrontendFree(Frontend->BackendPath);
        Frontend->BackendPath = NULL;
    }

    // release interfaces
    SUSPEND(Release, Frontend->Suspend);
    Frontend->Suspend = NULL;
    
    GNTTAB(Release, Frontend->Gnttab);
    Frontend->Gnttab = NULL;
    
    EVTCHN(Release, Frontend->Evtchn);
    Frontend->Evtchn = NULL;
    
    STORE(Release, Frontend->Store);
    Frontend->Store = NULL;

    KeReleaseSpinLock(&Frontend->StateLock, Irql);
}

static DECLSPEC_NOINLINE NTSTATUS
__FrontendSetState(
    __in  PXENVBD_FRONTEND        Frontend,
    __in  XENVBD_STATE            State
    )
{
    NTSTATUS    Status;
    const ULONG TargetId = Frontend->TargetId;
    BOOLEAN     Failed = FALSE;

    Trace("Target[%d] @ (%d) =====>\n", TargetId, KeGetCurrentIrql());
    Verbose("Target[%d] : %s ----> %s\n", 
                TargetId, 
                __XenvbdStateName(Frontend->State), 
                __XenvbdStateName(State));
    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    while (!Failed && Frontend->State != State) {
        switch (Frontend->State) {
        case XENVBD_INITIALIZED:
            switch (State) {
            case XENVBD_CLOSED:
            case XENVBD_PREPARED:
            case XENVBD_CONNECTED:
            case XENVBD_ENABLED:
                Status = FrontendClose(Frontend);
                if (NT_SUCCESS(Status)) {
                    Frontend->State = XENVBD_CLOSED;
                } else {
                    Failed = TRUE;
                }
                break;
            default:
                Failed = TRUE;
                break;
            }
            break;

        case XENVBD_CLOSED:
            switch (State) {
            case XENVBD_PREPARED:
            case XENVBD_CONNECTED:
            case XENVBD_ENABLED:
                Status = FrontendPrepare(Frontend);
                if (NT_SUCCESS(Status)) {
                    Frontend->State = XENVBD_PREPARED;
                } else {
                    Status = FrontendClose(Frontend);
                    if (NT_SUCCESS(Status))
                        Frontend->State = XENVBD_CLOSED;
                    else
                        Frontend->State = XENVBD_STATE_INVALID;
                    Failed = TRUE;
                }
                break;
            default:
                Failed = TRUE;
                break;
            }
            break;

        case XENVBD_PREPARED:
            switch (State) {
            case XENVBD_CONNECTED:
            case XENVBD_ENABLED:
                Status = FrontendConnect(Frontend);
                if (NT_SUCCESS(Status)) {
                    Frontend->State = XENVBD_CONNECTED;
                } else {
                    Status = FrontendClose(Frontend);
                    if (NT_SUCCESS(Status))
                        Frontend->State = XENVBD_CLOSED;
                    else
                        Frontend->State = XENVBD_STATE_INVALID;
                    Failed = TRUE;
                }
                break;
            case XENVBD_CLOSED:
                Status = FrontendClose(Frontend);
                if (NT_SUCCESS(Status)) {
                    Frontend->State = XENVBD_CLOSED;
                } else {
                    Frontend->State = XENVBD_STATE_INVALID;
                    Failed = TRUE;
                }
                break;
            default:
                Failed = TRUE;
                break;
            }
            break;
            
        case XENVBD_CONNECTED:
            switch (State) {
            case XENVBD_ENABLED:
                FrontendEnable(Frontend);
                Frontend->State = XENVBD_ENABLED;
                break;
            case XENVBD_CLOSED:
            case XENVBD_PREPARED:
                Status = FrontendClose(Frontend);
                FrontendDisconnect(Frontend);
                if (NT_SUCCESS(Status)) {
                    Frontend->State = XENVBD_CLOSED;
                } else {
                    Frontend->State = XENVBD_STATE_INVALID;
                    Failed = TRUE;
                }
                break;
            default:
                Failed = TRUE;
                break;
            }
            break;

        case XENVBD_ENABLED:
            switch (State) {
            case XENVBD_CLOSED:
            case XENVBD_PREPARED:
            case XENVBD_CONNECTED:
                FrontendDisable(Frontend);
                Frontend->State = XENVBD_CONNECTED;
                break;
            default:
                Failed = TRUE;
                break;
            }
            break;

        default:
            Failed = TRUE;
            break;
        }
        Verbose("Target[%d] : in state %s\n", TargetId, __XenvbdStateName(Frontend->State));
    }
    Trace("Target[%d] @ (%d) <===== (%s)\n", TargetId, KeGetCurrentIrql(), Failed ? "FAILED" : "SUCCEEDED");
    return Failed ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}

__checkReturn
NTSTATUS
FrontendSetState(
    __in  PXENVBD_FRONTEND        Frontend,
    __in  XENVBD_STATE            State
    )
{
    NTSTATUS    Status;
    KIRQL       Irql;

    KeAcquireSpinLock(&Frontend->StateLock, &Irql);

    Status = __FrontendSetState(Frontend, State);

    KeReleaseSpinLock(&Frontend->StateLock, Irql);
    return Status;
}

__drv_requiresIRQL(DISPATCH_LEVEL)
VOID
FrontendBackendPathChanged(
    __in  PXENVBD_FRONTEND        Frontend
    )
{
    // Only attempt this if Active, Active is set/cleared on D3->D0/D0->D3
    if (Frontend->Active) {
        // Note: Nothing may have changed with this target, this could be caused by another target changing
        if (__ReadDiskInfo(Frontend)) {
            Verbose("Target[%d] : %lld sectors of %d bytes (%lld MB), Info %08x %s\n", Frontend->TargetId,
                        Frontend->DiskInfo.SectorCount, Frontend->DiskInfo.SectorSize,
                        (Frontend->DiskInfo.SectorSize * Frontend->DiskInfo.SectorCount) / (1024 * 1024),
                        Frontend->DiskInfo.DiskInfo, Frontend->Caps.SurpriseRemovable ? "SURPRISE_REMOVABLE" : "");
        }
        __CheckBackendForEject(Frontend);
    }
}

//=============================================================================
// Writing
__drv_maxIRQL(DISPATCH_LEVEL)
NTSTATUS
FrontendWriteUsage(
    __in  PXENVBD_FRONTEND        Frontend
    )
{
    NTSTATUS    Status;

    Status = STORE(Printf, Frontend->Store, NULL, Frontend->TargetPath, 
                        "paging", "%u", Frontend->Caps.Paging);
    if (!NT_SUCCESS(Status))
        goto out;

    Status = STORE(Printf, Frontend->Store, NULL, Frontend->TargetPath, 
                        "hibernation", "%u", Frontend->Caps.Hibernation);
    if (!NT_SUCCESS(Status))
        goto out;

    Status = STORE(Printf, Frontend->Store, NULL, Frontend->TargetPath, 
                        "dump", "%u", Frontend->Caps.DumpFile);
    if (!NT_SUCCESS(Status))
        goto out;

    Verbose("Target[%d] : %s %s %s\n", Frontend->TargetId,
                    Frontend->Caps.DumpFile ? "DUMP" : "NOT_DUMP", 
                    Frontend->Caps.Hibernation ? "HIBER" : "NOT_HIBER",
                    Frontend->Caps.Paging ? "PAGE" : "NOT_PAGE");

out:
    return Status;
}

//=============================================================================
// Debug
static DECLSPEC_NOINLINE VOID
FrontendDebugRequests(
    __in  blkif_sring_t*          SharedRing,
    __in  ULONG                   nr_ents,
    __in  PXENBUS_DEBUG_INTERFACE Debug,
    __in  PXENBUS_DEBUG_CALLBACK  Callback
    )
{
    union blkif_sring_entry*  Entry;
    blkif_request_discard_t*  Discard;
    PXENVBD_REQUEST     Request;
    PVOID               Srb;
    ULONG               Ptr;
    ULONG               Idx;
    ULONG               Start;
    ULONG               End;

    __try {
        // dump outstanding requests
        Start = SharedRing->req_event;
        End   = SharedRing->req_prod + 1;
        if (Start != End) {
            for (Ptr = Start; Ptr < End; ++Ptr) {
                Idx = __Idx(Ptr, nr_ents);
                Entry = &(SharedRing->ring[Idx]);

                switch (Entry->req.operation) {
                case BLKIF_OP_DISCARD:
                    Discard = (blkif_request_discard_t*)Entry;
                    Request = (PXENVBD_REQUEST)(ULONG_PTR)Discard->id;
                    Srb = Request ? Request->Srb : NULL;
                    DEBUG(Printf, Debug, Callback,
                          "FRONTEND: REQ [%-3d] { %02x, %02x, %04x, 0x%p, %lld, %lld } (0x%p)\n", 
                          Idx,  BLKIF_OP_DISCARD,  0, 
                          Discard->handle, (PVOID)(ULONG_PTR)Discard->id, 
                          Discard->sector_number,  Discard->nr_sectors,
                          Srb);
                    break;

                default:
                    Request = (PXENVBD_REQUEST)(ULONG_PTR)Entry->req.id;
                    Srb = Request ? Request->Srb : NULL;
                    DEBUG(Printf, Debug, Callback,
                          "FRONTEND: REQ [%-3d] { %02x, %02x, %04x, 0x%p, %lld, {...} } (0x%p)\n", 
                          Idx,  Entry->req.operation,  Entry->req.nr_segments, 
                          Entry->req.handle, (PVOID)(ULONG_PTR)Entry->req.id, 
                          Entry->req.sector_number, Srb);
                    break;
                }
            }
        }
#pragma warning(suppress: 6320)
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DEBUG(Printf, Debug, Callback, "FRONTEND: EXCEPTION\n");
    }
    
    __try {
        // dump outstanding responses
        Start = SharedRing->rsp_event - 1;
        End   = SharedRing->rsp_prod;
        if (Start != End) {
            for (Ptr = Start; Ptr < End; ++Ptr) {
                Idx = __Idx(Ptr, nr_ents);
                Entry = &(SharedRing->ring[Idx]);
                Request = (PXENVBD_REQUEST)(ULONG_PTR)Entry->rsp.id;
                Srb = Request ? Request->Srb : NULL;

                DEBUG(Printf, Debug, Callback,
                      "FRONTEND: RSP [%-3d] { 0x%p, %02x, %04x } (0x%p)\n", 
                      Idx,  (PVOID)(ULONG_PTR)Entry->rsp.id, 
                      Entry->rsp.operation,  Entry->rsp.status, Srb);
            }
        }
#pragma warning(suppress: 6320)
    } __except (EXCEPTION_EXECUTE_HANDLER) {
         DEBUG(Printf, Debug, Callback, "FRONTEND: EXCEPTION\n");
    }
}
VOID
FrontendDebugCallback(
    __in  PXENVBD_FRONTEND        Frontend,
    __in  PXENBUS_DEBUG_INTERFACE Debug,
    __in  PXENBUS_DEBUG_CALLBACK  Callback
    )
{
    ULONG   Index;
    ULONG   RingPages = (ULONG)(1 << Frontend->RingOrder);

    DEBUG(Printf, Debug, Callback,
            "FRONTEND: TargetId            : %d\n", 
            Frontend->TargetId);
    DEBUG(Printf, Debug, Callback,
            "FRONTEND: DeviceId            : %d\n", 
            Frontend->DeviceId);
    DEBUG(Printf, Debug, Callback,
            "FRONTEND: FrontendPath        : %s\n", 
            Frontend->FrontendPath);
    DEBUG(Printf, Debug, Callback,
            "FRONTEND: BackendPath         : %s\n", 
            Frontend->BackendPath ? Frontend->BackendPath : "NULL");
    DEBUG(Printf, Debug, Callback,
            "FRONTEND: TargetPath          : %s\n", 
            Frontend->TargetPath);
    DEBUG(Printf, Debug, Callback,
            "FRONTEND: BackendId           : %d\n", 
            Frontend->BackendId);
    DEBUG(Printf, Debug, Callback,
            "FRONTEND: State               : %s\n",
            __XenvbdStateName(Frontend->State));
    DEBUG(Printf, Debug, Callback,
            "FRONTEND: Events              : %d Events, %d DPCs\n",
            Frontend->NumEvents, Frontend->NumDpcs);
    DEBUG(Printf, Debug, Callback,
            "FRONTEND: Connected           : %s\n", 
            Frontend->Caps.Connected ? "TRUE" : "FALSE");
    DEBUG(Printf, Debug, Callback,
            "FRONTEND: Removable           : %s\n", 
            Frontend->Caps.Removable ? "TRUE" : "FALSE");
    DEBUG(Printf, Debug, Callback,
            "FRONTEND: SurpriseRemovable   : %s\n", 
            Frontend->Caps.SurpriseRemovable ? "TRUE" : "FALSE");
    DEBUG(Printf, Debug, Callback,
            "FRONTEND: FeatureBarrier      : %s\n", 
            Frontend->Features.Barrier ? "TRUE" : "FALSE");
    DEBUG(Printf, Debug, Callback,
            "FRONTEND: FeatureDiscard      : %s\n", 
            Frontend->Features.Discard ? "TRUE" : "FALSE");
    DEBUG(Printf, Debug, Callback,
            "FRONTEND: FeatureFlushCache   : %s\n",
            Frontend->Features.FlushCache ? "TRUE" : "FALSE");
    DEBUG(Printf, Debug, Callback,
            "FRONTEND: Paging              : %s\n", 
            Frontend->Caps.Paging ? "TRUE" : "FALSE");
    DEBUG(Printf, Debug, Callback,
            "FRONTEND: Hibernation         : %s\n", 
            Frontend->Caps.Hibernation ? "TRUE" : "FALSE");
    DEBUG(Printf, Debug, Callback,
            "FRONTEND: DumpFile            : %s\n", 
            Frontend->Caps.DumpFile ? "TRUE" : "FALSE");
    DEBUG(Printf, Debug, Callback,
            "FRONTEND: SectorSize          : %d\n", 
            Frontend->DiskInfo.SectorSize);
    DEBUG(Printf, Debug, Callback,
            "FRONTEND: SectorCount         : %lld\n", 
            Frontend->DiskInfo.SectorCount);
    DEBUG(Printf, Debug, Callback,
            "FRONTEND: DiskInfo            : %d\n", 
            Frontend->DiskInfo.DiskInfo);
    DEBUG(Printf, Debug, Callback,
            "FRONTEND: RequestsOutstanding : %d\n", 
            Frontend->RequestsOutstanding);
    DEBUG(Printf, Debug, Callback,
            "FRONTEND: RequestsSubmitted   : %d\n", 
            Frontend->RequestsSubmitted);
    DEBUG(Printf, Debug, Callback,
            "FRONTEND: ResponsesRecieved   : %d\n", 
            Frontend->ResponsesRecieved);
    DEBUG(Printf, Debug, Callback,
            "FRONTEND: SharedRing          : 0x%p\n", 
            Frontend->SharedRing);
    if (Frontend->SharedRing) {
        DEBUG(Printf, Debug, Callback,
                "FRONTEND: SharedRing.req_prod : %d (%d)\n", 
                Frontend->SharedRing->req_prod, 
                __Idx(Frontend->SharedRing->req_prod, 
                Frontend->FrontRing.nr_ents));
        DEBUG(Printf, Debug, Callback,
                "FRONTEND: SharedRing.req_event: %d (%d)\n", 
                Frontend->SharedRing->req_event, 
                __Idx(Frontend->SharedRing->req_event, 
                Frontend->FrontRing.nr_ents));
        DEBUG(Printf, Debug, Callback,
                "FRONTEND: SharedRing.rsp_prod : %d (%d)\n", 
                Frontend->SharedRing->rsp_prod, 
                __Idx(Frontend->SharedRing->rsp_prod, 
                Frontend->FrontRing.nr_ents));
        DEBUG(Printf, Debug, Callback,
                "FRONTEND: SharedRing.rsp_event: %d (%d)\n", 
                Frontend->SharedRing->rsp_event, 
                __Idx(Frontend->SharedRing->rsp_event, 
                Frontend->FrontRing.nr_ents));
        FrontendDebugRequests(Frontend->SharedRing, Frontend->FrontRing.nr_ents, Debug, Callback);
    }
    DEBUG(Printf, Debug, Callback,
            "FRONTEND: FrontRing.req_prod  : %d (%d)\n", 
            Frontend->FrontRing.req_prod_pvt, 
            __Idx(Frontend->FrontRing.req_prod_pvt, 
            Frontend->FrontRing.nr_ents));
    DEBUG(Printf, Debug, Callback,
            "FRONTEND: FrontRing.rsp_cons  : %d (%d)\n", 
            Frontend->FrontRing.rsp_cons, 
            __Idx(Frontend->FrontRing.rsp_cons, 
            Frontend->FrontRing.nr_ents));
    DEBUG(Printf, Debug, Callback,
            "FRONTEND: FrontRing.nr_ents   : %d\n", 
            Frontend->FrontRing.nr_ents);
    DEBUG(Printf, Debug, Callback,
            "FRONTEND: RingOrder           : %d (%d pages)\n", 
            Frontend->RingOrder,
            RingPages);
    for (Index = 0; Index < RingPages; ++Index) {
        DEBUG(Printf, Debug, Callback,
                "FRONTEND: RingGrantRef[%-2d]    : %d\n", 
                Index, Frontend->RingGrantRefs[Index]);
    }
    if (Frontend->EvtchnPort) {
        DEBUG(Printf, Debug, Callback,
                "FRONTEND: EvtchnPort          : %p (%d)\n", 
                Frontend->EvtchnPort, Frontend->EvtchnPortNumber);
    } else {
        DEBUG(Printf, Debug, Callback,
                "FRONTEND: EvtchnPort          : NULL\n");
    }

    Frontend->NumEvents = 0;
    Frontend->NumDpcs = 0;
    Frontend->RequestsSubmitted = 0;
    Frontend->ResponsesRecieved = 0;
}

