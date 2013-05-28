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

#include "austere.h"
#include "store.h"
#include "evtchn.h"
#include "gnttab.h"

#include "log.h"
#include "assert.h"
#include "util.h"

#include <stdlib.h>

#define XEN_IO_PROTO_ABI_NATIVE     "x86_32-abi"

#define DOMID_INVALID (0x7FF4U)
// States in XenStore (Note - numbers must match!)
typedef enum _XENBUS_STATE {
    XENBUS_STATE_INVALID = 0,   // 0
    XENBUS_STATE_INITIALIZING,  // 1
    XENBUS_STATE_INITWAIT,      // 2
    XENBUS_STATE_INITIALIZED,   // 3
    XENBUS_STATE_CONNECTED,     // 4
    XENBUS_STATE_CLOSING,       // 5
    XENBUS_STATE_CLOSED         // 6
} XENBUS_STATE, *PXENBUS_STATE;

static FORCEINLINE const PCHAR
__XenbusStateName(
    IN  XENBUS_STATE                        State
    )
{
    switch (State) {
    case XENBUS_STATE_INVALID:      return "INVALID";
    case XENBUS_STATE_INITIALIZING: return "INITIALIZING";
    case XENBUS_STATE_INITWAIT:     return "INITWAIT";
    case XENBUS_STATE_INITIALIZED:  return "INITIALIZED";
    case XENBUS_STATE_CONNECTED:    return "CONNECTED";
    case XENBUS_STATE_CLOSING:      return "CLOSING";
    case XENBUS_STATE_CLOSED:       return "CLOSED";
    default:                        return "UNKNOWN";
    }
}
static FORCEINLINE const PCHAR
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
static FORCEINLINE PVOID
__FrontendAlloc(
    IN  ULONG                   Size
    )
{
    return AustereAllocate(Size);
}
static FORCEINLINE VOID
__FrontendFree(
    IN  PVOID                   Buffer
    )
{
    AustereFree(Buffer);
}

//=============================================================================
static FORCEINLINE VOID
__MemoryBarrier()
{
    KeMemoryBarrier();
    _ReadWriteBarrier();
}
static FORCEINLINE VOID
__WriteMemoryBarrier()
{
    KeMemoryBarrier();
    _WriteBarrier();
}
static FORCEINLINE BOOLEAN
__HasUnconsumedResponses(
    IN  PXENVBD_FRONTEND        Frontend
    )
{
    return (Frontend->SharedRing->rsp_prod - Frontend->FrontRing.rsp_cons) > 0;
}
static FORCEINLINE BOOLEAN
__FinalCheckForResponses(
    IN  PXENVBD_FRONTEND        Frontend
    )
{
    if (__HasUnconsumedResponses(Frontend))
        return TRUE;

    Frontend->SharedRing->rsp_event = Frontend->FrontRing.rsp_cons + 1;
    
    __MemoryBarrier();
    
    return __HasUnconsumedResponses(Frontend);
}
static FORCEINLINE BOOLEAN
__IsValidStatus(
    IN  SHORT                   Status
    )
{
    if (Status == BLKIF_RSP_OKAY ||
        Status == BLKIF_RSP_ERROR ||
        Status == BLKIF_RSP_EOPNOTSUPP)
        return TRUE;
    return FALSE;
}
static FORCEINLINE ULONG
__Idx(
    IN  ULONG   Index,
    IN  ULONG   nr_ents
    )
{
    return Index & (nr_ents - 1);
}
static FORCEINLINE VOID
FrontendCompleteResponses(
    IN  PXENVBD_FRONTEND        Frontend
    )
{
    for (;;) {
        ULONG   rsp_prod;
        ULONG   rsp_cons;

        rsp_prod = Frontend->SharedRing->rsp_prod;
        rsp_cons = Frontend->FrontRing.rsp_cons;

        __MemoryBarrier();

        while (rsp_cons != rsp_prod) {
            blkif_response_t*   Response;
            PXENVBD_REQUEST     Request;
            SHORT               Status;

            Response = RING_GET_RESPONSE(&Frontend->FrontRing, rsp_cons);
            Status = Response->status;
            Request = (PXENVBD_REQUEST)(ULONG_PTR)(Response->id);

            ++rsp_cons;

            if (Request) {
                PdoCompleteSubmittedRequest(Frontend->Pdo, Request, Status);
            }

            // zero request slot now its read
            RtlZeroMemory(Response, sizeof(blkif_response_t));
        }

        Frontend->FrontRing.rsp_cons = rsp_cons;

        __MemoryBarrier();

        if (!__FinalCheckForResponses(Frontend))
            break;
    }
}

VOID
FrontendEvtchnCallback(
    IN  PXENVBD_FRONTEND        Frontend
    )
{
    // complete responses
    FrontendCompleteResponses(Frontend);

    // prepare fresh srbs
    PdoPrepareFresh(Frontend->Pdo);
    
    // submit prepared srbs
    PdoSubmitPrepared(Frontend->Pdo);
    
    // possibly complete shutdown srbs
    PdoCompleteShutdown(Frontend->Pdo);
}
//=============================================================================
// Ring Slots
BOOLEAN
FrontendCanSubmitRequest(
    IN  PXENVBD_FRONTEND        Frontend,
    IN  ULONG                   NumRequests
    )
{
    // RING_PROD_SLOTS_AVAIL(...)
    ULONG   Available = Frontend->FrontRing.nr_ents - (Frontend->FrontRing.req_prod_pvt - Frontend->FrontRing.rsp_cons);
    if (Available > NumRequests)
        return TRUE;
    return FALSE;
}

VOID
FrontendInsertRequestOnRing(
    IN  PXENVBD_FRONTEND        Frontend,
    IN  PXENVBD_REQUEST         Request
    )
{
    ULONG               Index;
    blkif_request_t*    RingReq;
    //blkif_request_discard_t*    Discard;

    RingReq = RING_GET_REQUEST(&Frontend->FrontRing, Frontend->FrontRing.req_prod_pvt);
    Frontend->FrontRing.req_prod_pvt++;

    switch (Request->Operation) {
    //case BLKIF_OP_DISCARD:
    //    Discard = (blkif_request_discard_t*)Request;
    //    Discard->operation       = BLKIF_OP_DISCARD;
    //    Discard->handle          = (USHORT)Frontend->DeviceId;
    //    Discard->id              = (ULONG64)Request;
    //    Discard->sector_number   = Request->FirstSector;
    //    Discard->nr_sectors      = Request->NrSectors;
    //    break;
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

VOID
FrontendPushRequestAndCheckNotify(
    IN  PXENVBD_FRONTEND        Frontend
    )
{
    // RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(..)
    ULONG       __old;
    ULONG       __new;
    
    __old = Frontend->SharedRing->req_prod;
    __new = Frontend->FrontRing.req_prod_pvt;

    __WriteMemoryBarrier();
    
    Frontend->SharedRing->req_prod = __new;
    
    __MemoryBarrier();
    
    if ((__new - Frontend->SharedRing->req_event) < (__new - __old)) {
        EventChannelSend(Frontend->EvtchnPort);
    }
}

//=============================================================================
extern PHYSICAL_ADDRESS MmGetPhysicalAddress(IN PVOID Buffer);
static FORCEINLINE PFN_NUMBER
__VirtToPfn(
    IN  PVOID                   VirtAddr
    )
{
    PHYSICAL_ADDRESS PhysAddr = MmGetPhysicalAddress(VirtAddr);
    return (PFN_NUMBER)(ULONG_PTR)(PhysAddr.QuadPart >> 12);
}
//=============================================================================
static FORCEINLINE ULONG
__Min(
    IN  ULONG                   A,
    IN  ULONG                   B
    )
{
    if (A < B)  return A;
    else        return B;
}
static FORCEINLINE NTSTATUS
__UpdateBackendPath(
    IN  PXENVBD_FRONTEND        Frontend
    )
{
    NTSTATUS    Status;
    PCHAR       Path;

    if (Frontend->BackendPath) {
        LogTrace("<< %s\n", Frontend->BackendPath);
        AustereFree(Frontend->BackendPath);
        Frontend->BackendPath = NULL;
    }

    Status = StoreRead(NULL, Frontend->FrontendPath, 
                        "backend-id", &Path);
    if (NT_SUCCESS(Status)) {
        Frontend->BackendId = (USHORT)strtoul(Path, NULL, 10);
        AustereFree(Path);
    } else {
        Frontend->BackendId = 0;
    }

    Status = StoreRead(NULL, Frontend->FrontendPath, 
                    "backend", &Path);
    if (NT_SUCCESS(Status)) {
        LogTrace(">> %s\n", Path);
        Frontend->BackendPath = Path;
    }
    
    return Status;
}
static FORCEINLINE NTSTATUS
__ReadState(
    IN  PXENVBD_FRONTEND        Frontend,
    IN  PCHAR                   Path,
    OUT PXENBUS_STATE           State
    )
{
    NTSTATUS        Status;
    PCHAR           Buffer;

    UNREFERENCED_PARAMETER(Frontend);

    Status = StoreRead(NULL, Path, 
                    "state", &Buffer);
    if (!NT_SUCCESS(Status))
        goto fail;
    *State = (XENBUS_STATE)strtoul(Buffer, NULL, 10);
    AustereFree(Buffer);

    return STATUS_SUCCESS;

fail:
    *State = XENBUS_STATE_INVALID;
    return Status;
}
static FORCEINLINE NTSTATUS
__PollState(
    IN  PXENVBD_FRONTEND        Frontend,
    IN OUT PXENBUS_STATE        State
    )
{
    NTSTATUS        Status;
    XENBUS_STATE    OldState = *State;

    while (OldState == *State) {
        Status = __ReadState(Frontend, Frontend->BackendPath, State);
        if (!NT_SUCCESS(Status))
            goto fail;

        if (*State == OldState)
            KeStallExecutionProcessor(100000);
    }

    LogTrace("Target[%d] : BACKEND_STATE  -> %s\n", Frontend->TargetId, __XenbusStateName(*State));
    return STATUS_SUCCESS;

fail:
    return Status;
}
static NTSTATUS
__WaitState(
    IN  PXENVBD_FRONTEND        Frontend,
    IN OUT PXENBUS_STATE        State
    )
{
    return __PollState(Frontend, State);
}
static FORCEINLINE NTSTATUS
___SetState(
    IN  PXENVBD_FRONTEND        Frontend,
    IN  XENBUS_STATE            State
    )
{
    NTSTATUS    Status;

    Status = StorePrintf(NULL, Frontend->FrontendPath,
                    "state", "%u", State);
    if (NT_SUCCESS(Status)) {
        LogTrace("Target[%d] : FRONTEND_STATE -> %s\n", Frontend->TargetId, __XenbusStateName(State));
    }

    return Status;
}
static FORCEINLINE NTSTATUS
__WriteTargetPath(
    IN  PXENVBD_FRONTEND        Frontend
    )
{
    NTSTATUS    Status;

    Status = StorePrintf(NULL, Frontend->TargetPath, 
                        "frontend", "%s", Frontend->FrontendPath);
    if (!NT_SUCCESS(Status))
        goto out;

    Status = StorePrintf(NULL, Frontend->TargetPath, 
                        "device", "%u", Frontend->DeviceId);
    if (!NT_SUCCESS(Status))
        goto out;

    Status = StorePrintf(NULL, Frontend->TargetPath, 
                        "filter", "absent");
    if (!NT_SUCCESS(Status))
        goto out;

out:
    return Status;
}
static VOID
__ReadFeatures(
    IN  PXENVBD_FRONTEND        Frontend
    )
{
    NTSTATUS    Status;
    PCHAR       Buffer;

    Status = StoreRead(NULL, Frontend->BackendPath, 
                        "removable", &Buffer);
    if (NT_SUCCESS(Status)) {
        Frontend->Removable = (strtoul(Buffer, NULL, 10) == 1);
        AustereFree(Buffer);
    }

    Status = StoreRead(NULL, Frontend->BackendPath,
                        "feature-barrier", &Buffer);
    if (NT_SUCCESS(Status)) {
        Frontend->FeatureBarrier = (strtoul(Buffer, NULL, 10) == 1);
        AustereFree(Buffer);
    } else {
        Frontend->FeatureBarrier = FALSE;
    }

    Status = StoreRead(NULL, Frontend->BackendPath,
                        "feature-discard", &Buffer);
    if (NT_SUCCESS(Status)) {
        Frontend->FeatureDiscard = (strtoul(Buffer, NULL, 10) == 1);
        AustereFree(Buffer);
    } else {
        Frontend->FeatureDiscard = FALSE;
    }

    LogVerbose("Features: DomId=%d, RingOrder=0, %s %s %s\n", 
                Frontend->BackendId,
                Frontend->Removable ? "REMOVABLE" : "NOT_REMOVABLE",
                Frontend->FeatureBarrier ? "BARRIER" : "NOT_BARRIER",
                Frontend->FeatureDiscard ? "DISCARD" : "NOT_DISCARD");
}
static VOID
__ReadDiskInfo(
    IN  PXENVBD_FRONTEND        Frontend
    )
{
    NTSTATUS    Status;
    PCHAR       Buffer;
    BOOLEAN     Updated = FALSE;

    Status = StoreRead(NULL, Frontend->BackendPath, 
                        "info", &Buffer);
    if (NT_SUCCESS(Status)) {
        Frontend->DiskInfo = strtoul(Buffer, NULL, 10);
        AustereFree(Buffer);
        Updated = TRUE;
    }

    Status = StoreRead(NULL, Frontend->BackendPath, 
                        "sector-size", &Buffer);
    if (NT_SUCCESS(Status)) {
        Frontend->SectorSize = strtoul(Buffer, NULL, 10);
        AustereFree(Buffer);
        Updated = TRUE;
    }

    Status = StoreRead(NULL, Frontend->BackendPath, 
                        "sectors", &Buffer);
    if (NT_SUCCESS(Status)) {
        Frontend->SectorCount = _strtoui64(Buffer, NULL, 10);
        AustereFree(Buffer);
        Updated = TRUE;
    }

    if (Frontend->SectorCount == 0) {
        LogError("Invalid SectorCount!\n");
    }
    if (Frontend->SectorSize == 0) {
        LogError("Invalid SectorSize!\n");
    }
    if (Updated) {
        LogVerbose("DiskInfo: %08x, %lld sectors of %d bytes (%lld KB or %lld MB)\n", 
                    Frontend->DiskInfo, Frontend->SectorCount, Frontend->SectorSize, 
                    (Frontend->SectorSize * Frontend->SectorCount) / 1024,
                    (Frontend->SectorSize * Frontend->SectorCount) / (1024 * 1024));
    }
    if (Frontend->DiskInfo & VDISK_READONLY) {
        LogWarning("DiskInfo contains VDISK_READONLY flag!\n");
    }
    if (Frontend->DiskInfo & VDISK_CDROM) {
        LogWarning("DiskInfo contains VDISK_CDROM flag!\n");
    }
}
static FORCEINLINE NTSTATUS
__AllocRing(
    IN  PXENVBD_FRONTEND        Frontend
    )
{
    NTSTATUS    Status;
    ULONG       RingRef;
    PFN_NUMBER  Pfn;

    // SharedRing
    ASSERT3P(Frontend->SharedRing, ==, NULL);
    Frontend->SharedRing = __FrontendAlloc(PAGE_SIZE);
    Status = STATUS_INSUFFICIENT_RESOURCES;
    if (!Frontend->SharedRing)
        goto fail1;

#pragma warning(push)
#pragma warning(disable: 4305)
    SHARED_RING_INIT(Frontend->SharedRing);
    FRONT_RING_INIT(&Frontend->FrontRing, Frontend->SharedRing, PAGE_SIZE);
#pragma warning (pop)

    // GNTTAB
    Pfn = __VirtToPfn(Frontend->SharedRing);

    Status = GnttabGet(&RingRef);
    if (!NT_SUCCESS(Status))
        goto fail2;

    GnttabPermitForeignAccess(RingRef, Frontend->BackendId, Pfn, FALSE);

    Frontend->RingGrantRef = RingRef;

    // EVTCHN
    Status = EventChannelAllocate(Frontend->BackendId, &Frontend->EvtchnPort);
    if (!NT_SUCCESS(Status))
        goto fail3;

    return STATUS_SUCCESS;

fail3:
    LogError("Fail3\n");
    if (Frontend->RingGrantRef != 0) {
        GnttabRevokeForeignAccess(Frontend->RingGrantRef);
        GnttabPut(Frontend->RingGrantRef);
        Frontend->RingGrantRef = 0;
    }

fail2:
    LogError("Fail2\n");
    RtlZeroMemory(&Frontend->FrontRing, sizeof(Frontend->FrontRing));
    __FrontendFree(Frontend->SharedRing);
    Frontend->SharedRing = NULL;

fail1:
    LogError("Fail1 (%08x)\n", Status);
    return Status;
}
static FORCEINLINE VOID
__FreeRing(
    IN  PXENVBD_FRONTEND        Frontend
    )
{
    // EVTCHN
    if (Frontend->EvtchnPort) {
        EventChannelClose(Frontend->EvtchnPort);
        Frontend->EvtchnPort = 0;
    }

    // GNTTAB
    if (Frontend->RingGrantRef != 0) {
        GnttabRevokeForeignAccess(Frontend->RingGrantRef);
        GnttabPut(Frontend->RingGrantRef);
        Frontend->RingGrantRef = 0;
    }

    // SharedRing
    RtlZeroMemory(&Frontend->FrontRing, sizeof(Frontend->FrontRing));
    if (Frontend->SharedRing) {
        __FrontendFree(Frontend->SharedRing);
        Frontend->SharedRing = NULL;
    }
}
static NTSTATUS
__WriteRing(
    IN  PXENVBD_FRONTEND        Frontend
    )
{
    NTSTATUS    Status;
    
    for (;;) {
        PVOID                       Transaction;

        Status = StoreTransactionStart(&Transaction);
        if (!NT_SUCCESS(Status))
            break;

        Status = StorePrintf(Transaction, Frontend->FrontendPath, 
                        "event-channel", "%u", Frontend->EvtchnPort);
        if (!NT_SUCCESS(Status))
            goto abort;

        Status = StorePrintf(Transaction, Frontend->FrontendPath,
                        "ring-ref", "%u", Frontend->RingGrantRef);
        if (!NT_SUCCESS(Status))
            goto abort;

        Status = StoreWrite(Transaction, Frontend->FrontendPath,
                        "protocol", "x86_32-abi");
        if (!NT_SUCCESS(Status))
            goto abort;

        Status = StoreWrite(Transaction, Frontend->FrontendPath,
                        "feature-surprise-remove", "1");
        if (!NT_SUCCESS(Status))
            goto abort;

        Status = StoreWrite(Transaction, Frontend->FrontendPath,
                        "feature-online-resize", "1");
        if (!NT_SUCCESS(Status))
            goto abort;

        Status = StoreTransactionEnd(Transaction, TRUE);
        if (Status == STATUS_RETRY)
            continue;

        return Status;

abort:
        (VOID) StoreTransactionEnd(Transaction, FALSE);
        break;
    }

    return Status;
}
//=============================================================================
static NTSTATUS
FrontendClose(
    IN  PXENVBD_FRONTEND        Frontend
    )
{
    NTSTATUS        Status;
    XENBUS_STATE    BackendState;

    // get/update backend path
    Status = __UpdateBackendPath(Frontend);
    if (!NT_SUCCESS(Status))
        goto fail1;

    // free inquiry data
    if (Frontend->Inquiry) {
        PdoFreeInquiryData(Frontend->Inquiry);
        Frontend->Inquiry = NULL;
    }

    // Backend : -> !INITIALIZING)
    BackendState = XENBUS_STATE_INVALID;
    do {
        Status = __WaitState(Frontend, &BackendState);
        if (!NT_SUCCESS(Status))
            goto fail2;
    } while (BackendState == XENBUS_STATE_INITIALIZING);

    // Frontend: -> CLOSING 
    // Backend : -> CLOSING 
    while (BackendState != XENBUS_STATE_CLOSING &&
           BackendState != XENBUS_STATE_CLOSED) {
        Status = ___SetState(Frontend, XENBUS_STATE_CLOSING);
        if (!NT_SUCCESS(Status))
            goto fail3;
        Status = __WaitState(Frontend, &BackendState);
        if (!NT_SUCCESS(Status))
            goto fail4;
    }

    // Frontend: -> CLOSED
    // Backend : -> CLOSED
    while (BackendState != XENBUS_STATE_CLOSED) {
        Status = ___SetState(Frontend, XENBUS_STATE_CLOSED);
        if (!NT_SUCCESS(Status))
            goto fail5;
        Status = __WaitState(Frontend, &BackendState);
        if (!NT_SUCCESS(Status))
            goto fail6;
    }

    return STATUS_SUCCESS;

fail6:
    LogError("Fail6\n");
fail5:
    LogError("Fail5\n");
fail4:
    LogError("Fail4\n");
fail3:
    LogError("Fail3\n");
fail2:
    LogError("Fail2\n");
fail1:
    LogError("Fail1 (%08x)\n", Status);
    return Status;
}
static NTSTATUS
FrontendPrepare(
    IN  PXENVBD_FRONTEND        Frontend
    )
{
    NTSTATUS        Status;
    XENBUS_STATE    BackendState;

    // ASSERT(Backend : CLOSED)
    //__AssertBackendState(Frontend, XENBUS_STATE_CLOSED);

    // write targetpath
    Status = __WriteTargetPath(Frontend);
    if (!NT_SUCCESS(Status))
        goto fail1;

    // Frontend: -> INITIALIZING
    Status = ___SetState(Frontend, XENBUS_STATE_INITIALIZING);
    if (!NT_SUCCESS(Status))
        goto fail2;

    // Backend : -> INITWAIT
    BackendState = XENBUS_STATE_INVALID;
    do {
        Status = __WaitState(Frontend, &BackendState);
        if (!NT_SUCCESS(Status))
            goto fail3;
    } while (BackendState == XENBUS_STATE_CLOSED || 
             BackendState == XENBUS_STATE_INITIALIZING);
    Status = STATUS_UNSUCCESSFUL;
    if (BackendState != XENBUS_STATE_INITWAIT)
        goto fail4;

    // read inquiry data
    PdoReadInquiryData(Frontend, &Frontend->Inquiry);

    // read features and caps (removable, ring-order, ...)
    __ReadFeatures(Frontend);
    
    return STATUS_SUCCESS;

fail4:
    LogError("Fail4\n");
fail3:
    LogError("Fail3\n");
fail2:
    LogError("Fail2\n");
fail1:
    LogError("Fail1 (%08x)\n", Status);
    return Status;
}
static NTSTATUS
FrontendConnect(
    IN  PXENVBD_FRONTEND        Frontend
    )
{
    NTSTATUS        Status;
    XENBUS_STATE    BackendState;

    // ASSERT(Backend: INITWAIT)
    //__AssertBackendState(Frontend, XENBUS_STATE_INITWAIT);

    // Alloc Ring, Create Evtchn, Gnttab map
    Status = __AllocRing(Frontend);
    if (!NT_SUCCESS(Status))
        goto fail1;

    // write evtchn/gnttab details in xenstore
    Status = __WriteRing(Frontend);
    if (!NT_SUCCESS(Status))
        goto fail2;

    // Frontend: -> INITIALIZED
    Status = ___SetState(Frontend, XENBUS_STATE_INITIALIZED);
    if (!NT_SUCCESS(Status))
        goto fail3;

    // Backend : -> CONNECTED
    BackendState = XENBUS_STATE_INVALID;
    do {
        Status = __WaitState(Frontend, &BackendState);
        if (!NT_SUCCESS(Status))
            goto fail4;
    } while (BackendState == XENBUS_STATE_INITWAIT ||
             BackendState == XENBUS_STATE_INITIALIZING ||
             BackendState == XENBUS_STATE_INITIALIZED);
    Status = STATUS_UNSUCCESSFUL;
    if (BackendState != XENBUS_STATE_CONNECTED)
        goto fail5;

    // Frontend: -> CONNECTED
    Status = ___SetState(Frontend, XENBUS_STATE_CONNECTED);
    if (!NT_SUCCESS(Status))
        goto fail6;

    // read disk info
    __ReadDiskInfo(Frontend);
    
    return STATUS_SUCCESS;

fail6:
    LogError("Fail6\n");
fail5:
    LogError("Fail5\n");
fail4:
    LogError("Fail4\n");
fail3:
    LogError("Fail3\n");
fail2:
    LogError("Fail2\n");
    __FreeRing(Frontend);
fail1:
    LogError("Fail1 (%08x)\n", Status);
    return Status;
}
static FORCEINLINE VOID
FrontendDisconnect(
    IN  PXENVBD_FRONTEND        Frontend
    )
{
    // Free Ring, Close Evtchn, Gnttab unmap
    __FreeRing(Frontend);
}
static FORCEINLINE VOID
FrontendEnable(
    IN  PXENVBD_FRONTEND        Frontend
    )
{
    Frontend->Connected = TRUE;
}
static FORCEINLINE VOID
FrontendDisable(
    IN  PXENVBD_FRONTEND        Frontend
    )
{
    Frontend->Connected = FALSE;
}
//=============================================================================
// Init/Term
NTSTATUS
FrontendCreate(
    IN  PXENVBD_FRONTEND        Frontend,
    IN  PCHAR                   DeviceId, 
    IN  ULONG                   TargetId, 
    IN  PXENVBD_PDO             Pdo
    )
{
    LogTrace("Target[%d] @ (%d) =====>\n", TargetId, KeGetCurrentIrql());

    // populate members
    Frontend->Pdo = Pdo;
    Frontend->TargetId = TargetId;
    Frontend->DeviceId = strtoul(DeviceId, NULL, 10);
    Frontend->State = XENVBD_INITIALIZED;
    Frontend->SectorSize = 512; // default value

    Frontend->FrontendPath = DriverFormat("device/vbd/%s", DeviceId);
    if (Frontend->FrontendPath == NULL)
        goto fail1;

    Frontend->TargetPath = DriverFormat("data/scsi/target/%d", TargetId);
    if (Frontend->TargetPath == NULL)
        goto fail2;

    LogTrace("Target[%d] @ (%d) <===== (STATUS_SUCCESS)\n", Frontend->TargetId, KeGetCurrentIrql());
    return STATUS_SUCCESS;

fail2:
    LogError("fail2\n");
    AustereFree(Frontend->FrontendPath);

fail1:
    LogError("fail1 (%08x)\n", STATUS_INSUFFICIENT_RESOURCES);
    return STATUS_INSUFFICIENT_RESOURCES;
}

VOID
FrontendDestroy(
    IN  PXENVBD_FRONTEND        Frontend
    )
{
    const ULONG TargetId = Frontend->TargetId;

    LogTrace("Target[%d] @ (%d) =====>\n", TargetId, KeGetCurrentIrql());

    ASSERT3U(Frontend->RingGrantRef, ==, 0);
    ASSERT3P(Frontend->EvtchnPort, ==, 0);

    // free memory
    if (Frontend->FrontendPath) {
        AustereFree(Frontend->FrontendPath);
        Frontend->FrontendPath = NULL;
    }
    if (Frontend->TargetPath) {
        AustereFree(Frontend->TargetPath);
        Frontend->TargetPath = NULL;
    }
    if (Frontend->BackendPath) {
        AustereFree(Frontend->BackendPath);
        Frontend->BackendPath = NULL;
    }

    LogTrace("Target[%d] @ (%d) <=====\n", TargetId, KeGetCurrentIrql());
}

NTSTATUS
FrontendSetState(
    IN  PXENVBD_FRONTEND        Frontend,
    IN  XENVBD_STATE            State
    )
{
    NTSTATUS    Status;
    const ULONG TargetId = Frontend->TargetId;
    BOOLEAN     Failed = FALSE;

    LogTrace("Target[%d] @ (%d) =====>\n", TargetId, KeGetCurrentIrql());
    LogVerbose("Target[%d] : %s ----> %s\n", TargetId, __XenvbdStateName(Frontend->State), 
                                        __XenvbdStateName(State));

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
                FrontendDisconnect(Frontend);
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
        LogVerbose("Target[%d] : in state %s\n", TargetId, __XenvbdStateName(Frontend->State));
    }
    LogTrace("Target[%d] @ (%d) <===== (%s)\n", TargetId, KeGetCurrentIrql(), Failed ? "FAILED" : "SUCCEEDED");
    return Failed ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}

static FORCEINLINE NTSTATUS
__WaitState2(
    IN  PCHAR                   BackendPath,
    IN OUT PXENBUS_STATE        State
    )
{
    NTSTATUS        Status;
    PCHAR           Buffer;
    XENBUS_STATE    OldState = *State;

    while (OldState == *State) {
        Status = StoreRead(NULL, BackendPath, "state", &Buffer);
        if (!NT_SUCCESS(Status))
            goto fail;
        *State = (XENBUS_STATE)strtoul(Buffer, NULL, 10);
        AustereFree(Buffer);

        if (*State == OldState)
            KeStallExecutionProcessor(100000);
    }

    LogTrace("BACKEND_STATE  -> %s\n", __XenbusStateName(*State));
    return STATUS_SUCCESS;

fail:
    return Status;
}
static FORCEINLINE NTSTATUS
___SetState2(
    IN  PCHAR                   FrontendPath,
    IN  XENBUS_STATE            State
    )
{
    NTSTATUS    Status;

    Status = StorePrintf(NULL, FrontendPath,
                    "state", "%u", State);
    if (NT_SUCCESS(Status)) {
        LogTrace("FRONTEND_STATE -> %s\n", __XenbusStateName(State));
    }

    return Status;
}
NTSTATUS
FrontendCloseTarget(
    IN  PCHAR                   FrontendPath,
    IN  PCHAR                   BackendPath
    )
{
    NTSTATUS        Status;
    XENBUS_STATE    BackendState;

    // Backend : -> !INITIALIZING)
    BackendState = XENBUS_STATE_INVALID;
    do {
        Status = __WaitState2(BackendPath, &BackendState);
        if (!NT_SUCCESS(Status))
            goto fail1;
    } while (BackendState == XENBUS_STATE_INITIALIZING);

    // Frontend: -> CLOSING 
    // Backend : -> CLOSING 
    while (BackendState != XENBUS_STATE_CLOSING &&
           BackendState != XENBUS_STATE_CLOSED) {
        Status = ___SetState2(FrontendPath, XENBUS_STATE_CLOSING);
        if (!NT_SUCCESS(Status))
            goto fail2;
        Status = __WaitState2(BackendPath, &BackendState);
        if (!NT_SUCCESS(Status))
            goto fail3;
    }

    // Frontend: -> CLOSED
    // Backend : -> CLOSED
    while (BackendState != XENBUS_STATE_CLOSED) {
        Status = ___SetState2(FrontendPath, XENBUS_STATE_CLOSED);
        if (!NT_SUCCESS(Status))
            goto fail4;
        Status = __WaitState2(BackendPath, &BackendState);
        if (!NT_SUCCESS(Status))
            goto fail5;
    }

    return STATUS_SUCCESS;

fail5:
    LogError("Fail5\n");
fail4:
    LogError("Fail4\n");
fail3:
    LogError("Fail3\n");
fail2:
    LogError("Fail2\n");
fail1:
    LogError("Fail1 (%08x)\n", Status);
    return Status;
}


