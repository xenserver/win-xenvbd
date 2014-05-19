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

#include "pdo.h"

#include "driver.h"
#include "fdo.h"
#include "frontend.h"
#include "queue.h"
#include "ring.h"
#include "srbext.h"
#include "buffer.h"
#include "pdoinquiry.h"

#include "austere.h"
#include "store.h"
#include "gnttab.h"
#include "evtchn.h"

#include <xencdb.h>
#include "log.h"
#include "assert.h"
#include "util.h"

typedef struct _XENVBD_SG_INDEX {
    ULONG       Index;
    ULONG       Offset;
    ULONG       LastLength;
} XENVBD_SG_INDEX, *PXENVBD_SG_INDEX;

struct _XENVBD_PDO {
    PXENVBD_FDO                 Fdo;
    LONG                        ReferenceCount;

    // Frontend (Ring, includes XenBus interfaces)
    XENVBD_FRONTEND             Frontend;

    // State
    BOOLEAN                     NeedsWake;

    // SRBs
    SRB_QUEUE                   FreshSrbs;
    SRB_QUEUE                   PreparedSrbs;
    SRB_QUEUE                   SubmittedSrbs;
    SRB_QUEUE                   ShutdownSrbs;

    // Stats
    ULONG                       Reads;
    ULONG                       Writes;
    ULONG                       Others;
};

//=============================================================================
static FORCEINLINE PVOID
__PdoAlloc(
    IN  ULONG                   Size
    )
{
    return AustereAllocate(Size);
}
static FORCEINLINE VOID
__PdoFree(
    IN  PVOID                   Buffer
    )
{
    AustereFree(Buffer);
}

//=============================================================================
// Creation/Deletion
NTSTATUS
PdoCreate(
    IN  PXENVBD_FDO             Fdo,
    IN  PCHAR                   DeviceId,
    IN  ULONG                   TargetId,
    OUT PXENVBD_PDO*            _Pdo
    )
{
    PXENVBD_PDO         Pdo;
    NTSTATUS            Status;

    Status = STATUS_INSUFFICIENT_RESOURCES;
    Pdo = __PdoAlloc(sizeof(XENVBD_PDO));
    if (!Pdo)
        goto fail1;

    Pdo->Fdo            = Fdo;
    Pdo->ReferenceCount = 1;

    FrontendCreate(&Pdo->Frontend, DeviceId, TargetId, Pdo);
    
    PdoD3ToD0(Pdo);

    *_Pdo = Pdo;
    return STATUS_SUCCESS;

fail1:
    LogError("Fail1 (%08x)\n", Status);
    return Status;
}

VOID
PdoDestroy(
    IN  PXENVBD_PDO             Pdo
    )
{
    LARGE_INTEGER       Timeout;

    Timeout.QuadPart = -1000000;
    while (InterlockedCompareExchange(&Pdo->ReferenceCount, 0, 0) > 0) {
        KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
    }

    PdoD0ToD3(Pdo);

    FrontendDestroy(&Pdo->Frontend);

    ASSERT(IsZeroMemory(Pdo, sizeof(XENVBD_PDO)));
    __PdoFree(Pdo);
}

DECLSPEC_NOINLINE VOID
PdoD3ToD0(
    IN  PXENVBD_PDO             Pdo
    )
{
    LogTrace("Target[%d] =====> (Irql=%d)\n", Pdo->Frontend.TargetId, KeGetCurrentIrql());

    // connect to backend
    FrontendSetState(&Pdo->Frontend, XENVBD_ENABLED);

    LogTrace("Target[%d] <===== (Irql=%d)\n", Pdo->Frontend.TargetId, KeGetCurrentIrql());
}

DECLSPEC_NOINLINE VOID
PdoD0ToD3(
    IN  PXENVBD_PDO             Pdo
    )
{
    LogTrace("Target[%d] =====> (Irql=%d)\n", Pdo->Frontend.TargetId, KeGetCurrentIrql());

    // disconnect from backend
    FrontendSetState(&Pdo->Frontend, XENVBD_CLOSED);

    // target suspended
    LogTrace("Target[%d] <===== (Irql=%d)\n", Pdo->Frontend.TargetId, KeGetCurrentIrql());
}

//=============================================================================
// Reference Counting
VOID
PdoReference(
    IN  PXENVBD_PDO             Pdo
    )
{
    if (Pdo)
        InterlockedIncrement(&Pdo->ReferenceCount);
}

VOID
PdoDereference(
    IN  PXENVBD_PDO             Pdo
    )
{
    if (Pdo)
        InterlockedDecrement(&Pdo->ReferenceCount);
}

//=============================================================================
// Query Methods

ULONG
PdoSectorSize(
    IN  PXENVBD_PDO             Pdo
    )
{
    ASSERT3U(Pdo->Frontend.SectorSize, !=, 0);
    return Pdo->Frontend.SectorSize;
}

//=============================================================================
// REQUEST related
static VOID
__CleanupRequest(
    IN  PXENVBD_REQUEST         Request,
    IN  BOOLEAN                 CopyOut
    )
{
    ULONG               Index;

    for (Index = 0; Index < Request->NrSegments; ++Index) {
        // ungrant request
        if (Request->Segments[Index].GrantRef) {
            GnttabRevokeForeignAccess(Request->Segments[Index].GrantRef);
            GnttabPut(Request->Segments[Index].GrantRef);
            Request->Segments[Index].GrantRef = 0;
        }

        // free bounce buffer
        if (Request->Segments[Index].BufferId) {
            if (Request->Operation == BLKIF_OP_READ && CopyOut) {
                BufferCopyOut(Request->Segments[Index].BufferId, (PUCHAR)Request->Segments[Index].Buffer, Request->Segments[Index].Length);
            } 
            BufferPut(Request->Segments[Index].BufferId);
            Request->Segments[Index].BufferId = 0;
            MmUnmapLockedPages(Request->Segments[Index].Buffer, &Request->Segments[Index].Mdl);
        }
    }

}
static VOID
__CleanupSrb(
    IN  PSCSI_REQUEST_BLOCK     Srb
    )
{
    PXENVBD_SRBEXT      SrbExt = GetSrbExt(Srb);
    ULONG               Index;

    for (Index = 0; Index < SrbExt->NumRequests; ++Index) {
        PXENVBD_REQUEST Request = &SrbExt->Requests[Index];
        __CleanupRequest(Request, FALSE);
    }
}

//=============================================================================
// Preparing Requests
static FORCEINLINE VOID
__UpdateStats(
    __in PXENVBD_PDO             Pdo,
    __in UCHAR                   Operation
    )
{
    switch (Operation) {
    case BLKIF_OP_READ:
        Pdo->Reads++;
        break;
    case BLKIF_OP_WRITE:
        Pdo->Writes++;
        break;
    default:
        Pdo->Others++;
        break;
    }
}
static FORCEINLINE ULONG
__Min(
    IN  ULONG                   Val1,
    IN  ULONG                   Val2
    )
{
    if (Val1 < Val2)
        return Val1;
    else
        return Val2;
}
extern PHYSICAL_ADDRESS MmGetPhysicalAddress(IN PVOID Buffer);
static FORCEINLINE PFN_NUMBER
VirtToPfn(
    IN  PVOID                   VirtAddr
    )
{
    PHYSICAL_ADDRESS PhysAddr = MmGetPhysicalAddress(VirtAddr);
    return (PFN_NUMBER)(PhysAddr.QuadPart >> PAGE_SHIFT);
}
static FORCEINLINE ULONG __SectorSize(
    IN  PXENVBD_PDO             Pdo
    )
{
    ASSERT3U(Pdo->Frontend.SectorSize, !=, 0);
    return Pdo->Frontend.SectorSize;
}
static FORCEINLINE ULONG __SectorsPerPage(
    IN  ULONG                   SectorSize
    )
{
    ASSERT3U(SectorSize, !=, 0);
    return PAGE_SIZE / SectorSize;
}
static FORCEINLINE VOID
__Operation(
    IN  UCHAR                   CdbOp,
    OUT PUCHAR                  RingOp,
    OUT PBOOLEAN                ReadOnly
    )
{
    switch (CdbOp) {
    case SCSIOP_READ:
        *RingOp     = BLKIF_OP_READ;
        *ReadOnly   = FALSE;
        break;
    case SCSIOP_WRITE:
        *RingOp     = BLKIF_OP_WRITE;
        *ReadOnly   = TRUE;
        break;
    default:
        ASSERT(FALSE);
    }
}
static FORCEINLINE ULONG
__Offset(
    IN  STOR_PHYSICAL_ADDRESS   PhysAddr
    )
{
    return (ULONG)(PhysAddr.QuadPart & (PAGE_SIZE - 1));
}
static FORCEINLINE VOID
__GetPhysAddr(
    IN  PSTOR_SCATTER_GATHER_LIST   SGList,
    IN OUT PXENVBD_SG_INDEX         SGIndex,
    OUT PSTOR_PHYSICAL_ADDRESS      SGPhysAddr,
    OUT PULONG                      SGPhysLen
    )
{
    PSTOR_SCATTER_GATHER_ELEMENT    SGElement;

    ASSERT3U(SGIndex->Index, <, SGList->NumberOfElements);
    
    SGElement = &SGList->List[SGIndex->Index];
    SGPhysAddr->QuadPart = SGElement->PhysicalAddress.QuadPart + SGIndex->Offset;
    *SGPhysLen           = __Min(PAGE_SIZE - __Offset(*SGPhysAddr) - SGIndex->LastLength, SGElement->Length - SGIndex->Offset);

    ASSERT3U(*SGPhysLen, <=, PAGE_SIZE);
    ASSERT3U(SGIndex->Offset, <, SGElement->Length);

    // advance pointers
    SGIndex->LastLength = *SGPhysLen;
    SGIndex->Offset = SGIndex->Offset + *SGPhysLen;
    if (SGIndex->Offset >= SGElement->Length) {
        // next element
        SGIndex->Index  = SGIndex->Index + 1;
        SGIndex->Offset = 0;
    }    
}
static FORCEINLINE BOOLEAN
__PhysAddrIsAligned(
    IN  STOR_PHYSICAL_ADDRESS   PhysAddr,
    IN  ULONG                   Length,
    IN  ULONG                   Alignment
    )
{
    if ((PhysAddr.QuadPart & Alignment) || (Length & Alignment))
        return FALSE;
    else
        return TRUE;
}
static FORCEINLINE PFN_NUMBER
__Pfn(
    IN  STOR_PHYSICAL_ADDRESS   PhysAddr
    )
{
    return (PFN_NUMBER)(PhysAddr.QuadPart >> PAGE_SHIFT);
}
static NTSTATUS
PrepareReadWrite(
    IN  PXENVBD_PDO             Pdo,
    IN  PSCSI_REQUEST_BLOCK     Srb
    )
{
    NTSTATUS        Status;
    ULONG           SectorsDone;
    UCHAR           Operation;
    BOOLEAN         ReadOnly;
    ULONG           Index1, Index2;
    ULONG           SectorsNow;

    PSTOR_SCATTER_GATHER_LIST   SGList;
    XENVBD_SG_INDEX             SGIndex;

    PXENVBD_SRBEXT  SrbExt = GetSrbExt(Srb);

    const ULONG64   StartSector     = Cdb_LogicalBlock(Srb);
    const ULONG     NumSectors      = Cdb_TransferBlock(Srb);
    const ULONG     SectorSize      = __SectorSize(Pdo);
    const ULONG     SectorsPerPage  = __SectorsPerPage(SectorSize);
    __Operation(Cdb_OperationEx(Srb), &Operation, &ReadOnly);

    SGList = StorPortGetScatterGatherList(Pdo->Fdo, Srb);
    RtlZeroMemory(&SGIndex, sizeof(SGIndex));

    SectorsDone = 0;
    SrbExt->NumRequests = 0;
    for (Index1 = 0; Index1 < 2; ++Index1) {
        PXENVBD_REQUEST Request = &SrbExt->Requests[Index1];
        ++SrbExt->NumRequests;

        Request->Srb        = Srb;
        Request->Operation  = Operation;
        Request->NrSegments = 0;
        Request->FirstSector = StartSector + SectorsDone;
        Request->NrSectors  = 0; // not used for Read/Write

        for (Index2 = 0; Index2 < BLKIF_MAX_SEGMENTS_PER_REQUEST; ++Index2) {
            STOR_PHYSICAL_ADDRESS   PhysAddr;
            ULONG                   PhysLen;
            PFN_NUMBER              Pfn;
            ULONG                   GrantRef, FirstSector, LastSector;

            Request->NrSegments++;

            SGIndex.LastLength = 0;
            __GetPhysAddr(SGList, &SGIndex, &PhysAddr, &PhysLen);
            if (__PhysAddrIsAligned(PhysAddr, PhysLen, SectorSize - 1)) {
                // get first sector, last sector and count
                FirstSector = (__Offset(PhysAddr) + SectorSize - 1) / SectorSize;
                SectorsNow  = __Min(NumSectors - SectorsDone, SectorsPerPage - FirstSector);
                LastSector  = FirstSector + SectorsNow - 1;

                ASSERT3U((PhysLen / SectorSize), ==, SectorsNow);
                ASSERT3U((PhysLen & (SectorSize - 1)), ==, 0);
               
                // simples - grab Pfn of PhysAddr
                Pfn         = __Pfn(PhysAddr);
            } else {
                PMDL        Mdl;
                ULONG       BufferId;
                PVOID       Buffer;
                ULONG       Length;

                // get first sector, last sector and count
                FirstSector = 0;
                SectorsNow  = __Min(NumSectors - SectorsDone, SectorsPerPage);
                LastSector  = SectorsNow - 1;

                // map PhysAddr to 1 or 2 pages and lock for VirtAddr
#pragma warning(push)
#pragma warning(disable:28145)
                Mdl = &Request->Segments[Index2].Mdl;
                Mdl->Next           = NULL;
                Mdl->Size           = (SHORT)(sizeof(MDL) + sizeof(PFN_NUMBER));
                Mdl->MdlFlags       = MDL_PAGES_LOCKED;
                Mdl->Process        = NULL;
                Mdl->MappedSystemVa = NULL;
                Mdl->StartVa        = NULL;
                Mdl->ByteCount      = PhysLen;
                Mdl->ByteOffset     = __Offset(PhysAddr);
                Request->Segments[Index2].Pfn[0] = __Pfn(PhysAddr);
#pragma warning(pop)

                if (PhysLen < SectorsNow * SectorSize) {
                    __GetPhysAddr(SGList, &SGIndex, &PhysAddr, &PhysLen);
                    Mdl->Size       += sizeof(PFN_NUMBER);
                    Mdl->ByteCount  = Mdl->ByteCount + PhysLen;
                    Request->Segments[Index2].Pfn[1] = __Pfn(PhysAddr);
                }

                ASSERT((Mdl->ByteCount & (SectorSize - 1)) == 0);
                ASSERT3U(Mdl->ByteCount, <=, PAGE_SIZE);
                ASSERT3U(SectorsNow, ==, (Mdl->ByteCount / SectorSize));
                
                Length = __Min(Mdl->ByteCount, PAGE_SIZE);
                Buffer = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, 
                                        MmCached, NULL, FALSE, HighPagePriority);
                if (!Buffer) {
                    Pdo->NeedsWake = TRUE;
                    __CleanupSrb(Srb);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                // get and fill a buffer
                if (!BufferGet(&BufferId, &Pfn)) {
                    Pdo->NeedsWake = TRUE;
                    __CleanupSrb(Srb);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                if (Operation == BLKIF_OP_WRITE) {
                    BufferCopyIn(BufferId, Buffer, Length);
                }
                Request->Segments[Index2].BufferId       = BufferId;
                Request->Segments[Index2].Buffer         = Buffer;
                Request->Segments[Index2].Length         = Length;
            }

            // Grant and Fill in last details
            Status = GnttabGet(&GrantRef);
            if (!NT_SUCCESS(Status)) {
                Pdo->NeedsWake = TRUE;
                __CleanupSrb(Srb);
                return Status;
            }
            GnttabPermitForeignAccess(GrantRef, Pdo->Frontend.BackendId, 
                                        Pfn, ReadOnly);
            
            Request->Segments[Index2].GrantRef       = GrantRef;
            Request->Segments[Index2].FirstSector    = (UCHAR)FirstSector;
            Request->Segments[Index2].LastSector     = (UCHAR)LastSector;

            SectorsDone += SectorsNow;
            if (SectorsDone >= NumSectors) {
                ASSERT3U(SectorsDone, ==, NumSectors);
                goto done;
            }
        }
        ASSERT3U(Request->NrSegments, >, 0);
        ASSERT3U(Request->NrSegments, <=, BLKIF_MAX_SEGMENTS_PER_REQUEST);
        if (SectorsDone >= NumSectors) {
            ASSERT3U(SectorsDone, ==, NumSectors);
            goto done;
        }
    }

done:
    __UpdateStats(Pdo, Operation);
    QueueInsertTail(&Pdo->PreparedSrbs, Srb);
    return STATUS_SUCCESS;
}
static VOID
PrepareSyncCache(
    IN  PXENVBD_PDO             Pdo,
    IN  PSCSI_REQUEST_BLOCK     Srb
    )
{
    PXENVBD_SRBEXT          SrbExt = GetSrbExt(Srb);
    PXENVBD_REQUEST         Request;
    
    SrbExt->NumRequests = 1;
    Request = &SrbExt->Requests[0];
    Request->Srb = Srb;

    Request->Operation      = BLKIF_OP_WRITE_BARRIER;
    Request->NrSegments     = 0;
    Request->FirstSector    = Cdb_LogicalBlock(Srb);
    Request->NrSectors      = 0;

    __UpdateStats(Pdo, BLKIF_OP_WRITE_BARRIER);
    QueueInsertTail(&Pdo->PreparedSrbs, Srb);
}

//=============================================================================
// Queue-Related

VOID
PdoPrepareFresh(
    IN  PXENVBD_PDO             Pdo
    )
{
    PSCSI_REQUEST_BLOCK     Srb;

    while ((Srb = QueuePop(&Pdo->FreshSrbs)) != NULL) {
        // popped a SRB, process it
        const UCHAR Operation = Cdb_OperationEx(Srb);
        // idea: handle all srbs, with a completesrb option
        switch (Operation) {
        case SCSIOP_READ:
        case SCSIOP_WRITE:
            PrepareReadWrite(Pdo, Srb);
            break;
        case SCSIOP_SYNCHRONIZE_CACHE:
            PrepareSyncCache(Pdo, Srb);
            break;
        default:
            ASSERT(FALSE);
            break;
        }
    }
}

VOID
PdoSubmitPrepared(
    IN  PXENVBD_PDO             Pdo
    )
{
    for (;;) {
        PSCSI_REQUEST_BLOCK Srb;
        PXENVBD_SRBEXT      SrbExt;
        ULONG               Index;

        Srb = QueuePop(&Pdo->PreparedSrbs);
        if (Srb == NULL) {
            break;
        }

        SrbExt = GetSrbExt(Srb);
        if (!FrontendCanSubmitRequest(&Pdo->Frontend, SrbExt->NumRequests)) {
            QueueInsertHead(&Pdo->PreparedSrbs, Srb);
            break;
        }

        for (Index = 0; Index < SrbExt->NumRequests; ++Index) {
            PXENVBD_REQUEST Request = &SrbExt->Requests[Index];
            FrontendInsertRequestOnRing(&Pdo->Frontend, Request);
        }
        QueueInsertTail(&Pdo->SubmittedSrbs, Srb);
        Srb->SrbStatus = SRB_STATUS_SUCCESS;

        FrontendPushRequestAndCheckNotify(&Pdo->Frontend);
    }
}

VOID
PdoCompleteShutdown(
    IN  PXENVBD_PDO             Pdo
    )
{
    PSCSI_REQUEST_BLOCK     Srb;

    if (QueuePeek(&Pdo->ShutdownSrbs) == NULL)
        return;

    if (QueuePeek(&Pdo->FreshSrbs) ||
        QueuePeek(&Pdo->PreparedSrbs) ||
        QueuePeek(&Pdo->SubmittedSrbs))
        return;

    while ((Srb = QueuePop(&Pdo->ShutdownSrbs)) != NULL) {
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        FdoCompleteSrb(Pdo->Fdo, Srb);
    }
}

VOID
PdoCompleteSubmittedRequest(
    IN  PXENVBD_PDO             Pdo,
    IN  PXENVBD_REQUEST         Request,
    IN  SHORT                   Status
    )
{
    PSCSI_REQUEST_BLOCK Srb = Request->Srb;
    PXENVBD_SRBEXT      SrbExt = GetSrbExt(Srb);

    if (Status != BLKIF_RSP_OKAY) {
        LogError("Request 0x%p was failed by the backend with %d\n", Request, Status);
        LogError("    { %02x, %02x, %lld, %lld, { ... } }\n", Request->Operation, 
                        Request->NrSegments, Request->FirstSector, Request->NrSectors);
    }
 
    switch (Request->Operation) {
    case BLKIF_OP_READ:
    case BLKIF_OP_WRITE:
        // cleanup buffers (LogVerbose is too verbose!)
        //LogVerbose("%s : (%d, %lld @ %lld)\n",
        //            Request->Operation == BLKIF_OP_READ ? "READ " : "WRITE",
        //            Status, Request->NrSectors, Request->FirstSector);
        __CleanupRequest(Request, TRUE);
        break;
    case BLKIF_OP_WRITE_BARRIER:
        LogVerbose("BARRIER\n");
        if (Status == BLKIF_RSP_EOPNOTSUPP) {
            // remove supported feature
            Pdo->Frontend.FeatureBarrier = FALSE;
        }
        break;
    case BLKIF_OP_DISCARD:
        LogVerbose("DISCARD\n");
        if (Status == BLKIF_RSP_EOPNOTSUPP) {
            // remove supported feature
            Pdo->Frontend.FeatureDiscard = FALSE;
        }
        break;
    default:
        LogVerbose("OTHER\n");
        ASSERT(FALSE);
        break;
    }

    --SrbExt->NumRequests;

    // complete srb
    if (SrbExt->NumRequests == 0) {
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        Srb->ScsiStatus = 0x00; // SCSI_GOOD
        
        QueueRemove(&Pdo->SubmittedSrbs, Srb);
        FdoCompleteSrb(Pdo->Fdo, Srb);
    }
}

//=============================================================================
// SRBs

static FORCEINLINE BOOLEAN
__ValidateSectors(
    IN  ULONG64                 SectorCount,
    IN  ULONG64                 Start,
    IN  ULONG                   Length
    )
{
    // Deal with overflow
    return (Start < SectorCount) && ((Start + Length) < SectorCount);
}
static BOOLEAN
PdoReadWrite(
    IN  PXENVBD_PDO            Pdo,
    IN  PSCSI_REQUEST_BLOCK    Srb
    )
{
    NTSTATUS Status;

    if (!Pdo->Frontend.Connected) {
        LogTrace("Target[%d] : Not Ready, fail SRB\n", Pdo->Frontend.TargetId);
        Srb->ScsiStatus = 0x40; // SCSI_ABORT;
        return TRUE;
    }
    // check valid sectors
    if (!__ValidateSectors(Pdo->Frontend.SectorCount, Cdb_LogicalBlock(Srb), Cdb_TransferBlock(Srb))) {
        LogTrace("Target[%d] : Invalid Sectors (%lld, %lld, %d)\n", Pdo->Frontend.TargetId, Pdo->Frontend.SectorCount, Cdb_LogicalBlock(Srb), Cdb_TransferBlock(Srb));
        Srb->ScsiStatus = 0x40; // SCSI_ABORT
        return TRUE; // Complete now
    }

    Status = PrepareReadWrite(Pdo, Srb);
    if (NT_SUCCESS(Status)) {
        PdoSubmitPrepared(Pdo);
        return FALSE;
    }
    QueueInsertTail(&Pdo->FreshSrbs, Srb);
    EventChannelSend(Pdo->Frontend.EvtchnPort);
    return FALSE;
}
static FORCEINLINE BOOLEAN
PdoSyncCache(
    IN  PXENVBD_PDO             Pdo,
    IN  PSCSI_REQUEST_BLOCK     Srb
    )
{
    if (!Pdo->Frontend.Connected) {
        LogTrace("Target[%d] : Not Ready, fail SRB\n", Pdo->Frontend.TargetId);
        Srb->ScsiStatus = 0x40; // SCSI_ABORT;
        return TRUE;
    }
 
    PrepareSyncCache(Pdo, Srb);
    PdoSubmitPrepared(Pdo);
    return FALSE;
}

#define MODE_CACHING_PAGE_LENGTH 20
static FORCEINLINE VOID
PdoModeSense(
    IN  PXENVBD_PDO             Pdo,
    IN  PSCSI_REQUEST_BLOCK     Srb
    )    
{
    PMODE_PARAMETER_HEADER  Header  = Srb->DataBuffer;
    const UCHAR PageCode            = Cdb_PageCode(Srb);
    ULONG LengthLeft                = Cdb_AllocationLength(Srb);
    PVOID CurrentPage               = Srb->DataBuffer;

    UNREFERENCED_PARAMETER(Pdo);

    RtlZeroMemory(Srb->DataBuffer, Srb->DataTransferLength);

    if (Srb->DataTransferLength < sizeof(struct _MODE_SENSE)) {
        Srb->SrbStatus = SRB_STATUS_DATA_OVERRUN;
        Srb->DataTransferLength = 0;
        return;
    }

    // Header
    Header->ModeDataLength  = sizeof(MODE_PARAMETER_HEADER) - 1;
    Header->MediumType      = 0;
    Header->DeviceSpecificParameter = 0;
    Header->BlockDescriptorLength   = 0;
    LengthLeft -= sizeof(MODE_PARAMETER_HEADER);
    CurrentPage = ((PUCHAR)CurrentPage + sizeof(MODE_PARAMETER_HEADER));

    // Fill in Block Parameters (if Specified and space)
    // when the DBD (Disable Block Descriptor) is set, ignore the block page
    if (Cdb_Dbd(Srb) == 0 && 
        LengthLeft >= sizeof(MODE_PARAMETER_BLOCK)) {
        PMODE_PARAMETER_BLOCK Block = (PMODE_PARAMETER_BLOCK)CurrentPage;
        // Fill in BlockParams
        Block->DensityCode                  =   0;
        Block->NumberOfBlocks[0]            =   0;
        Block->NumberOfBlocks[1]            =   0;
        Block->NumberOfBlocks[2]            =   0;
        Block->BlockLength[0]               =   0;
        Block->BlockLength[1]               =   0;
        Block->BlockLength[2]               =   0;

        Header->BlockDescriptorLength = sizeof(MODE_PARAMETER_BLOCK);
        Header->ModeDataLength += sizeof(MODE_PARAMETER_BLOCK);
        LengthLeft -= sizeof(MODE_PARAMETER_BLOCK);
        CurrentPage = ((PUCHAR)CurrentPage + sizeof(MODE_PARAMETER_BLOCK));
    }

    // Fill in Cache Parameters (if Specified and space)
    if ((PageCode == MODE_PAGE_CACHING || PageCode == MODE_SENSE_RETURN_ALL) &&
        LengthLeft >= MODE_CACHING_PAGE_LENGTH) {
        PMODE_CACHING_PAGE Caching = (PMODE_CACHING_PAGE)CurrentPage;
        // Fill in CachingParams
        Caching->PageCode                   = MODE_PAGE_CACHING;
        Caching->PageSavable                = 0;
        Caching->PageLength                 = MODE_CACHING_PAGE_LENGTH;
        Caching->ReadDisableCache           = 0;
        Caching->MultiplicationFactor       = 0;
        Caching->WriteCacheEnable           = 0;
        Caching->WriteRetensionPriority     = 0;
        Caching->ReadRetensionPriority      = 0;
        Caching->DisablePrefetchTransfer[0] = 0;
        Caching->DisablePrefetchTransfer[1] = 0;
        Caching->MinimumPrefetch[0]         = 0;
        Caching->MinimumPrefetch[1]         = 0;
        Caching->MaximumPrefetch[0]         = 0;
        Caching->MaximumPrefetch[1]         = 0;
        Caching->MaximumPrefetchCeiling[0]  = 0;
        Caching->MaximumPrefetchCeiling[1]  = 0;

        Header->ModeDataLength += MODE_CACHING_PAGE_LENGTH;
        LengthLeft -= MODE_CACHING_PAGE_LENGTH;
        CurrentPage = ((PUCHAR)CurrentPage + MODE_CACHING_PAGE_LENGTH);
    }

    // Fill in Informational Exception Parameters (if Specified and space)
    if ((PageCode == MODE_PAGE_FAULT_REPORTING || PageCode == MODE_SENSE_RETURN_ALL) &&
        LengthLeft >= sizeof(MODE_INFO_EXCEPTIONS)) {
        PMODE_INFO_EXCEPTIONS Exceptions = (PMODE_INFO_EXCEPTIONS)CurrentPage;
        // Fill in Exceptions
        Exceptions->PageCode                = MODE_PAGE_FAULT_REPORTING;
        Exceptions->PSBit                   = 0;
        Exceptions->PageLength              = sizeof(MODE_INFO_EXCEPTIONS);
        Exceptions->Flags                   = 0;
        Exceptions->Dexcpt                  = 1; // disabled
        Exceptions->ReportMethod            = 0;
        Exceptions->IntervalTimer[0]        = 0;
        Exceptions->IntervalTimer[1]        = 0;
        Exceptions->IntervalTimer[2]        = 0;
        Exceptions->IntervalTimer[3]        = 0;
        Exceptions->ReportCount[0]          = 0;
        Exceptions->ReportCount[1]          = 0;
        Exceptions->ReportCount[2]          = 0;
        Exceptions->ReportCount[3]          = 0;

        Header->ModeDataLength += sizeof(MODE_INFO_EXCEPTIONS);
        LengthLeft -= sizeof(MODE_INFO_EXCEPTIONS);
        CurrentPage = ((PUCHAR)CurrentPage + sizeof(MODE_INFO_EXCEPTIONS));
    }

    // Finish this SRB
    Srb->SrbStatus = SRB_STATUS_SUCCESS;
    Srb->DataTransferLength = __Min(Cdb_AllocationLength(Srb), Header->ModeDataLength + 1);
}
static FORCEINLINE VOID
PdoRequestSense(
    IN  PXENVBD_PDO             Pdo,
    IN  PSCSI_REQUEST_BLOCK     Srb
    )
{
    PSENSE_DATA         Sense = Srb->DataBuffer;

    UNREFERENCED_PARAMETER(Pdo);

    RtlZeroMemory(Sense, sizeof(SENSE_DATA));

    Sense->ErrorCode            = 0x70;
    Sense->Valid                = 1;
    Sense->AdditionalSenseCodeQualifier = 0;
    Sense->SenseKey             = SCSI_SENSE_NO_SENSE;
    Sense->AdditionalSenseCode  = SCSI_ADSENSE_NO_SENSE;
    Srb->DataTransferLength     = sizeof(SENSE_DATA);
    Srb->SrbStatus              = SRB_STATUS_SUCCESS;
}
static FORCEINLINE VOID
PdoReportLuns(
    IN  PXENVBD_PDO             Pdo,
    IN  PSCSI_REQUEST_BLOCK     Srb
    )
{
    ULONG           Length;
    ULONG           Offset;
    ULONG           AllocLength = Cdb_AllocationLength(Srb);
    PUCHAR          Buffer = Srb->DataBuffer;

    UNREFERENCED_PARAMETER(Pdo);

    RtlZeroMemory(Buffer, AllocLength);

    Length = 0;
    Offset = 8;

    if (Offset + 8 <= AllocLength) {
        Buffer[Offset] = 0;
        Offset += 8;
        Length += 8;
    }

    if (Offset + 8 <= AllocLength) {
        Buffer[Offset] = XENVBD_MAX_TARGETS;
        Offset += 8;
        Length += 8;
    }

    REVERSE_BYTES(Buffer, &Length);

    Srb->DataTransferLength = __Min(Length, AllocLength);
    Srb->SrbStatus = SRB_STATUS_SUCCESS;
}
static FORCEINLINE VOID
PdoReadCapacity(
    IN  PXENVBD_PDO             Pdo,
    IN  PSCSI_REQUEST_BLOCK     Srb
    )
{
    PREAD_CAPACITY_DATA     Capacity = Srb->DataBuffer;
    ULONG64                 SectorCount;
    ULONG                   SectorSize;
    ULONG                   LastBlock;
    
    SectorCount = Pdo->Frontend.SectorCount;
    SectorSize = Pdo->Frontend.SectorSize;

    if (SectorCount == (ULONG)SectorCount)
        LastBlock = (ULONG)SectorCount - 1;
    else
        LastBlock = ~(ULONG)0;

    if (Capacity) {
        Capacity->LogicalBlockAddress = _byteswap_ulong(LastBlock);
        Capacity->BytesPerBlock = _byteswap_ulong(SectorSize);
    }

    Srb->SrbStatus = SRB_STATUS_SUCCESS;
}
static FORCEINLINE VOID
PdoReadCapacity16(
    IN  PXENVBD_PDO             Pdo,
    IN  PSCSI_REQUEST_BLOCK     Srb
    )
{
    PREAD_CAPACITY_DATA_EX  Capacity = Srb->DataBuffer;
    ULONG64                 SectorCount;
    ULONG                   SectorSize;

    SectorCount = Pdo->Frontend.SectorCount;
    SectorSize = Pdo->Frontend.SectorSize;

    if (Capacity) {
        Capacity->LogicalBlockAddress.QuadPart = _byteswap_uint64(SectorCount - 1);
        Capacity->BytesPerBlock = _byteswap_ulong(SectorSize);
    }

    Srb->SrbStatus = SRB_STATUS_SUCCESS;
}

//=============================================================================
// StorPort Methods
static FORCEINLINE VOID
__DisplayStats(
    IN  PXENVBD_PDO             Pdo
    )
{
    LogVerbose("Target[%d] : BLKIF_OP_'s Reads %d / Writes %d / Others %d\n",
                Pdo->Frontend.TargetId,
                Pdo->Reads, Pdo->Writes, Pdo->Others);
    Pdo->Reads = Pdo->Writes = Pdo->Others = 0;
}
static VOID
__AbortSrbQueue(
    IN  PSRB_QUEUE              Queue,
    IN  PXENVBD_PDO             Pdo,
    IN  BOOLEAN                 Free,
    IN  PCHAR                   Name
    )
{
    PSCSI_REQUEST_BLOCK Srb;

    while ((Srb = QueuePop(Queue)) != NULL) {
        LogVerbose("Target[%d] : Aborting SRB %p from %s\n", Pdo->Frontend.TargetId, Srb, Name);
        if (Free)
            __CleanupSrb(Srb);

        Srb->ScsiStatus = 0x40; // SCSI_ABORTED;
        FdoCompleteSrb(Pdo->Fdo, Srb);
    }
}
static BOOLEAN
PdoExecuteScsi(
    IN  PXENVBD_PDO             Pdo,
    IN  PSCSI_REQUEST_BLOCK     Srb
    )
{
    const UCHAR Operation = Cdb_OperationEx(Srb);
    // idea: check pdo state here. still push to freshsrbs
    //LogVerbose("Target[%d] ====> %02x:%s\n", Pdo->Frontend.TargetId, Operation, Cdb_OperationName(Operation));
    switch (Operation) {
    case SCSIOP_READ:
    case SCSIOP_WRITE:
        return PdoReadWrite(Pdo, Srb);
        break;
        
    case SCSIOP_SYNCHRONIZE_CACHE:
        LogVerbose("SCSIOP_SYNCHRONIZE_CACHE\n");
        return PdoSyncCache(Pdo, Srb);
        break;

    case SCSIOP_INQUIRY:
        LogVerbose("SCSIOP_INQUIRY\n");
        PdoInquiry(Pdo->Frontend.Inquiry, Srb);
        break;
    case SCSIOP_MODE_SENSE:
        LogVerbose("SCSIOP_MODE_SENSE\n");
        PdoModeSense(Pdo, Srb);
        break;
    case SCSIOP_REQUEST_SENSE:
        LogVerbose("SCSIOP_REQUEST_SENSE\n");
        PdoRequestSense(Pdo, Srb);
        break;
    case SCSIOP_REPORT_LUNS:
        LogVerbose("SCSIOP_REPORT_LUNS\n");
        PdoReportLuns(Pdo, Srb);
        break;
    case SCSIOP_READ_CAPACITY:
        LogVerbose("SCSIOP_READ_CAPACITY\n");
        PdoReadCapacity(Pdo, Srb);
        break;
    case SCSIOP_READ_CAPACITY16:
        LogVerbose("SCSIOP_READ_CAPACITY16\n");
        PdoReadCapacity16(Pdo, Srb);
        break;
    case SCSIOP_MEDIUM_REMOVAL:
    case SCSIOP_TEST_UNIT_READY:
    case SCSIOP_RESERVE_UNIT:
    case SCSIOP_RESERVE_UNIT10:
    case SCSIOP_RELEASE_UNIT:
    case SCSIOP_RELEASE_UNIT10:
    case SCSIOP_VERIFY:
    case SCSIOP_VERIFY16:
    case SCSIOP_START_STOP_UNIT:
        LogVerbose("Target[%d] : (%02x:%s)\n", Pdo->Frontend.TargetId, Operation, Cdb_OperationName(Operation));
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        break;
    default:
        LogVerbose("Target[%d] : (%02x:%s) Unsupported\n", Pdo->Frontend.TargetId, Operation, Cdb_OperationName(Operation));
        break;
    }
    //LogVerbose("Target[%d] <==== %02x:%s\n", Pdo->Frontend.TargetId, Operation, Cdb_OperationName(Operation));
    return TRUE;
}
static FORCEINLINE VOID
PdoQueueShutdown(
    IN  PXENVBD_PDO             Pdo,
    IN  PSCSI_REQUEST_BLOCK     Srb
    )
{
    LogVerbose("Target[%d] : shutdown\n", Pdo->Frontend.TargetId);
    QueueInsertTail(&Pdo->ShutdownSrbs, Srb);
    EventChannelSend(Pdo->Frontend.EvtchnPort);
}

VOID
PdoReset(
    IN  PXENVBD_PDO             Pdo
    )
{
    PSCSI_REQUEST_BLOCK     Srb;
    ULONG                   Count = 0;

    LogTrace("Target[%d] ====> (Irql=%d)\n", Pdo->Frontend.TargetId, KeGetCurrentIrql());

    while ((Srb = QueuePop(&Pdo->FreshSrbs)) != NULL) {
        LogVerbose("Target[%d] : Aborting SRB %p from Fresh\n", Pdo->Frontend.TargetId, Srb);
        Srb->ScsiStatus = 0x40; //SCSI_STATUS_ABORTED;
        FdoCompleteSrb(Pdo->Fdo, Srb);
    }

    while (QueuePeek(&Pdo->PreparedSrbs) || 
           QueuePeek(&Pdo->SubmittedSrbs)) {

        if (++Count > 1000) {
            LogWarning("Target[%d] : Waiting for Prepared(%d) or Submitted(%d) requests\n", 
                Pdo->Frontend.TargetId, Pdo->PreparedSrbs.Count, Pdo->SubmittedSrbs.Count);
            Count = 0;
        }
        FrontendEvtchnCallback(&Pdo->Frontend);
        EventChannelSend(Pdo->Frontend.EvtchnPort);

        if (QueuePeek(&Pdo->PreparedSrbs) || 
            QueuePeek(&Pdo->SubmittedSrbs)) {
            StorPortStallExecution(1000);
        }
    }
    FrontendEvtchnCallback(&Pdo->Frontend);
    EventChannelSend(Pdo->Frontend.EvtchnPort);
    
    LogTrace("Target[%d] <==== (Irql=%d)\n", Pdo->Frontend.TargetId, KeGetCurrentIrql());
}
static FORCEINLINE BOOLEAN
ValidateSrbForPdo(
    IN  PXENVBD_PDO             Pdo,
    IN  PSCSI_REQUEST_BLOCK     Srb
    )
{
    if (Srb->PathId != 0) {
        LogVerbose("(%02x) Srb->PathId(%d) != 0 -> SRB_STATUS_INVALID_PATH_ID\n", Srb->Function, Srb->PathId);
        Srb->SrbStatus = SRB_STATUS_INVALID_PATH_ID;
        return FALSE;
    }
    if (Srb->Lun != 0) {
        LogVerbose("(%02x) Srb->Lun(%d) != 0 -> SRB_STATUS_INVALID_LUN\n", Srb->Function, Srb->Lun);
        Srb->SrbStatus = SRB_STATUS_INVALID_LUN;
        return FALSE;
    }

    if (Pdo == NULL) {
        LogVerbose("(%02x) Pdo == NULL -> SRB_STATUS_INVALID_TARGET_ID\n", Srb->Function);
        Srb->SrbStatus = SRB_STATUS_INVALID_TARGET_ID;
        return FALSE;
    }

    return TRUE;
}
BOOLEAN
PdoStartIo(
    IN  PXENVBD_PDO             Pdo,
    IN  PSCSI_REQUEST_BLOCK     Srb
    )
{
    if (!ValidateSrbForPdo(Pdo, Srb))
        return TRUE;

    switch (Srb->Function) {
    case SRB_FUNCTION_EXECUTE_SCSI:
        return PdoExecuteScsi(Pdo, Srb);

    case SRB_FUNCTION_RESET_DEVICE:
        LogVerbose("SRB_FUNCTION_RESET_DEVICE\n");
        PdoReset(Pdo);
        return TRUE;

    case SRB_FUNCTION_FLUSH:
        LogVerbose("SRB_FUNCTION_FLUSH\n");
        PdoQueueShutdown(Pdo, Srb);
        return FALSE;

    case SRB_FUNCTION_SHUTDOWN:
        LogVerbose("SRB_FUNCTION_SHUTDOWN\n");
        __DisplayStats(Pdo);
        PdoQueueShutdown(Pdo, Srb);
        return FALSE;

    default:
        LogVerbose("Unhandled SRB %02x\n", Srb->Function);
        return TRUE;
    }
}

VOID
PdoAbortAllSrbs(
    IN  PXENVBD_PDO             Pdo
    )
{
    __AbortSrbQueue(&Pdo->FreshSrbs, Pdo, FALSE, "Fresh");
    __AbortSrbQueue(&Pdo->PreparedSrbs, Pdo, TRUE, "Prepared");
    __AbortSrbQueue(&Pdo->SubmittedSrbs, Pdo, TRUE, "Submitted");
}

VOID
PdoEvtchnInterruptHandler(
    IN  PXENVBD_PDO             Pdo
    )
{
    FrontendEvtchnCallback(&Pdo->Frontend);
}