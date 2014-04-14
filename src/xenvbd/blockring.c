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

#include "blockring.h"
#include "frontend.h"
#include "pdo.h"
#include "fdo.h"
#include "util.h"
#include "debug.h"
#include "srbext.h"
#include "driver.h"
#include <stdlib.h>
#include <xenvbd-ntstrsafe.h>

#define MAX_OUTSTANDING_REQUESTS    256
#define TAG_HEADER                  'gaTX'

struct _XENVBD_BLOCKRING {
    PXENVBD_FRONTEND                Frontend;
    BOOLEAN                         Connected;
    BOOLEAN                         Enabled;

    PXENBUS_STORE_INTERFACE         StoreInterface;

    KSPIN_LOCK                      Lock;
    PMDL                            Mdl;
    blkif_sring_t*                  SharedRing;
    blkif_front_ring_t              FrontRing;
    ULONG                           DeviceId;
    ULONG                           Order;
    PVOID                           Grants[XENVBD_MAX_RING_PAGES];
    ULONG                           Outstanding;
    ULONG                           Submitted;
    ULONG                           Recieved;
    PXENVBD_REQUEST                 Tags[MAX_OUTSTANDING_REQUESTS];
};

#define MAX_NAME_LEN                64
#define BLOCKRING_POOL_TAG          'gnRX'

#define XEN_IO_PROTO_ABI    "x86_64-abi"

extern PHYSICAL_ADDRESS MmGetPhysicalAddress(IN PVOID Buffer);

static FORCEINLINE PVOID
__BlockRingAllocate(
    IN  ULONG                       Length
    )
{
    return __AllocateNonPagedPoolWithTag(__FUNCTION__,
                                        __LINE__,
                                        Length,
                                        BLOCKRING_POOL_TAG);
}

static FORCEINLINE VOID
__BlockRingFree(
    IN  PVOID                       Buffer
    )
{
    if (Buffer)
        __FreePoolWithTag(Buffer, BLOCKRING_POOL_TAG);
}

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

static FORCEINLINE PFN_NUMBER
__Pfn(
    __in  PVOID                   VirtAddr
    )
{
    return (PFN_NUMBER)(ULONG_PTR)(MmGetPhysicalAddress(VirtAddr).QuadPart >> PAGE_SHIFT);
}

static FORCEINLINE ULONG64
__BlockRingGetTag(
    IN  PXENVBD_BLOCKRING           BlockRing,
    IN  PXENVBD_REQUEST             Request
    )
{
    USHORT      Index;

    for (Index = 0; Index < MAX_OUTSTANDING_REQUESTS; ++Index) {
        if (BlockRing->Tags[Index] == NULL) {
            BlockRing->Tags[Index] = Request;

            ++Index; // Tag value of 0 is invalid - make tags 1-based
            return (((ULONG64)TAG_HEADER << 32) | ((ULONG64)Index << 16) | (ULONG64)Index);
        }
    }

    Error("GET_TAG - out of free tags\n");
    return ((ULONG64)TAG_HEADER << 32) | 0xFFFFFFFF;
}

static FORCEINLINE PXENVBD_REQUEST
__BlockRingPutTag(
    IN  PXENVBD_BLOCKRING           BlockRing,
    IN  ULONG64                     Tag
    )
{
    PXENVBD_REQUEST Request;
    ULONG           Header;
    USHORT          Tag1, Tag2;

    Header  = (ULONG)((Tag >> 32) & 0xFFFFFFFF);
    Tag1    = (USHORT)((Tag >> 16) & 0xFFFF);
    Tag2    = (USHORT)(Tag & 0xFFFF);

    if (Header != TAG_HEADER) {
        Error("PUT_TAG (%llx) TAG_HEADER (%08x%04x%04x)\n", Tag, Header, Tag1, Tag2);
        return NULL;
    }
    if (Tag1 != Tag2) {
        Error("PUT_TAG (%llx) Tag1 != Tag2 (%08x%04x%04x)\n", Tag, Header, Tag1, Tag2);
        return NULL;
    }
    if (Tag1 == 0) {
        Error("PUT_TAG (%llx) Tag1 == 0 (%08x%04x%04x)\n", Tag, Header, Tag1, Tag2);
        return NULL;
    }
    if (Tag1 > MAX_OUTSTANDING_REQUESTS) {
        Error("PUT_TAG (%llx) Tag1 > %x (%08x%04x%04x)\n", Tag, MAX_OUTSTANDING_REQUESTS, Header, Tag1, Tag2);
        return NULL;
    }

    Request = BlockRing->Tags[Tag1 - 1];
    BlockRing->Tags[Tag1 - 1] = NULL;

    return Request;
}

static FORCEINLINE VOID
__BlockRingInsert(
    IN  PXENVBD_BLOCKRING           BlockRing,
    IN  PXENVBD_REQUEST             Request,
    IN  blkif_request_t*            req
    )
{
    PXENVBD_GRANTER                 Granter = FrontendGetGranter(BlockRing->Frontend);
    ULONG                           Index;
    blkif_request_discard_t*        req_discard;
    blkif_request_indirect_t*       req_indirect;

    switch (Request->Operation) {
    case BLKIF_OP_READ:
    case BLKIF_OP_WRITE:
        req->operation                  = Request->Operation;
        req->nr_segments                = Request->u.ReadWrite.NrSegments;
        req->handle                     = (USHORT)BlockRing->DeviceId;
        req->id                         = __BlockRingGetTag(BlockRing, Request);
        req->sector_number              = Request->u.ReadWrite.FirstSector;
        for (Index = 0; Index < Request->u.ReadWrite.NrSegments; ++Index) {
            req->seg[Index].gref        = GranterReference(Granter, Request->u.ReadWrite.Segments[Index].Grant);
            req->seg[Index].first_sect  = Request->u.ReadWrite.Segments[Index].FirstSector;
            req->seg[Index].last_sect   = Request->u.ReadWrite.Segments[Index].LastSector;
        }
        break;

    case BLKIF_OP_WRITE_BARRIER:
        req->operation                  = Request->Operation;
        req->nr_segments                = 0;
        req->handle                     = (USHORT)BlockRing->DeviceId;
        req->id                         = __BlockRingGetTag(BlockRing, Request);
        req->sector_number              = Request->u.Barrier.FirstSector;
        break;

    case BLKIF_OP_DISCARD:
        req_discard = (blkif_request_discard_t*)req;
        req_discard->operation          = BLKIF_OP_DISCARD;
        req_discard->flag               = Request->u.Discard.Flags;
        req_discard->handle             = (USHORT)BlockRing->DeviceId;
        req_discard->id                 = __BlockRingGetTag(BlockRing, Request);
        req_discard->sector_number      = Request->u.Discard.FirstSector;
        req_discard->nr_sectors         = Request->u.Discard.NrSectors;
        break;

    case BLKIF_OP_INDIRECT:
        req_indirect = (blkif_request_indirect_t*)req;
        req_indirect->operation         = BLKIF_OP_INDIRECT;
        req_indirect->indirect_op       = Request->u.Indirect.Operation;
        req_indirect->nr_segments       = Request->u.Indirect.NrSegments;
        req_indirect->id                = __BlockRingGetTag(BlockRing, Request);
        req_indirect->sector_number     = Request->u.Indirect.FirstSector;
        req_indirect->handle            = (USHORT)BlockRing->DeviceId;
        for (Index = 0; Index < BLKIF_MAX_INDIRECT_PAGES_PER_REQUEST; ++Index) {
            req_indirect->indirect_grefs[Index] = GranterReference(Granter, Request->u.Indirect.Grants[Index]);
        }
        break;

    default:
        ASSERT(FALSE);
        break;
    }
    ++BlockRing->Submitted;
    ++BlockRing->Outstanding;
}

NTSTATUS
BlockRingCreate(
    IN  PXENVBD_FRONTEND            Frontend,
    IN  ULONG                       DeviceId,
    OUT PXENVBD_BLOCKRING*          BlockRing
    )
{
    *BlockRing = __BlockRingAllocate(sizeof(XENVBD_BLOCKRING));
    if (*BlockRing == NULL)
        goto fail1;

    (*BlockRing)->Frontend = Frontend;
    (*BlockRing)->DeviceId = DeviceId;
    KeInitializeSpinLock(&(*BlockRing)->Lock);

    return STATUS_SUCCESS;

fail1:
    return STATUS_NO_MEMORY;
}

VOID
BlockRingDestroy(
    IN  PXENVBD_BLOCKRING           BlockRing
    )
{
    BlockRing->Frontend = NULL;
    BlockRing->DeviceId = 0;
    BlockRing->Order = 0;
    RtlZeroMemory(&BlockRing->Lock, sizeof(KSPIN_LOCK));
    
    ASSERT(IsZeroMemory(BlockRing, sizeof(XENVBD_BLOCKRING)));
    
    __BlockRingFree(BlockRing);
}

NTSTATUS
BlockRingConnect(
    IN  PXENVBD_BLOCKRING           BlockRing
    )
{
    NTSTATUS        status;
    PCHAR           Value;
    ULONG           Index, RingPages;
    PXENVBD_FDO     Fdo = PdoGetFdo(FrontendGetPdo(BlockRing->Frontend));
    PXENVBD_GRANTER Granter = FrontendGetGranter(BlockRing->Frontend);

    ASSERT(BlockRing->Connected == FALSE);

    BlockRing->StoreInterface = FdoAcquireStore(Fdo);

    status = FrontendStoreReadBackend(BlockRing->Frontend, "max-ring-page-order", &Value);
    if (NT_SUCCESS(status)) {
        BlockRing->Order = __min(strtoul(Value, NULL, 10), XENVBD_MAX_RING_PAGE_ORDER);
        FrontendStoreFree(BlockRing->Frontend, Value);
    } else {
        BlockRing->Order = 0;
    }

    status = STATUS_NO_MEMORY;
    BlockRing->SharedRing = __AllocPages((SIZE_T)PAGE_SIZE << BlockRing->Order, &BlockRing->Mdl);
    if (BlockRing->SharedRing == NULL)
        goto fail1;

#pragma warning(push)
#pragma warning(disable: 4305)
    SHARED_RING_INIT(BlockRing->SharedRing);
    FRONT_RING_INIT(&BlockRing->FrontRing, BlockRing->SharedRing, PAGE_SIZE << BlockRing->Order);
#pragma warning(pop)

    RingPages = (1 << BlockRing->Order);
    for (Index = 0; Index < RingPages; ++Index) {
        status = GranterGet(Granter, __Pfn((PUCHAR)BlockRing->SharedRing + (Index * PAGE_SIZE)), 
                                FALSE, &BlockRing->Grants[Index]);
        if (!NT_SUCCESS(status))
            goto fail2;
    }

    BlockRing->Connected = TRUE;
    return STATUS_SUCCESS;

fail2:
    for (Index = 0; Index < XENVBD_MAX_RING_PAGES; ++Index) {
        if (BlockRing->Grants[Index])
            GranterPut(Granter, BlockRing->Grants[Index]);
        BlockRing->Grants[Index] = 0;
    }

    RtlZeroMemory(&BlockRing->FrontRing, sizeof(BlockRing->FrontRing));
    __FreePages(BlockRing->SharedRing, BlockRing->Mdl);
    BlockRing->SharedRing = NULL;
    BlockRing->Mdl = NULL;

fail1:
    return status;
}

NTSTATUS
BlockRingStoreWrite(
    IN  PXENVBD_BLOCKRING           BlockRing,
    IN  PXENBUS_STORE_TRANSACTION   Transaction,
    IN  PCHAR                       FrontendPath
    )
{
    PXENVBD_GRANTER                 Granter = FrontendGetGranter(BlockRing->Frontend);
    NTSTATUS                        status;

    if (BlockRing->Order == 0) {
        status = STORE(Printf, 
                       BlockRing->StoreInterface, 
                        Transaction, 
                       FrontendPath,
                       "ring-ref", 
                       "%u", 
                       GranterReference(Granter, BlockRing->Grants[0]));
        if (!NT_SUCCESS(status))
            return status;
    } else {
        ULONG   Index, RingPages;

        status = STORE(Printf, 
                        BlockRing->StoreInterface, 
                        Transaction, 
                        FrontendPath, 
                        "ring-page-order", 
                        "%u", 
                        BlockRing->Order);
        if (!NT_SUCCESS(status))
            return status;

        RingPages = (1 << BlockRing->Order);
        for (Index = 0; Index < RingPages; ++Index) {
            CHAR    Name[MAX_NAME_LEN+1];
            status = RtlStringCchPrintfA(Name, MAX_NAME_LEN, "ring-ref%d", Index);
            if (!NT_SUCCESS(status))
                return status;
            status = STORE(Printf, 
                           BlockRing->StoreInterface, 
                           Transaction, 
                           FrontendPath,
                           Name, 
                           "%u", 
                           GranterReference(Granter, BlockRing->Grants[Index]));
            if (!NT_SUCCESS(status))
                return status;
        }
    }

    status = STORE(Write, 
                    BlockRing->StoreInterface, 
                    Transaction, 
                    FrontendPath,
                    "protocol", 
                    XEN_IO_PROTO_ABI);
    if (!NT_SUCCESS(status))
        return status;

    return STATUS_SUCCESS;
}

VOID
BlockRingEnable(
    IN  PXENVBD_BLOCKRING           BlockRing
    )
{
    ASSERT(BlockRing->Enabled == FALSE);

    BlockRing->Enabled = TRUE;
}

VOID
BlockRingDisable(
    IN  PXENVBD_BLOCKRING           BlockRing
    )
{
    ASSERT(BlockRing->Enabled == TRUE);

    BlockRing->Enabled = FALSE;
}

VOID
BlockRingDisconnect(
    IN  PXENVBD_BLOCKRING           BlockRing
    )
{
    ULONG           Index;
    PXENVBD_GRANTER Granter = FrontendGetGranter(BlockRing->Frontend);

    ASSERT(BlockRing->Connected == TRUE);

    for (Index = 0; Index < XENVBD_MAX_RING_PAGES; ++Index) {
        if (BlockRing->Grants[Index]) {
            GranterPut(Granter, BlockRing->Grants[Index]);
        }
        BlockRing->Grants[Index] = 0;
    }

    RtlZeroMemory(&BlockRing->FrontRing, sizeof(BlockRing->FrontRing));
    __FreePages(BlockRing->SharedRing, BlockRing->Mdl);
    BlockRing->SharedRing = NULL;
    BlockRing->Mdl = NULL;

    STORE(Release, BlockRing->StoreInterface);
    BlockRing->StoreInterface = NULL;

    BlockRing->Connected = FALSE;
}

VOID
BlockRingDebugCallback(
    IN  PXENVBD_BLOCKRING           BlockRing,
    IN  PXENBUS_DEBUG_INTERFACE     Debug,
    IN  PXENBUS_DEBUG_CALLBACK      Callback
    )
{
    ULONG   Index;

    DEBUG(Printf, Debug, Callback,
            "BLOCKRING: Requests : %d / %d / %d\n", 
            BlockRing->Outstanding,
            BlockRing->Submitted,
            BlockRing->Recieved);

    DEBUG(Printf, Debug, Callback,
            "BLOCKRING: SharedRing : 0x%p\n", 
            BlockRing->SharedRing);

    if (BlockRing->SharedRing) {
        DEBUG(Printf, Debug, Callback,
                "BLOCKRING: SharedRing : %d / %d - %d / %d\n",
                BlockRing->SharedRing->req_prod, 
                BlockRing->SharedRing->req_event, 
                BlockRing->SharedRing->rsp_prod, 
                BlockRing->SharedRing->rsp_event);
    }

    DEBUG(Printf, Debug, Callback,
            "BLOCKRING: FrontRing : %d / %d (%d)\n", 
            BlockRing->FrontRing.req_prod_pvt,
            BlockRing->FrontRing.rsp_cons, 
            BlockRing->FrontRing.nr_ents);

    DEBUG(Printf, Debug, Callback,
            "BLOCKRING: Order : %d\n", 
            BlockRing->Order);
    for (Index = 0; Index < (1ul << BlockRing->Order); ++Index) {
        DEBUG(Printf, Debug, Callback,
                "BLOCKRING: Grants[%-2d] : %d\n", 
                Index, BlockRing->Grants[Index]);
    }

    BlockRing->Submitted = BlockRing->Recieved = 0;
}

VOID
BlockRingPoll(
    IN  PXENVBD_BLOCKRING           BlockRing
    )
{
    PXENVBD_PDO Pdo = FrontendGetPdo(BlockRing->Frontend);

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);
    KeAcquireSpinLockAtDpcLevel(&BlockRing->Lock);

    // Guard against this locked region being called after the 
    // lock on FrontendSetState
    if (BlockRing->Enabled == FALSE)
        goto done;

    for (;;) {
        ULONG   rsp_prod;
        ULONG   rsp_cons;

        KeMemoryBarrier();

        rsp_prod = BlockRing->SharedRing->rsp_prod;
        rsp_cons = BlockRing->FrontRing.rsp_cons;

        KeMemoryBarrier();

        if (rsp_cons == rsp_prod)
            break;

        while (rsp_cons != rsp_prod) {
            blkif_response_t*   Response;
            PXENVBD_REQUEST     Request;

            Response = RING_GET_RESPONSE(&BlockRing->FrontRing, rsp_cons);
            ++rsp_cons;

            Request = __BlockRingPutTag(BlockRing, Response->id);
            if (Request) {
                ++BlockRing->Recieved;
                --BlockRing->Outstanding;
                PdoCompleteSubmitted(Pdo, Request, Response->status);
            }

            RtlZeroMemory(Response, sizeof(union blkif_sring_entry));
        }

        KeMemoryBarrier();

        BlockRing->FrontRing.rsp_cons = rsp_cons;
        BlockRing->SharedRing->rsp_event = rsp_cons + 1;
    }

done:
    KeReleaseSpinLockFromDpcLevel(&BlockRing->Lock);
}

BOOLEAN
BlockRingSubmit(
    IN  PXENVBD_BLOCKRING           BlockRing,
    IN  PXENVBD_REQUEST             Request
    )
{
    KIRQL               Irql;
    blkif_request_t*    req;

    KeAcquireSpinLock(&BlockRing->Lock, &Irql);
    if (RING_FULL(&BlockRing->FrontRing)) {
        KeReleaseSpinLock(&BlockRing->Lock, Irql);
        return FALSE;
    }

    req = RING_GET_REQUEST(&BlockRing->FrontRing, BlockRing->FrontRing.req_prod_pvt);
    __BlockRingInsert(BlockRing, Request, req);
    KeMemoryBarrier();
    ++BlockRing->FrontRing.req_prod_pvt;

    KeReleaseSpinLock(&BlockRing->Lock, Irql);
    return TRUE;
}

BOOLEAN
BlockRingPush(
    IN  PXENVBD_BLOCKRING           BlockRing
    )
{
    BOOLEAN Notify;

    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&BlockRing->FrontRing, Notify);
    
    return Notify;
}

