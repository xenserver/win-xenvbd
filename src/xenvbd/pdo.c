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
#include "srbext.h"
#include "buffer.h"
#include "pdo-inquiry.h"
#include "debug.h"
#include "assert.h"
#include "util.h"
#include <xencdb.h>
#include <names.h>
#include <store_interface.h>
#include <evtchn_interface.h>
#include <gnttab_interface.h>
#include <debug_interface.h>
#include <suspend_interface.h>

typedef struct _XENVBD_SG_LIST {
    // SGList from SRB
    PSTOR_SCATTER_GATHER_LIST   SGList;
    // "current" values
    STOR_PHYSICAL_ADDRESS       PhysAddr;
    ULONG                       PhysLen;
    // iteration
    ULONG                       Index;
    ULONG                       Offset;
    ULONG                       Length;
} XENVBD_SG_LIST, *PXENVBD_SG_LIST;

#define PDO_SIGNATURE           'odpX'

typedef struct _XENVBD_LOOKASIDE {
    KEVENT                      Empty;
    LONG                        Used;
    LONG                        Max;
    ULONG                       Failed;
    ULONG                       Size;
    NPAGED_LOOKASIDE_LIST       List;
} XENVBD_LOOKASIDE, *PXENVBD_LOOKASIDE;

struct _XENVBD_PDO {
    ULONG                       Signature;
    PXENVBD_FDO                 Fdo;
    PDEVICE_OBJECT              DeviceObject;
    KEVENT                      RemoveEvent;
    LONG                        ReferenceCount;
    DEVICE_PNP_STATE            DevicePnpState;
    DEVICE_PNP_STATE            PrevPnpState;
    DEVICE_POWER_STATE          DevicePowerState;
    KSPIN_LOCK                  Lock;

    // Frontend (Ring, includes XenBus interfaces)
    PXENVBD_FRONTEND            Frontend;
    XENVBD_DEVICE_TYPE          DeviceType;

    // State
    BOOLEAN                     EmulatedUnplugged;
    LONG                        Paused;

    // Eject
    BOOLEAN                     WrittenEjected;
    BOOLEAN                     EjectRequested;
    BOOLEAN                     EjectPending;
    BOOLEAN                     Missing;
    const CHAR*                 Reason;

    // SRBs
    XENVBD_LOOKASIDE            SegmentList;
    XENVBD_LOOKASIDE            MappingList;
    XENVBD_LOOKASIDE            RequestList;
    XENVBD_QUEUE                FreshSrbs;
    XENVBD_QUEUE                PreparedReqs;
    XENVBD_QUEUE                SubmittedReqs;
    XENVBD_QUEUE                ShutdownSrbs;

    // Stats - SRB Counts by BLKIF_OP_
    ULONG                       BlkOpRead;
    ULONG                       BlkOpWrite;
    ULONG                       BlkOpIndirectRead;
    ULONG                       BlkOpIndirectWrite;
    ULONG                       BlkOpBarrier;
    ULONG                       BlkOpDiscard;
    // Stats - Failures
    ULONG                       FailedMaps;
    ULONG                       FailedBounces;
    ULONG                       FailedGrants;
    // Stats - Segments
    ULONG64                     SegsGranted;
    ULONG64                     SegsBounced;
};

//=============================================================================
#define PDO_POOL_TAG            'odPX'
#define REQUEST_POOL_TAG        'qeRX'
#define SEGMENT_POOL_TAG        'geSX'
#define MAPPING_POOL_TAG        'paMX'
#define SEGMENTS_PER_PAGE       (PAGE_SIZE / sizeof(XENVBD_SEGMENT))
#define SEGMENT_LIST_SIZE       (SEGMENTS_PER_PAGE * sizeof(XENVBD_SEGMENT))
#define MAPPING_LIST_SIZE       (SEGMENTS_PER_PAGE * sizeof(XENVBD_MAPPING))

__checkReturn
__drv_allocatesMem(mem)
__bcount(Size)
static FORCEINLINE PVOID
#pragma warning(suppress: 28195)
___PdoAlloc(
    __in PCHAR                   Caller,
    __in ULONG                   Line,
    __in ULONG                   Size
    )
{
    return __AllocateNonPagedPoolWithTag(Caller, Line, Size, PDO_POOL_TAG);
}
#define __PdoAlloc(Size) ___PdoAlloc(__FUNCTION__, __LINE__, Size)

static FORCEINLINE VOID
#pragma warning(suppress: 28197)
__PdoFree(
    __in __drv_freesMem(mem) PVOID Buffer
    )
{
    if (Buffer)
        __FreePoolWithTag(Buffer, PDO_POOL_TAG);
}

//=============================================================================
// Debug
static FORCEINLINE PCHAR
__PnpStateName(
    __in DEVICE_PNP_STATE        State
    )
{
    switch (State) {
    case Invalid:               return "Invalid";
    case Present:               return "Present";
    case Enumerated:            return "Enumerated";
    case Added:                 return "Added";
    case Started:               return "Started";
    case StopPending:           return "StopPending";
    case Stopped:               return "Stopped";
    case RemovePending:         return "RemovePending";
    case SurpriseRemovePending: return "SurpriseRemovePending";
    case Deleted:               return "Deleted";
    default:                    return "UNKNOWN";
    }
}

static FORCEINLINE VOID
__LookasideDebug(
    IN  PXENVBD_LOOKASIDE           Lookaside,
    IN  PXENBUS_DEBUG_INTERFACE     Debug,
    IN  PXENBUS_DEBUG_CALLBACK      Callback,
    IN  PCHAR                       Name
    )
{
    DEBUG(Printf, Debug, Callback,
          "PDO: %s: %u / %u (%u failed)\n",
          Name, Lookaside->Used,
          Lookaside->Max, Lookaside->Failed);

    Lookaside->Max = Lookaside->Used;
    Lookaside->Failed = 0;
}

DECLSPEC_NOINLINE VOID
PdoDebugCallback(
    __in PXENVBD_PDO Pdo,
    __in PXENBUS_DEBUG_INTERFACE DebugInterface,
    __in PXENBUS_DEBUG_CALLBACK  DebugCallback
    )
{
    if (Pdo == NULL || DebugInterface == NULL || DebugCallback == NULL)
        return;
    if (Pdo->Signature != PDO_SIGNATURE)
        return;

    DEBUG(Printf, DebugInterface, DebugCallback,
          "PDO: Fdo 0x%p DeviceObject 0x%p\n",
          Pdo->Fdo,
          Pdo->DeviceObject);
    DEBUG(Printf, DebugInterface, DebugCallback,
          "PDO: ReferenceCount %d\n",
          Pdo->ReferenceCount);
    DEBUG(Printf, DebugInterface, DebugCallback,
          "PDO: DevicePnpState %s (%s)\n",
          __PnpStateName(Pdo->DevicePnpState),
          __PnpStateName(Pdo->PrevPnpState));
    DEBUG(Printf, DebugInterface, DebugCallback,
          "PDO: DevicePowerState %s\n",
          PowerDeviceStateName(Pdo->DevicePowerState));
    DEBUG(Printf, DebugInterface, DebugCallback,
          "PDO: %s %s\n",
          Pdo->EmulatedUnplugged ? "PV" : "EMULATED",
          Pdo->Missing ? Pdo->Reason : "Not Missing");

    DEBUG(Printf, DebugInterface, DebugCallback,
          "PDO: BLKIF_OPs: READ=%u WRITE=%u\n",
          Pdo->BlkOpRead, Pdo->BlkOpWrite);
    DEBUG(Printf, DebugInterface, DebugCallback,
          "PDO: BLKIF_OPs: INDIRECT_READ=%u INDIRECT_WRITE=%u\n",
          Pdo->BlkOpIndirectRead, Pdo->BlkOpIndirectWrite);
    DEBUG(Printf, DebugInterface, DebugCallback,
          "PDO: BLKIF_OPs: BARRIER=%u DISCARD=%u\n",
          Pdo->BlkOpBarrier, Pdo->BlkOpDiscard);
    DEBUG(Printf, DebugInterface, DebugCallback,
          "PDO: Failed: Maps=%u Bounces=%u Grants=%u\n",
          Pdo->FailedMaps, Pdo->FailedBounces, Pdo->FailedGrants);
    DEBUG(Printf, DebugInterface, DebugCallback,
          "PDO: Segments Granted=%llu Bounced=%llu\n",
          Pdo->SegsGranted, Pdo->SegsBounced);

    __LookasideDebug(&Pdo->RequestList, DebugInterface, DebugCallback, "REQUESTs");
    __LookasideDebug(&Pdo->SegmentList, DebugInterface, DebugCallback, "SEGMENTs");
    __LookasideDebug(&Pdo->MappingList, DebugInterface, DebugCallback, "MAPPINGs");

    FrontendDebugCallback(Pdo->Frontend, DebugInterface, DebugCallback);
    QueueDebugCallback(&Pdo->FreshSrbs,    "Fresh    ", DebugInterface, DebugCallback);
    QueueDebugCallback(&Pdo->PreparedReqs, "Prepared ", DebugInterface, DebugCallback);
    QueueDebugCallback(&Pdo->SubmittedReqs, "Submitted", DebugInterface, DebugCallback);
    QueueDebugCallback(&Pdo->ShutdownSrbs, "Shutdown ", DebugInterface, DebugCallback);

    Pdo->BlkOpRead = Pdo->BlkOpWrite = 0;
    Pdo->BlkOpIndirectRead = Pdo->BlkOpIndirectWrite = 0;
    Pdo->BlkOpBarrier = Pdo->BlkOpDiscard = 0;
    Pdo->FailedMaps = Pdo->FailedBounces = Pdo->FailedGrants = 0;
    Pdo->SegsGranted = Pdo->SegsBounced = 0;
}

//=============================================================================
// Power States
__checkReturn
static FORCEINLINE BOOLEAN
PdoSetDevicePowerState(
    __in PXENVBD_PDO             Pdo,
    __in DEVICE_POWER_STATE      State
    )
{
    KIRQL       Irql;
    BOOLEAN     Changed = FALSE;

    KeAcquireSpinLock(&Pdo->Lock, &Irql);
    if (Pdo->DevicePowerState != State) {
        Verbose("Target[%d] : POWER %s to %s\n", PdoGetTargetId(Pdo), PowerDeviceStateName(Pdo->DevicePowerState), PowerDeviceStateName(State));
        Pdo->DevicePowerState = State;
        Changed = TRUE;
    }
    KeReleaseSpinLock(&Pdo->Lock, Irql);
    
    return Changed;
}

//=============================================================================
// PnP States
FORCEINLINE VOID
PdoSetMissing(
    __in PXENVBD_PDO             Pdo,
    __in __nullterminated const CHAR* Reason
    )
{
    KIRQL   Irql;

    ASSERT3P(Reason, !=, NULL);

    KeAcquireSpinLock(&Pdo->Lock, &Irql);
    if (Pdo->Missing) {
        Verbose("Target[%d] : Already MISSING (%s) when trying to set (%s)\n", PdoGetTargetId(Pdo), Pdo->Reason, Reason);
    } else {
        Verbose("Target[%d] : MISSING %s\n", PdoGetTargetId(Pdo), Reason);
        Pdo->Missing = TRUE;
        Pdo->Reason = Reason;
    }
    KeReleaseSpinLock(&Pdo->Lock, Irql);
}

__checkReturn
FORCEINLINE BOOLEAN
PdoIsMissing(
    __in PXENVBD_PDO             Pdo
    )
{
    KIRQL   Irql;
    BOOLEAN Missing;

    KeAcquireSpinLock(&Pdo->Lock, &Irql);
    Missing = Pdo->Missing;
    KeReleaseSpinLock(&Pdo->Lock, Irql);

    return Missing;
}

FORCEINLINE const CHAR*
PdoMissingReason(
    __in PXENVBD_PDO            Pdo
    )
{
    KIRQL       Irql;
    const CHAR* Reason;

    KeAcquireSpinLock(&Pdo->Lock, &Irql);
    Reason = Pdo->Reason;
    KeReleaseSpinLock(&Pdo->Lock, Irql);

    return Reason;
}

__checkReturn
FORCEINLINE BOOLEAN
PdoIsEmulatedUnplugged(
    __in PXENVBD_PDO             Pdo
    )
{
    return Pdo->EmulatedUnplugged;
}

FORCEINLINE VOID
PdoSetDevicePnpState(
    __in PXENVBD_PDO             Pdo,
    __in DEVICE_PNP_STATE        State
    )
{
    ASSERT(Pdo->DevicePnpState != Deleted || State == Deleted);
    Verbose("Target[%d] : PNP %s to %s\n", PdoGetTargetId(Pdo), __PnpStateName(Pdo->DevicePnpState), __PnpStateName(State));
    Pdo->PrevPnpState = Pdo->DevicePnpState;
    Pdo->DevicePnpState = State;
}

__checkReturn
FORCEINLINE DEVICE_PNP_STATE
PdoGetDevicePnpState(
    __in PXENVBD_PDO             Pdo
    )
{
    return Pdo->DevicePnpState;
}

static FORCEINLINE VOID
__PdoRestoreDevicePnpState(
    __in PXENVBD_PDO             Pdo,
    __in DEVICE_PNP_STATE        State
    )
{
    if (Pdo->DevicePnpState == State) {
        Verbose("Target[%d] : PNP %s to %s\n", PdoGetTargetId(Pdo), __PnpStateName(Pdo->DevicePnpState), __PnpStateName(Pdo->PrevPnpState));
        Pdo->DevicePnpState = Pdo->PrevPnpState;
    }
}

__drv_maxIRQL(APC_LEVEL)
static FORCEINLINE VOID
__PdoPauseDataPath(
    __in PXENVBD_PDO             Pdo
    )
{
    KIRQL               Irql;
    LARGE_INTEGER       Timeout;
    PXENVBD_NOTIFIER    Notifier = FrontendGetNotifier(Pdo->Frontend);

    KeAcquireSpinLock(&Pdo->Lock, &Irql);
    ++Pdo->Paused;
    KeReleaseSpinLock(&Pdo->Lock, Irql);

    Verbose("Target[%d] : Waiting for %d Submitted requests\n", PdoGetTargetId(Pdo), QueueCount(&Pdo->SubmittedReqs));

    Timeout.QuadPart = -10000000;
    while (QueueCount(&Pdo->SubmittedReqs)) {
        NotifierSend(Notifier); // let backend know it needs to do some work
        KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
    }
}

static FORCEINLINE VOID
__PdoUnpauseDataPath(
    __in PXENVBD_PDO             Pdo
    )
{
    KIRQL   Irql;

    KeAcquireSpinLock(&Pdo->Lock, &Irql);
    --Pdo->Paused;
    KeReleaseSpinLock(&Pdo->Lock, Irql);
}

static FORCEINLINE VOID
__LookasideInit(
    IN OUT  PXENVBD_LOOKASIDE   Lookaside,
    IN  ULONG                   Size,
    IN  ULONG                   Tag
    )
{
    RtlZeroMemory(Lookaside, sizeof(XENVBD_LOOKASIDE));
    Lookaside->Size = Size;
    KeInitializeEvent(&Lookaside->Empty, SynchronizationEvent, TRUE);
    ExInitializeNPagedLookasideList(&Lookaside->List, NULL, NULL, 0,
                                    Size, Tag, 0);
}

static FORCEINLINE VOID
__LookasideTerm(
    IN  PXENVBD_LOOKASIDE       Lookaside
    )
{
    ASSERT3U(Lookaside->Used, ==, 0);
    ExDeleteNPagedLookasideList(&Lookaside->List);
    RtlZeroMemory(Lookaside, sizeof(XENVBD_LOOKASIDE));
}

static FORCEINLINE PVOID
__LookasideAlloc(
    IN  PXENVBD_LOOKASIDE       Lookaside
    )
{
    LONG    Result;
    PVOID   Buffer;

    Buffer = ExAllocateFromNPagedLookasideList(&Lookaside->List);
    if (Buffer == NULL) {
        ++Lookaside->Failed;
        return NULL;
    }

    RtlZeroMemory(Buffer, Lookaside->Size);
    Result = InterlockedIncrement(&Lookaside->Used);
    ASSERT3S(Result, >, 0);
    if (Result > Lookaside->Max)
        Lookaside->Max = Result;
    KeClearEvent(&Lookaside->Empty);

    return Buffer;
}

static FORCEINLINE VOID
__LookasideFree(
    IN  PXENVBD_LOOKASIDE       Lookaside,
    IN  PVOID                   Buffer
    )
{
    LONG            Result;

    ExFreeToNPagedLookasideList(&Lookaside->List, Buffer);
    Result = InterlockedDecrement(&Lookaside->Used);
    ASSERT3S(Result, >=, 0);
        
    if (Result == 0) {
        KeSetEvent(&Lookaside->Empty, IO_NO_INCREMENT, FALSE);
    }
}

//=============================================================================
// Creation/Deletion
__checkReturn
NTSTATUS
PdoCreate(
    __in PXENVBD_FDO             Fdo,
    __in __nullterminated PCHAR  DeviceId,
    __in ULONG                   TargetId,
    __in BOOLEAN                 EmulatedUnplugged,
    __in PKEVENT                 FrontendEvent,
    __in XENVBD_DEVICE_TYPE      DeviceType
    )
{
    NTSTATUS    Status;
    PXENVBD_PDO Pdo;

    Trace("Target[%d] @ (%d) =====>\n", TargetId, KeGetCurrentIrql());

    Status = STATUS_INSUFFICIENT_RESOURCES;
#pragma warning(suppress: 6014)
    Pdo = __PdoAlloc(sizeof(XENVBD_PDO));
    if (!Pdo)
        goto fail1;

    Verbose("Target[%d] : Creating (%s)\n", TargetId, EmulatedUnplugged ? "PV" : "Emulated");
    Pdo->Signature      = PDO_SIGNATURE;
    Pdo->Fdo            = Fdo;
    Pdo->DeviceObject   = NULL; // filled in later
    KeInitializeEvent(&Pdo->RemoveEvent, SynchronizationEvent, FALSE);
    Pdo->ReferenceCount = 1;
    Pdo->Paused         = 1; // Paused until D3->D0 transition
    Pdo->DevicePnpState = Present;
    Pdo->DevicePowerState = PowerDeviceD3;
    Pdo->EmulatedUnplugged = EmulatedUnplugged;
    Pdo->DeviceType     = DeviceType;

    KeInitializeSpinLock(&Pdo->Lock);
    QueueInit(&Pdo->FreshSrbs);
    QueueInit(&Pdo->PreparedReqs);
    QueueInit(&Pdo->SubmittedReqs);
    QueueInit(&Pdo->ShutdownSrbs);

    Status = FrontendCreate(Pdo, DeviceId, TargetId, FrontendEvent, &Pdo->Frontend);
    if (!NT_SUCCESS(Status))
        goto fail2;

    __LookasideInit(&Pdo->RequestList, sizeof(XENVBD_REQUEST), REQUEST_POOL_TAG);
    __LookasideInit(&Pdo->SegmentList, SEGMENT_LIST_SIZE, SEGMENT_POOL_TAG);
    __LookasideInit(&Pdo->MappingList, MAPPING_LIST_SIZE, MAPPING_POOL_TAG);

    Status = PdoD3ToD0(Pdo);
    if (!NT_SUCCESS(Status))
        goto fail3;

    if (!FdoLinkPdo(Fdo, Pdo))
        goto fail4;

    Verbose("Target[%d] : Created (%s)\n", TargetId, EmulatedUnplugged ? "PV" : "Emulated");
    Trace("Target[%d] @ (%d) <=====\n", TargetId, KeGetCurrentIrql());
    return STATUS_SUCCESS;

fail4:
    Error("Fail4\n");
    PdoD0ToD3(Pdo);

fail3:
    Error("Fail3\n");
    __LookasideTerm(&Pdo->MappingList);
    __LookasideTerm(&Pdo->SegmentList);
    __LookasideTerm(&Pdo->RequestList);
    FrontendDestroy(Pdo->Frontend);
    Pdo->Frontend = NULL;

fail2:
    Error("Fail2\n");
    __PdoFree(Pdo);

fail1:
    Error("Fail1 (%08x)\n", Status);
    return Status;
}

VOID
PdoDestroy(
    __in PXENVBD_PDO             Pdo
    )
{
    const ULONG TargetId = PdoGetTargetId(Pdo);
    PVOID       Objects[4];

    Trace("Target[%d] @ (%d) =====>\n", TargetId, KeGetCurrentIrql());
    Verbose("Target[%d] : Destroying\n", TargetId);

    ASSERT3U(Pdo->Signature, ==, PDO_SIGNATURE);
    if (!FdoUnlinkPdo(PdoGetFdo(Pdo), Pdo)) {
        Error("Target[%d] : PDO 0x%p not linked to FDO 0x%p\n", TargetId, Pdo, PdoGetFdo(Pdo));
    }

    PdoD0ToD3(Pdo);
    PdoDereference(Pdo); // drop initial ref count

    // Wait for ReferenceCount == 0 and RequestListUsed == 0
    Verbose("Target[%d] : ReferenceCount %d, RequestListUsed %d\n", TargetId, Pdo->ReferenceCount, Pdo->RequestList.Used);
    Objects[0] = &Pdo->RemoveEvent;
    Objects[1] = &Pdo->RequestList.Empty;
    Objects[2] = &Pdo->SegmentList.Empty;
    Objects[3] = &Pdo->MappingList.Empty;
    KeWaitForMultipleObjects(4, Objects, WaitAll, Executive, KernelMode, FALSE, NULL, NULL);
    ASSERT3S(Pdo->ReferenceCount, ==, 0);
    ASSERT3U(PdoGetDevicePnpState(Pdo), ==, Deleted);

    __LookasideTerm(&Pdo->MappingList);
    __LookasideTerm(&Pdo->SegmentList);
    __LookasideTerm(&Pdo->RequestList);

    FrontendDestroy(Pdo->Frontend);
    Pdo->Frontend = NULL;

    ASSERT3U(Pdo->Signature, ==, PDO_SIGNATURE);
    RtlZeroMemory(Pdo, sizeof(XENVBD_PDO));
    __PdoFree(Pdo);

    Verbose("Target[%d] : Destroyed\n", TargetId);
    Trace("Target[%d] @ (%d) <=====\n", TargetId, KeGetCurrentIrql());
}

__checkReturn
NTSTATUS
PdoD3ToD0(
    __in PXENVBD_PDO             Pdo
    )
{
    NTSTATUS    Status;
    const ULONG TargetId = PdoGetTargetId(Pdo);

    if (!PdoSetDevicePowerState(Pdo, PowerDeviceD0))
        return STATUS_SUCCESS;

    Trace("Target[%d] @ (%d) =====>\n", TargetId, KeGetCurrentIrql());
    Verbose("Target[%d] : D3->D0 (%s)\n", TargetId, Pdo->EmulatedUnplugged ? "PV" : "Emulated");

    // power up frontend
    Status = FrontendD3ToD0(Pdo->Frontend);
    if (!NT_SUCCESS(Status))
        goto fail1;
    
    // connect frontend
    if (Pdo->EmulatedUnplugged) {
        Status = FrontendSetState(Pdo->Frontend, XENVBD_ENABLED);
        if (!NT_SUCCESS(Status))
            goto fail2;
        __PdoUnpauseDataPath(Pdo);
    }

    Trace("Target[%d] @ (%d) <=====\n", TargetId, KeGetCurrentIrql());
    return STATUS_SUCCESS;

fail2:
    Error("Fail2\n");
    FrontendD0ToD3(Pdo->Frontend);

fail1:
    Error("Fail1 (%08x)\n", Status);

    Pdo->DevicePowerState = PowerDeviceD3;

    return Status;
}

VOID
PdoD0ToD3(
    __in PXENVBD_PDO             Pdo
    )
{
    const ULONG TargetId = PdoGetTargetId(Pdo);

    if (!PdoSetDevicePowerState(Pdo, PowerDeviceD3))
        return;

    Trace("Target[%d] @ (%d) =====>\n", TargetId, KeGetCurrentIrql());
    Verbose("Target[%d] : D0->D3 (%s)\n", TargetId, Pdo->EmulatedUnplugged ? "PV" : "Emulated");

    // close frontend
    if (Pdo->EmulatedUnplugged) {
        __PdoPauseDataPath(Pdo);
        (VOID) FrontendSetState(Pdo->Frontend, XENVBD_CLOSED);
        PdoAbortAllSrbs(Pdo);
        ASSERT3U(QueueCount(&Pdo->SubmittedReqs), ==, 0);
    }

    // power down frontend
    FrontendD0ToD3(Pdo->Frontend);

    Trace("Target[%d] @ (%d) <=====\n", TargetId, KeGetCurrentIrql());
}

__drv_requiresIRQL(DISPATCH_LEVEL)
VOID
PdoBackendPathChanged(
    __in PXENVBD_PDO             Pdo
    )
{
    FrontendBackendPathChanged(Pdo->Frontend);
}

//=============================================================================
// Reference Counting
FORCEINLINE LONG
__PdoReference(
    __in PXENVBD_PDO             Pdo,
    __in PCHAR                   Caller
    )
{
    LONG Result;

    ASSERT3P(Pdo, !=, NULL);
    Result = InterlockedIncrement(&Pdo->ReferenceCount);
    ASSERTREFCOUNT(Result, >, 0, Caller);

    if (Result == 1) {
        Result = InterlockedDecrement(&Pdo->ReferenceCount);
        Error("Target[%d] : %s: Attempting to take reference of removed PDO from %d\n", PdoGetTargetId(Pdo), Caller, Result);
        return 0;
    } else {
        ASSERTREFCOUNT(Result, >, 1, Caller);
        return Result;
    }
}

FORCEINLINE LONG
__PdoDereference(
    __in PXENVBD_PDO             Pdo,
    __in PCHAR                   Caller
    )
{
    LONG    Result;
    
    ASSERT3P(Pdo, !=, NULL);
    Result = InterlockedDecrement(&Pdo->ReferenceCount);
    ASSERTREFCOUNT(Result, >=, 0, Caller);
    
    if (Result == 0) {
        Verbose("Final ReferenceCount dropped, Target[%d] able to be removed\n", PdoGetTargetId(Pdo));
        KeSetEvent(&Pdo->RemoveEvent, IO_NO_INCREMENT, FALSE);
    }
    return Result;
}

//=============================================================================
// Query Methods
FORCEINLINE ULONG
PdoGetTargetId(
    __in PXENVBD_PDO             Pdo
    )
{
    ASSERT3P(Pdo, !=, NULL);
    return FrontendGetTargetId(Pdo->Frontend);
}

__checkReturn
FORCEINLINE PDEVICE_OBJECT
PdoGetDeviceObject(
    __in PXENVBD_PDO             Pdo
    )
{
    ASSERT3P(Pdo, !=, NULL);
    return Pdo->DeviceObject;
}

FORCEINLINE VOID
PdoSetDeviceObject(
    __in PXENVBD_PDO             Pdo,
    __in PDEVICE_OBJECT          DeviceObject
    )
{
    Verbose("Target[%d] : Setting DeviceObject = 0x%p\n", PdoGetTargetId(Pdo), DeviceObject);

    ASSERT3P(Pdo->DeviceObject, ==, NULL);
    Pdo->DeviceObject = DeviceObject;
}

__checkReturn
FORCEINLINE BOOLEAN
PdoIsPaused(
    __in PXENVBD_PDO             Pdo
    )
{
    BOOLEAN Paused;
    KIRQL   Irql;

    KeAcquireSpinLock(&Pdo->Lock, &Irql);
    Paused = (Pdo->Paused > 0);
    KeReleaseSpinLock(&Pdo->Lock, Irql);
    
    return Paused;
}

__checkReturn
FORCEINLINE ULONG
PdoOutstandingReqs(
    __in PXENVBD_PDO             Pdo
    )
{
    return QueueCount(&Pdo->SubmittedReqs);
}

__checkReturn
FORCEINLINE PXENVBD_FDO
PdoGetFdo( 
    __in PXENVBD_PDO             Pdo
    )
{
    return Pdo->Fdo;
}

FORCEINLINE ULONG
PdoSectorSize(
    __in PXENVBD_PDO             Pdo
    )
{
    return FrontendGetDiskInfo(Pdo->Frontend)->SectorSize;
}

//=============================================================================

static FORCEINLINE VOID
__PdoIncBlkifOpCount(
    __in PXENVBD_PDO             Pdo,
    __in PXENVBD_REQUEST         Request
    )
{
    switch (Request->Operation) {
    case BLKIF_OP_READ:             ++Pdo->BlkOpRead;       break;
    case BLKIF_OP_WRITE:            ++Pdo->BlkOpWrite;      break;
    case BLKIF_OP_WRITE_BARRIER:    ++Pdo->BlkOpBarrier;    break;
    case BLKIF_OP_DISCARD:          ++Pdo->BlkOpDiscard;    break;
    case BLKIF_OP_INDIRECT:
        switch (Request->u.Indirect.Operation) {
        case BLKIF_OP_READ:         ++Pdo->BlkOpIndirectRead;   break;
        case BLKIF_OP_WRITE:        ++Pdo->BlkOpIndirectWrite;  break;
        default:                    ASSERT(FALSE);              break;
        }
        break;
    default:                        ASSERT(FALSE);          break;
    }
}

static FORCEINLINE ULONG
__SectorsPerPage(
    __in ULONG                   SectorSize
    )
{
    ASSERT3U(SectorSize, !=, 0);
    return PAGE_SIZE / SectorSize;
}

static FORCEINLINE VOID
__Operation(
    __in UCHAR                   CdbOp,
    __out PUCHAR                 RingOp,
    __out PBOOLEAN               ReadOnly
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
    __in STOR_PHYSICAL_ADDRESS   PhysAddr
    )
{
    return (ULONG)(PhysAddr.QuadPart & (PAGE_SIZE - 1));
}

static FORCEINLINE PFN_NUMBER
__Phys2Pfn(
    __in STOR_PHYSICAL_ADDRESS   PhysAddr
    )
{
    return (PFN_NUMBER)(PhysAddr.QuadPart >> PAGE_SHIFT);
}

extern PHYSICAL_ADDRESS MmGetPhysicalAddress(PVOID);

static FORCEINLINE PFN_NUMBER
__Virt2Pfn(
    __in PVOID                   VirtAddr
    )
{
    return (PFN_NUMBER)(MmGetPhysicalAddress(VirtAddr).QuadPart >> PAGE_SHIFT);
}

static FORCEINLINE MM_PAGE_PRIORITY
__PdoPriority(
    __in PXENVBD_PDO             Pdo
    )
{
    PXENVBD_CAPS   Caps = FrontendGetCaps(Pdo->Frontend);
    if (!(Caps->Paging || 
          Caps->Hibernation || 
          Caps->DumpFile))
        return NormalPagePriority;

    return HighPagePriority;
}

static FORCEINLINE VOID
SGListGet(
    IN OUT  PXENVBD_SG_LIST         SGList
    )
{
    PSTOR_SCATTER_GATHER_ELEMENT    SGElement;

    ASSERT3U(SGList->Index, <, SGList->SGList->NumberOfElements);

    SGElement = &SGList->SGList->List[SGList->Index];

    SGList->PhysAddr.QuadPart = SGElement->PhysicalAddress.QuadPart + SGList->Offset;
    SGList->PhysLen           = __min(PAGE_SIZE - __Offset(SGList->PhysAddr) - SGList->Length, SGElement->Length - SGList->Offset);

    ASSERT3U(SGList->PhysLen, <=, PAGE_SIZE);
    ASSERT3U(SGList->Offset, <, SGElement->Length);

    SGList->Length = SGList->PhysLen; // gets reset every time for Granted, every 1or2 times for Bounced
    SGList->Offset = SGList->Offset + SGList->PhysLen;
    if (SGList->Offset >= SGElement->Length) {
        SGList->Index  = SGList->Index + 1;
        SGList->Offset = 0;
    }
}

static FORCEINLINE BOOLEAN
SGListNext(
    IN OUT  PXENVBD_SG_LIST         SGList,
    IN  ULONG                       AlignmentMask
    )
{
    SGList->Length = 0;
    SGListGet(SGList);  // get next PhysAddr and PhysLen
    return !((SGList->PhysAddr.QuadPart & AlignmentMask) || (SGList->PhysLen & AlignmentMask));
}

static FORCEINLINE BOOLEAN
MapSegmentBuffer(
    IN  PXENVBD_PDO             Pdo,
    IN  PXENVBD_MAPPING         Mapping,
    IN  PXENVBD_SG_LIST         SGList,
    IN  ULONG                   SectorSize,
    IN  ULONG                   SectorsNow
    )
{
    PMDL    Mdl;

    // map PhysAddr to 1 or 2 pages and lock for VirtAddr
#pragma warning(push)
#pragma warning(disable:28145)
    Mdl = &Mapping->Mdl;
    Mdl->Next           = NULL;
    Mdl->Size           = (SHORT)(sizeof(MDL) + sizeof(PFN_NUMBER));
    Mdl->MdlFlags       = MDL_PAGES_LOCKED;
    Mdl->Process        = NULL;
    Mdl->MappedSystemVa = NULL;
    Mdl->StartVa        = NULL;
    Mdl->ByteCount      = SGList->PhysLen;
    Mdl->ByteOffset     = __Offset(SGList->PhysAddr);
    Mapping->Pfn[0]     = __Phys2Pfn(SGList->PhysAddr);

    if (SGList->PhysLen < SectorsNow * SectorSize) {
        SGListGet(SGList);
        Mdl->Size       += sizeof(PFN_NUMBER);
        Mdl->ByteCount  = Mdl->ByteCount + SGList->PhysLen;
        Mapping->Pfn[1] = __Phys2Pfn(SGList->PhysAddr);
    }
#pragma warning(pop)

    ASSERT((Mdl->ByteCount & (SectorSize - 1)) == 0);
    ASSERT3U(Mdl->ByteCount, <=, PAGE_SIZE);
    ASSERT3U(SectorsNow, ==, (Mdl->ByteCount / SectorSize));
                
    Mapping->Length = __min(Mdl->ByteCount, PAGE_SIZE);
    Mapping->Buffer = MmMapLockedPagesSpecifyCache(Mdl, KernelMode,
                            MmCached, NULL, FALSE, __PdoPriority(Pdo));
    if (!Mapping->Buffer) {
        goto fail;
    }

    ASSERT3P(MmGetMdlPfnArray(Mdl)[0], ==, Mapping->Pfn[0]);
    ASSERT3P(MmGetMdlPfnArray(Mdl)[1], ==, Mapping->Pfn[1]);
 
    return TRUE;

fail:
    return FALSE;
}

static FORCEINLINE VOID
UnmapSegmentBuffer(
    IN  PXENVBD_MAPPING         Mapping
    )
{
    MmUnmapLockedPages(Mapping->Buffer, &Mapping->Mdl);
    RtlZeroMemory(&Mapping->Mdl, sizeof(Mapping->Mdl));
    RtlZeroMemory(Mapping->Pfn, sizeof(Mapping->Pfn));
    Mapping->Buffer = NULL;
    Mapping->Length = 0;
}

static FORCEINLINE VOID
RequestCleanup(
    IN  PXENVBD_PDO             Pdo,
    IN  PXENVBD_REQUEST         Request
    )
{
    ULONG           Index, Index2;
    PXENVBD_GRANTER Granter = FrontendGetGranter(Pdo->Frontend);

    // cleanup granted/mapped buffers
    switch (Request->Operation) {
    case BLKIF_OP_READ:
    case BLKIF_OP_WRITE:
        for (Index = 0; Index < XENVBD_MAX_SEGMENTS_PER_REQUEST; ++Index) {
            PXENVBD_SEGMENT Segment = &Request->u.ReadWrite.Segments[Index];
            if (Segment->Grant)
                GranterPut(Granter, Segment->Grant);
            Segment->Grant = NULL;
        }
        for (Index = 0; Index < XENVBD_MAX_SEGMENTS_PER_REQUEST; ++Index) {
            PXENVBD_MAPPING Mapping = &Request->u.ReadWrite.Mappings[Index];
            if (Mapping->BufferId)
                BufferPut(Mapping->BufferId);
            Mapping->BufferId = NULL;
            if (Mapping->Buffer)
                UnmapSegmentBuffer(Mapping);
        }
        break;

    case BLKIF_OP_INDIRECT:
        for (Index = 0; Index < BLKIF_MAX_INDIRECT_PAGES_PER_REQUEST; ++Index) {
            if (Request->u.Indirect.Grants[Index])
                GranterPut(Granter, Request->u.Indirect.Grants[Index]);
            Request->u.Indirect.Grants[Index] = 0;
        }
        for (Index = 0; Index < BLKIF_MAX_INDIRECT_PAGES_PER_REQUEST; ++Index) {
            PXENVBD_SEGMENT SegmentList = Request->u.Indirect.Segments[Index];
            if (SegmentList == NULL)
                continue;
            for (Index2 = 0; Index2 < SEGMENTS_PER_PAGE; ++Index2) {
                PXENVBD_SEGMENT Segment = &SegmentList[Index2];
                if (Segment->Grant)
                    GranterPut(Granter, Segment->Grant);
                Segment->Grant = NULL;
            }
            __LookasideFree(&Pdo->SegmentList, SegmentList);
            Request->u.Indirect.Segments[Index] = NULL;
        }
        for (Index = 0; Index < BLKIF_MAX_INDIRECT_PAGES_PER_REQUEST; ++Index) {
            PXENVBD_MAPPING MappingList = Request->u.Indirect.Mappings[Index];
            if (MappingList == NULL)
                continue;
            for (Index2 = 0; Index2 < SEGMENTS_PER_PAGE; ++Index2) {
                PXENVBD_MAPPING Mapping = &MappingList[Index2];
                if (Mapping->BufferId)
                    BufferPut(Mapping->BufferId);
                Mapping->BufferId = NULL;
                if (Mapping->Buffer)
                    UnmapSegmentBuffer(Mapping);
            }
            __LookasideFree(&Pdo->MappingList, MappingList);
            Request->u.Indirect.Mappings[Index] = NULL;
        }
        break;

    default:
        // no special cleanup
        break;
    }
}

static FORCEINLINE VOID
RequestCopyOutput(
    __in PXENVBD_REQUEST         Request
    )
{
    ULONG       Index, Index2;
    ULONG       NrSegments;

    switch (Request->Operation) {
    case BLKIF_OP_READ:
        NrSegments = Request->u.ReadWrite.NrSegments;
        for (Index = 0;
                    Index < BLKIF_MAX_SEGMENTS_PER_REQUEST &&
                    NrSegments > 0;
                            ++Index, --NrSegments) {
            PXENVBD_MAPPING Mapping = &Request->u.ReadWrite.Mappings[Index];

            if (Mapping->BufferId)
                BufferCopyOut(Mapping->BufferId, Mapping->Buffer, Mapping->Length);
        }
        break;

    case BLKIF_OP_INDIRECT:
        if (Request->u.Indirect.Operation != BLKIF_OP_READ)
            break; // not an INDIRECT READ, dont copy any data

        NrSegments = Request->u.Indirect.NrSegments;
        for (Index = 0;
                    Index < BLKIF_MAX_INDIRECT_PAGES_PER_REQUEST &&
                    NrSegments > 0;
                            ++Index) {
            PXENVBD_MAPPING MappingList = Request->u.Indirect.Mappings[Index];
            if (MappingList == NULL)
                continue;
            for (Index2 = 0;
                        Index2 < SEGMENTS_PER_PAGE &&
                        NrSegments > 0;
                                ++Index2, --NrSegments) {
                PXENVBD_MAPPING Mapping = &MappingList[Index2];

                if (Mapping->BufferId)
                    BufferCopyOut(Mapping->BufferId, Mapping->Buffer, Mapping->Length);
            }
        }
        break;

    default:
        // not a READ, dont copy any data
        break;
    }
}

static NTSTATUS
PrepareSegment(
    IN  PXENVBD_PDO             Pdo,
    IN  PXENVBD_SEGMENT         Segment,
    IN  PXENVBD_MAPPING         Mapping,
    IN  PXENVBD_SG_LIST         SGList,
    IN  BOOLEAN                 ReadOnly,
    IN  ULONG                   SectorsLeft,
    OUT PULONG                  SectorsNow
    )
{
    PFN_NUMBER      Pfn;
    NTSTATUS        Status = STATUS_UNSUCCESSFUL;
    PXENVBD_GRANTER Granter = FrontendGetGranter(Pdo->Frontend);
    const ULONG     SectorSize = PdoSectorSize(Pdo);
    const ULONG     SectorsPerPage = __SectorsPerPage(SectorSize);

    if (SGListNext(SGList, SectorSize - 1)) {
        ++Pdo->SegsGranted;
        // get first sector, last sector and count
        Segment->FirstSector    = (UCHAR)((__Offset(SGList->PhysAddr) + SectorSize - 1) / SectorSize);
        *SectorsNow             = __min(SectorsLeft, SectorsPerPage - Segment->FirstSector);
        Segment->LastSector     = (UCHAR)(Segment->FirstSector + *SectorsNow - 1);
        Mapping->BufferId       = NULL; // granted, ensure its null
        Mapping->Buffer         = NULL; // granted, ensure its null
        Mapping->Length         = 0;    // granted, ensure its 0
        Pfn                     = __Phys2Pfn(SGList->PhysAddr);

        ASSERT3U((SGList->PhysLen / SectorSize), ==, *SectorsNow);
        ASSERT3U((SGList->PhysLen & (SectorSize - 1)), ==, 0);
    } else {
        ++Pdo->SegsBounced;
        // get first sector, last sector and count
        Segment->FirstSector    = 0;
        *SectorsNow             = __min(SectorsLeft, SectorsPerPage);
        Segment->LastSector     = (UCHAR)(*SectorsNow - 1);

        // map SGList to Virtual Address. Populates Segment->Buffer and Segment->Length
        if (!MapSegmentBuffer(Pdo, Mapping, SGList, SectorSize, *SectorsNow)) {
            ++Pdo->FailedMaps;
            goto fail;
        }

        // get a buffer
        if (!BufferGet(Segment, &Mapping->BufferId, &Pfn)) {
            ++Pdo->FailedBounces;
            goto fail;
        }

        // copy contents in
        if (ReadOnly) { // Operation == BLKIF_OP_WRITE
            BufferCopyIn(Mapping->BufferId, Mapping->Buffer, Mapping->Length);
        }
    }

    // Grant segment's page
    Status = GranterGet(Granter, Pfn, ReadOnly, &Segment->Grant);
    if (!NT_SUCCESS(Status)) {
        ++Pdo->FailedGrants;
        goto fail;
    }

    return STATUS_SUCCESS;

fail:
    return Status;
}

static NTSTATUS
PrepareBlkifReadWrite(
    IN  PXENVBD_PDO             Pdo,
    IN  PXENVBD_REQUEST         Request,
    IN  PXENVBD_SG_LIST         SGList,
    IN  ULONG64                 SectorStart,
    IN  ULONG                   SectorsLeft,
    OUT PULONG                  SectorsDone
    )
{
    NTSTATUS        Status;
    UCHAR           Operation;
    BOOLEAN         ReadOnly;
    ULONG           Index;
    __Operation(Cdb_OperationEx(Request->Srb), &Operation, &ReadOnly);

    Request->Operation  = Operation;
    Request->u.ReadWrite.NrSegments = 0;
    Request->u.ReadWrite.FirstSector = SectorStart;

    for (Index = 0;
                Index < BLKIF_MAX_SEGMENTS_PER_REQUEST &&
                SectorsLeft > 0;
                        ++Index) {
        PXENVBD_SEGMENT Segment = &Request->u.ReadWrite.Segments[Index];
        PXENVBD_MAPPING Mapping = &Request->u.ReadWrite.Mappings[Index];
        ULONG           SectorsNow;

        Request->u.ReadWrite.NrSegments++;
        Status = PrepareSegment(Pdo,
                                Segment,
                                Mapping,
                                SGList,
                                ReadOnly,
                                SectorsLeft,
                                &SectorsNow);
        if (!NT_SUCCESS(Status))
            goto fail;

        *SectorsDone += SectorsNow;
        SectorsLeft  -= SectorsNow;
    }
    ASSERT3U(Request->u.ReadWrite.NrSegments, >, 0);
    ASSERT3U(Request->u.ReadWrite.NrSegments, <=, BLKIF_MAX_SEGMENTS_PER_REQUEST);

    return STATUS_SUCCESS;

fail:
    return Status;
}

static NTSTATUS
PrepareBlkifIndirect(
    IN  PXENVBD_PDO             Pdo,
    IN  PXENVBD_REQUEST         Request,
    IN  PXENVBD_SG_LIST         SGList,
    IN  ULONG64                 SectorStart,
    IN  ULONG                   SectorsLeft,
    OUT PULONG                  SectorsDone
    )
{
    ULONG           Index, Index2;
    UCHAR           Operation;
    BOOLEAN         ReadOnly;
    NTSTATUS        Status;
    PXENVBD_GRANTER Granter = FrontendGetGranter(Pdo->Frontend);
    const ULONG     MaxSegments = FrontendGetFeatures(Pdo->Frontend)->Indirect;
    __Operation(Cdb_OperationEx(Request->Srb), &Operation, &ReadOnly);

    Request->Operation = BLKIF_OP_INDIRECT;
    Request->u.Indirect.Operation = Operation;
    Request->u.Indirect.NrSegments = 0;
    Request->u.Indirect.FirstSector = SectorStart;

    for (Index = 0;
                Index < BLKIF_MAX_INDIRECT_PAGES_PER_REQUEST &&
                SectorsLeft > 0 &&
                Request->u.Indirect.NrSegments < MaxSegments;
                        ++Index) {
        PXENVBD_SEGMENT SegmentList;
        PXENVBD_MAPPING MappingList;

        Status = STATUS_NO_MEMORY;
        Request->u.Indirect.Segments[Index] = SegmentList = __LookasideAlloc(&Pdo->SegmentList);
        if (SegmentList == NULL)
            goto fail;

        Status = STATUS_NO_MEMORY;
        Request->u.Indirect.Mappings[Index] = MappingList = __LookasideAlloc(&Pdo->MappingList);
        if (MappingList == NULL)
            goto fail;

        for (Index2 = 0;
                    Index2 < SEGMENTS_PER_PAGE &&
                    SectorsLeft > 0 &&
                    Request->u.Indirect.NrSegments < MaxSegments;
                            ++Index2) {
            PXENVBD_SEGMENT Segment = &SegmentList[Index2];
            PXENVBD_MAPPING Mapping = &MappingList[Index2];
            ULONG           SectorsNow = 0;

            Request->u.Indirect.NrSegments++;
            Status = PrepareSegment(Pdo,
                                    Segment,
                                    Mapping,
                                    SGList,
                                    ReadOnly,
                                    SectorsLeft,
                                    &SectorsNow);
            if(!NT_SUCCESS(Status))
                goto fail;

            *SectorsDone += SectorsNow;
            SectorsLeft  -= SectorsNow;
        }

        Status = GranterGet(Granter,
                            __Virt2Pfn(SegmentList),
                            TRUE,
                            &Request->u.Indirect.Grants[Index]);
        if (!NT_SUCCESS(Status)) {
            ++Pdo->FailedGrants;
            goto fail;
        }
    }

    ASSERT3U(Request->u.Indirect.NrSegments, >, 0);
    ASSERT3U(Request->u.Indirect.NrSegments, <=, MaxSegments);
    return STATUS_SUCCESS;

fail:
    return Status;
}

static FORCEINLINE BOOLEAN
UseIndirect(
    IN  PXENVBD_PDO             Pdo,
    IN  ULONG                   SectorsLeft
    )
{
    const ULONG SectorsPerPage = __SectorsPerPage(PdoSectorSize(Pdo));

    if (FrontendGetFeatures(Pdo->Frontend)->Indirect == 0)
        return FALSE; // not supported

    if (SectorsLeft < BLKIF_MAX_SEGMENTS_PER_REQUEST * SectorsPerPage)
        return FALSE; // first into a single BLKIF_OP_{READ/WRITE}

    return TRUE;
}

__checkReturn
static NTSTATUS
PrepareReadWrite(
    __in PXENVBD_PDO             Pdo,
    __in PSCSI_REQUEST_BLOCK     Srb
    )
{
    NTSTATUS        Status;
    LIST_ENTRY      ReqList;
    XENVBD_SG_LIST  SGList;
    PXENVBD_SRBEXT  SrbExt = GetSrbExt(Srb);
    ULONG64         SectorStart = Cdb_LogicalBlock(Srb);
    ULONG           SectorsLeft = Cdb_TransferBlock(Srb);

    InitializeListHead(&ReqList);
    RtlZeroMemory(&SGList, sizeof(SGList));
    SGList.SGList = StorPortGetScatterGatherList(PdoGetFdo(Pdo), Srb);

    SrbExt->Count = 0;
    // mark the SRB as pending, completion will check for pending to detect failures
    Srb->SrbStatus = SRB_STATUS_PENDING;

    while (SectorsLeft > 0) {
        ULONG           SectorsDone = 0;
        PXENVBD_REQUEST Request = __LookasideAlloc(&Pdo->RequestList);

        Status = STATUS_NO_MEMORY;
        if (Request == NULL) 
            goto fail;
        
        Request->Srb        = Srb;
        InsertTailList(&ReqList, &Request->Entry);
        InterlockedIncrement(&SrbExt->Count);

        if (UseIndirect(Pdo, SectorsLeft)) {
            Status = PrepareBlkifIndirect(Pdo,
                                           Request,
                                           &SGList,
                                           SectorStart,
                                           SectorsLeft,
                                           &SectorsDone);
        } else {
            Status = PrepareBlkifReadWrite(Pdo,
                                           Request,
                                           &SGList,
                                           SectorStart,
                                           SectorsLeft,
                                           &SectorsDone);
        }
        if (!NT_SUCCESS(Status))
            goto fail;

        SectorsLeft -= SectorsDone;
        SectorStart += SectorsDone;
    }

    // completed preparing SRB, move requests to pending queue
    for (;;) {
        PXENVBD_REQUEST Request;
        PLIST_ENTRY     Entry = RemoveHeadList(&ReqList);
        if (Entry == &ReqList)
            break;

        Request = CONTAINING_RECORD(Entry, XENVBD_REQUEST, Entry);
        __PdoIncBlkifOpCount(Pdo, Request);
        QueueAppend(&Pdo->PreparedReqs, Entry);
    }
    return STATUS_SUCCESS;

fail:
    for (;;) {
        PXENVBD_REQUEST Request;
        PLIST_ENTRY     Entry = RemoveHeadList(&ReqList);
        if (Entry == &ReqList)
            break;

        Request = CONTAINING_RECORD(Entry, XENVBD_REQUEST, Entry);
        RequestCleanup(Pdo, Request);
        __LookasideFree(&Pdo->RequestList, Request);
        InterlockedDecrement(&SrbExt->Count);
    }
    ASSERT3S(SrbExt->Count, ==, 0);
    ASSERT(!NT_SUCCESS(Status));
    return Status;
}

__checkReturn
static NTSTATUS
PrepareSyncCache(
    __in PXENVBD_PDO             Pdo,
    __in PSCSI_REQUEST_BLOCK     Srb
    )
{
    PXENVBD_SRBEXT  SrbExt = GetSrbExt(Srb);
    PXENVBD_REQUEST Request = __LookasideAlloc(&Pdo->RequestList);
    if (Request == NULL)
        return STATUS_UNSUCCESSFUL;
    
    SrbExt->Count = 1;
    // mark the SRB as pending, completion will check for pending to detect failures
    Srb->SrbStatus = SRB_STATUS_PENDING;

    Request->Srb = Srb;
    Request->Operation      = BLKIF_OP_WRITE_BARRIER;

    Request->u.Barrier.FirstSector = Cdb_LogicalBlock(Srb);

    __PdoIncBlkifOpCount(Pdo, Request);
    QueueAppend(&Pdo->PreparedReqs, &Request->Entry);
    return STATUS_SUCCESS;
}

__checkReturn
static NTSTATUS
PrepareUnmap(
    __in PXENVBD_PDO             Pdo,
    __in PSCSI_REQUEST_BLOCK     Srb
    )
{
    PXENVBD_SRBEXT  SrbExt = GetSrbExt(Srb);
    PXENVBD_REQUEST Request = __LookasideAlloc(&Pdo->RequestList);
    if (Request == NULL)
        return STATUS_UNSUCCESSFUL;

    SrbExt->Count = 1;
    // mark the SRB as pending, completion will check for pending to detect failures
    Srb->SrbStatus = SRB_STATUS_PENDING;

    Request->Srb = Srb;
    Request->Operation      = BLKIF_OP_DISCARD;

    Request->u.Discard.FirstSector = Cdb_LogicalBlock(Srb);
    Request->u.Discard.NrSectors   = Cdb_TransferBlock(Srb);
    Request->u.Discard.Flags       = 0;

    __PdoIncBlkifOpCount(Pdo, Request);
    QueueAppend(&Pdo->PreparedReqs, &Request->Entry);
    return STATUS_SUCCESS;
}

//=============================================================================
// Queue-Related
VOID
PdoPrepareFresh(
    __in PXENVBD_PDO             Pdo
    )
{
    for (;;) {
        NTSTATUS        Status;
        PXENVBD_SRBEXT  SrbExt;
        PLIST_ENTRY     Entry = QueuePop(&Pdo->FreshSrbs);
        if (Entry == NULL)
            break;
        SrbExt = CONTAINING_RECORD(Entry, XENVBD_SRBEXT, Entry);

        // popped a SRB, process it
        switch (Cdb_OperationEx(SrbExt->Srb)) {
        case SCSIOP_READ:
        case SCSIOP_WRITE:
            Status = PrepareReadWrite(Pdo, SrbExt->Srb);
            break;
        case SCSIOP_SYNCHRONIZE_CACHE:
            Status = PrepareSyncCache(Pdo, SrbExt->Srb);
            break;
        case SCSIOP_UNMAP:
            Status = PrepareUnmap(Pdo, SrbExt->Srb);
            break;
        default:
            ASSERT(FALSE);
            Status = STATUS_NOT_SUPPORTED;
            break;
        }

        // if failed to prepare, put on fresh and finish up
        if (!NT_SUCCESS(Status)) {
            QueueUnPop(&Pdo->FreshSrbs, &SrbExt->Entry);
            break;
        }
    }
}

VOID
PdoSubmitPrepared(
    __in PXENVBD_PDO             Pdo
    )
{
    PXENVBD_BLOCKRING   BlockRing = FrontendGetBlockRing(Pdo->Frontend);
    PXENVBD_NOTIFIER    Notifier = FrontendGetNotifier(Pdo->Frontend);

    for (;;) {
        PXENVBD_REQUEST Request;
        PLIST_ENTRY     Entry = QueuePop(&Pdo->PreparedReqs);
        if (Entry == NULL)
            break;
        Request = CONTAINING_RECORD(Entry, XENVBD_REQUEST, Entry);

        QueueAppend(&Pdo->SubmittedReqs, &Request->Entry);
        KeMemoryBarrier();
        if (!BlockRingSubmit(BlockRing, Request)) {
            QueueRemove(&Pdo->SubmittedReqs, &Request->Entry);
            QueueUnPop(&Pdo->PreparedReqs, &Request->Entry);
            break;
        }
    }

    if (BlockRingPush(BlockRing)) {
        NotifierSend(Notifier);
    }
}

VOID
PdoCompleteSubmitted(
    __in PXENVBD_PDO             Pdo,
    __in PXENVBD_REQUEST         Request,
    __in SHORT                   Status
    )
{
    PSCSI_REQUEST_BLOCK Srb = Request->Srb;
    PXENVBD_SRBEXT      SrbExt = GetSrbExt(Srb);
    ASSERT3P(SrbExt, !=, NULL);

    switch (Status) {
    case BLKIF_RSP_OKAY:
        RequestCopyOutput(Request);
        break;

    case BLKIF_RSP_EOPNOTSUPP:
        // Remove appropriate feature support
        FrontendRemoveFeature(Pdo->Frontend, Request->Operation);
        Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
        Warning("Target[%d] : %s BLKIF_RSP_EOPNOTSUPP\n", 
                PdoGetTargetId(Pdo), Cdb_OperationName(Request->Operation));
        break;

    case BLKIF_RSP_ERROR:
    default:
        Warning("Target[%d] : %s BLKIF_RSP_ERROR\n", 
                PdoGetTargetId(Pdo), Cdb_OperationName(Request->Operation));
        Srb->SrbStatus = SRB_STATUS_ERROR;
        break;
    }

    QueueRemove(&Pdo->SubmittedReqs, &Request->Entry);
    RequestCleanup(Pdo, Request);
    __LookasideFree(&Pdo->RequestList, Request);

    // complete srb
    if (InterlockedDecrement(&SrbExt->Count) == 0) {
        if (Srb->SrbStatus == SRB_STATUS_PENDING) {
            // SRB has not hit a failure condition (BLKIF_RSP_ERROR | BLKIF_RSP_EOPNOTSUPP)
            // from any of its responses. SRB must have succeeded
            Srb->SrbStatus = SRB_STATUS_SUCCESS;
            Srb->ScsiStatus = 0x00; // SCSI_GOOD
        } else {
            // Srb->SrbStatus has already been set by 1 or more requests with Status != BLKIF_RSP_OKAY
            Srb->ScsiStatus = 0x40; // SCSI_ABORTED
        }

        FdoCompleteSrb(PdoGetFdo(Pdo), Srb);
    }
}

VOID
PdoCompleteShutdown(
    __in PXENVBD_PDO             Pdo
    )
{
    if (QueueCount(&Pdo->ShutdownSrbs) == 0)
        return;

    if (QueueCount(&Pdo->FreshSrbs) ||
        QueueCount(&Pdo->PreparedReqs) ||
        QueueCount(&Pdo->SubmittedReqs))
        return;

    for (;;) {
        PXENVBD_SRBEXT  SrbExt;
        PLIST_ENTRY     Entry = QueuePop(&Pdo->ShutdownSrbs);
        if (Entry == NULL)
            break;
        SrbExt = CONTAINING_RECORD(Entry, XENVBD_SRBEXT, Entry);
        SrbExt->Srb->SrbStatus = SRB_STATUS_SUCCESS;
        FdoCompleteSrb(PdoGetFdo(Pdo), SrbExt->Srb);
    }
}

VOID
PdoPreResume(
    __in PXENVBD_PDO             Pdo
    )
{
    LIST_ENTRY      List;
    
    InitializeListHead(&List);

    // pop all submitted requests, cleanup and add associated SRB to a list
    for (;;) {
        PXENVBD_SRBEXT  SrbExt;
        PXENVBD_REQUEST Request;
        PLIST_ENTRY     Entry = QueuePop(&Pdo->SubmittedReqs);
        if (Entry == NULL)
            break;
        Request = CONTAINING_RECORD(Entry, XENVBD_REQUEST, Entry);
        SrbExt = GetSrbExt(Request->Srb);

        RequestCleanup(Pdo, Request);
        __LookasideFree(&Pdo->RequestList, Request);

        if (InterlockedDecrement(&SrbExt->Count) == 0) {
            InsertTailList(&List, &SrbExt->Entry);
        }
    }

    // pop all prepared requests, cleanup and add associated SRB to a list
    for (;;) {
        PXENVBD_SRBEXT  SrbExt;
        PXENVBD_REQUEST Request;
        PLIST_ENTRY     Entry = QueuePop(&Pdo->PreparedReqs);
        if (Entry == NULL)
            break;
        Request = CONTAINING_RECORD(Entry, XENVBD_REQUEST, Entry);
        SrbExt = GetSrbExt(Request->Srb);

        RequestCleanup(Pdo, Request);
        __LookasideFree(&Pdo->RequestList, Request);

        if (InterlockedDecrement(&SrbExt->Count) == 0) {
            InsertTailList(&List, &SrbExt->Entry);
        }
    }

    // foreach SRB in list, put on start of FreshSrbs
    for (;;) {
        PXENVBD_SRBEXT  SrbExt;
        PLIST_ENTRY     Entry = RemoveTailList(&List);
        if (Entry == &List)
            break;
        SrbExt = CONTAINING_RECORD(Entry, XENVBD_SRBEXT, Entry);

        QueueUnPop(&Pdo->FreshSrbs, &SrbExt->Entry);
    }

    // now the first set of requests popped off submitted list is the next SRB 
    // to be popped off the fresh list
}

VOID
PdoPostResume(
    __in PXENVBD_PDO             Pdo
    )
{
    KIRQL   Irql;

    Verbose("Target[%d] : %d Fresh SRBs\n", PdoGetTargetId(Pdo), QueueCount(&Pdo->FreshSrbs));
    
    // clear missing flag
    KeAcquireSpinLock(&Pdo->Lock, &Irql);
    Verbose("Target[%d] : %s (%s)\n", PdoGetTargetId(Pdo), Pdo->Missing ? "MISSING" : "NOT_MISSING", Pdo->Reason);
    Pdo->Missing = FALSE;
    Pdo->Reason = NULL;
    KeReleaseSpinLock(&Pdo->Lock, Irql);
}

//=============================================================================
// SRBs
__checkReturn
static FORCEINLINE BOOLEAN
__ValidateSectors(
    __in ULONG64                 SectorCount,
    __in ULONG64                 Start,
    __in ULONG                   Length
    )
{
    // Deal with overflow
    return (Start < SectorCount) && ((Start + Length) <= SectorCount);
}

__checkReturn
static FORCEINLINE BOOLEAN
__ValidateSrbBuffer(
    __in PCHAR                  Caller,
    __in PSCSI_REQUEST_BLOCK    Srb,
    __in ULONG                  MinLength
    )
{
    if (Srb->DataBuffer == NULL) {
        Error("%s: Srb[0x%p].DataBuffer = NULL\n", Caller, Srb);
        return FALSE;
    }
    if (MinLength) {
        if (Srb->DataTransferLength < MinLength) {
            Error("%s: Srb[0x%p].DataTransferLength < %d\n", Caller, Srb, MinLength);
            return FALSE;
        }
    } else {
        if (Srb->DataTransferLength == 0) {
            Error("%s: Srb[0x%p].DataTransferLength = 0\n", Caller, Srb);
            return FALSE;
        }
    }

    return TRUE;
}

__checkReturn
static DECLSPEC_NOINLINE BOOLEAN
PdoReadWrite(
    __in PXENVBD_PDO            Pdo,
    __in PSCSI_REQUEST_BLOCK    Srb
    )
{
    NTSTATUS            Status;
    PXENVBD_DISKINFO    DiskInfo = FrontendGetDiskInfo(Pdo->Frontend);
    PXENVBD_SRBEXT      SrbExt = GetSrbExt(Srb);
    PXENVBD_NOTIFIER    Notifier = FrontendGetNotifier(Pdo->Frontend);

    if (FrontendGetCaps(Pdo->Frontend)->Connected == FALSE) {
        Trace("Target[%d] : Not Ready, fail SRB\n", PdoGetTargetId(Pdo));
        Srb->ScsiStatus = 0x40; // SCSI_ABORT;
        return TRUE;
    }

    // check valid sectors
    if (!__ValidateSectors(DiskInfo->SectorCount, Cdb_LogicalBlock(Srb), Cdb_TransferBlock(Srb))) {
        Trace("Target[%d] : Invalid Sector (%d @ %lld < %lld)\n", PdoGetTargetId(Pdo), Cdb_TransferBlock(Srb), Cdb_LogicalBlock(Srb), DiskInfo->SectorCount);
        Srb->ScsiStatus = 0x40; // SCSI_ABORT
        return TRUE; // Complete now
    }

    Status = PrepareReadWrite(Pdo, Srb);
    if (NT_SUCCESS(Status)) {
        PdoSubmitPrepared(Pdo);
        return FALSE;
    }

    QueueAppend(&Pdo->FreshSrbs, &SrbExt->Entry);
    NotifierTrigger(Notifier);

    return FALSE;
}

__checkReturn
static DECLSPEC_NOINLINE BOOLEAN
PdoSyncCache(
    __in PXENVBD_PDO             Pdo,
    __in PSCSI_REQUEST_BLOCK     Srb
    )
{
    NTSTATUS            Status;
    PXENVBD_SRBEXT      SrbExt = GetSrbExt(Srb);
    PXENVBD_NOTIFIER    Notifier = FrontendGetNotifier(Pdo->Frontend);

    if (FrontendGetCaps(Pdo->Frontend)->Connected == FALSE) {
        Trace("Target[%d] : Not Ready, fail SRB\n", PdoGetTargetId(Pdo));
        Srb->ScsiStatus = 0x40; // SCSI_ABORT;
        return TRUE;
    }

    if (FrontendGetDiskInfo(Pdo->Frontend)->Barrier == FALSE) {
        Trace("Target[%d] : BARRIER not supported, suppressing\n", PdoGetTargetId(Pdo));
        Srb->ScsiStatus = 0x00; // SCSI_GOOD
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        return TRUE;
    }

    Status = PrepareSyncCache(Pdo, Srb);
    if (NT_SUCCESS(Status)) {
        PdoSubmitPrepared(Pdo);
        return FALSE;
    }

    QueueAppend(&Pdo->FreshSrbs, &SrbExt->Entry);
    NotifierTrigger(Notifier);

    return FALSE;
}

__checkReturn
static DECLSPEC_NOINLINE BOOLEAN
PdoUnmap(
    __in PXENVBD_PDO             Pdo,
    __in PSCSI_REQUEST_BLOCK     Srb
    )
{
    NTSTATUS            Status;
    PXENVBD_SRBEXT      SrbExt = GetSrbExt(Srb);
    PXENVBD_NOTIFIER    Notifier = FrontendGetNotifier(Pdo->Frontend);

    if (FrontendGetCaps(Pdo->Frontend)->Connected == FALSE) {
        Trace("Target[%d] : Not Ready, fail SRB\n", PdoGetTargetId(Pdo));
        Srb->ScsiStatus = 0x40; // SCSI_ABORT;
        return TRUE;
    }

    if (FrontendGetDiskInfo(Pdo->Frontend)->Discard == FALSE) {
        Trace("Target[%d] : DISCARD not supported, suppressing\n", PdoGetTargetId(Pdo));
        Srb->ScsiStatus = 0x00; // SCSI_GOOD
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        return TRUE;
    }

    Status = PrepareUnmap(Pdo, Srb);
    if (NT_SUCCESS(Status)) {
        PdoSubmitPrepared(Pdo);
        return FALSE;
    }

    QueueAppend(&Pdo->FreshSrbs, &SrbExt->Entry);
    NotifierTrigger(Notifier);

    return FALSE;
}

#define MODE_CACHING_PAGE_LENGTH 20
static DECLSPEC_NOINLINE VOID
PdoModeSense(
    __in PXENVBD_PDO             Pdo,
    __in PSCSI_REQUEST_BLOCK     Srb
    )    
{
    PMODE_PARAMETER_HEADER  Header  = Srb->DataBuffer;
    const UCHAR PageCode            = Cdb_PageCode(Srb);
    ULONG LengthLeft                = Cdb_AllocationLength(Srb);
    PVOID CurrentPage               = Srb->DataBuffer;

    UNREFERENCED_PARAMETER(Pdo);

    RtlZeroMemory(Srb->DataBuffer, Srb->DataTransferLength);

    if (!__ValidateSrbBuffer(__FUNCTION__, Srb, (ULONG)sizeof(struct _MODE_SENSE))) {
        Srb->ScsiStatus = 0x40;
        Srb->SrbStatus = SRB_STATUS_DATA_OVERRUN;
        Srb->DataTransferLength = 0;
        return;
    }

    // TODO : CDROM requires more ModePage entries
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
    Srb->DataTransferLength = __min(Cdb_AllocationLength(Srb), Header->ModeDataLength + 1);
}

static DECLSPEC_NOINLINE VOID
PdoRequestSense(
    __in PXENVBD_PDO             Pdo,
    __in PSCSI_REQUEST_BLOCK     Srb
    )
{
    PSENSE_DATA         Sense = Srb->DataBuffer;

    UNREFERENCED_PARAMETER(Pdo);

    if (!__ValidateSrbBuffer(__FUNCTION__, Srb, (ULONG)sizeof(SENSE_DATA))) {
        Srb->ScsiStatus = 0x40;
        Srb->SrbStatus = SRB_STATUS_DATA_OVERRUN;
        return;
    }

    RtlZeroMemory(Sense, sizeof(SENSE_DATA));

    Sense->ErrorCode            = 0x70;
    Sense->Valid                = 1;
    Sense->AdditionalSenseCodeQualifier = 0;
    Sense->SenseKey             = SCSI_SENSE_NO_SENSE;
    Sense->AdditionalSenseCode  = SCSI_ADSENSE_NO_SENSE;
    Srb->DataTransferLength     = sizeof(SENSE_DATA);
    Srb->SrbStatus              = SRB_STATUS_SUCCESS;
}

static DECLSPEC_NOINLINE VOID
PdoReportLuns(
    __in PXENVBD_PDO             Pdo,
    __in PSCSI_REQUEST_BLOCK     Srb
    )
{
    ULONG           Length;
    ULONG           Offset;
    ULONG           AllocLength = Cdb_AllocationLength(Srb);
    PUCHAR          Buffer = Srb->DataBuffer;

    UNREFERENCED_PARAMETER(Pdo);

    if (!__ValidateSrbBuffer(__FUNCTION__, Srb, 8)) {
        Srb->ScsiStatus = 0x40;
        Srb->SrbStatus = SRB_STATUS_DATA_OVERRUN;
        Srb->DataTransferLength = 0;
        return;
    }

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

    Srb->DataTransferLength = __min(Length, AllocLength);
    Srb->SrbStatus = SRB_STATUS_SUCCESS;
}

static DECLSPEC_NOINLINE VOID
PdoReadCapacity(
    __in PXENVBD_PDO             Pdo,
    __in PSCSI_REQUEST_BLOCK     Srb
    )
{
    PREAD_CAPACITY_DATA     Capacity = Srb->DataBuffer;
    PXENVBD_DISKINFO        DiskInfo = FrontendGetDiskInfo(Pdo->Frontend);
    ULONG64                 SectorCount;
    ULONG                   SectorSize;
    ULONG                   LastBlock;

    if (Cdb_PMI(Srb) == 0 && Cdb_LogicalBlock(Srb) != 0) {
        Srb->ScsiStatus = 0x02; // CHECK_CONDITION
        return;
    }
    
    SectorCount = DiskInfo->SectorCount;
    SectorSize = DiskInfo->SectorSize;

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

static DECLSPEC_NOINLINE VOID
PdoReadCapacity16(
    __in PXENVBD_PDO             Pdo,
    __in PSCSI_REQUEST_BLOCK     Srb
    )
{
    PREAD_CAPACITY_DATA_EX  Capacity = Srb->DataBuffer;
    PXENVBD_DISKINFO        DiskInfo = FrontendGetDiskInfo(Pdo->Frontend);
    ULONG64                 SectorCount;
    ULONG                   SectorSize;

    if (Cdb_PMI(Srb) == 0 && Cdb_LogicalBlock(Srb) != 0) {
        Srb->ScsiStatus = 0x02; // CHECK_CONDITION
        return;
    }

    SectorCount = DiskInfo->SectorCount;
    SectorSize = DiskInfo->SectorSize;

    if (Capacity) {
        Capacity->LogicalBlockAddress.QuadPart = _byteswap_uint64(SectorCount - 1);
        Capacity->BytesPerBlock = _byteswap_ulong(SectorSize);
    }

    Srb->SrbStatus = SRB_STATUS_SUCCESS;
}

//=============================================================================
// StorPort Methods
__checkReturn
static FORCEINLINE BOOLEAN
__PdoExecuteScsi(
    __in PXENVBD_PDO             Pdo,
    __in PSCSI_REQUEST_BLOCK     Srb
    )
{
    const UCHAR Operation = Cdb_OperationEx(Srb);
    PXENVBD_DISKINFO    DiskInfo = FrontendGetDiskInfo(Pdo->Frontend);

    if (DiskInfo->DiskInfo & VDISK_READONLY) {
        Trace("Target[%d] : (%08x) Read-Only, fail SRB (%02x:%s)\n", PdoGetTargetId(Pdo),
                DiskInfo->DiskInfo, Operation, Cdb_OperationName(Operation));
        Srb->ScsiStatus = 0x40; // SCSI_ABORT
        return TRUE;
    }

    // idea: check pdo state here. still push to freshsrbs
    switch (Operation) {
    case SCSIOP_READ:
    case SCSIOP_WRITE:
        return PdoReadWrite(Pdo, Srb);
        break;
        
    case SCSIOP_SYNCHRONIZE_CACHE:
        return PdoSyncCache(Pdo, Srb);
        break;

    case SCSIOP_UNMAP:
        return PdoUnmap(Pdo, Srb);
        break;

    case SCSIOP_INQUIRY:
        PdoInquiry(PdoGetTargetId(Pdo), FrontendGetInquiry(Pdo->Frontend), Srb, Pdo->DeviceType);
        break;
    case SCSIOP_MODE_SENSE:
        PdoModeSense(Pdo, Srb);
        break;
    case SCSIOP_REQUEST_SENSE:
        PdoRequestSense(Pdo, Srb);
        break;
    case SCSIOP_REPORT_LUNS:
        PdoReportLuns(Pdo, Srb);
        break;
    case SCSIOP_READ_CAPACITY:
        PdoReadCapacity(Pdo, Srb);
        break;
    case SCSIOP_READ_CAPACITY16:
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
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        break;
    case SCSIOP_START_STOP_UNIT:
        Trace("Target[%d] : Start/Stop Unit (%02X)\n", PdoGetTargetId(Pdo), Srb->Cdb[4]);
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        break;
    default:
        Trace("Target[%d] : Unsupported CDB (%02x:%s)\n", PdoGetTargetId(Pdo), Operation, Cdb_OperationName(Operation));
        break;
    }
    return TRUE;
}

static FORCEINLINE VOID
__PdoQueueShutdown(
    __in PXENVBD_PDO             Pdo,
    __in PSCSI_REQUEST_BLOCK     Srb
    )
{
    PXENVBD_SRBEXT      SrbExt = GetSrbExt(Srb);
    PXENVBD_NOTIFIER    Notifier = FrontendGetNotifier(Pdo->Frontend);

    QueueAppend(&Pdo->ShutdownSrbs, &SrbExt->Entry);
    NotifierTrigger(Notifier);
}

VOID
PdoReset(
    __in PXENVBD_PDO             Pdo
    )
{
    ULONG               Count;
    PXENVBD_NOTIFIER    Notifier = FrontendGetNotifier(Pdo->Frontend);

    Trace("Target[%d] ====> (Irql=%d)\n", PdoGetTargetId(Pdo), KeGetCurrentIrql());

    // Handles FreshSrbs and PreparedReqs
    PdoAbortAllSrbs(Pdo);

    // SubmittedReqs (5 secs)
    for (Count = 0; QueueCount(&Pdo->SubmittedReqs) && Count < 50000; ++Count) {
        FrontendNotifyResponses(Pdo->Frontend);
        NotifierSend(Notifier);
        StorPortStallExecution(100); // 100 micro-seconds
    }
    if (QueueCount(&Pdo->SubmittedReqs)) {
        Warning("Target[%d] : Still have %u requests outstanding\n", PdoGetTargetId(Pdo),
                                QueueCount(&Pdo->SubmittedReqs));

        for (;;) {
            PXENVBD_SRBEXT  SrbExt;
            PXENVBD_REQUEST Request;
            PLIST_ENTRY     Entry = QueuePop(&Pdo->SubmittedReqs);
            if (Entry == NULL)
                break;
            Request = CONTAINING_RECORD(Entry, XENVBD_REQUEST, Entry);
            SrbExt = GetSrbExt(Request->Srb);

            Verbose("Target[%d] : SubmittedReq 0x%p -> FAILED\n", PdoGetTargetId(Pdo), Request);
        
            SrbExt->Srb->SrbStatus = SRB_STATUS_ABORTED;
            RequestCleanup(Pdo, Request);
            __LookasideFree(&Pdo->RequestList, Request);

            if (InterlockedDecrement(&SrbExt->Count) == 0) {
                SrbExt->Srb->ScsiStatus = 0x40; // SCSI_ABORTED
                FdoCompleteSrb(PdoGetFdo(Pdo), SrbExt->Srb);
            }
        }
    }

    Trace("Target[%d] <==== (Irql=%d)\n", PdoGetTargetId(Pdo), KeGetCurrentIrql());
}

__checkReturn
static FORCEINLINE BOOLEAN
__ValidateSrbForPdo(
    __in PXENVBD_PDO             Pdo,
    __in PSCSI_REQUEST_BLOCK     Srb
    )
{
    const UCHAR Operation = Cdb_OperationEx(Srb);

    if (Pdo == NULL) {
        Error("Invalid Pdo(NULL) (%02x:%s)\n", 
                Operation, Cdb_OperationName(Operation));
        Srb->SrbStatus = SRB_STATUS_INVALID_TARGET_ID;
        return FALSE;
    }

    if (Srb->PathId != 0) {
        Error("Target[%d] : Invalid PathId(%d) (%02x:%s)\n", 
                PdoGetTargetId(Pdo), Srb->PathId, Operation, Cdb_OperationName(Operation));
        Srb->SrbStatus = SRB_STATUS_INVALID_PATH_ID;
        return FALSE;
    }

    if (Srb->Lun != 0) {
        Error("Target[%d] : Invalid Lun(%d) (%02x:%s)\n", 
                PdoGetTargetId(Pdo), Srb->Lun, Operation, Cdb_OperationName(Operation));
        Srb->SrbStatus = SRB_STATUS_INVALID_LUN;
        return FALSE;
    }

    if (PdoIsMissing(Pdo)) {
        Error("Target[%d] : %s (%s) (%02x:%s)\n", 
                PdoGetTargetId(Pdo), Pdo->Missing ? "MISSING" : "NOT_MISSING", Pdo->Reason, Operation, Cdb_OperationName(Operation));
        Srb->SrbStatus = SRB_STATUS_NO_DEVICE;
        return FALSE;
    }

    if (!Pdo->EmulatedUnplugged) {
        Error("Target[%d] : Disk is Emulated (%02x:%s)\n", 
                PdoGetTargetId(Pdo), Operation, Cdb_OperationName(Operation));
        Srb->SrbStatus = SRB_STATUS_NO_DEVICE;
        return FALSE;
    }

    return TRUE;
}

__checkReturn
BOOLEAN
PdoStartIo(
    __in PXENVBD_PDO             Pdo,
    __in PSCSI_REQUEST_BLOCK     Srb
    )
{
    if (!__ValidateSrbForPdo(Pdo, Srb))
        return TRUE;

    switch (Srb->Function) {
    case SRB_FUNCTION_EXECUTE_SCSI:
        return __PdoExecuteScsi(Pdo, Srb);

    case SRB_FUNCTION_RESET_DEVICE:
        PdoReset(Pdo);
        return TRUE;

    case SRB_FUNCTION_FLUSH:
    case SRB_FUNCTION_SHUTDOWN:
        __PdoQueueShutdown(Pdo, Srb);
        return FALSE;

    default:
        return TRUE;
    }
}

VOID
PdoAbortAllSrbs(
    __in PXENVBD_PDO             Pdo
    )
{
    // Abort Fresh SRBs
    for (;;) {
        PXENVBD_SRBEXT  SrbExt;
        PLIST_ENTRY     Entry = QueuePop(&Pdo->FreshSrbs);
        if (Entry == NULL)
            break;
        SrbExt = CONTAINING_RECORD(Entry, XENVBD_SRBEXT, Entry);

        Verbose("Target[%d] : FreshSrb 0x%p -> SCSI_ABORTED\n", PdoGetTargetId(Pdo), SrbExt->Srb);
        SrbExt->Srb->SrbStatus = SRB_STATUS_ABORTED;
        SrbExt->Srb->ScsiStatus = 0x40; // SCSI_ABORTED;
        FdoCompleteSrb(PdoGetFdo(Pdo), SrbExt->Srb);
    }

    // Fail PreparedReqs
    for (;;) {
        PXENVBD_SRBEXT  SrbExt;
        PXENVBD_REQUEST Request;
        PLIST_ENTRY     Entry = QueuePop(&Pdo->PreparedReqs);
        if (Entry == NULL)
            break;
        Request = CONTAINING_RECORD(Entry, XENVBD_REQUEST, Entry);
        SrbExt = GetSrbExt(Request->Srb);

        Verbose("Target[%d] : PreparedReq 0x%p -> FAILED\n", PdoGetTargetId(Pdo), Request);
        
        SrbExt->Srb->SrbStatus = SRB_STATUS_ABORTED;
        RequestCleanup(Pdo, Request);
        __LookasideFree(&Pdo->RequestList, Request);

        if (InterlockedDecrement(&SrbExt->Count) == 0) {
            SrbExt->Srb->ScsiStatus = 0x40; // SCSI_ABORTED
            FdoCompleteSrb(PdoGetFdo(Pdo), SrbExt->Srb);
        }
    }
}

VOID
PdoSrbPnp(
    __in PXENVBD_PDO             Pdo,
    __in PSCSI_PNP_REQUEST_BLOCK Srb
    )
{
    switch (Srb->PnPAction) {
    case StorQueryCapabilities: {
        PSTOR_DEVICE_CAPABILITIES DeviceCaps = Srb->DataBuffer;
        PXENVBD_CAPS    Caps = FrontendGetCaps(Pdo->Frontend);

        if (Caps->Removable)
            DeviceCaps->Removable = 1;
        if (Caps->Removable)
            DeviceCaps->EjectSupported = 1;
        if (Caps->SurpriseRemovable)
            DeviceCaps->SurpriseRemovalOK = 1;
    
        DeviceCaps->UniqueID = 1;

        } break;

    default:
        break;
    }
}

//=============================================================================
// PnP Handler
extern PDRIVER_DISPATCH StorPortDispatchPnp;

static FORCEINLINE VOID
__PdoDeviceUsageNotification(
    __in PXENVBD_PDO             Pdo,
    __in PIRP                    Irp
    )
{
    PIO_STACK_LOCATION      StackLocation;
    BOOLEAN                 Value;
    DEVICE_USAGE_NOTIFICATION_TYPE  Type;
    PXENVBD_CAPS            Caps = FrontendGetCaps(Pdo->Frontend);

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    Value = StackLocation->Parameters.UsageNotification.InPath;
    Type  = StackLocation->Parameters.UsageNotification.Type;

    switch (Type) {
    case DeviceUsageTypePaging:
        if (Caps->Paging == Value)
            return;
        Caps->Paging = Value;
        break;

    case DeviceUsageTypeHibernation:
        if (Caps->Hibernation == Value)
            return;
        Caps->Hibernation = Value;
        break;

    case DeviceUsageTypeDumpFile:
        if (Caps->DumpFile == Value)
            return;
        Caps->DumpFile = Value;
        break;

    default:
        return;
    }
    FrontendWriteUsage(Pdo->Frontend);
}

static FORCEINLINE VOID
__PdoCheckEjectPending(
    __in PXENVBD_PDO             Pdo
    )
{
    KIRQL               Irql;
    BOOLEAN             EjectPending = FALSE;

    KeAcquireSpinLock(&Pdo->Lock, &Irql);
    if (Pdo->EjectPending) {
        EjectPending = TRUE;
        Pdo->EjectPending = FALSE;
        Pdo->EjectRequested = TRUE;
    }
    KeReleaseSpinLock(&Pdo->Lock, Irql);

    if (EjectPending) {
        Verbose("Target[%d] : IoRequestDeviceEject(0x%p)\n", PdoGetTargetId(Pdo), Pdo->DeviceObject);
        IoRequestDeviceEject(Pdo->DeviceObject);
    }
}

static FORCEINLINE VOID
__PdoCheckEjectFailed(
    __in PXENVBD_PDO             Pdo
    )
{
    KIRQL               Irql;
    BOOLEAN             EjectFailed = FALSE;

    KeAcquireSpinLock(&Pdo->Lock, &Irql);
    if (Pdo->EjectRequested) {
        EjectFailed = TRUE;
        Pdo->EjectRequested = FALSE;
    }
    KeReleaseSpinLock(&Pdo->Lock, Irql);

    if (EjectFailed) {
        Error("Target[%d] : Unplug failed due to open handle(s)!\n", PdoGetTargetId(Pdo));
        FrontendStoreWriteFrontend(Pdo->Frontend, "error", "Unplug failed due to open handle(s)!");
    }
}

static FORCEINLINE VOID
__PdoRemoveDevice(
    __in PXENVBD_PDO             Pdo
    )
{
    PdoD0ToD3(Pdo);

    switch (PdoGetDevicePnpState(Pdo)) {
    case SurpriseRemovePending:
        PdoSetMissing(Pdo, "Surprise Remove");
        PdoSetDevicePnpState(Pdo, Deleted);
        StorPortNotification(BusChangeDetected, PdoGetFdo(Pdo), 0);
        break;

    case Enumerated:
        PdoSetMissing(Pdo, "Removed");
        PdoSetDevicePnpState(Pdo, Deleted);
        StorPortNotification(BusChangeDetected, PdoGetFdo(Pdo), 0);
        break;

    default:
        PdoSetDevicePnpState(Pdo, Enumerated);
        break;
    }
}

static FORCEINLINE VOID
__PdoEject(
    __in PXENVBD_PDO             Pdo
    )
{
    PdoSetMissing(Pdo, "Ejected");
    PdoSetDevicePnpState(Pdo, Deleted);
    StorPortNotification(BusChangeDetected, PdoGetFdo(Pdo), 0);
}

__checkReturn
NTSTATUS
PdoDispatchPnp(
    __in PXENVBD_PDO             Pdo,
    __in PDEVICE_OBJECT          DeviceObject,
    __in PIRP                    Irp
    )
{
    PIO_STACK_LOCATION  Stack = IoGetCurrentIrpStackLocation(Irp);
    UCHAR               Minor = Stack->MinorFunction;
    ULONG               TargetId = PdoGetTargetId(Pdo);
    NTSTATUS            Status;

    __PdoCheckEjectPending(Pdo);

    switch (Stack->MinorFunction) {
    case IRP_MN_START_DEVICE:
        (VOID) PdoD3ToD0(Pdo);
        PdoSetDevicePnpState(Pdo, Started);
        break;

    case IRP_MN_QUERY_STOP_DEVICE:
        PdoSetDevicePnpState(Pdo, StopPending);
        break;

    case IRP_MN_CANCEL_STOP_DEVICE:
        __PdoRestoreDevicePnpState(Pdo, StopPending);
        break;

    case IRP_MN_STOP_DEVICE:
        PdoSetDevicePnpState(Pdo, Stopped);
        break;

    case IRP_MN_QUERY_REMOVE_DEVICE:
        PdoSetDevicePnpState(Pdo, RemovePending);
        break;

    case IRP_MN_CANCEL_REMOVE_DEVICE:
        __PdoCheckEjectFailed(Pdo);
        __PdoRestoreDevicePnpState(Pdo, RemovePending);
        break;

    case IRP_MN_SURPRISE_REMOVAL:
        PdoSetDevicePnpState(Pdo, SurpriseRemovePending);
        break;

    case IRP_MN_REMOVE_DEVICE:
        __PdoRemoveDevice(Pdo);
        break;

    case IRP_MN_EJECT:
        __PdoEject(Pdo);
        break;

    case IRP_MN_DEVICE_USAGE_NOTIFICATION:
        __PdoDeviceUsageNotification(Pdo, Irp);
        break;

    default:
        break;
    }
    PdoDereference(Pdo);
    Status = StorPortDispatchPnp(DeviceObject, Irp);
    if (!NT_SUCCESS(Status)) {
        Verbose("Target[%d] : %02x:%s -> %08x\n", TargetId, Minor, PnpMinorFunctionName(Minor), Status);
    }
    return Status;
}

__drv_maxIRQL(DISPATCH_LEVEL)
VOID
PdoIssueDeviceEject(
    __in PXENVBD_PDO             Pdo,
    __in __nullterminated const CHAR* Reason
    )
{
    KIRQL       Irql;
    BOOLEAN     DoEject = FALSE;

    KeAcquireSpinLock(&Pdo->Lock, &Irql);
    if (Pdo->DeviceObject) {
        DoEject = TRUE;
        Pdo->EjectRequested = TRUE;
    } else {
        Pdo->EjectPending = TRUE;
    }
    KeReleaseSpinLock(&Pdo->Lock, Irql);

    Verbose("Target[%d] : Ejecting (%s - %s)\n", PdoGetTargetId(Pdo), DoEject ? "Now" : "Next PnP IRP", Reason);
    if (!Pdo->WrittenEjected) {
        Pdo->WrittenEjected = TRUE;
        FrontendStoreWriteFrontend(Pdo->Frontend, "ejected", "1");
    }
    if (DoEject) {
        Verbose("Target[%d] : IoRequestDeviceEject(0x%p)\n", PdoGetTargetId(Pdo), Pdo->DeviceObject);
        IoRequestDeviceEject(Pdo->DeviceObject);
    } else {
        Verbose("Target[%d] : Triggering BusChangeDetected to detect device\n", PdoGetTargetId(Pdo));
        StorPortNotification(BusChangeDetected, PdoGetFdo(Pdo), 0);
    }
}

