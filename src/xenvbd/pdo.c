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

typedef struct _XENVBD_SG_INDEX {
    ULONG       Index;  // SGList Index
    ULONG       Offset; // Offset into SGElement
    ULONG       LastLength; // Last length of SGElement
} XENVBD_SG_INDEX, *PXENVBD_SG_INDEX;

#define PDO_SIGNATURE           'odpX'

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
    BOOLEAN                     EmulatedMasked;
    LONG                        Paused;

    // Eject
    BOOLEAN                     WrittenEjected;
    BOOLEAN                     EjectRequested;
    BOOLEAN                     EjectPending;
    BOOLEAN                     Missing;
    const CHAR*                 Reason;

    // SRBs
    KEVENT                      RequestListEmpty;
    LONG                        RequestListUsed;
    NPAGED_LOOKASIDE_LIST       RequestList;
    SRB_QUEUE                   FreshSrbs;
    SRB_QUEUE                   PreparedSrbs;
    SRB_QUEUE                   SubmittedSrbs;
    SRB_QUEUE                   ShutdownSrbs;

    // Stats
    ULONG                       OutstandingMappedPages;
    ULONG                       GrantOpFails;
    ULONG                       MapFails;
    ULONG                       BounceFails;
    ULONG                       Reads;
    ULONG                       Writes;
    ULONG                       Other;
    ULONG                       Aborted;
    ULONG64                     GrantedSegments;
    ULONG64                     BouncedSegments;
};

//=============================================================================
#define PDO_POOL_TAG            'odPX'
#define REQUEST_POOL_TAG        'qeRX'

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
DECLSPEC_NOINLINE VOID
PdoDebugCallback(
    __in PXENVBD_PDO Pdo,
    __in PXENBUS_DEBUG_INTERFACE DebugInterface,
    __in PXENBUS_DEBUG_CALLBACK  DebugCallback
    )
{
    if (Pdo == NULL || DebugInterface == NULL || DebugCallback == NULL)
        return;

    DEBUG(Printf, DebugInterface, DebugCallback,
          "PDO: Signature              : %08x\n", 
          Pdo->Signature);

    if (Pdo->Signature != PDO_SIGNATURE)
        return;

    DEBUG(Printf, DebugInterface, DebugCallback,
          "PDO: Fdo                    : 0x%p\n", 
          Pdo->Fdo);
    DEBUG(Printf, DebugInterface, DebugCallback,
          "PDO: DeviceObject           : 0x%p\n", 
          Pdo->DeviceObject);
    DEBUG(Printf, DebugInterface, DebugCallback,
          "PDO: ReferenceCount         : %d\n", 
          Pdo->ReferenceCount);
    DEBUG(Printf, DebugInterface, DebugCallback,
          "PDO: DevicePnpState         : %s (%s)\n",
          __PnpStateName(Pdo->DevicePnpState),
          __PnpStateName(Pdo->PrevPnpState));
    DEBUG(Printf, DebugInterface, DebugCallback,
          "PDO: DevicePowerState       : %s\n",
          PowerDeviceStateName(Pdo->DevicePowerState));
    DEBUG(Printf, DebugInterface, DebugCallback,
          "PDO: EmulatedMasked         : %s\n", 
          Pdo->EmulatedMasked ? "TRUE" : "FALSE");
    DEBUG(Printf, DebugInterface, DebugCallback,
          "PDO: Missing                : %s\n",
          Pdo->Missing ? Pdo->Reason : "Not Missing");
    DEBUG(Printf, DebugInterface, DebugCallback,
          "PDO: OutstandingMappedPages : %d\n",
          Pdo->OutstandingMappedPages);
    DEBUG(Printf, DebugInterface, DebugCallback,
          "PDO: GrantOpFails           : %d\n",
          Pdo->GrantOpFails);
    DEBUG(Printf, DebugInterface, DebugCallback,
          "PDO: MapFails               : %d\n",
          Pdo->MapFails);
    DEBUG(Printf, DebugInterface, DebugCallback,
          "PDO: BounceFails            : %d\n",
          Pdo->BounceFails);
    DEBUG(Printf, DebugInterface, DebugCallback,
          "PDO: ReadSRBs               : %d\n", 
          Pdo->Reads);
    DEBUG(Printf, DebugInterface, DebugCallback,
          "PDO: WriteSRBs              : %d\n", 
          Pdo->Writes);
    DEBUG(Printf, DebugInterface, DebugCallback,
          "PDO: SyncSRBs               : %d\n", 
          Pdo->Other);
    DEBUG(Printf, DebugInterface, DebugCallback,
          "PDO: AbortedSRBs            : %d\n",
          Pdo->Aborted);
    DEBUG(Printf, DebugInterface, DebugCallback,
          "PDO: BouncedSegments        : %lld\n", 
          Pdo->BouncedSegments);
    DEBUG(Printf, DebugInterface, DebugCallback,
          "PDO: GrantedSegments        : %lld\n", 
          Pdo->GrantedSegments);

    FrontendDebugCallback(Pdo->Frontend, DebugInterface, DebugCallback);
    QueueDebugCallback(&Pdo->FreshSrbs, "Fresh", DebugInterface, DebugCallback);
    QueueDebugCallback(&Pdo->PreparedSrbs, "Prepared", DebugInterface, DebugCallback);
    QueueDebugCallback(&Pdo->SubmittedSrbs, "Submitted", DebugInterface, DebugCallback);
    QueueDebugCallback(&Pdo->ShutdownSrbs, "Shutdown", DebugInterface, DebugCallback);

    Pdo->OutstandingMappedPages = 0;
    Pdo->GrantOpFails = 0;
    Pdo->MapFails = 0;
    Pdo->BounceFails = 0;
    Pdo->Reads = 0;
    Pdo->Writes = 0;
    Pdo->Other = 0;
    Pdo->BouncedSegments = Pdo->GrantedSegments = 0;
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
PdoIsMasked(
    __in PXENVBD_PDO             Pdo
    )
{
    return Pdo->EmulatedMasked;
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
    KIRQL         Irql;
    LARGE_INTEGER Timeout;

    KeAcquireSpinLock(&Pdo->Lock, &Irql);
    ++Pdo->Paused;
    KeReleaseSpinLock(&Pdo->Lock, Irql);

    Verbose("Target[%d] : Waiting for %d Submitted SRBs\n", PdoGetTargetId(Pdo), QueueCount(&Pdo->SubmittedSrbs));

    Timeout.QuadPart = -10000000;
    while (QueueCount(&Pdo->SubmittedSrbs)) {
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

//=============================================================================
// Creation/Deletion
__checkReturn
NTSTATUS
PdoCreate(
    __in PXENVBD_FDO             Fdo,
    __in __nullterminated PCHAR  DeviceId,
    __in ULONG                   TargetId,
    __in BOOLEAN                 EmulatedMasked,
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

    Verbose("Target[%d] : Creating (%s)\n", TargetId, EmulatedMasked ? "PV" : "Emulated");
    Pdo->Signature      = PDO_SIGNATURE;
    Pdo->Fdo            = Fdo;
    Pdo->DeviceObject   = NULL; // filled in later
    KeInitializeEvent(&Pdo->RemoveEvent, SynchronizationEvent, FALSE);
    Pdo->ReferenceCount = 1;
    Pdo->Paused         = 1; // Paused until D3->D0 transition
    Pdo->DevicePnpState = Present;
    Pdo->DevicePowerState = PowerDeviceD3;
    Pdo->EmulatedMasked = EmulatedMasked;
    Pdo->DeviceType     = DeviceType;

    KeInitializeSpinLock(&Pdo->Lock);
    QueueInit(&Pdo->FreshSrbs);
    QueueInit(&Pdo->PreparedSrbs);
    QueueInit(&Pdo->SubmittedSrbs);
    QueueInit(&Pdo->ShutdownSrbs);

    Status = FrontendCreate(Pdo, DeviceId, TargetId, FrontendEvent, &Pdo->Frontend);
    if (!NT_SUCCESS(Status))
        goto fail2;

    Pdo->RequestListUsed = 0;
    KeInitializeEvent(&Pdo->RequestListEmpty, SynchronizationEvent, TRUE);
    ExInitializeNPagedLookasideList(&Pdo->RequestList, NULL, NULL, 0, 
                                    sizeof(XENVBD_REQUEST), REQUEST_POOL_TAG, 0);

    Status = PdoD3ToD0(Pdo);
    if (!NT_SUCCESS(Status))
        goto fail3;

    if (!FdoLinkPdo(Fdo, Pdo))
        goto fail4;

    Verbose("Target[%d] : Created (%s)\n", TargetId, EmulatedMasked ? "PV" : "Emulated");
    Trace("Target[%d] @ (%d) <=====\n", TargetId, KeGetCurrentIrql());
    return STATUS_SUCCESS;

fail4:
    Error("Fail4\n");
    PdoD0ToD3(Pdo);

fail3:
    Error("Fail3\n");
    ExDeleteNPagedLookasideList(&Pdo->RequestList);
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
    PVOID       Objects[2];

    Trace("Target[%d] @ (%d) =====>\n", TargetId, KeGetCurrentIrql());
    Verbose("Target[%d] : Destroying\n", TargetId);

    ASSERT3U(Pdo->Signature, ==, PDO_SIGNATURE);
    if (!FdoUnlinkPdo(PdoGetFdo(Pdo), Pdo)) {
        Error("Target[%d] : PDO 0x%p not linked to FDO 0x%p\n", TargetId, Pdo, PdoGetFdo(Pdo));
    }

    PdoD0ToD3(Pdo);
    PdoDereference(Pdo); // drop initial ref count

    // Wait for ReferenceCount == 0 and RequestListUsed == 0
    Verbose("Target[%d] : ReferenceCount %d, RequestListUsed %d\n", TargetId, Pdo->ReferenceCount, Pdo->RequestListUsed);
    Objects[0] = &Pdo->RemoveEvent;
    Objects[1] = &Pdo->RequestListEmpty;
    KeWaitForMultipleObjects(2, Objects, WaitAll, Executive, KernelMode, FALSE, NULL, NULL);
    ASSERT3S(Pdo->ReferenceCount, ==, 0);
    ASSERT3U(PdoGetDevicePnpState(Pdo), ==, Deleted);

    ASSERT3U(Pdo->RequestListUsed, ==, 0);
    ExDeleteNPagedLookasideList(&Pdo->RequestList);

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
    Verbose("Target[%d] : D3->D0 (%s)\n", TargetId, Pdo->EmulatedMasked ? "PV" : "Emulated");

    // power up frontend
    Status = FrontendD3ToD0(Pdo->Frontend);
    if (!NT_SUCCESS(Status))
        goto fail1;
    
    // connect frontend
    if (Pdo->EmulatedMasked) {
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
    Verbose("Target[%d] : D0->D3 (%s)\n", TargetId, Pdo->EmulatedMasked ? "PV" : "Emulated");

    // close frontend
    if (Pdo->EmulatedMasked) {
        __PdoPauseDataPath(Pdo);
        (VOID) FrontendSetState(Pdo->Frontend, XENVBD_CLOSED);
        PdoAbortAllSrbs(Pdo);
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
    if (Pdo == NULL)    
        return 0;
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
PdoOutstandingSrbs(
    __in PXENVBD_PDO             Pdo
    )
{
    return QueueCount(&Pdo->SubmittedSrbs);
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
// REQUEST related
static FORCEINLINE VOID
__PdoIncMappedPages(
    __in PXENVBD_PDO             Pdo,
    __in PFN_NUMBER              Pfn0,
    __in PFN_NUMBER              Pfn1
    )
{
    if (Pfn0)
        ++Pdo->OutstandingMappedPages;
    if (Pfn1)
        ++Pdo->OutstandingMappedPages;
}
static FORCEINLINE VOID
__PdoDecMappedPages(
    __in PXENVBD_PDO             Pdo,
    __in PFN_NUMBER              Pfn0,
    __in PFN_NUMBER              Pfn1
    )
{
    if (Pfn0)
        --Pdo->OutstandingMappedPages;
    if (Pfn1)
        --Pdo->OutstandingMappedPages;
}
__checkReturn
static FORCEINLINE PXENVBD_REQUEST
__AllocRequest(
    __in PXENVBD_PDO             Pdo
    )
{
    PVOID Request;
    Request = ExAllocateFromNPagedLookasideList(&Pdo->RequestList);
    if (Request) {
        LONG    Result;
        
        Result = InterlockedIncrement(&Pdo->RequestListUsed);
        ASSERT3S(Result, >, 0);

        RtlZeroMemory(Request, sizeof(XENVBD_REQUEST));
        KeClearEvent(&Pdo->RequestListEmpty);
    }
    return Request;
}
static FORCEINLINE VOID
__FreeRequest(
    __in PXENVBD_PDO             Pdo,
    __in PXENVBD_REQUEST         Request
    )
{
    if (Request) {
        LONG    Result;

        ExFreeToNPagedLookasideList(&Pdo->RequestList, Request);
        Result = InterlockedDecrement(&Pdo->RequestListUsed);
        ASSERT3S(Result, >=, 0);
        
        if (Result == 0) {
            KeSetEvent(&Pdo->RequestListEmpty, IO_NO_INCREMENT, FALSE);
        }
    }
}
static VOID
__CleanupRequest(
    __in PXENVBD_PDO             Pdo,
    __in PXENVBD_REQUEST         Request,
    __in BOOLEAN                 CopyOut
    )
{
    ULONG               Index;

    if (Request == NULL)
        return;

    // ungrant request
    for (Index = 0; Index < XENVBD_MAX_SEGMENTS_PER_REQUEST; ++Index) {
        // ungrant (if granted)
        if (Request->Segments[Index].GrantRef) {
            FrontendGnttabPut(Pdo->Frontend, Request->Segments[Index].GrantRef);
            Request->Segments[Index].GrantRef = 0;
        }

        // release buffer (if got)
        if (Request->Segments[Index].BufferId) {
            if (Request->Operation == BLKIF_OP_READ && CopyOut) {
                ASSERT3P(Request->Segments[Index].Buffer, !=, NULL);
                BufferCopyOut(Request->Segments[Index].BufferId, Request->Segments[Index].Buffer, Request->Segments[Index].Length);
            }
            BufferPut(Request->Segments[Index].BufferId);

            Request->Segments[Index].BufferId = NULL;
        }

        // unmap buffer (if mapped)
        if (Request->Segments[Index].Buffer) {
            __PdoDecMappedPages(Pdo, Request->Segments[Index].Pfn[0], Request->Segments[Index].Pfn[1]);

            MmUnmapLockedPages(Request->Segments[Index].Buffer, &Request->Segments[Index].Mdl);
            RtlZeroMemory(&Request->Segments[Index].Mdl, sizeof(Request->Segments[Index].Mdl));
            RtlZeroMemory(Request->Segments[Index].Pfn, sizeof(Request->Segments[Index].Pfn));

            Request->Segments[Index].Buffer = NULL;
            Request->Segments[Index].Length = 0;
        }
    }
}
static VOID
__CleanupSrb(
    __in PXENVBD_PDO             Pdo,
    __in PSCSI_REQUEST_BLOCK     Srb
    )
{
    PXENVBD_SRBEXT      SrbExt = GetSrbExt(Srb);
    PLIST_ENTRY         Entry;

    if (SrbExt == NULL)
        return;
    while ((Entry = RemoveHeadList(&SrbExt->RequestList)) != &SrbExt->RequestList) {
        PXENVBD_REQUEST Request = CONTAINING_RECORD(Entry, XENVBD_REQUEST, Entry);
        __CleanupRequest(Pdo, Request, FALSE);
        __FreeRequest(Pdo, Request);
        InterlockedDecrement(&SrbExt->RequestSize);
    }
    ASSERT3S(SrbExt->RequestSize, ==, 0);
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
        Pdo->Other++;
        break;
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
static FORCEINLINE VOID
__GetPhysAddr(
    __in PSTOR_SCATTER_GATHER_LIST   SGList,
    __inout PXENVBD_SG_INDEX         SGIndex,
    __out PSTOR_PHYSICAL_ADDRESS     SGPhysAddr,
    __out PULONG                     SGPhysLen
    )
{
    PSTOR_SCATTER_GATHER_ELEMENT    SGElement;

    ASSERT3U(SGIndex->Index, <, SGList->NumberOfElements);

    SGElement = &SGList->List[SGIndex->Index];

    SGPhysAddr->QuadPart = SGElement->PhysicalAddress.QuadPart + SGIndex->Offset;
    *SGPhysLen           = __min(PAGE_SIZE - __Offset(*SGPhysAddr) - SGIndex->LastLength, SGElement->Length - SGIndex->Offset);

    ASSERT3U(*SGPhysLen, <=, PAGE_SIZE);
    ASSERT3U(SGIndex->Offset, <, SGElement->Length);

    SGIndex->LastLength = *SGPhysLen; // gets reset every time for Granted, every 1or2 times for Bounced
    SGIndex->Offset = SGIndex->Offset + *SGPhysLen;
    if (SGIndex->Offset >= SGElement->Length) {
        SGIndex->Index  = SGIndex->Index + 1;
        SGIndex->Offset = 0;
    }
}
__checkReturn
static FORCEINLINE BOOLEAN
__PhysAddrIsAligned(
    __in STOR_PHYSICAL_ADDRESS   PhysAddr,
    __in ULONG                   Length,
    __in ULONG                   Alignment
    )
{
    if ((PhysAddr.QuadPart & Alignment) || (Length & Alignment))
        return FALSE;
    else
        return TRUE;
}
static FORCEINLINE PFN_NUMBER
__Pfn(
    __in STOR_PHYSICAL_ADDRESS   PhysAddr
    )
{
    return (PFN_NUMBER)(PhysAddr.QuadPart >> PAGE_SHIFT);
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
__checkReturn
static NTSTATUS
PrepareReadWrite(
    __in PXENVBD_PDO             Pdo,
    __in PSCSI_REQUEST_BLOCK     Srb
    )
{
    NTSTATUS        Status;
    ULONG           SectorsDone;
    UCHAR           Operation;
    BOOLEAN         ReadOnly;
    ULONG           Index;
    ULONG           SectorsNow;

    PMDL             OriginalMDL;
    ULONG           GotMDL;

    PSTOR_SCATTER_GATHER_LIST   SGList;
    XENVBD_SG_INDEX             SGIndex;

    PXENVBD_SRBEXT  SrbExt = GetSrbExt(Srb);

    const ULONG64   StartSector     = Cdb_LogicalBlock(Srb);
    const ULONG     NumSectors      = Cdb_TransferBlock(Srb);
    const ULONG     SectorSize      = PdoSectorSize(Pdo);
    const ULONG     SectorsPerPage  = __SectorsPerPage(SectorSize);
    __Operation(Cdb_OperationEx(Srb), &Operation, &ReadOnly);

    SGList = StorPortGetScatterGatherList(PdoGetFdo(Pdo), Srb);
    RtlZeroMemory(&SGIndex, sizeof(SGIndex));
    GotMDL = StorPortGetOriginalMdl(PdoGetFdo(Pdo), Srb, &OriginalMDL);

    if (GotMDL !=STATUS_SUCCESS) {
        Warning("Didn't get mdl to check if mapped\n");
    }
    
    if (SrbExt == NULL)
        goto fail;

    SectorsDone = 0;
    SrbExt->RequestSize = 0;
    do {
        PXENVBD_REQUEST Request = __AllocRequest(Pdo);
        if (!Request) {
            Trace("Target[%d] : AllocRequest failed\n", PdoGetTargetId(Pdo));
            goto fail;
        }
        InsertTailList(&SrbExt->RequestList, &Request->Entry);
        InterlockedIncrement(&SrbExt->RequestSize);

        Request->Srb        = Srb;
        Request->Operation  = Operation;
        Request->NrSegments = 0;
        Request->FirstSector = StartSector + SectorsDone;
        Request->NrSectors  = 0; // not used for Read/Write

        for (Index = 0; Index < BLKIF_MAX_SEGMENTS_PER_REQUEST; ++Index) {
            STOR_PHYSICAL_ADDRESS   PhysAddr;
            ULONG                   PhysLen;
            PFN_NUMBER              Pfn;
            ULONG                   GrantRef, FirstSector, LastSector;

            Request->NrSegments++;
            
            SGIndex.LastLength = 0;
            __GetPhysAddr(SGList, &SGIndex, &PhysAddr, &PhysLen);
            if (__PhysAddrIsAligned(PhysAddr, PhysLen, SectorSize - 1)) {
                ++Pdo->GrantedSegments;
                // get first sector, last sector and count
                FirstSector = (__Offset(PhysAddr) + SectorSize - 1) / SectorSize;
                SectorsNow  = __min(NumSectors - SectorsDone, SectorsPerPage - FirstSector);
                LastSector  = FirstSector + SectorsNow - 1;

                ASSERT3U((PhysLen / SectorSize), ==, SectorsNow);
                ASSERT3U((PhysLen & (SectorSize - 1)), ==, 0);
               
                // simples - grab Pfn of PhysAddr
                Pfn         = __Pfn(PhysAddr);

                // ensure NULL
                Request->Segments[Index].Buffer         = NULL;
                Request->Segments[Index].Length         = 0;
                Request->Segments[Index].BufferId       = NULL;
            } else {
                PMDL        Mdl;
                PVOID       BufferId;
                PVOID       Buffer;
                ULONG       Length;


                ++Pdo->BouncedSegments;
                // get first sector, last sector and count
                FirstSector = 0;
                SectorsNow  = __min(NumSectors - SectorsDone, SectorsPerPage);
                LastSector  = SectorsNow - 1;

                // FIXME - This depends on an opaque MDL field, and should
                // not be released to the public.  It is for investigation
                // purposes only
                if ((GotMDL == STATUS_SUCCESS) && ((OriginalMDL->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA) != 0)) {
                    Warning("Mapping a previously kernel mapped MDL\n");
                }

                // map PhysAddr to 1 or 2 pages and lock for VirtAddr
#pragma warning(push)
#pragma warning(disable:28145)
                Mdl = &Request->Segments[Index].Mdl;
                Mdl->Next           = NULL;
                Mdl->Size           = (SHORT)(sizeof(MDL) + sizeof(PFN_NUMBER));
                Mdl->MdlFlags       = MDL_PAGES_LOCKED;
                Mdl->Process        = NULL;
                Mdl->MappedSystemVa = NULL;
                Mdl->StartVa        = NULL;
                Mdl->ByteCount      = PhysLen;
                Mdl->ByteOffset     = __Offset(PhysAddr);
                Request->Segments[Index].Pfn[0] = __Pfn(PhysAddr);
#pragma warning(pop)

                if (PhysLen < SectorsNow * SectorSize) {
                    __GetPhysAddr(SGList, &SGIndex, &PhysAddr, &PhysLen);
                    Mdl->Size       += sizeof(PFN_NUMBER);
                    Mdl->ByteCount  = Mdl->ByteCount + PhysLen;
                    Request->Segments[Index].Pfn[1] = __Pfn(PhysAddr);
                }

                ASSERT((Mdl->ByteCount & (SectorSize - 1)) == 0);
                ASSERT3U(Mdl->ByteCount, <=, PAGE_SIZE);
                ASSERT3U(SectorsNow, ==, (Mdl->ByteCount / SectorSize));
                
                Length = __min(Mdl->ByteCount, PAGE_SIZE);
                Buffer = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, 
                                        MmCached, NULL, FALSE, __PdoPriority(Pdo));
                if (!Buffer) {
                    ++Pdo->MapFails;
                    Warning("Target[%d] : MmMapLockedPagesSpecifyCache failed\n", PdoGetTargetId(Pdo));
                    goto fail;
                }
                __PdoIncMappedPages(Pdo, Request->Segments[Index].Pfn[0], Request->Segments[Index].Pfn[1]);

                ASSERT3P(MmGetMdlPfnArray(Mdl)[0], ==, Request->Segments[Index].Pfn[0]);
                ASSERT3P(MmGetMdlPfnArray(Mdl)[1], ==, Request->Segments[Index].Pfn[1]);
                
                Request->Segments[Index].Buffer         = Buffer;
                Request->Segments[Index].Length         = Length;

                // get and fill a buffer
                if (!BufferGet(Srb, &BufferId, &Pfn)) {
                    ++Pdo->BounceFails;
                    Warning("Target[%d] : BufferGet failed\n", PdoGetTargetId(Pdo));
                    goto fail;
                }
                Request->Segments[Index].BufferId       = BufferId;

                // copy contents in
                if (Operation == BLKIF_OP_WRITE) {
                    BufferCopyIn(BufferId, Buffer, Length);
                }
            }

            // Grant and Fill in last details
            Status = FrontendGnttabGet(Pdo->Frontend, Pfn, ReadOnly, &GrantRef);
            if (!NT_SUCCESS(Status)) {
                ++Pdo->GrantOpFails;
                Warning("Target[%d] : GNTTAB(Get) failed (%08x)\n", PdoGetTargetId(Pdo), Status);
                goto fail;
            }
            
            Request->Segments[Index].GrantRef       = GrantRef;
            Request->Segments[Index].FirstSector    = (UCHAR)FirstSector;
            Request->Segments[Index].LastSector     = (UCHAR)LastSector;

            SectorsDone += SectorsNow;
            if (SectorsDone >= NumSectors) {
                ASSERT3U(SectorsDone, ==, NumSectors);
                goto done;
            }
        }
        ASSERT3U(Request->NrSegments, >, 0);
        ASSERT3U(Request->NrSegments, <=, BLKIF_MAX_SEGMENTS_PER_REQUEST);
    } while (SectorsDone < NumSectors);

done:
    __UpdateStats(Pdo, Operation);
    QueueInsertTail(&Pdo->PreparedSrbs, Srb);
    return STATUS_SUCCESS;

fail:
    __CleanupSrb(Pdo, Srb);
    return STATUS_UNSUCCESSFUL;
}
__checkReturn
static NTSTATUS
PrepareSyncCache(
    __in PXENVBD_PDO             Pdo,
    __in PSCSI_REQUEST_BLOCK     Srb
    )
{
    PXENVBD_SRBEXT          SrbExt = GetSrbExt(Srb);
    PXENVBD_REQUEST         Request;
    
    if (SrbExt == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    Request = __AllocRequest(Pdo);
    if (!Request) {
        Trace("Target[%d] : AllocRequests failed\n", PdoGetTargetId(Pdo));
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    SrbExt->RequestSize = 1;
    InsertHeadList(&SrbExt->RequestList, &Request->Entry);

    Request->Srb = Srb;

    Request->Operation      = BLKIF_OP_WRITE_BARRIER;
    Request->NrSegments     = 0;
    Request->FirstSector    = Cdb_LogicalBlock(Srb);
    Request->NrSectors      = 0;

    __UpdateStats(Pdo, BLKIF_OP_WRITE_BARRIER);
    QueueInsertTail(&Pdo->PreparedSrbs, Srb);
    return STATUS_SUCCESS;
}

//=============================================================================
// Queue-Related
ULONG
PdoPrepareFresh(
    __in PXENVBD_PDO             Pdo
    )
{
    ULONG   Count = 0;
    for (;;) {
        PSCSI_REQUEST_BLOCK     Srb;
        NTSTATUS                Status;

        Srb = QueuePop(&Pdo->FreshSrbs);
        if (Srb == NULL) {
            goto done;
        }

        // popped a SRB, process it
        switch (Cdb_OperationEx(Srb)) {
        case SCSIOP_READ:
        case SCSIOP_WRITE:
            Status = PrepareReadWrite(Pdo, Srb);
            break;
        case SCSIOP_SYNCHRONIZE_CACHE:
            Status = PrepareSyncCache(Pdo, Srb);
            break;
        default:
            ASSERT(FALSE);
            Status = STATUS_NOT_SUPPORTED;
            break;
        }

        // if failed to prepare, put on fresh and finish up
        if (NT_SUCCESS(Status)) {
            ++Count;
        } else {
            QueueInsertHead(&Pdo->FreshSrbs, Srb);
            goto done;
        }
    }
done:
    return Count;
}

ULONG
PdoSubmitPrepared(
    __in PXENVBD_PDO             Pdo
    )
{
    ULONG                       Count = 0;

    for (;;) {
        PSCSI_REQUEST_BLOCK Srb;

        Srb = QueuePop(&Pdo->PreparedSrbs);
        if (Srb == NULL) {
            break;
        }

        if (!FrontendSubmitRequest(Pdo->Frontend, Srb)) {
            QueueInsertHead(&Pdo->PreparedSrbs, Srb);
            break;
        }

        QueueInsertTail(&Pdo->SubmittedSrbs, Srb);
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        ++Count;

        FrontendPushRequests(Pdo->Frontend);
    }

    return Count;
}

static FORCEINLINE VOID
__PdoResetSrbToFresh(
    __in PXENVBD_PDO             Pdo,
    __in PSCSI_REQUEST_BLOCK     Srb
    )
{
    PXENVBD_SRBEXT  SrbExt = GetSrbExt(Srb);

    __CleanupSrb(Pdo, Srb);

    if (SrbExt) {
        RtlZeroMemory(SrbExt, sizeof(XENVBD_SRBEXT));
        InitializeListHead(&SrbExt->RequestList);
        SrbExt->Srb = Srb;
    }

    Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
}
VOID
PdoPreResume(
    __in PXENVBD_PDO             Pdo
    )
{
    ULONG   Count;

    // Move PreparedSrbs to FreshSrbs
    Count = 0;
    for (;;) {
        PSCSI_REQUEST_BLOCK Srb;
        
        Srb = QueueRemoveTail(&Pdo->PreparedSrbs);
        if (Srb == NULL)
            break;

        ++Count;
        __PdoResetSrbToFresh(Pdo, Srb);

        QueueInsertHead(&Pdo->FreshSrbs, Srb);
    }
    Verbose("Target[%d] : Reverting %d Prepared SRBs to Fresh\n", 
                PdoGetTargetId(Pdo), Count);

    // Move SubmittedSrbs to FreshSrbs
    Count = 0;
    for (;;) {
        PSCSI_REQUEST_BLOCK Srb;
        
        Srb = QueueRemoveTail(&Pdo->SubmittedSrbs);
        if (Srb == NULL)
            break;

        ++Count;
        __PdoResetSrbToFresh(Pdo, Srb);

        QueueInsertHead(&Pdo->FreshSrbs, Srb);
    }

    Verbose("Target[%d] : Reverting %d Submitted SRBs to Fresh\n", 
                PdoGetTargetId(Pdo), Count);
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

VOID
PdoCompleteShutdown(
    __in PXENVBD_PDO             Pdo
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
        FdoCompleteSrb(PdoGetFdo(Pdo), Srb);
    }
}

static FORCEINLINE PCHAR
__ErrorCode(
    __in SHORT                   Status
    )
{
    switch (Status) {
    case BLKIF_RSP_OKAY:        return "OKAY";
    case BLKIF_RSP_EOPNOTSUPP:  return "EOPNOTSUPP";
    case BLKIF_RSP_ERROR:       return "ERROR";
    default:                    return "UNKNOWN";
    }
}
VOID
PdoCompleteSubmittedRequest(
    __in PXENVBD_PDO             Pdo,
    __in PXENVBD_REQUEST         Request,
    __in SHORT                   Status
    )
{
    PSCSI_REQUEST_BLOCK Srb = Request->Srb;
    PXENVBD_SRBEXT      SrbExt = GetSrbExt(Srb);
    ASSERT3P(SrbExt, !=, NULL);

    if (Status != BLKIF_RSP_OKAY) {
        Srb->SrbStatus = SRB_STATUS_ERROR;
        Warning("Target[%d] : %s %s\n", PdoGetTargetId(Pdo), Cdb_OperationName(Request->Operation), __ErrorCode(Status));
    }

    switch (Request->Operation) {
    case BLKIF_OP_READ:
    case BLKIF_OP_WRITE:
        // cleanup buffers
        __CleanupRequest(Pdo, Request, TRUE);
        break;
    case BLKIF_OP_WRITE_BARRIER:
        if (Status == BLKIF_RSP_EOPNOTSUPP) {
            // remove supported feature
            FrontendGetFeatures(Pdo->Frontend)->Barrier = FALSE;
            Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
        }
        break;
    case BLKIF_OP_DISCARD:
        if (Status == BLKIF_RSP_EOPNOTSUPP) {
            // remove supported feature
            FrontendGetFeatures(Pdo->Frontend)->Discard = FALSE;
            Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
        }
        break;
    default:
        ASSERT(FALSE);
        break;
    }

    RemoveEntryList(&Request->Entry);
    InterlockedDecrement(&SrbExt->RequestSize);

    __FreeRequest(Pdo, Request);

    // complete srb
    if (IsListEmpty(&SrbExt->RequestList)) {
        ASSERT3S(SrbExt->RequestSize, ==, 0);
        if (Srb->SrbStatus == SRB_STATUS_SUCCESS) {
            Srb->ScsiStatus = 0x00; // SCSI_GOOD
        } else {
            Srb->ScsiStatus = 0x40; // SCSI_ABORTED
        }

        QueueRemove(&Pdo->SubmittedSrbs, Srb);
        FdoCompleteSrb(PdoGetFdo(Pdo), Srb);
    }
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
    NTSTATUS    Status;
    PXENVBD_DISKINFO    DiskInfo = FrontendGetDiskInfo(Pdo->Frontend);

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

    QueueInsertTail(&Pdo->FreshSrbs, Srb);
    FrontendEvtchnTrigger(Pdo->Frontend);

    return FALSE;
}
__checkReturn
static DECLSPEC_NOINLINE BOOLEAN
PdoSyncCache(
    __in PXENVBD_PDO             Pdo,
    __in PSCSI_REQUEST_BLOCK     Srb
    )
{
    NTSTATUS    Status;

    if (FrontendGetCaps(Pdo->Frontend)->Connected == FALSE) {
        Trace("Target[%d] : Not Ready, fail SRB\n", PdoGetTargetId(Pdo));
        Srb->ScsiStatus = 0x40; // SCSI_ABORT;
        return TRUE;
    }

    if (FrontendGetFeatures(Pdo->Frontend)->Barrier == FALSE) {
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

    QueueInsertTail(&Pdo->FreshSrbs, Srb);
    FrontendEvtchnTrigger(Pdo->Frontend);

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
static VOID
__AbortSrbQueue(
    __in PSRB_QUEUE              Queue,
    __in PXENVBD_PDO             Pdo,
    __in BOOLEAN                 Free,
    __in PCHAR                   Name
    )
{
    PSCSI_REQUEST_BLOCK Srb;

    while ((Srb = QueuePop(Queue)) != NULL) {
        ++Pdo->Aborted;
        Trace("Target[%d] : Aborting SRB %p from %s\n", PdoGetTargetId(Pdo), Srb, Name);
        if (Free)
            __CleanupSrb(Pdo, Srb);

        Srb->ScsiStatus = 0x40; // SCSI_ABORTED;
        FdoCompleteSrb(PdoGetFdo(Pdo), Srb);
    }
}
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
    QueueInsertTail(&Pdo->ShutdownSrbs, Srb);
    FrontendEvtchnTrigger(Pdo->Frontend);
}

VOID
PdoReset(
    __in PXENVBD_PDO             Pdo
    )
{
    PSCSI_REQUEST_BLOCK     Srb;
    ULONG                   Count = 0;

    Trace("Target[%d] ====> (Irql=%d)\n", PdoGetTargetId(Pdo), KeGetCurrentIrql());

    while ((Srb = QueuePop(&Pdo->FreshSrbs)) != NULL) {
        Srb->ScsiStatus = 0x40; //SCSI_STATUS_ABORTED;
        FdoCompleteSrb(PdoGetFdo(Pdo), Srb);
    }

    while (QueuePeek(&Pdo->PreparedSrbs) || 
           QueuePeek(&Pdo->SubmittedSrbs)) {

        /* For prepared and submitted SRBs we just wait until they
            complete normally.  We need to keep calling the event
            channel callback directly, since scsiport won't run the
            callback itself until we finish this SRB (which is also
            why we don't need to worry about races). */
        FrontendNotifyResponses(Pdo->Frontend);
        FrontendEvtchnSend(Pdo->Frontend);

        if (QueuePeek(&Pdo->PreparedSrbs) || 
            QueuePeek(&Pdo->SubmittedSrbs)) {
            StorPortStallExecution(1000);
            if (Count > 1000) {
                Verbose("Target[%d] : Outstanding SRBs (%d Prepared, %d Submitted)\n", 
                            PdoGetTargetId(Pdo), QueueCount(&Pdo->PreparedSrbs), QueueCount(&Pdo->SubmittedSrbs));
                Count = 0;
            } else {
                Count++;
            }
        }
    }

    FrontendNotifyResponses(Pdo->Frontend);
    FrontendEvtchnSend(Pdo->Frontend);

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

    if (!Pdo->EmulatedMasked) {
        Error("Target[%d] : Emulated Masked (%02x:%s)\n", 
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
    const ULONG   Aborted = Pdo->Aborted;
    __AbortSrbQueue(&Pdo->FreshSrbs, Pdo, FALSE, "Fresh");
    __AbortSrbQueue(&Pdo->PreparedSrbs, Pdo, TRUE, "Prepared");
    __AbortSrbQueue(&Pdo->SubmittedSrbs, Pdo, TRUE, "Submitted");
    Verbose("Target[%d] : %d / %d Aborted SRBs\n", PdoGetTargetId(Pdo), Aborted, Pdo->Aborted);
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

