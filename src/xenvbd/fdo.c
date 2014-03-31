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

#define INITGUID 1

#include "fdo.h"
#include "driver.h"
#include "pdo.h"
#include "srbext.h"
#include "thread.h"
#include "buffer.h"
#include "debug.h"
#include "assert.h"
#include "util.h"
#include <version.h>
#include <xencdb.h>
#include <names.h>
#include <store_interface.h>
#include <evtchn_interface.h>
#include <gnttab_interface.h>
#include <debug_interface.h>
#include <suspend_interface.h>
#include <emulated_interface.h>

#include <stdlib.h>

#define FDO_SIGNATURE   'odfX'

struct _XENVBD_FDO {
    ULONG                       Signature;
    KEVENT                      RemoveEvent;
    LONG                        ReferenceCount;
    PDEVICE_OBJECT              DeviceObject;
    PDEVICE_OBJECT              LowerDeviceObject;
    PDEVICE_OBJECT              PhysicalDeviceObject;
    KSPIN_LOCK                  Lock;
    DEVICE_POWER_STATE          DevicePower;
    ANSI_STRING                 Enumerator;

    // Power
    PXENVBD_THREAD              DevicePowerThread;
    PIRP                        DevicePowerIrp;

    // Interfaces to XenBus
    PXENBUS_STORE_INTERFACE     Store;
    PXENBUS_EVTCHN_INTERFACE    Evtchn;
    PXENBUS_GNTTAB_INTERFACE    Gnttab;
    PXENBUS_DEBUG_INTERFACE     Debug;
    PXENBUS_SUSPEND_INTERFACE   Suspend;
    PXENFILT_EMULATED_INTERFACE Emulated;
    
    // Debug Callback
    PXENBUS_DEBUG_CALLBACK      DebugCallback;
    PXENBUS_SUSPEND_CALLBACK    SuspendCallback;

    // Targets
    KSPIN_LOCK                  TargetLock;
    PXENVBD_PDO                 Targets[XENVBD_MAX_TARGETS];

    // Target Enumeration
    PXENVBD_THREAD              RescanThread;
    PXENBUS_STORE_WATCH         RescanWatch;
    PXENVBD_THREAD              FrontendThread;

    // Statistics
    LONG                        CurrentSrbs;
    LONG                        MaximumSrbs;
    LONG                        TotalSrbs;
};

extern PDRIVER_DISPATCH StorPortDispatchPower;

//=============================================================================
static FORCEINLINE BOOLEAN
__FdoSetDevicePowerState(
    __in PXENVBD_FDO                 Fdo,
    __in DEVICE_POWER_STATE          State
    )
{
    KIRQL       Irql;
    BOOLEAN     Changed = FALSE;

    KeAcquireSpinLock(&Fdo->Lock, &Irql);

    if (Fdo->DevicePower != State) {
        Verbose("POWER %s to %s\n", PowerDeviceStateName(Fdo->DevicePower), PowerDeviceStateName(State));
        Changed = TRUE;
        Fdo->DevicePower = State;
    }

    KeReleaseSpinLock(&Fdo->Lock, Irql);

    return Changed;
}

__checkReturn
static FORCEINLINE PXENVBD_PDO
__FdoGetPdoAlways(
    __in PXENVBD_FDO                 Fdo,
    __in ULONG                       TargetId,
    __in PCHAR                       Caller
    )
{
    PXENVBD_PDO Pdo;
    KIRQL       Irql;

    ASSERT3U(TargetId, <, XENVBD_MAX_TARGETS);

    KeAcquireSpinLock(&Fdo->TargetLock, &Irql);
    Pdo = Fdo->Targets[TargetId];
    if (Pdo) {
        __PdoReference(Pdo, Caller);
    }
    KeReleaseSpinLock(&Fdo->TargetLock, Irql);
    
    return Pdo;
}

__checkReturn
static FORCEINLINE PXENVBD_PDO
___FdoGetPdo(
    __in PXENVBD_FDO                 Fdo,
    __in ULONG                       TargetId,
    __in PCHAR                       Caller
    )
{
    PXENVBD_PDO Pdo = NULL;
    KIRQL       Irql;

    ASSERT3U(TargetId, <, XENVBD_MAX_TARGETS);

    KeAcquireSpinLock(&Fdo->TargetLock, &Irql);
    if (Fdo->Targets[TargetId] && 
        __PdoReference(Fdo->Targets[TargetId], Caller) > 0) {
        Pdo = Fdo->Targets[TargetId];
    }
    KeReleaseSpinLock(&Fdo->TargetLock, Irql);
    
    return Pdo;
}
#define __FdoGetPdo(f, t) ___FdoGetPdo(f, t, __FUNCTION__)

// Reference Counting
LONG
__FdoReference(
    __in PXENVBD_FDO                 Fdo,
    __in PCHAR                       Caller
    )
{
    LONG Result;
    
    ASSERT3P(Fdo, !=, NULL);
    Result = InterlockedIncrement(&Fdo->ReferenceCount);
    ASSERTREFCOUNT(Result, >, 0, Caller);

    if (Result == 1) {
        Result = InterlockedDecrement(&Fdo->ReferenceCount);
        Error("%s: Attempting to take reference of removed FDO from %d\n", Caller, Result);
        return 0;
    } else {
        ASSERTREFCOUNT(Result, >, 1, Caller);
        return Result;
    }
}
FORCEINLINE LONG
__FdoDereference(
    __in PXENVBD_FDO                 Fdo,
    __in PCHAR                       Caller
    )
{
    LONG    Result;
    
    ASSERT3P(Fdo, !=, NULL);
    Result = InterlockedDecrement(&Fdo->ReferenceCount);
    ASSERTREFCOUNT(Result, >=, 0, Caller);
    
    if (Result == 0) {
        Verbose("Final ReferenceCount dropped, 0x%p able to be removed\n", Fdo);
        KeSetEvent(&Fdo->RemoveEvent, IO_NO_INCREMENT, FALSE);
    }
    return Result;
}
BOOLEAN
FdoLinkPdo(
    __in PXENVBD_FDO                 Fdo,
    __in PXENVBD_PDO                 Pdo
    )
{
    KIRQL       Irql;
    PXENVBD_PDO Current;
    BOOLEAN     Result = FALSE;
    ULONG       TargetId = PdoGetTargetId(Pdo);

    KeAcquireSpinLock(&Fdo->TargetLock, &Irql);
    Current = Fdo->Targets[TargetId];
    if (Fdo->Targets[TargetId] == NULL) {
        Fdo->Targets[TargetId] = Pdo;
        Result = TRUE;
    }
    KeReleaseSpinLock(&Fdo->TargetLock, Irql);

    if (!Result) {
        Warning("Target[%d] : Current 0x%p, New 0x%p\n", TargetId, Current, Pdo);
    }
    return Result;
}
BOOLEAN
FdoUnlinkPdo(
    __in PXENVBD_FDO                 Fdo,
    __in PXENVBD_PDO                 Pdo
    )
{
    KIRQL       Irql;
    PXENVBD_PDO Current;
    BOOLEAN     Result = FALSE;
    ULONG       TargetId = PdoGetTargetId(Pdo);

    KeAcquireSpinLock(&Fdo->TargetLock, &Irql);
    Current = Fdo->Targets[TargetId];
    if (Fdo->Targets[TargetId] == Pdo) {
        Fdo->Targets[TargetId] = NULL;
        Result = TRUE;
    }
    KeReleaseSpinLock(&Fdo->TargetLock, Irql);

    if (!Result) {
        Warning("Target[%d] : Current 0x%p, Expected 0x%p\n", TargetId, Current, Pdo);
    }
    return Result;
}
//=============================================================================
// QueryInterface
__checkReturn
__drv_maxIRQL(APC_LEVEL)
static NTSTATUS
__QueryInterface(
    __in PDEVICE_OBJECT              DeviceObject,
    __in PCHAR                       Name,
    __in GUID                        Guid,
    __in ULONG                       Version,
    OUT PVOID*                      Result
    )
{
    KEVENT                  Event;
    IO_STATUS_BLOCK         StatusBlock;
    PIRP                    Irp;
    PIO_STACK_LOCATION      StackLocation;
    NTSTATUS                status;
    INTERFACE               Interface;

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    RtlZeroMemory(&StatusBlock, sizeof(IO_STATUS_BLOCK));
    RtlZeroMemory(&Interface, sizeof(INTERFACE));

    Irp = IoBuildSynchronousFsdRequest(IRP_MJ_PNP,
                                       DeviceObject,
                                       NULL,
                                       0,
                                       NULL,
                                       &Event,
                                       &StatusBlock);

    status = STATUS_UNSUCCESSFUL;
    if (Irp == NULL)
        goto fail1;

    StackLocation = IoGetNextIrpStackLocation(Irp);
    StackLocation->MinorFunction = IRP_MN_QUERY_INTERFACE;

    StackLocation->Parameters.QueryInterface.InterfaceType = &Guid;
    StackLocation->Parameters.QueryInterface.Size = (USHORT)sizeof(INTERFACE);
    StackLocation->Parameters.QueryInterface.Version = (USHORT)Version;
    StackLocation->Parameters.QueryInterface.Interface = &Interface;
    
    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    status = IoCallDriver(DeviceObject, Irp);
    if (status == STATUS_PENDING) {
        (VOID) KeWaitForSingleObject(&Event,
                              Executive,
                              KernelMode,
                              FALSE,
                              NULL);
        status = StatusBlock.Status;
    }

    if (!NT_SUCCESS(status))
        goto fail2;

    status = STATUS_INVALID_PARAMETER;
    if (Interface.Version != Version) 
        goto fail3;
    if (Interface.Size != sizeof(INTERFACE))
        goto fail4;

    *Result = Interface.Context;
    return STATUS_SUCCESS;

fail4:
    Error("%s:%d:fail4\n", Name, Version);

fail3:
    Error("%s:%d:fail3\n", Name, Version);

fail2:
    Error("%s:%d:fail2\n", Name, Version);
    
fail1:
    Error("%s:%d:fail1 (%08x)\n", Name, Version, status);

    return status;
}

//=============================================================================
// Debug

static DECLSPEC_NOINLINE VOID
FdoDebugCallback(
    __in PVOID                       Context,
    __in BOOLEAN                     Crashing
    )
{
    PXENVBD_FDO     Fdo = Context;
    ULONG           TargetId;

    if (Fdo == NULL || Fdo->Debug == NULL || Fdo->DebugCallback == NULL)
        return;

    DEBUG(Printf, Fdo->Debug, Fdo->DebugCallback,
          "FDO: Version: %d.%d.%d.%d (%d/%d/%d)\n",
          MAJOR_VERSION, MINOR_VERSION, MICRO_VERSION, BUILD_NUMBER,
          DAY, MONTH, YEAR); 
    DEBUG(Printf, Fdo->Debug, Fdo->DebugCallback,
          "FDO: Fdo: 0x%p (ref-count %d) %s\n",
          Context,
          Fdo->ReferenceCount,
          Crashing ? "CRASHING" : "");
    DEBUG(Printf, Fdo->Debug, Fdo->DebugCallback,
          "FDO: DevObj 0x%p LowerDevObj 0x%p PhysDevObj 0x%p\n",
          Fdo->DeviceObject,
          Fdo->LowerDeviceObject,
          Fdo->PhysicalDeviceObject);
    DEBUG(Printf, Fdo->Debug, Fdo->DebugCallback,
          "FDO: DevicePowerState: %s\n",
          PowerDeviceStateName(Fdo->DevicePower));
    DEBUG(Printf, Fdo->Debug, Fdo->DebugCallback,
          "FDO: Enumerator      : %s (0x%p)\n",
          FdoEnum(Fdo), Fdo->Enumerator.Buffer);
    DEBUG(Printf, Fdo->Debug, Fdo->DebugCallback,
          "FDO: Srbs            : %d / %d (%d Total)\n",
          Fdo->CurrentSrbs, Fdo->MaximumSrbs, Fdo->TotalSrbs);

    BufferDebugCallback(Fdo->Debug, Fdo->DebugCallback);
    
    for (TargetId = 0; TargetId < XENVBD_MAX_TARGETS; ++TargetId) {
        // no need to use __FdoGetPdo (which is locked at DISPATCH) as called at HIGH_LEVEL
        PXENVBD_PDO Pdo = Fdo->Targets[TargetId];
        if (Pdo == NULL)
            continue;

        DEBUG(Printf, Fdo->Debug, Fdo->DebugCallback,
              "FDO: ====> Target[%-3d]    : 0x%p\n",                  
              TargetId, Pdo);

        // call Target's debug callback directly
        PdoDebugCallback(Pdo, Fdo->Debug, Fdo->DebugCallback);

        DEBUG(Printf, Fdo->Debug, Fdo->DebugCallback,
              "FDO: <==== Target[%-3d]    : 0x%p\n",                  
              TargetId, Pdo);
    }

    Fdo->MaximumSrbs = Fdo->CurrentSrbs;
    Fdo->TotalSrbs = 0;
}

//=============================================================================
// Enumeration
__checkReturn
static FORCEINLINE PCHAR
__NextSz(
    __in PCHAR                       Str
    )
{
    for (; *Str; ++Str) ;
    ++Str;
    return Str;
}
static FORCEINLINE ULONG
__ParseVbd(
    __in PCHAR                       DeviceIdStr
    )
{
    ULONG   DeviceId = strtoul(DeviceIdStr, NULL, 10);
    
    ASSERT3U((DeviceId & ~((1 << 29) - 1)), ==, 0);

    if (DeviceId & (1 << 28)) { 
        return (DeviceId & ((1 << 20) - 1)) >> 8;           /* xvd    */
    } else {
        switch (DeviceId >> 8) {
        case 202:   return (DeviceId & 0xF0) >> 4;          /* xvd    */
        case 8:     return (DeviceId & 0xF0) >> 4;          /* sd     */
        case 3:     return (DeviceId & 0xC0) >> 6;          /* hda..b */
        case 22:    return ((DeviceId & 0xC0) >> 6) + 2;    /* hdc..d */
        case 33:    return ((DeviceId & 0xC0) >> 6) + 4;    /* hde..f */
        case 34:    return ((DeviceId & 0xC0) >> 6) + 6;    /* hdg..h */
        case 56:    return ((DeviceId & 0xC0) >> 6) + 8;    /* hdi..j */
        case 57:    return ((DeviceId & 0xC0) >> 6) + 10;   /* hdk..l */
        case 88:    return ((DeviceId & 0xC0) >> 6) + 12;   /* hdm..n */
        case 89:    return ((DeviceId & 0xC0) >> 6) + 14;   /* hdo..p */
        default:    break;
        }
        ASSERT3U(DeviceId, ==, ~0);
    }
    return 0xFFFFFFFF; // OBVIOUS ERROR VALUE
}
static FORCEINLINE XENVBD_DEVICE_TYPE
__DeviceType(
    __in PCHAR                      Type
    )
{
    if (strcmp(Type, "disk") == 0)
        return XENVBD_DEVICE_TYPE_DISK;
    if (strcmp(Type, "cdrom") == 0)
        return XENVBD_DEVICE_TYPE_CDROM;
    return XENVBD_DEVICE_TYPE_UNKNOWN;
}
__checkReturn
static FORCEINLINE BOOLEAN
__FdoHiddenTarget(
    __in PXENVBD_FDO                 Fdo,
    __in PCHAR                       DeviceId,
    __out PXENVBD_DEVICE_TYPE        DeviceType
    )
{
    NTSTATUS    Status;
    PCHAR       FrontendPath;
    PCHAR       Buffer;
    ULONG       Value;
    
    *DeviceType = XENVBD_DEVICE_TYPE_UNKNOWN;
    FrontendPath = DriverFormat("device/%s/%s", FdoEnum(Fdo), DeviceId);
    if (!FrontendPath)
        goto fail;

    // Ejected?
    Status = STORE(Read, Fdo->Store, NULL, FrontendPath, "ejected", &Buffer);
    if (NT_SUCCESS(Status)) {
        Value = strtoul(Buffer, NULL, 10);
        STORE(Free, Fdo->Store, Buffer);

        if (Value)
            goto ignore;
    }

    // Not Disk?
    Status = STORE(Read, Fdo->Store, NULL, FrontendPath, "device-type", &Buffer);
    if (!NT_SUCCESS(Status))
        goto ignore;
    *DeviceType = __DeviceType(Buffer);
    STORE(Free, Fdo->Store, Buffer);
    
    switch (*DeviceType) {
    case XENVBD_DEVICE_TYPE_DISK:   
        break;
    case XENVBD_DEVICE_TYPE_CDROM:  
        if (DriverParameters.PVCDRom)   
            break;
        // intentional fall-through
    default:                        
        goto ignore;
    }

    // Try to Create
    DriverFormatFree(FrontendPath);
    return FALSE;

fail:
    Error("Fail\n");
    return TRUE;

ignore:
    DriverFormatFree(FrontendPath);
    return TRUE;
}
__checkReturn
static FORCEINLINE BOOLEAN
__FdoIsPdoUnplugged(
    __in PXENVBD_FDO                 Fdo,
    __in PCHAR                       Enumerator,
    __in PCHAR                       Device,
    __in ULONG                       Target
    )
{
    // Only check targets that could be emulated
    if (Target > 3) {
        Verbose("Target[%d] : (%s/%s) Emulated NOT_APPLICABLE (non-IDE device)\n", 
                            Target, Enumerator, Device);
        return TRUE;
    }
     
    // Check presense of Emulated interface. Absence indicates emulated cannot be unplugged
    if (Fdo->Emulated == NULL) {
        Warning("Target[%d] : (%s/%s) Emulated NOT_KNOWN (assumed PRESENT)\n", 
                            Target, Enumerator, Device);
        return FALSE;
    }

    // Ask XenFilt if Ctrlr(0), Target(Target), Lun(0) is present
    if (EMULATED(IsDiskPresent, Fdo->Emulated, 0, Target, 0)) {
        Verbose("Target[%d] : (%s/%s) Emulated PRESENT\n", 
                            Target, Enumerator, Device);
        return FALSE;
    } else {
        Verbose("Target[%d] : (%s/%s) Emulated NOT_PRESENT\n", 
                            Target, Enumerator, Device);
        return TRUE;
    }
}
static VOID
__FdoNotifyInstaller(
    __in PXENVBD_FDO                Fdo
    )
{
    UNICODE_STRING                  Unicode;
    PKEY_VALUE_PARTIAL_INFORMATION  Partial;
    NTSTATUS                        status;

    UNREFERENCED_PARAMETER(Fdo);

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    Partial = __AllocateNonPagedPoolWithTag(__FUNCTION__,
                                            __LINE__,
                                            FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) +
                                            sizeof (ULONG),
                                            FDO_SIGNATURE);
    status = STATUS_NO_MEMORY;
    if (Partial == NULL)
        goto fail1;

    Partial->TitleIndex = 0;
    Partial->Type = REG_DWORD;
    Partial->DataLength = sizeof (ULONG);
    *(PULONG)Partial->Data = 1;            

    RtlInitUnicodeString(&Unicode, L"NeedReboot");

    status = ZwSetValueKey(DriverServiceKey,
                           &Unicode,
                           Partial->TitleIndex,
                           Partial->Type,
                           Partial->Data,
                           Partial->DataLength);
    if (!NT_SUCCESS(status))
        goto fail2;

    __FreePoolWithTag(Partial, FDO_SIGNATURE);

    return;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);
}
static FORCEINLINE VOID
__FdoEnumerate(
    __in    PXENVBD_FDO Fdo,
    __in    PCHAR       Devices,
    __out   PBOOLEAN    NeedInvalidate,
    __out   PBOOLEAN    NeedReboot
    )
{
    ULONG               TargetId;
    PCHAR               Device;
    PXENVBD_PDO         Pdo;
    NTSTATUS            Status;

    *NeedInvalidate = FALSE;
    *NeedReboot = FALSE;

    for (TargetId = 0; TargetId < XENVBD_MAX_TARGETS; ++TargetId) {
        Pdo = __FdoGetPdo(Fdo, TargetId);
        if (Pdo == NULL)
            continue;

        if (!PdoIsMissing(Pdo)) {
            BOOLEAN Missing = TRUE;
            for (Device = Devices; *Device; Device = __NextSz(Device)) {
                ULONG DeviceTargetId = __ParseVbd(Device);
                if (TargetId == DeviceTargetId) {
                    Missing = FALSE;
                    break;
                }
            }
            if (Missing) {
                PdoSetMissing(Pdo, "Device Dissappeared");
                if (PdoGetDevicePnpState(Pdo) == Present)
                    PdoSetDevicePnpState(Pdo, Deleted);
                else
                    *NeedInvalidate = TRUE;
            }
        }
        
        if (PdoIsMissing(Pdo) && 
            PdoGetDevicePnpState(Pdo) == Deleted) {
            // drop reference count before destroying
            PdoDereference(Pdo);
            PdoDestroy(Pdo);
        } else {
            PdoDereference(Pdo);
        }
    }

    // add new targets
    for (Device = Devices; *Device; Device = __NextSz(Device)) {
        BOOLEAN     EmulatedUnplugged;
        XENVBD_DEVICE_TYPE  DeviceType;

        TargetId = __ParseVbd(Device);
        if (TargetId == 0xFFFFFFFF) {
            continue;
        }

        Pdo = __FdoGetPdo(Fdo, TargetId);
        if (Pdo) {
            PdoDereference(Pdo);
            continue;
        }

        if (__FdoHiddenTarget(Fdo, Device, &DeviceType)) {
            continue;
        }

        EmulatedUnplugged = __FdoIsPdoUnplugged(Fdo,
                                                FdoEnum(Fdo),
                                                Device,
                                                TargetId);
        *NeedReboot |= !EmulatedUnplugged;

        Status = PdoCreate(Fdo,
                           Device,
                           TargetId,
                           EmulatedUnplugged,
                           ThreadGetEvent(Fdo->FrontendThread), DeviceType);
        *NeedInvalidate |= (NT_SUCCESS(Status)) ? TRUE : FALSE;
    }
}
__drv_requiresIRQL(DISPATCH_LEVEL)
static DECLSPEC_NOINLINE VOID
FdoScanTargets(
    __in    PXENVBD_FDO Fdo,
    __out   PBOOLEAN    NeedInvalidate,
    __out   PBOOLEAN    NeedReboot
    )
{
    NTSTATUS        Status;
    PCHAR           Buffer;

    Status = STORE(Directory, Fdo->Store, NULL, "device", FdoEnum(Fdo), &Buffer);
    if (NT_SUCCESS(Status)) {
        __FdoEnumerate(Fdo, Buffer, NeedInvalidate, NeedReboot);
        STORE(Free, Fdo->Store, Buffer);
    } else {
        *NeedInvalidate = FALSE;
        *NeedReboot = FALSE;
    }
}

static DECLSPEC_NOINLINE VOID
FdoLogTargets(
    __in PCHAR                       Caller,
    __in PXENVBD_FDO                 Fdo
    )
{
    ULONG   TargetId;

    Verbose("%s ===>\n", Caller);
    for (TargetId = 0; TargetId < XENVBD_MAX_TARGETS; ++TargetId) {
        PXENVBD_PDO Pdo = __FdoGetPdoAlways(Fdo, TargetId, __FUNCTION__);
        if (Pdo) {
            const CHAR* Reason = PdoMissingReason(Pdo);
            Verbose("%s : Target[%d] = 0x%p %s\n", Caller, TargetId, Pdo, 
                        (Reason != NULL) ? Reason : "(present)");
            PdoDereference(Pdo);
        }
    }
    Verbose("%s <===\n", Caller);
}

__checkReturn
static DECLSPEC_NOINLINE NTSTATUS
FdoScan(
    __in PXENVBD_THREAD              Thread,
    __in PVOID                       Context
    )
{
    PXENVBD_FDO     Fdo = Context;

    for (;;) {
        KIRQL   Irql;
        BOOLEAN NeedInvalidate;
        BOOLEAN NeedReboot;
        
        if (!ThreadWait(Thread))
            break;
        
        KeAcquireSpinLock(&Fdo->Lock, &Irql);
        if (Fdo->DevicePower != PowerDeviceD0) {
            KeReleaseSpinLock(&Fdo->Lock, Irql);
            continue;
        }
        
        FdoScanTargets(Fdo, &NeedInvalidate, &NeedReboot);

        KeReleaseSpinLock(&Fdo->Lock, Irql);

        if (NeedInvalidate) {
            FdoLogTargets("ScanThread", Fdo);
            StorPortNotification(BusChangeDetected, Fdo, 0);
        }

        if (NeedReboot)
            __FdoNotifyInstaller(Fdo);
    }

    return STATUS_SUCCESS;
}

__checkReturn
static DECLSPEC_NOINLINE NTSTATUS
FdoFrontend(
    __in PXENVBD_THREAD              Thread,
    __in PVOID                       Context
    )
{
    PXENVBD_FDO     Fdo = Context;

    for (;;) {
        ULONG       TargetId;
        KIRQL       Irql;
        
        if (!ThreadWait(Thread))
            break;

        KeAcquireSpinLock(&Fdo->Lock, &Irql);

        if (Fdo->DevicePower != PowerDeviceD0) {
            KeReleaseSpinLock(&Fdo->Lock, Irql);
            continue;
        }

        for (TargetId = 0; TargetId < XENVBD_MAX_TARGETS; ++TargetId) {
            PXENVBD_PDO Pdo = __FdoGetPdo(Fdo, TargetId);
            if (Pdo) {
                PdoBackendPathChanged(Pdo);
                PdoDereference(Pdo);
            }
        }

        KeReleaseSpinLock(&Fdo->Lock, Irql);
    }

    return STATUS_SUCCESS;
}

//=============================================================================
// Initialize, Start, Stop
__drv_requiresIRQL(DISPATCH_LEVEL)
static VOID
FdoSuspendLateCallback(
    __in PVOID                   Argument
    )
{
    PXENVBD_FDO     Fdo = Argument;
    NTSTATUS        Status;

    Verbose("%s (%s)\n",
         MAJOR_VERSION_STR "." MINOR_VERSION_STR "." MICRO_VERSION_STR "." BUILD_NUMBER_STR,
         DAY_STR "/" MONTH_STR "/" YEAR_STR);

    // remove watch
    if (Fdo->RescanWatch != NULL) {
        STORE(Unwatch, Fdo->Store, Fdo->RescanWatch);
        Fdo->RescanWatch = NULL;
    }

    // re-create watch
    Status = STORE(Watch, Fdo->Store, "device", FdoEnum(Fdo), 
                    ThreadGetEvent(Fdo->RescanThread), &Fdo->RescanWatch);
    ASSERT(NT_SUCCESS(Status));
}

__checkReturn
__drv_maxIRQL(APC_LEVEL)
static FORCEINLINE NTSTATUS
__FdoQueryInterfaces(
    __in PXENVBD_FDO             Fdo
    )
{
    NTSTATUS        Status;

    ASSERT3U(KeGetCurrentIrql(), <=, APC_LEVEL);

    // Get STORE Interface
    Status = __QueryInterface(Fdo->LowerDeviceObject, "STORE",
                            GUID_STORE_INTERFACE, STORE_INTERFACE_VERSION,
                            (PVOID*)&Fdo->Store);
    if (!NT_SUCCESS(Status))
        goto fail1;

    // Get EVTCHN Interface
    Status = __QueryInterface(Fdo->LowerDeviceObject, "EVTCHN",
                            GUID_EVTCHN_INTERFACE, EVTCHN_INTERFACE_VERSION,
                            (PVOID*)&Fdo->Evtchn);
    if (!NT_SUCCESS(Status))
        goto fail2;

    // Get GNTTAB Interface
    Status = __QueryInterface(Fdo->LowerDeviceObject, "GNTTAB",
                            GUID_GNTTAB_INTERFACE, GNTTAB_INTERFACE_VERSION,
                            (PVOID*)&Fdo->Gnttab);
    if (!NT_SUCCESS(Status))
        goto fail3;

    // Get SUSPEND Interface
    Status = __QueryInterface(Fdo->LowerDeviceObject, "SUSPEND",
                            GUID_SUSPEND_INTERFACE, SUSPEND_INTERFACE_VERSION,
                            (PVOID*)&Fdo->Suspend);
    if (!NT_SUCCESS(Status))
        goto fail4;

    // Get DEBUG Interface
    Status = __QueryInterface(Fdo->LowerDeviceObject, "DEBUG",
                            GUID_DEBUG_INTERFACE, DEBUG_INTERFACE_VERSION,
                            (PVOID*)&Fdo->Debug);
    if (!NT_SUCCESS(Status))
        goto fail5;

    // Get EMULATED Interface (non-fatal)
    Status = __QueryInterface(Fdo->LowerDeviceObject, "EMULATED",
                            GUID_EMULATED_INTERFACE, EMULATED_INTERFACE_VERSION,
                            (PVOID*)&Fdo->Emulated);
    if (!NT_SUCCESS(Status))
        Fdo->Emulated = NULL;

    return STATUS_SUCCESS;;

fail5:
    Fdo->Suspend = NULL;
fail4:
    Fdo->Gnttab = NULL;
fail3:
    Fdo->Evtchn = NULL;
fail2:
    Fdo->Store = NULL;
fail1:
    return Status;
}
static FORCEINLINE VOID
__FdoZeroInterfaces(
    __in PXENVBD_FDO             Fdo
    )
{
    Fdo->Emulated = NULL;
    Fdo->Suspend = NULL;
    Fdo->Debug = NULL;
    Fdo->Gnttab = NULL;
    Fdo->Evtchn = NULL;
    Fdo->Store = NULL;
}
static FORCEINLINE VOID
__FdoAcquire(
    __in PXENVBD_FDO             Fdo
    )
{
    if (Fdo->Emulated) {
        EMULATED(Acquire, Fdo->Emulated);
    }
    ASSERT3P(Fdo->Suspend, !=, NULL);
    ASSERT3P(Fdo->Debug, !=, NULL);
    ASSERT3P(Fdo->Gnttab, !=, NULL);
    ASSERT3P(Fdo->Evtchn, !=, NULL);
    ASSERT3P(Fdo->Store, !=, NULL);
    SUSPEND(Acquire, Fdo->Suspend);
    DEBUG  (Acquire, Fdo->Debug);
    GNTTAB (Acquire, Fdo->Gnttab);
    EVTCHN (Acquire, Fdo->Evtchn);
    STORE  (Acquire, Fdo->Store);
}
static FORCEINLINE VOID
__FdoRelease(
    __in PXENVBD_FDO             Fdo
    )
{
    if (Fdo->Emulated) {
        EMULATED(Release, Fdo->Emulated);
    }
    ASSERT3P(Fdo->Suspend, !=, NULL);
    ASSERT3P(Fdo->Debug, !=, NULL);
    ASSERT3P(Fdo->Gnttab, !=, NULL);
    ASSERT3P(Fdo->Evtchn, !=, NULL);
    ASSERT3P(Fdo->Store, !=, NULL);
    SUSPEND(Release, Fdo->Suspend);
    DEBUG  (Release, Fdo->Debug);
    GNTTAB (Release, Fdo->Gnttab);
    EVTCHN (Release, Fdo->Evtchn);
    STORE  (Release, Fdo->Store);
}

static NTSTATUS
__FdoD3ToD0(
    __in PXENVBD_FDO             Fdo
    )
{
    NTSTATUS    Status;
    ULONG       TargetId;

    if (!__FdoSetDevicePowerState(Fdo, PowerDeviceD0))
        return STATUS_SUCCESS;

    Trace("=====> (%d)\n", KeGetCurrentIrql());
    Verbose("D3->D0\n");

    // Get Interfaces
    __FdoAcquire(Fdo);
    
    // register debug callback
    ASSERT3P(Fdo->DebugCallback, ==, NULL);
    Status = DEBUG(Register, 
                   Fdo->Debug, 
                   __MODULE__, 
                   FdoDebugCallback, 
                   Fdo, 
                   &Fdo->DebugCallback);
    if (!NT_SUCCESS(Status))
        goto fail1;

    // Power UP any PDOs
    for (TargetId = 0; TargetId < XENVBD_MAX_TARGETS; ++TargetId) {
        PXENVBD_PDO Pdo = __FdoGetPdo(Fdo, TargetId);
        if (Pdo) {
            Status = PdoD3ToD0(Pdo);
            PdoDereference(Pdo);

            if (!NT_SUCCESS(Status))
                goto fail2;
        }
    }

    // register suspend callback to re-register the watch
    ASSERT3P(Fdo->SuspendCallback, ==, NULL);
    Status = SUSPEND(Register, Fdo->Suspend, SUSPEND_CALLBACK_LATE,
                    FdoSuspendLateCallback, Fdo, &Fdo->SuspendCallback);
    if (!NT_SUCCESS(Status))
        goto fail2;

    // register watch on device/vbd
    ASSERT3P(Fdo->RescanWatch, ==, NULL);
    Status = STORE(Watch, Fdo->Store, "device", FdoEnum(Fdo), 
                    ThreadGetEvent(Fdo->RescanThread), &Fdo->RescanWatch);
    if (!NT_SUCCESS(Status))
        goto fail3;

    Trace("<===== (%d)\n", KeGetCurrentIrql());
    return STATUS_SUCCESS;

fail3:
    Error("Fail3\n");
    if (Fdo->SuspendCallback != NULL) {
        SUSPEND(Deregister, Fdo->Suspend, Fdo->SuspendCallback);
        Fdo->SuspendCallback = NULL;
    }

fail2:
    Error("Fail2\n");
    for (TargetId = 0; TargetId < XENVBD_MAX_TARGETS; ++TargetId) {
        PXENVBD_PDO Pdo = __FdoGetPdo(Fdo, TargetId);
        if (Pdo) {
            PdoD0ToD3(Pdo);
            PdoDereference(Pdo);
        }
    }

    if (Fdo->DebugCallback != NULL) {
        DEBUG(Deregister, Fdo->Debug, Fdo->DebugCallback);
        Fdo->DebugCallback = NULL;
    }
   
fail1:
    Error("Fail1 (%08x)\n", Status);
    __FdoRelease(Fdo);
    __FdoSetDevicePowerState(Fdo, PowerDeviceD3);
    return Status;
}
static VOID
__FdoD0ToD3(
    __in PXENVBD_FDO             Fdo
    )
{
    ULONG       TargetId;

    if (!__FdoSetDevicePowerState(Fdo, PowerDeviceD3))
        return;

    Trace("=====> (%d)\n", KeGetCurrentIrql());
    Verbose("D0->D3\n");

    // remove suspend callback
    if (Fdo->SuspendCallback != NULL) {
        SUSPEND(Deregister, Fdo->Suspend, Fdo->SuspendCallback);
        Fdo->SuspendCallback = NULL;
    }

    // unregister watch on device/vbd
    if (Fdo->RescanWatch != NULL) {
        STORE(Unwatch, Fdo->Store, Fdo->RescanWatch);
        Fdo->RescanWatch = NULL;
    }

    // Power DOWN any PDOs
    for (TargetId = 0; TargetId < XENVBD_MAX_TARGETS; ++TargetId) {
        PXENVBD_PDO Pdo = __FdoGetPdo(Fdo, TargetId);
        if (Pdo) {
            PdoD0ToD3(Pdo);
            PdoDereference(Pdo);
        }
    }

    // free debug callback
    if (Fdo->DebugCallback != NULL) {
        DEBUG(Deregister, Fdo->Debug, Fdo->DebugCallback);
        Fdo->DebugCallback = NULL;
    }

    // Release Interfaces
    __FdoRelease(Fdo);

    Trace("<===== (%d)\n", KeGetCurrentIrql());
}

__checkReturn
static DECLSPEC_NOINLINE NTSTATUS
FdoDevicePower(
    __in PXENVBD_THREAD             Thread,
    __in PVOID                      Context
    )
{
    PXENVBD_FDO     Fdo = Context;

    for (;;) {
        PIRP                Irp;
        PIO_STACK_LOCATION  Stack;
        DEVICE_POWER_STATE  DeviceState;
        POWER_ACTION        Action;
        NTSTATUS            Status;

        if (!ThreadWait(Thread))
            break;

        // must have a pended DevicePowerIrp
        ASSERT3P(Fdo->DevicePowerIrp, !=, NULL);

        Irp = Fdo->DevicePowerIrp;
        Fdo->DevicePowerIrp = NULL;

        Stack = IoGetCurrentIrpStackLocation(Irp);
        DeviceState = Stack->Parameters.Power.State.DeviceState;
        Action = Stack->Parameters.Power.ShutdownType;

        switch (Stack->MinorFunction) {
        case IRP_MN_SET_POWER:
            switch (DeviceState) {
            case PowerDeviceD0:
                Verbose("FDO:PowerDeviceD0\n");
                __FdoD3ToD0(Fdo);
                break;

            case PowerDeviceD3:
                Verbose("FDO:PowerDeviceD3 (%s)\n", PowerActionName(Action));
                __FdoD0ToD3(Fdo);
                break;

            default:
                break;
            }
            break;
        case IRP_MN_QUERY_POWER:
        default:
            break;
        }
        FdoDereference(Fdo);
        Status = StorPortDispatchPower(Fdo->DeviceObject, Irp);
        if (!NT_SUCCESS(Status)) {
            Warning("StorPort failed PowerIRP with %08x\n", Status);
        }
    }

    return STATUS_SUCCESS;
}

__checkReturn
__drv_maxIRQL(DISPATCH_LEVEL)
static NTSTATUS
__FdoInitialize(
    __in PXENVBD_FDO             Fdo
    )
{
    ULONG       StorStatus;
    NTSTATUS    Status;

    Trace("=====> (%d)\n", KeGetCurrentIrql());
    
    ASSERT3U(KeGetCurrentIrql(), <=, DISPATCH_LEVEL);
    // initialize the memory
    Fdo->DevicePower = PowerDeviceD3;
    KeInitializeSpinLock(&Fdo->TargetLock);
    KeInitializeSpinLock(&Fdo->Lock);
    KeInitializeEvent(&Fdo->RemoveEvent, SynchronizationEvent, FALSE);

    Fdo->ReferenceCount = 1;
    Fdo->Signature = FDO_SIGNATURE;

    StorStatus = StorPortGetDeviceObjects(Fdo,
                                          &Fdo->DeviceObject,
                                          &Fdo->PhysicalDeviceObject,
                                          &Fdo->LowerDeviceObject);
    Status = STATUS_UNSUCCESSFUL;
    if (StorStatus != STOR_STATUS_SUCCESS) {
        Error("StorPortGetDeviceObjects() (%x:%s)\n", StorStatus, StorStatusName(StorStatus));
        goto fail1;
    }

    // get interfaces
    Status = __FdoQueryInterfaces(Fdo);
    if (!NT_SUCCESS(Status))
        goto fail2;

    // start enum thread
    Status = ThreadCreate(FdoScan, Fdo, &Fdo->RescanThread);
    if (!NT_SUCCESS(Status))
        goto fail3;

    Status = ThreadCreate(FdoFrontend, Fdo, &Fdo->FrontendThread);
    if (!NT_SUCCESS(Status))
        goto fail4;

    Status = ThreadCreate(FdoDevicePower, Fdo, &Fdo->DevicePowerThread);
    if (!NT_SUCCESS(Status))
        goto fail5;

    // query enumerator
    // fix this up to query from device location(?)
    //RtlInitAnsiString(&Fdo->Enumerator, "vbd");

    // link fdo
    DriverLinkFdo(Fdo);

    Trace("<===== (%d)\n", KeGetCurrentIrql());
    return STATUS_SUCCESS;

fail5:
    Error("fail5\n");
    ThreadAlert(Fdo->FrontendThread);
    ThreadJoin(Fdo->FrontendThread);
    Fdo->FrontendThread = NULL;
fail4:
    Error("fail4\n");
    ThreadAlert(Fdo->RescanThread);
    ThreadJoin(Fdo->RescanThread);
    Fdo->RescanThread = NULL;
fail3:
    Error("fail3\n");
    __FdoZeroInterfaces(Fdo);
fail2:
    Error("fail2\n");
    Fdo->DeviceObject = NULL;
    Fdo->PhysicalDeviceObject = NULL;
    Fdo->LowerDeviceObject = NULL;
fail1:
    Error("fail1 (%08x)\n", Status);
    return Status;
}
__drv_maxIRQL(PASSIVE_LEVEL)
static VOID
__FdoTerminate(
    __in PXENVBD_FDO             Fdo
    )
{
    ULONG   TargetId;

    Trace("=====> (%d)\n", KeGetCurrentIrql());

    DriverUnlinkFdo(Fdo);
    ASSERT3U(Fdo->DevicePower, ==, PowerDeviceD3);
    FdoDereference(Fdo);

    // should wait until ReferenceCount == 0
    Verbose("Terminating, %d Refs\n", Fdo->ReferenceCount);
    ASSERT3S(Fdo->ReferenceCount, >=, 0);
    KeWaitForSingleObject(&Fdo->RemoveEvent, Executive, KernelMode, FALSE, NULL);
    ASSERT3S(Fdo->ReferenceCount, ==, 0);

    // stop device power thread
    ThreadAlert(Fdo->DevicePowerThread);
    ThreadJoin(Fdo->DevicePowerThread);
    Fdo->DevicePowerThread = NULL;

    // stop frontend thread
    ThreadAlert(Fdo->FrontendThread);
    ThreadJoin(Fdo->FrontendThread);
    Fdo->FrontendThread = NULL;

    // stop enum thread
    ThreadAlert(Fdo->RescanThread);
    ThreadJoin(Fdo->RescanThread);
    Fdo->RescanThread = NULL;

    // clear device objects
    Fdo->DeviceObject = NULL;
    Fdo->PhysicalDeviceObject = NULL;
    Fdo->LowerDeviceObject = NULL;
    
    // delete targets
    for (TargetId = 0; TargetId < XENVBD_MAX_TARGETS; ++TargetId) {
        PXENVBD_PDO Pdo = __FdoGetPdoAlways(Fdo, TargetId, __FUNCTION__);
        if (Pdo) {
            // Pdo may not be in Deleted state yet, force it as Fdo is terminating
            if (PdoGetDevicePnpState(Pdo) != Deleted)
                PdoSetDevicePnpState(Pdo, Deleted);
            // update missing (for debug output more than anything else
            PdoSetMissing(Pdo, "FdoTerminate");
            // drop ref-count acquired in __FdoGetPdo *before* destroying Pdo
            PdoDereference(Pdo);
            PdoDestroy(Pdo);
        }
    }

    // cleanup memory
    ASSERT3U(Fdo->DevicePower, ==, PowerDeviceD3);
    ASSERT3P(Fdo->DebugCallback, ==, NULL);
    ASSERT3P(Fdo->SuspendCallback, ==, NULL);

    Fdo->Signature = 0;
    Fdo->DevicePower = 0;
    Fdo->CurrentSrbs = Fdo->MaximumSrbs = Fdo->TotalSrbs = 0;
    RtlZeroMemory(&Fdo->Enumerator, sizeof(ANSI_STRING));
    RtlZeroMemory(&Fdo->TargetLock, sizeof(KSPIN_LOCK));
    RtlZeroMemory(&Fdo->Lock, sizeof(KSPIN_LOCK));
    RtlZeroMemory(&Fdo->RemoveEvent, sizeof(KEVENT));
    __FdoZeroInterfaces(Fdo);

    ASSERT(IsZeroMemory(Fdo, sizeof(XENVBD_FDO)));
    Trace("<===== (%d)\n", KeGetCurrentIrql());
}
//=============================================================================
// Query Methods
__checkReturn
FORCEINLINE PDEVICE_OBJECT
FdoGetDeviceObject(
    __in PXENVBD_FDO                 Fdo
    )
{
    if (Fdo)
        return Fdo->DeviceObject;
    return NULL;
}

FORCEINLINE ULONG
FdoSizeofXenvbdFdo(
    )
{
    return (ULONG)sizeof(XENVBD_FDO);
}

FORCEINLINE PCHAR
FdoEnum(
    __in PXENVBD_FDO                 Fdo
    )
{
    if (Fdo->Enumerator.Buffer)
        return Fdo->Enumerator.Buffer;
    else
        return "vbd";
}

//=============================================================================
// SRB Methods
FORCEINLINE VOID
FdoStartSrb(
    __in PXENVBD_FDO                 Fdo,
    __in PSCSI_REQUEST_BLOCK         Srb
    )
{
    LONG    Value;

    UNREFERENCED_PARAMETER(Srb);

    Value = InterlockedIncrement(&Fdo->CurrentSrbs);
    if (Value > Fdo->MaximumSrbs)
        Fdo->MaximumSrbs = Value;
    InterlockedIncrement(&Fdo->TotalSrbs);
}

FORCEINLINE VOID
FdoCompleteSrb(
    __in PXENVBD_FDO                 Fdo,
    __in PSCSI_REQUEST_BLOCK         Srb
    )
{
    ASSERT3U(Srb->SrbStatus, !=, SRB_STATUS_PENDING);

    InterlockedDecrement(&Fdo->CurrentSrbs);

    StorPortNotification(RequestComplete, Fdo, Srb);
}

//=============================================================================
// StorPort Methods
BOOLEAN
FdoResetBus(
    __in PXENVBD_FDO                 Fdo
    )
{
    ULONG           TargetId;

    for (TargetId = 0; TargetId < XENVBD_MAX_TARGETS; ++TargetId) {
        PXENVBD_PDO Pdo = __FdoGetPdo(Fdo, TargetId);
        if (Pdo) {
            PdoReset(Pdo);
            PdoDereference(Pdo);
        }
    }

    return TRUE;
}

SCSI_ADAPTER_CONTROL_STATUS
FdoAdapterControl(
    __in PXENVBD_FDO                 Fdo,
    __in SCSI_ADAPTER_CONTROL_TYPE   ControlType,
    __in PVOID                       Parameters
    )
{
    UNREFERENCED_PARAMETER(Fdo);

    switch (ControlType) {
    case ScsiQuerySupportedControlTypes:
        {
            PSCSI_SUPPORTED_CONTROL_TYPE_LIST List = Parameters;

#define SET_SUPPORTED(_l, _i, _v)           \
    if (_l->MaxControlType > _i)    _l->SupportedTypeList[_i] = _v;

            SET_SUPPORTED(List, 0, TRUE);   // ScsiQuerySupportedControlTypes
            SET_SUPPORTED(List, 1, FALSE);  // ScsiStopAdapter
            SET_SUPPORTED(List, 2, FALSE);  // ScsiRestartAdapter
            SET_SUPPORTED(List, 3, FALSE);  // ScsiSetBootConfig
            SET_SUPPORTED(List, 4, FALSE);  // ScsiSetRunningConfig

#undef SET_SUPPORTED

        } break;
    case ScsiStopAdapter:
    case ScsiRestartAdapter:
    case ScsiSetBootConfig:
    case ScsiSetRunningConfig:
        {
            Trace("<----> %s (%d)\n", ScsiAdapterControlTypeName(ControlType), KeGetCurrentIrql());
        } break;
    default:
        break;
    }
    return ScsiAdapterControlSuccess;
}

ULONG
FdoFindAdapter(
    __in PXENVBD_FDO                 Fdo,
    __inout PPORT_CONFIGURATION_INFORMATION  ConfigInfo
    )
{
    // setup config info
    ConfigInfo->MaximumTransferLength       = XENVBD_MAX_TRANSFER_LENGTH;
    ConfigInfo->NumberOfPhysicalBreaks      = XENVBD_MAX_PHYSICAL_BREAKS;
    ConfigInfo->AlignmentMask               = 0; // Byte-Aligned
    ConfigInfo->NumberOfBuses               = 1;
    ConfigInfo->InitiatorBusId[0]           = 1;
    ConfigInfo->ScatterGather               = TRUE;
    ConfigInfo->Master                      = TRUE;
    ConfigInfo->CachesData                  = FALSE;
    ConfigInfo->MapBuffers                  = STOR_MAP_NON_READ_WRITE_BUFFERS;
    ConfigInfo->MaximumNumberOfTargets      = XENVBD_MAX_TARGETS;
    ConfigInfo->MaximumNumberOfLogicalUnits = 1;
    ConfigInfo->WmiDataProvider             = FALSE; // should be TRUE
    ConfigInfo->SynchronizationModel        = StorSynchronizeFullDuplex;

    if (ConfigInfo->Dma64BitAddresses == SCSI_DMA64_SYSTEM_SUPPORTED) {
        Trace("64bit DMA\n");
        ConfigInfo->Dma64BitAddresses = SCSI_DMA64_MINIPORT_SUPPORTED;
    }

    // gets called on resume from hibernate, so only setup if not already done
    if (Fdo->Signature == FDO_SIGNATURE) {
        Verbose("FDO already initalized (0x%p)\n", Fdo);
        return SP_RETURN_FOUND;
    }

    // We need to do this to avoid an assertion in a checked kernel
    (VOID) StorPortGetUncachedExtension(Fdo, ConfigInfo, PAGE_SIZE);

    if (!NT_SUCCESS(__FdoInitialize(Fdo)))
        return SP_RETURN_ERROR;
    if (!NT_SUCCESS(__FdoD3ToD0(Fdo)))
        return SP_RETURN_ERROR;

    return SP_RETURN_FOUND;
}

static FORCEINLINE VOID
__FdoSrbPnp(
    __in PXENVBD_FDO                 Fdo,
    __in PSCSI_PNP_REQUEST_BLOCK     Srb
    )
{
    if (!(Srb->SrbPnPFlags & SRB_PNP_FLAGS_ADAPTER_REQUEST)) {
        PXENVBD_PDO     Pdo;

        Pdo = __FdoGetPdo(Fdo, Srb->TargetId);
        if (Pdo) {
            PdoSrbPnp(Pdo, Srb);
            PdoDereference(Pdo);
        }
    }
}

BOOLEAN 
FdoBuildIo(
    __in PXENVBD_FDO                 Fdo,
    __in PSCSI_REQUEST_BLOCK         Srb
    )
{
    InitSrbExt(Srb);

    switch (Srb->Function) {
    case SRB_FUNCTION_EXECUTE_SCSI:
    case SRB_FUNCTION_RESET_DEVICE:
    case SRB_FUNCTION_FLUSH:
    case SRB_FUNCTION_SHUTDOWN:
        FdoStartSrb(Fdo, Srb);
        return TRUE;

        // dont pass to StartIo
    case SRB_FUNCTION_PNP:
        __FdoSrbPnp(Fdo, (PSCSI_PNP_REQUEST_BLOCK)Srb);
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        break;
    case SRB_FUNCTION_ABORT_COMMAND:
        Srb->SrbStatus = SRB_STATUS_ABORT_FAILED;
        break;
    case SRB_FUNCTION_RESET_BUS:
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        FdoResetBus(Fdo);
        break;
        
    default:
        break;
    }
    
    StorPortNotification(RequestComplete, Fdo, Srb);
    return FALSE;
}   

BOOLEAN 
FdoStartIo(
    __in PXENVBD_FDO                 Fdo,
    __in PSCSI_REQUEST_BLOCK         Srb
    )
{
    PXENVBD_PDO Pdo;
    BOOLEAN     CompleteSrb = TRUE;

    Pdo = __FdoGetPdo(Fdo, Srb->TargetId);
    if (Pdo) {
        CompleteSrb = PdoStartIo(Pdo, Srb);
        PdoDereference(Pdo);
    }

    if (CompleteSrb) {
        FdoCompleteSrb(Fdo, Srb);
    }
    return TRUE;
}

//=============================================================================
// PnP Handler
extern PDRIVER_DISPATCH StorPortDispatchPnp;

__checkReturn
NTSTATUS
FdoDispatchPnp(
    __in PXENVBD_FDO                 Fdo,
    __in PDEVICE_OBJECT              DeviceObject,
    __in PIRP                        Irp
    )
{
    PIO_STACK_LOCATION  Stack = IoGetCurrentIrpStackLocation(Irp);
    UCHAR               Minor = Stack->MinorFunction;
    NTSTATUS            Status;

    switch (Stack->MinorFunction) {
    case IRP_MN_REMOVE_DEVICE:
        Verbose("FDO:IRP_MN_REMOVE_DEVICE\n");
        __FdoD0ToD3(Fdo);
        // drop ref-count acquired in DriverGetFdo *before* destroying Fdo
        FdoDereference(Fdo);
        __FdoTerminate(Fdo);
        break;

    case IRP_MN_QUERY_DEVICE_RELATIONS:
        if (Stack->Parameters.QueryDeviceRelations.Type == BusRelations) {
            KIRQL   Irql;
            BOOLEAN NeedInvalidate;
            BOOLEAN NeedReboot;

            KeAcquireSpinLock(&Fdo->Lock, &Irql);
            
            if (Fdo->DevicePower == PowerDeviceD0) {
                FdoScanTargets(Fdo, &NeedInvalidate, &NeedReboot);
            } else {
                NeedInvalidate = FALSE;
                NeedReboot = FALSE;
            }
            
            KeReleaseSpinLock(&Fdo->Lock, Irql);

            if (NeedInvalidate)
                FdoLogTargets("QUERY_RELATIONS", Fdo);
        }
        FdoDereference(Fdo);
        break;

    default:
        FdoDereference(Fdo);
        break;
    }

    Status = StorPortDispatchPnp(DeviceObject, Irp);
    if (!NT_SUCCESS(Status)) {
        Verbose("%02x:%s -> %08x\n", Minor, PnpMinorFunctionName(Minor), Status);
    }
    return Status;
}

__checkReturn
PXENVBD_PDO
FdoGetPdoFromDeviceObject(
    __in PXENVBD_FDO                 Fdo,
    __in PDEVICE_OBJECT              DeviceObject
    )
{
    ULONG           TargetId;

    ASSERT3P(DeviceObject, !=, NULL);

    for (TargetId = 0; TargetId < XENVBD_MAX_TARGETS; ++TargetId) {
        PXENVBD_PDO Pdo = __FdoGetPdo(Fdo, TargetId);
        if (Pdo) {
            if (PdoGetDeviceObject(Pdo) == DeviceObject)
                return Pdo;
            PdoDereference(Pdo);
        }
    }

    return NULL;
}

__checkReturn
static FORCEINLINE NTSTATUS
__FdoSendQueryId(
    __in PDEVICE_OBJECT              DeviceObject,
    __out PWCHAR*                    _String
    )
{
    KEVENT              Complete;
    PIRP                Irp;
    IO_STATUS_BLOCK     StatusBlock;
    PIO_STACK_LOCATION  Stack;
    NTSTATUS            Status;

    KeInitializeEvent(&Complete, NotificationEvent, FALSE);
    
    Irp = IoBuildSynchronousFsdRequest(IRP_MJ_PNP, DeviceObject, NULL, 0, NULL, &Complete, &StatusBlock);
    if (!Irp)
        return STATUS_INSUFFICIENT_RESOURCES;

    Stack = IoGetNextIrpStackLocation(Irp);
    Stack->MinorFunction = IRP_MN_QUERY_ID;
    Stack->Parameters.QueryId.IdType = BusQueryInstanceID;

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    Status = IoCallDriver(DeviceObject, Irp);
    if (Status == STATUS_PENDING) {
        (VOID) KeWaitForSingleObject(&Complete, Executive, KernelMode, FALSE, NULL);
        Status = StatusBlock.Status;
    }
    if (NT_SUCCESS(Status)) {
        *_String = (PWCHAR)StatusBlock.Information;
    }
    return Status;
}

__checkReturn
static FORCEINLINE NTSTATUS
__FdoExtractTargetId(
    __in PWCHAR                      String,
    __out PULONG                     TargetId
    )
{
    DECLARE_UNICODE_STRING_SIZE(UniStr, 4);

    switch (wcslen(String)) {
    case 3:
        UniStr.Length = 1 * sizeof(WCHAR);
        UniStr_buffer[0] = String[1];
        UniStr_buffer[1] = UNICODE_NULL;
        break;
    case 6:
        UniStr.Length = 2 * sizeof(WCHAR);
        UniStr_buffer[0] = String[2];
        UniStr_buffer[1] = String[3];
        UniStr_buffer[2] = UNICODE_NULL;
        break;
    default:
        return STATUS_INVALID_PARAMETER;
    }

    return RtlUnicodeStringToInteger(&UniStr, 16, TargetId);
}

static FORCEINLINE VOID
__FdoSetDeviceObject(
    __in PXENVBD_FDO                 Fdo,
    __in ULONG                       TargetId,
    __in PDEVICE_OBJECT              DeviceObject
    )
{
    PXENVBD_PDO Pdo;

    Pdo = __FdoGetPdo(Fdo, TargetId);
    if (Pdo) {
        PdoSetDeviceObject(Pdo, DeviceObject);
        PdoDereference(Pdo);
    }
}

__checkReturn
NTSTATUS
FdoMapDeviceObjectToPdo(
    __in PXENVBD_FDO                 Fdo,
    __in PDEVICE_OBJECT              DeviceObject,
    __in PIRP                        Irp
    )
{
    PWCHAR              String;
    NTSTATUS            Status;
    ULONG               TargetId;
    PIO_STACK_LOCATION  StackLocation;
    UCHAR               Minor;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    Minor = StackLocation->MinorFunction;

    if (!(StackLocation->MinorFunction == IRP_MN_QUERY_ID &&
          StackLocation->Parameters.QueryId.IdType == BusQueryDeviceID)) {
        goto done;
    }

    Status = __FdoSendQueryId(DeviceObject, &String);
    if (!NT_SUCCESS(Status)) {
        goto done;
    }

    Status = __FdoExtractTargetId(String, &TargetId);
    if (NT_SUCCESS(Status)) {
        __FdoSetDeviceObject(Fdo, TargetId, DeviceObject);
    }

    Verbose("0x%p --> Target %d (%ws)\n", DeviceObject, TargetId, String);

    // String is PagedPool, allocated by lower driver
    ASSERT3U(KeGetCurrentIrql(), <=, APC_LEVEL);
    ExFreePool(String);

done:
    Status = StorPortDispatchPnp(DeviceObject, Irp);;
    if (!NT_SUCCESS(Status)) {
        Verbose("%02x:%s -> %08x\n", Minor, PnpMinorFunctionName(Minor), Status);
    }
    return Status;
}

//=============================================================================
// Power Handler
__checkReturn
NTSTATUS
FdoDispatchPower(
    __in PXENVBD_FDO                 Fdo,
    __in PDEVICE_OBJECT              DeviceObject,
    __in PIRP                        Irp
    )
{
    PIO_STACK_LOCATION  Stack;
    POWER_STATE_TYPE    PowerType;
    NTSTATUS            status;

    Stack = IoGetCurrentIrpStackLocation(Irp);
    PowerType = Stack->Parameters.Power.Type;

    switch (PowerType) {
    case DevicePowerState:
        if (Fdo->DevicePowerThread == NULL) {
            Verbose("DevicePower IRP before DevicePowerThread ready\n");
            FdoDereference(Fdo);
            status = StorPortDispatchPower(DeviceObject, Irp);
            break;
        }

        IoMarkIrpPending(Irp);

        ASSERT3P(Fdo->DevicePowerIrp, ==, NULL);
        ASSERT3P(DeviceObject, ==, Fdo->DeviceObject);

        Fdo->DevicePowerIrp = Irp;
        ThreadWake(Fdo->DevicePowerThread);
        
        status = STATUS_PENDING;
        break;

    case SystemPowerState:
    default:
        FdoDereference(Fdo);
        status = StorPortDispatchPower(DeviceObject, Irp);
        break;
    }

    return status;
}

//=============================================================================
// Interfaces
PXENBUS_STORE_INTERFACE
FdoAcquireStore(
    __in PXENVBD_FDO                 Fdo
    )
{
    ASSERT3P(Fdo->Store, !=, NULL);
    STORE(Acquire, Fdo->Store);
    return Fdo->Store;
}

PXENBUS_EVTCHN_INTERFACE
FdoAcquireEvtchn(
    __in PXENVBD_FDO                 Fdo
    )
{
    ASSERT3P(Fdo->Evtchn, !=, NULL);
    EVTCHN(Acquire, Fdo->Evtchn);
    return Fdo->Evtchn;
}

PXENBUS_GNTTAB_INTERFACE
FdoAcquireGnttab(
    __in PXENVBD_FDO                 Fdo
    )
{
    ASSERT3P(Fdo->Gnttab, !=, NULL);
    GNTTAB(Acquire, Fdo->Gnttab);
    return Fdo->Gnttab;
}

PXENBUS_DEBUG_INTERFACE
FdoAcquireDebug(
    __in PXENVBD_FDO                 Fdo
    )
{
    ASSERT3P(Fdo->Debug, !=, NULL);
    DEBUG(Acquire, Fdo->Debug);
    return Fdo->Debug;
}

PXENBUS_SUSPEND_INTERFACE
FdoAcquireSuspend(
    __in PXENVBD_FDO                 Fdo    
    )
{
    ASSERT3P(Fdo->Suspend, !=, NULL);
    SUSPEND(Acquire, Fdo->Suspend);
    return Fdo->Suspend;
}
