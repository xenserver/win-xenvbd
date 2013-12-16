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

#include "hvm.h"
#include "store.h"
#include "evtchn.h"
#include "gnttab.h"
#include "austere.h"
#include "frontend.h"

#include "log.h"
#include "assert.h"
#include "util.h"
#include <xencdb.h>
#include <names.h>

#include <stdlib.h>

struct _XENVBD_FDO {
    PXENVBD_PDO                 Target;
};

//=============================================================================
// Initialize, Start, Stop
static FORCEINLINE PCHAR
__Next(
    IN  PCHAR                   Ptr
    )
{
    if (Ptr == NULL)
        return NULL;

    while (*Ptr != '\0')
        ++Ptr;

    ++Ptr;
    if (*Ptr == '\0')
        return NULL;
    
    return Ptr;
}
static NTSTATUS
FdoCloseAllTargets(
    )
{
    NTSTATUS        Status;
    PCHAR           Device;
    PCHAR           DeviceList;
    
    Status = StoreDirectory(NULL, "device", "vbd", &DeviceList);
    if (!NT_SUCCESS(Status))
        goto fail1;

    for (Device = DeviceList; Device; Device = __Next(Device)) {
        PCHAR   FrontendPath;
        PCHAR   BackendPath;

        FrontendPath = DriverFormat("device/vbd/%s", Device);
        if (FrontendPath == NULL)
            continue;

        Status = StoreRead(NULL, FrontendPath, "backend", &BackendPath);
        if (!NT_SUCCESS(Status)) {
            AustereFree(FrontendPath);
            continue;
        }

        FrontendCloseTarget(FrontendPath, BackendPath);

        AustereFree(FrontendPath);
        AustereFree(BackendPath);
    }

    AustereFree(DeviceList);
    return STATUS_SUCCESS;

fail1:
    LogError("Fail1 (%08x)\n", Status);
    return Status;
}
static BOOLEAN
FdoGetFeatureFlag(
    IN  PCHAR                   Path,
    IN  PCHAR                   Feature
    )
{
    BOOLEAN     Ret = FALSE;
    NTSTATUS    Status;
    PCHAR       Value;

    Status = StoreRead(NULL, Path, Feature, &Value);
    if (NT_SUCCESS(Status)) {
        if (strtoul(Value, NULL, 10) > 0)
            Ret = TRUE;
        AustereFree(Value);
    }

    LogTrace("<===> (%08x) %s/%s = %s\n", Status, Path, Feature, Ret ? "TRUE" : "FALSE");

    return Ret;
}
static FORCEINLINE NTSTATUS
FdoCreateTarget(
    IN  PXENVBD_FDO             Fdo,
    IN  PCHAR                   DeviceId,
    IN  ULONG                   TargetId
    )
{
    NTSTATUS        Status;
    PXENVBD_PDO     Pdo;

    LogTrace("===> %p, %s, %d\n", Fdo, DeviceId, TargetId);

    Status = PdoCreate(Fdo, DeviceId, TargetId, &Pdo);
    if (NT_SUCCESS(Status)) {
        Fdo->Target = Pdo;
    }

    LogTrace("<=== (%08x)\n", Status);
    return Status;
}
static NTSTATUS
FdoFindTarget(
    IN  PXENVBD_FDO                 Fdo
    )
{
    NTSTATUS        Status;
    ULONG           TargetId;
    PCHAR           TargetPath;
    PCHAR           Disk = NULL;
    const ULONG     OperatingMode = DriverGetOperatingMode();

    LogTrace("====>\n");

    for (TargetId = 0; TargetId < XENVBD_MAX_TARGETS; ++TargetId) {
        TargetPath = DriverFormat("data/scsi/target/%d", TargetId);
        if (!TargetPath) 
            continue;

        LogTrace("Target[%d] = %s\n", TargetId, TargetPath);
        if (OperatingMode == DUMP_MODE) {
            if (!FdoGetFeatureFlag(TargetPath, "dump")) {
                AustereFree(TargetPath);
                continue;
            }
        } else if (OperatingMode == HIBER_MODE) {
            if (!FdoGetFeatureFlag(TargetPath, "hibernation")) {
                AustereFree(TargetPath);
                continue;
            }
        } else {
            Status = STATUS_INVALID_PARAMETER;
            goto done;
        }

        Status = StoreRead(NULL, TargetPath, "device", &Disk);
        if (!NT_SUCCESS(Status)) {
            AustereFree(TargetPath);
            continue;
        }

        AustereFree(TargetPath);
        LogVerbose("%s Target is %s (%d)\n", OperatingMode == DUMP_MODE ? "DUMP" : "HIBER", Disk, TargetId);
        Status = FdoCreateTarget(Fdo, Disk, TargetId);
        AustereFree(Disk);
        goto done;
    }

    LogVerbose("%s Target not found, trying Target[0]\n", OperatingMode == DUMP_MODE ? "DUMP" : "HIBER");
    Status = FdoCreateTarget(Fdo, "768", 0);

done:
    LogTrace("<==== (%08x)\n", Status);
    return Status;
}

static FORCEINLINE BOOLEAN
FdoInitialize(
    IN  PXENVBD_FDO                 Fdo
    )
{
    NTSTATUS    Status;

    LogTrace("====>\n");

    DriverLinkFdo(Fdo);

    Status = HvmInitialize();
    if (!NT_SUCCESS(Status)) {
        LogError("HvmInitialize (%08x)\n", Status);
        goto fail;
    }

    Status = StoreInitialize();
    if (!NT_SUCCESS(Status)) {
        LogError("StoreInitialize (%08x)\n", Status);
        goto fail;
    }

    Status = GnttabInitialize();
    if (!NT_SUCCESS(Status)) {
        LogError("GnttabInitialize (%08x)\n", Status);
        goto fail;
    }

    // Hack! force all targets to closed (if not already), so backends dont lock
    // creating the dump target will transition via closed anyway
    Status = FdoCloseAllTargets();
    if (!NT_SUCCESS(Status)) {
        LogError("FdoCloseAllTargets (%08x)\n", Status);
        goto fail;
    }

    Status = FdoFindTarget(Fdo);
    if (!NT_SUCCESS(Status)) {
        LogError("FdoFindTarget (%08x)\n", Status);
        goto fail;
    }

    LogTrace("<==== TRUE\n");
    return TRUE;

fail:
    LogTrace("<==== FALSE\n");
    return FALSE;
}

VOID
FdoTerminate(
    IN  PXENVBD_FDO                 Fdo
    )
{
    LogTrace("====>\n");

    DriverUnlinkFdo(Fdo);

    if (Fdo->Target)
        PdoDestroy(Fdo->Target);
    Fdo->Target = NULL;

    GnttabTerminate();
    StoreTerminate();
    HvmTerminate();

    LogTrace("<====\n");
}
//=============================================================================
// Query Methods
ULONG
FdoSizeofXenvbdFdo(
    )
{
    return (ULONG)sizeof(XENVBD_FDO);
}

PXENVBD_PDO
FdoGetPdo(
    IN  PXENVBD_FDO                 Fdo
    )
{
    return Fdo->Target;
}

//=============================================================================
// SRB Methods

FORCEINLINE VOID
FdoCompleteSrb(
    IN  PXENVBD_FDO                 Fdo,
    IN  PSCSI_REQUEST_BLOCK         Srb
    )
{
    StorPortNotification(RequestComplete, Fdo, Srb);
}

//=============================================================================
// StorPort Methods
BOOLEAN
FdoResetBus(
    IN  PXENVBD_FDO                 Fdo
    )
{
    PXENVBD_PDO     Pdo;

    LogTrace("===> (Irql=%d)\n", KeGetCurrentIrql());

    Pdo = Fdo->Target;
    if (Pdo) {
        PdoReference(Pdo);

        PdoReset(Pdo);

        PdoDereference(Pdo);
    }

    LogTrace("<=== TRUE (Irql=%d)\n", KeGetCurrentIrql());
    return TRUE;
}

SCSI_ADAPTER_CONTROL_STATUS
FdoAdapterControl(
    IN  PXENVBD_FDO                 Fdo,
    IN  SCSI_ADAPTER_CONTROL_TYPE   ControlType,
    IN  PVOID                       Parameters
    )
{
    LogTrace("%s ===> (Irql=%d)\n", ScsiAdapterControlTypeName(ControlType), KeGetCurrentIrql());

    UNREFERENCED_PARAMETER(Fdo);

    switch (ControlType) {
    case ScsiQuerySupportedControlTypes:
        {
            PSCSI_SUPPORTED_CONTROL_TYPE_LIST List = Parameters;

#define SET_SUPPORTED(_l, _i, _v)           \
    if (_l->MaxControlType > _i)    _l->SupportedTypeList[_i] = _v;

            SET_SUPPORTED(List, 0, TRUE);   // ScsiQuerySupportedControlTypes
            SET_SUPPORTED(List, 1, TRUE);   // ScsiStopAdapter
            SET_SUPPORTED(List, 2, TRUE);   // ScsiRestartAdapter
            SET_SUPPORTED(List, 3, TRUE);   // ScsiSetBootConfig
            SET_SUPPORTED(List, 4, TRUE);   // ScsiSetRunningConfig

#undef SET_SUPPORTED

        } break;
    default:
        LogVerbose("%s\n", ScsiAdapterControlTypeName(ControlType));
        break;
    }
    LogTrace("%s <=== ScsiAdapterControlSuccess (Irql=%d)\n", ScsiAdapterControlTypeName(ControlType), KeGetCurrentIrql());
    return ScsiAdapterControlSuccess;
}

ULONG
FdoFindAdapter(
    IN  PXENVBD_FDO                 Fdo,
    IN OUT PPORT_CONFIGURATION_INFORMATION  ConfigInfo
    )
{
    LogTrace("===> (Irql=%d)\n", KeGetCurrentIrql());

    if (!FdoInitialize(Fdo)) {
        LogTrace("<=== SP_RETURN_BAD_CONFIG (Irql=%d)\n", KeGetCurrentIrql());
        return SP_RETURN_BAD_CONFIG;
    }

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
        LogTrace("64bit DMA\n");
        ConfigInfo->Dma64BitAddresses = SCSI_DMA64_MINIPORT_SUPPORTED;
    }

    LogTrace("<=== SP_RETURN_FOUND (Irql=%d)\n", KeGetCurrentIrql());
    return SP_RETURN_FOUND;
}

BOOLEAN 
FdoBuildIo(
    IN  PXENVBD_FDO                 Fdo,
    IN  PSCSI_REQUEST_BLOCK         Srb
    )
{
    PXENVBD_SRBEXT  SrbExt = GetSrbExt(Srb);

    RtlZeroMemory(SrbExt, sizeof(XENVBD_SRBEXT));
    Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;

    switch (Srb->Function) {
    case SRB_FUNCTION_EXECUTE_SCSI:
    case SRB_FUNCTION_RESET_DEVICE:
    case SRB_FUNCTION_FLUSH:
    case SRB_FUNCTION_SHUTDOWN:
        return TRUE;

        // dont pass to StartIo
    case SRB_FUNCTION_ABORT_COMMAND:
        LogVerbose("SRB_FUNCTION_ABORT_COMMAND -> SRB_STATUS_ABORT_FAILED\n");
        Srb->SrbStatus = SRB_STATUS_ABORT_FAILED;
        break;
    case SRB_FUNCTION_RESET_BUS:
        LogVerbose("SRB_FUNCTION_RESET_BUS -> SRB_STATUS_SUCCESS\n");
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        FdoResetBus(Fdo);
        break;
        
    default:
        LogVerbose("Ignoring SRB %02x\n", Srb->Function);
        break;
    }
    
    StorPortNotification(RequestComplete, Fdo, Srb);
    StorPortNotification(NextRequest, Fdo);
    return FALSE;
}   

static FORCEINLINE PCHAR
SrbFunctionName(
    IN  UCHAR                       Func
    )
{
    switch (Func) {
    case SRB_FUNCTION_EXECUTE_SCSI: return "EXECUTE_SCSI";
    case SRB_FUNCTION_RESET_DEVICE: return "RESET_DEVICE";
    case SRB_FUNCTION_FLUSH:        return "FLUSH";
    case SRB_FUNCTION_SHUTDOWN:     return "SHUTDOWN";
    case SRB_FUNCTION_ABORT_COMMAND:return "ABORT_COMMAND";
    case SRB_FUNCTION_RESET_BUS:    return "RESET_BUS";
    default:                        return "UNKNOWN";
    }
}
BOOLEAN 
FdoStartIo(
    IN  PXENVBD_FDO                 Fdo,
    IN  PSCSI_REQUEST_BLOCK         Srb
    )
{
    PXENVBD_PDO Pdo = NULL;
    BOOLEAN     CompleteSrb = TRUE;
 
    if (Fdo->Target) {
        Pdo = Fdo->Target;
        PdoReference(Pdo);
    }

    if (Pdo) {
        CompleteSrb = PdoStartIo(Pdo, Srb);
        PdoDereference(Pdo);
    } else {
        LogVerbose("No PDO for SRB %s\n", SrbFunctionName(Srb->Function));
    }

    if (CompleteSrb) {
        FdoCompleteSrb(Fdo, Srb);
    }
    StorPortNotification(NextRequest, Fdo);
    return TRUE;
}
