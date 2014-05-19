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

#define XEN_API   __declspec(dllexport)

#include "driver.h"

#include "fdo.h"
#include "pdo.h"
#include "srbext.h"
#include "buffer.h"
#include <version.h>

#include "austere.h"

#include "log.h"
#include "assert.h"
#include <names.h>
#include <xencrsh_interface.h>
         
#include <xenvbd-ntstrsafe.h>

static ULONG    __OperatingMode;

FORCEINLINE ULONG DriverGetOperatingMode()
{
    return __OperatingMode;
}
static FORCEINLINE PCHAR
__OperatingModeName()
{
    switch (__OperatingMode) {
    case DUMP_MODE:     return "DUMP";
    case HIBER_MODE:    return "HIBER";
    case NORMAL_MODE:   return "NORMAL";
    default:            return "UNKNOWN";
    }
}

//=============================================================================
// Fdo Device Extension management
static PXENVBD_FDO              __XenvbdFdo;

VOID
DriverLinkFdo(
    IN  PXENVBD_FDO             Fdo
    )
{
    __XenvbdFdo = Fdo;
}

VOID
DriverUnlinkFdo(
    IN  PXENVBD_FDO             Fdo
    )
{
    UNREFERENCED_PARAMETER(Fdo);
    __XenvbdFdo = NULL;
}

//=============================================================================
// Global Functions
static FORCEINLINE PCHAR
__DriverFormatV(
    IN  PCHAR       Fmt,
    IN  va_list     Args
    )
{
    NTSTATUS    Status;
    PCHAR       Str;
    ULONG       Size = 32;

    for (;;) {
        Str = (PCHAR)AustereAllocate(Size);
        if (!Str) {
            return NULL;
        }
        RtlZeroMemory(Str, Size);

        Status = RtlStringCchVPrintfA(Str, Size - 1, Fmt, Args);

        if (Status == STATUS_SUCCESS) {
            Str[Size - 1] = '\0';
            return Str;
        } 
        
        AustereFree(Str);
        if (Status == STATUS_BUFFER_OVERFLOW) {
            Size *= 2;
        } else {
            return NULL;
        }
    }
}

PCHAR
DriverFormat(
    IN  PCHAR       Format,
    ...
    )
{
    va_list Args;
    PCHAR   Str;

    va_start(Args, Format);
    Str = __DriverFormatV(Format, Args);
    va_end(Args);
    return Str;
}

//=============================================================================
// StorPort redirections
HW_INITIALIZE       HwInitialize;

BOOLEAN 
HwInitialize(
    IN  PVOID   HwDeviceExtension
    )
{
    UNREFERENCED_PARAMETER(HwDeviceExtension);
    return TRUE;
}

HW_INTERRUPT        HwInterrupt;

BOOLEAN 
HwInterrupt(
    IN  PVOID   HwDeviceExtension
    )
{
    PXENVBD_PDO Pdo = FdoGetPdo((PXENVBD_FDO)HwDeviceExtension);
    
    if (Pdo)
        PdoEvtchnInterruptHandler(Pdo);

    return TRUE;
}

HW_RESET_BUS        HwResetBus;

BOOLEAN 
HwResetBus(
    IN  PVOID   HwDeviceExtension,
    IN  ULONG   PathId
    )
{
    UNREFERENCED_PARAMETER(PathId);
    return FdoResetBus((PXENVBD_FDO)HwDeviceExtension);
}

HW_ADAPTER_CONTROL  HwAdapterControl;

SCSI_ADAPTER_CONTROL_STATUS
HwAdapterControl(
    IN  PVOID                       HwDeviceExtension,
    IN  SCSI_ADAPTER_CONTROL_TYPE   ControlType,
    IN  PVOID                       Parameters
    )
{
    return FdoAdapterControl((PXENVBD_FDO)HwDeviceExtension, ControlType, Parameters);
}

HW_FIND_ADAPTER     HwFindAdapter;

ULONG
HwFindAdapter(
    IN  PVOID                               HwDeviceExtension,
    IN  PVOID                               Context,
    IN  PVOID                               BusInformation,
    IN  PCHAR                               ArgumentString,
    IN OUT PPORT_CONFIGURATION_INFORMATION  ConfigInfo,
    OUT PBOOLEAN                            Again
    )
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(BusInformation);
    UNREFERENCED_PARAMETER(ArgumentString);
    UNREFERENCED_PARAMETER(Again);

    return FdoFindAdapter((PXENVBD_FDO)HwDeviceExtension, ConfigInfo);
}

HW_BUILDIO          HwBuildIo;

BOOLEAN 
HwBuildIo(
    IN  PVOID               HwDeviceExtension,
    IN  PSCSI_REQUEST_BLOCK Srb
    )
{
    return FdoBuildIo((PXENVBD_FDO)HwDeviceExtension, Srb);
}

HW_STARTIO          HwStartIo;

BOOLEAN 
HwStartIo(
    IN  PVOID               HwDeviceExtension,
    IN  PSCSI_REQUEST_BLOCK Srb
    )
{
    return FdoStartIo((PXENVBD_FDO)HwDeviceExtension, Srb);
}

//=============================================================================
#pragma warning(disable : 28138)
#define CRASH_PORT  ((PULONG)((PVOID)(ULONG_PTR)0xED))

XEN_API NTSTATUS
XencrshEntryPoint(
    IN  PDRIVER_OBJECT  _DriverObject
    )
{
    NTSTATUS                Status;
    HW_INITIALIZATION_DATA  InitData;

    LogTrace("===> (Irql=%d)\n", KeGetCurrentIrql());
    LogVerbose("%s (%s)\n",
         MAJOR_VERSION_STR "." MINOR_VERSION_STR "." MICRO_VERSION_STR "." BUILD_NUMBER_STR,
         DAY_STR "/" MONTH_STR "/" YEAR_STR);

    LogVerbose("Loading PV Disk in %s mode\n", __OperatingModeName()); 
    if (DriverGetOperatingMode() == DUMP_MODE) {
        WRITE_PORT_ULONG(CRASH_PORT, 'PLEH');
    } 

    AustereInitialize();
    BufferInitialize();

    RtlZeroMemory(&InitData, sizeof(InitData));

    InitData.HwInitializationDataSize   =   sizeof(InitData);
    InitData.AdapterInterfaceType       =   Internal;
    InitData.HwInitialize               =   HwInitialize;
    InitData.HwStartIo                  =   HwStartIo;
    InitData.HwInterrupt                =   HwInterrupt;
#pragma warning(suppress : 4152)
    InitData.HwFindAdapter              =   HwFindAdapter;
    InitData.HwResetBus                 =   HwResetBus;
    InitData.HwDmaStarted               =   NULL;
    InitData.HwAdapterState             =   NULL;
    InitData.DeviceExtensionSize        =   FdoSizeofXenvbdFdo();
    InitData.SpecificLuExtensionSize    =   0;
    InitData.SrbExtensionSize           =   sizeof(XENVBD_SRBEXT);
    InitData.NumberOfAccessRanges       =   2;
    InitData.MapBuffers                 =   STOR_MAP_NON_READ_WRITE_BUFFERS;
    InitData.NeedPhysicalAddresses      =   TRUE;
    InitData.TaggedQueuing              =   TRUE;
    InitData.AutoRequestSense           =   TRUE;
    InitData.MultipleRequestPerLu       =   TRUE;
    InitData.HwAdapterControl           =   HwAdapterControl;
    InitData.HwBuildIo                  =   HwBuildIo;

#pragma prefast(suppress: 6387, "Crash Driver has no registry path")
    Status = StorPortInitialize(_DriverObject, NULL, &InitData, NULL);

    LogVerbose("(%08x)\n", Status);

    LogTrace("<=== (%08x) (Irql=%d)\n", Status, KeGetCurrentIrql());
    return Status;
}

//=============================================================================
static FORCEINLINE WCHAR
__ToUpper(
    IN  WCHAR   Ch
    )
{
    if (Ch >= L'a' && Ch <= L'z')
        return Ch - L'a' + L'A';
    return Ch;
}

static FORCEINLINE BOOLEAN
__StrStarts(
    IN  PWCHAR  Str,
    IN  PWCHAR  Starts
    )
{
    while (*Str != L'\0' && *Starts != L'\0') {
        if (__ToUpper(*Str) != __ToUpper(*Starts))
            return FALSE;
        ++Str;
        ++Starts;
    }
    return TRUE;
}

NTSTATUS
DllInitialize(
    IN  PUNICODE_STRING RegistryPath
    )
{
    PWSTR       Name;
    NTSTATUS    Status;
    LogTrace("===>\n");

    Name = wcsrchr(RegistryPath->Buffer, L'\\');
    if (Name) {
        Name++;
        if (__StrStarts(Name, L"dump_")) {
            __OperatingMode = DUMP_MODE;
        } else if (__StrStarts(Name, L"hiber_")) {
            __OperatingMode = HIBER_MODE;
        } else {
            __OperatingMode = NORMAL_MODE;
        }
    }

    Status = STATUS_SUCCESS;
    LogTrace("<=== (%08x)\n", Status);
    return Status;
}

NTSTATUS
DllUnload(
    VOID
    )
{
    return STATUS_SUCCESS;
}

DRIVER_INITIALIZE   DriverEntry;

NTSTATUS
DriverEntry(
    IN  PDRIVER_OBJECT  _DriverObject,
    IN  PUNICODE_STRING RegistryPath
    )
{
    UNREFERENCED_PARAMETER(_DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    return STATUS_SUCCESS;
}

DRIVER_UNLOAD               DriverUnload;

VOID
DriverUnload(
    IN PDRIVER_OBJECT  _DriverObject
    )
{
    UNREFERENCED_PARAMETER(_DriverObject);
}
