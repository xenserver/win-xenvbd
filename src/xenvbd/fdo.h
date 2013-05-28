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

#ifndef _XENVBD_FDO_H
#define _XENVBD_FDO_H

typedef struct _XENVBD_FDO XENVBD_FDO, *PXENVBD_FDO;

#include <wdm.h>
#include "..\..\include\xenvbd-storport.h"
#include "pdo.h"
#include "..\..\include\store_interface.h"
#include "..\..\include\evtchn_interface.h"
#include "..\..\include\gnttab_interface.h"
#include "..\..\include\debug_interface.h"
#include "..\..\include\suspend_interface.h"

// Reference Counting
extern LONG
__FdoReference(
    __in PXENVBD_FDO                 Fdo,
    __in PCHAR                       Caller
    );

#define FdoReference(_x_) __FdoReference(_x_, __FUNCTION__)

extern LONG
__FdoDereference(
    __in PXENVBD_FDO                 Fdo,
    __in PCHAR                       Caller
    );

#define FdoDereference(_x_) __FdoDereference(_x_, __FUNCTION__)

// Link PDOs
extern BOOLEAN
FdoLinkPdo(
    __in PXENVBD_FDO                 Fdo,
    __in PXENVBD_PDO                 Pdo
    );

extern BOOLEAN
FdoUnlinkPdo(
    __in PXENVBD_FDO                 Fdo,
    __in PXENVBD_PDO                 Pdo
    );
// Query Methods
__checkReturn
extern PDEVICE_OBJECT
FdoGetDeviceObject(
    __in PXENVBD_FDO                 Fdo
    );

extern ULONG
FdoSizeofXenvbdFdo(
    );

extern PCHAR
FdoEnum(
    __in PXENVBD_FDO                 Fdo
    );

// SRB Methods
extern VOID
FdoStartSrb(
    __in PXENVBD_FDO                 Fdo,
    __in PSCSI_REQUEST_BLOCK         Srb
    );

extern VOID
FdoCompleteSrb(
    __in PXENVBD_FDO                 Fdo,
    __in PSCSI_REQUEST_BLOCK         Srb
    );

// StorPort Methods
extern BOOLEAN
FdoResetBus(
    __in PXENVBD_FDO                 Fdo
    );

extern SCSI_ADAPTER_CONTROL_STATUS
FdoAdapterControl(
    __in PXENVBD_FDO                 Fdo,
    __in SCSI_ADAPTER_CONTROL_TYPE   ControlType,
    __in PVOID                       Parameters
    );

extern ULONG
FdoFindAdapter(
    __in PXENVBD_FDO                 Fdo,
    __inout PPORT_CONFIGURATION_INFORMATION  ConfigInfo
    );

extern BOOLEAN 
FdoBuildIo(
    __in PXENVBD_FDO                 Fdo,
    __in PSCSI_REQUEST_BLOCK         Srb
    );

extern BOOLEAN 
FdoStartIo(
    __in PXENVBD_FDO                 Fdo,
    __in PSCSI_REQUEST_BLOCK         Srb
    );

// PnP Handler
__checkReturn
extern NTSTATUS
FdoDispatchPnp(
    __in PXENVBD_FDO                 Fdo,
    __in PDEVICE_OBJECT              DeviceObject,
    __in PIRP                        Irp
    );

__checkReturn
extern PXENVBD_PDO
FdoGetPdoFromDeviceObject(
    __in PXENVBD_FDO                 Fdo,
    __in PDEVICE_OBJECT              DeviceObject
    );

__checkReturn
extern NTSTATUS
FdoMapDeviceObjectToPdo(
    __in PXENVBD_FDO                 Fdo,
    __in PDEVICE_OBJECT              DeviceObject,
    __in PIRP                        Irp
    );

// Power Handler
__checkReturn
extern NTSTATUS
FdoDispatchPower(
    __in PXENVBD_FDO                 Fdo,
    __in PDEVICE_OBJECT              DeviceObject,
    __in PIRP                        Irp
    );

// Interfaces
extern PXENBUS_STORE_INTERFACE
FdoAcquireStore(
    __in PXENVBD_FDO                 Fdo
    );

extern PXENBUS_EVTCHN_INTERFACE
FdoAcquireEvtchn(
    __in PXENVBD_FDO                 Fdo
    );

extern PXENBUS_GNTTAB_INTERFACE
FdoAcquireGnttab(
    __in PXENVBD_FDO                 Fdo
    );

extern PXENBUS_DEBUG_INTERFACE
FdoAcquireDebug(
    __in PXENVBD_FDO                 Fdo
    );

extern PXENBUS_SUSPEND_INTERFACE
FdoAcquireSuspend(
    __in PXENVBD_FDO                 Fdo
    );

#endif // _XENVBD_FDO_H
