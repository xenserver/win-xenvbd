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

#ifndef _XENVBD_PDO_H
#define _XENVBD_PDO_H

typedef struct _XENVBD_PDO XENVBD_PDO, *PXENVBD_PDO;

#include <wdm.h>
#include "..\..\include\xenvbd-storport.h"
#include "fdo.h"
#include "ring.h"
#include "types.h"
#include "..\..\include\debug_interface.h"

extern VOID
PdoDebugCallback(
    __in PXENVBD_PDO             Pdo,
    __in PXENBUS_DEBUG_INTERFACE Debug,
    __in PXENBUS_DEBUG_CALLBACK  Callback
    );

// Creation/Deletion
__checkReturn
extern NTSTATUS
PdoCreate(
    __in PXENVBD_FDO             Fdo,
    __in __nullterminated PCHAR  DeviceId,
    __in ULONG                   TargetId,
    __in BOOLEAN                 EmulatedMasked,
    __in PKEVENT                 FrontendEvent,
    __in XENVBD_DEVICE_TYPE      DeviceType
    );

extern VOID
PdoDestroy(
    __in PXENVBD_PDO             Pdo
    );

__checkReturn
extern NTSTATUS
PdoD3ToD0(
    __in PXENVBD_PDO             Pdo
    );

extern VOID
PdoD0ToD3(
    __in PXENVBD_PDO             Pdo
    );

__drv_requiresIRQL(DISPATCH_LEVEL)
extern VOID
PdoBackendPathChanged(
    __in PXENVBD_PDO             Pdo
    );

// PnP States
extern VOID
PdoSetMissing(
    __in PXENVBD_PDO             Pdo,
    __in __nullterminated const CHAR* Reason
    );

__checkReturn
extern BOOLEAN
PdoIsMissing(
    __in PXENVBD_PDO             Pdo
    );

extern const CHAR*
PdoMissingReason(
    __in PXENVBD_PDO            Pdo
    );

__checkReturn
extern BOOLEAN
PdoIsMasked(
    __in PXENVBD_PDO             Pdo
    );

extern VOID
PdoSetDevicePnpState(
    __in PXENVBD_PDO             Pdo,
    __in DEVICE_PNP_STATE        State
    );

__checkReturn
extern DEVICE_PNP_STATE
PdoGetDevicePnpState(
    __in PXENVBD_PDO             Pdo
    );

// Reference Counting
extern LONG
__PdoReference(
    __in PXENVBD_PDO             Pdo,
    __in PCHAR                   Caller
    );

#define PdoReference(_x_) __PdoReference(_x_, __FUNCTION__)

extern LONG
__PdoDereference(
    __in PXENVBD_PDO             Pdo,
    __in PCHAR                   Caller
    );

#define PdoDereference(_x_) __PdoDereference(_x_, __FUNCTION__)

// Query Methods
extern ULONG
PdoGetTargetId(
    __in PXENVBD_PDO             Pdo
    );

__checkReturn
extern PDEVICE_OBJECT
PdoGetDeviceObject(
    __in PXENVBD_PDO             Pdo
    );

extern VOID
PdoSetDeviceObject(
    __in PXENVBD_PDO             Pdo,
    __in PDEVICE_OBJECT          DeviceObject
    );

__checkReturn
extern BOOLEAN
PdoIsPaused(
    __in PXENVBD_PDO             Pdo
    );

__checkReturn
extern ULONG
PdoOutstandingSrbs(
    __in PXENVBD_PDO             Pdo
    );

__checkReturn
extern PXENVBD_FDO
PdoGetFdo( 
    __in PXENVBD_PDO             Pdo
    );

extern ULONG
PdoSectorSize(
    __in PXENVBD_PDO             Pdo
    );

// Queue-Related
extern ULONG
PdoPrepareFresh(
    __in PXENVBD_PDO             Pdo
    );

extern ULONG
PdoSubmitPrepared(
    __in PXENVBD_PDO             Pdo
    );

extern VOID
PdoPreResume(
    __in PXENVBD_PDO             Pdo
    );

extern VOID
PdoPostResume(
    __in PXENVBD_PDO             Pdo
    );

extern VOID
PdoCompleteShutdown(
    __in PXENVBD_PDO             Pdo
    );

extern VOID
PdoCompleteSubmittedRequest(
    __in PXENVBD_PDO             Pdo,
    __in PXENVBD_REQUEST         Request,
    __in SHORT                   Status
    );

// StorPort Methods
extern VOID
PdoReset(
    __in PXENVBD_PDO             Pdo
    );

__checkReturn
extern BOOLEAN
PdoStartIo(
    __in PXENVBD_PDO             Pdo,
    __in PSCSI_REQUEST_BLOCK     Srb
    );

extern VOID
PdoAbortAllSrbs(
    __in PXENVBD_PDO             Pdo
    );

extern VOID
PdoSrbPnp(
    __in PXENVBD_PDO             Pdo,
    __in PSCSI_PNP_REQUEST_BLOCK Srb
    );

// PnP Handler
__checkReturn
extern NTSTATUS
PdoDispatchPnp(
    __in PXENVBD_PDO             Pdo,
    __in PDEVICE_OBJECT          DeviceObject,
    __in PIRP                    Irp
    );

__drv_maxIRQL(DISPATCH_LEVEL)
extern VOID
PdoIssueDeviceEject(
    __in PXENVBD_PDO             Pdo,
    __in __nullterminated const CHAR* Reason
    );

#endif // _XENVBD_PDO_H
