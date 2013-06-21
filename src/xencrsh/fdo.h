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

#include <wdm.h>
#include <xenvbd-storport.h>


typedef struct _XENVBD_FDO XENVBD_FDO, *PXENVBD_FDO;

#include "pdo.h"

extern VOID
FdoTerminate(
    IN  PXENVBD_FDO                 Fdo
    );

// Query Methods
extern ULONG
FdoSizeofXenvbdFdo(
    );

extern PXENVBD_PDO
FdoGetPdo(
    IN  PXENVBD_FDO                 Fdo
    );

// SRB Methods
extern VOID
FdoCompleteSrb(
    IN  PXENVBD_FDO                 Fdo,
    IN  PSCSI_REQUEST_BLOCK         Srb
    );

// StorPort Methods
extern BOOLEAN
FdoResetBus(
    IN  PXENVBD_FDO                 Fdo
    );

extern SCSI_ADAPTER_CONTROL_STATUS
FdoAdapterControl(
    IN  PXENVBD_FDO                 Fdo,
    IN  SCSI_ADAPTER_CONTROL_TYPE   ControlType,
    IN  PVOID                       Parameters
    );

extern ULONG
FdoFindAdapter(
    IN  PXENVBD_FDO                 Fdo,
    IN OUT PPORT_CONFIGURATION_INFORMATION  ConfigInfo
    );

extern BOOLEAN 
FdoBuildIo(
    IN  PXENVBD_FDO                 Fdo,
    IN  PSCSI_REQUEST_BLOCK         Srb
    );

extern BOOLEAN 
FdoStartIo(
    IN  PXENVBD_FDO                 Fdo,
    IN  PSCSI_REQUEST_BLOCK         Srb
    );

#endif // _XENVBD_FDO_H
