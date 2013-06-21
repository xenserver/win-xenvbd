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

#include <wdm.h>
#include <xenvbd-storport.h>


typedef struct _XENVBD_PDO XENVBD_PDO, *PXENVBD_PDO;

#include "fdo.h"
#include "ring.h"

// Creation/Deletion
extern NTSTATUS
PdoCreate(
    IN  PXENVBD_FDO             Fdo,
    IN  PCHAR                   DeviceId,
    IN  ULONG                   TargetId,
    OUT PXENVBD_PDO*            _Pdo
    );

extern VOID
PdoDestroy(
    IN  PXENVBD_PDO             Pdo
    );

extern VOID
PdoD3ToD0(
    IN  PXENVBD_PDO             Pdo
    );

extern VOID
PdoD0ToD3(
    IN  PXENVBD_PDO             Pdo
    );

// Reference Counting
extern VOID
PdoReference(
    IN  PXENVBD_PDO             Pdo
    );

extern VOID
PdoDereference(
    IN  PXENVBD_PDO             Pdo
    );

// Query Methods
extern ULONG
PdoSectorSize(
    IN  PXENVBD_PDO             Pdo
    );

// Queue-Related
extern VOID
PdoPrepareFresh(
    IN  PXENVBD_PDO             Pdo
    );

extern VOID
PdoSubmitPrepared(
    IN  PXENVBD_PDO             Pdo
    );

extern VOID
PdoCompleteShutdown(
    IN  PXENVBD_PDO             Pdo
    );

extern VOID
PdoCompleteSubmittedRequest(
    IN  PXENVBD_PDO             Pdo,
    IN  PXENVBD_REQUEST         Request,
    IN  SHORT                   Status
    );

// StorPort Methods
extern VOID
PdoReset(
    IN  PXENVBD_PDO             Pdo
    );

extern BOOLEAN
PdoStartIo(
    IN  PXENVBD_PDO             Pdo,
    IN  PSCSI_REQUEST_BLOCK     Srb
    );

extern VOID
PdoAbortAllSrbs(
    IN  PXENVBD_PDO             Pdo
    );

extern VOID
PdoEvtchnInterruptHandler(
    IN  PXENVBD_PDO             Pdo
    );

#endif // _XENVBD_PDO_H
