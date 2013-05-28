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

#ifndef _XENVBD_FRONTEND_H
#define _XENVBD_FRONTEND_H

#include "driver.h"

#include "fdo.h"
#include "pdo.h"
#include "ring.h"

typedef enum _XENVBD_STATE {
    XENVBD_STATE_INVALID,
    XENVBD_INITIALIZED,
    XENVBD_CLOSED,
    XENVBD_PREPARED,
    XENVBD_CONNECTED,
    XENVBD_ENABLED
} XENVBD_STATE, *PXENVBD_STATE;

typedef struct _XENVBD_FRONTEND {
    // Frontend
    PXENVBD_PDO                 Pdo;
    ULONG                       TargetId;
    ULONG                       DeviceId;
    PCHAR                       FrontendPath;
    PCHAR                       BackendPath;
    PCHAR                       TargetPath;
    USHORT                      BackendId;
    XENVBD_STATE                State;

    // Capabilities
    BOOLEAN                     Connected;
    BOOLEAN                     Removable;
    BOOLEAN                     SurpriseRemovable;
    BOOLEAN                     FeatureBarrier;
    BOOLEAN                     FeatureDiscard;
    BOOLEAN                     Paging;
    BOOLEAN                     Hibernation;
    BOOLEAN                     DumpFile;

    // Disk Info
    ULONG                       SectorSize;
    ULONG64                     SectorCount;
    ULONG                       DiskInfo;

    // Inquiry
    PVOID                       Inquiry;

    // Ring
    blkif_sring_t*              SharedRing;
    blkif_front_ring_t          FrontRing;
    ULONG                       RingGrantRef;
    ULONG                       EvtchnPort;
} XENVBD_FRONTEND, *PXENVBD_FRONTEND;

// Init/Term
extern NTSTATUS
FrontendCreate(
    IN  PXENVBD_FRONTEND        Frontend,
    IN  PCHAR                   DeviceId, 
    IN  ULONG                   TargetId, 
    IN  PXENVBD_PDO             Pdo
    );

extern VOID
FrontendDestroy(
    IN  PXENVBD_FRONTEND        Frontend
    );

extern NTSTATUS
FrontendSetState(
    IN  PXENVBD_FRONTEND        Frontend,
    IN  XENVBD_STATE            State
    );

extern NTSTATUS
FrontendCloseTarget(
    IN  PCHAR                   FrontendPath,
    IN  PCHAR                   BackendPath
    );

// Ring Slots
extern VOID
FrontendEvtchnCallback(
    IN  PXENVBD_FRONTEND        Frontend
    );

extern BOOLEAN
FrontendCanSubmitRequest(
    IN  PXENVBD_FRONTEND        Frontend,
    IN  ULONG                   NumRequests
    );

extern VOID
FrontendInsertRequestOnRing(
    IN  PXENVBD_FRONTEND        Frontend,
    IN  PXENVBD_REQUEST         Request
    );

extern VOID
FrontendPushRequestAndCheckNotify(
    IN  PXENVBD_FRONTEND        Frontend
    );

#endif // _XENVBD_FRONTEND_H