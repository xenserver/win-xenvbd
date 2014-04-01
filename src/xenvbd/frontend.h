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

#include "pdo.h"
#include <debug_interface.h>

typedef enum _XENVBD_STATE {
    XENVBD_STATE_INVALID,
    XENVBD_INITIALIZED,
    XENVBD_CLOSED,
    XENVBD_PREPARED,
    XENVBD_CONNECTED,
    XENVBD_ENABLED
} XENVBD_STATE, *PXENVBD_STATE;

typedef struct _XENVBD_CAPS {
    BOOLEAN                     Connected;
    BOOLEAN                     Removable;
    BOOLEAN                     SurpriseRemovable;
    BOOLEAN                     Paging;
    BOOLEAN                     Hibernation;
    BOOLEAN                     DumpFile;
} XENVBD_CAPS, *PXENVBD_CAPS;

typedef struct _XENVBD_FEATURES {
    ULONG                       Indirect;
    BOOLEAN                     Persistent;
} XENVBD_FEATURES, *PXENVBD_FEATURES;

typedef struct _XENVBD_DISKINFO {
    ULONG64                     SectorCount;
    ULONG                       SectorSize;
    ULONG                       PhysSectorSize;
    ULONG                       DiskInfo;
    BOOLEAN                     Barrier;
    BOOLEAN                     FlushCache;
    BOOLEAN                     Discard;
    BOOLEAN                     DiscardSecure;
    ULONG                       DiscardAlignment;
    ULONG                       DiscardGranularity;
} XENVBD_DISKINFO, *PXENVBD_DISKINFO;

typedef struct _XENVBD_FRONTEND XENVBD_FRONTEND, *PXENVBD_FRONTEND;

// Accessors
extern VOID
FrontendRemoveFeature(
    IN  PXENVBD_FRONTEND        Frontend,
    IN  UCHAR                   BlkifOperation
    );
extern PXENVBD_CAPS
FrontendGetCaps(
    __in  PXENVBD_FRONTEND      Frontend
    );
extern PXENVBD_FEATURES
FrontendGetFeatures(
    __in  PXENVBD_FRONTEND      Frontend
    );
extern PXENVBD_DISKINFO
FrontendGetDiskInfo(
    __in  PXENVBD_FRONTEND      Frontend
    );
extern ULONG
FrontendGetTargetId(
    __in  PXENVBD_FRONTEND      Frontend
    );
extern PVOID
FrontendGetInquiry(
    __in  PXENVBD_FRONTEND      Frontend
    );
extern PXENVBD_PDO
FrontendGetPdo(
    __in  PXENVBD_FRONTEND      Frontend
    );
#include "blockring.h"
extern PXENVBD_BLOCKRING
FrontendGetBlockRing(
    __in  PXENVBD_FRONTEND      Frontend
    );
#include "notifier.h"
extern PXENVBD_NOTIFIER
FrontendGetNotifier(
    __in  PXENVBD_FRONTEND      Frontend
    );
#include "granter.h"
extern PXENVBD_GRANTER
FrontendGetGranter(
    __in  PXENVBD_FRONTEND      Frontend
    );

extern NTSTATUS
FrontendStoreWriteFrontend(
    __in  PXENVBD_FRONTEND      Frontend,
    __in  PCHAR                 Name,
    __in  PCHAR                 Value
    );
extern NTSTATUS
FrontendStoreReadBackend(
    __in  PXENVBD_FRONTEND      Frontend,
    __in  PCHAR                 Name,
    __out PCHAR*                Value
    );
extern VOID
FrontendStoreFree(
    __in  PXENVBD_FRONTEND      Frontend,
    __in  PCHAR                 Value
    );    
__drv_maxIRQL(DISPATCH_LEVEL)
extern NTSTATUS
FrontendWriteUsage(
    __in  PXENVBD_FRONTEND        Frontend
    );

// Ring
__drv_requiresIRQL(DISPATCH_LEVEL)
extern VOID
FrontendNotifyResponses(
    __in  PXENVBD_FRONTEND        Frontend
    );

// Init/Term
__checkReturn
__drv_maxIRQL(DISPATCH_LEVEL)
extern NTSTATUS
FrontendD3ToD0(
    __in  PXENVBD_FRONTEND        Frontend
    );

__drv_maxIRQL(DISPATCH_LEVEL)
extern VOID
FrontendD0ToD3(
    __in  PXENVBD_FRONTEND        Frontend
    );

__checkReturn
extern NTSTATUS
FrontendSetState(
    __in  PXENVBD_FRONTEND        Frontend,
    __in  XENVBD_STATE            State
    );

__drv_requiresIRQL(DISPATCH_LEVEL)
extern VOID
FrontendBackendPathChanged(
    __in  PXENVBD_FRONTEND        Frontend
    );

__checkReturn
extern NTSTATUS
FrontendCreate(
    __in  PXENVBD_PDO             Pdo,
    __in  PCHAR                   DeviceId, 
    __in  ULONG                   TargetId, 
    __in  PKEVENT                 Event,
    __out PXENVBD_FRONTEND*       _Frontend
    );

extern VOID
FrontendDestroy(
    __in  PXENVBD_FRONTEND        Frontend
    );

// Debug
extern VOID
FrontendDebugCallback(
    __in  PXENVBD_FRONTEND        Frontend,
    __in  PXENBUS_DEBUG_INTERFACE Debug,
    __in  PXENBUS_DEBUG_CALLBACK  Callback
    );

#endif // _XENVBD_FRONTEND_H