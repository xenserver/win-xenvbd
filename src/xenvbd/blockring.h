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

#ifndef _XENVBD_BLOCKRING_H
#define _XENVBD_BLOCKRING_H

typedef struct _XENVBD_BLOCKRING XENVBD_BLOCKRING, *PXENVBD_BLOCKRING;

#include "frontend.h"
#include <debug_interface.h>
#include <store_interface.h>

extern NTSTATUS
BlockRingCreate(
    IN  PXENVBD_FRONTEND            Frontend,
    IN  ULONG                       DeviceId,
    OUT PXENVBD_BLOCKRING*          BlockRing
    );

extern VOID
BlockRingDestroy(
    IN  PXENVBD_BLOCKRING           BlockRing
    );

extern NTSTATUS
BlockRingConnect(
    IN  PXENVBD_BLOCKRING           BlockRing
    );

extern NTSTATUS
BlockRingStoreWrite(
    IN  PXENVBD_BLOCKRING           BlockRing,
    IN  PXENBUS_STORE_TRANSACTION   Transaction,
    IN  PCHAR                       FrontendPath
    );

extern VOID
BlockRingEnable(
    IN  PXENVBD_BLOCKRING           BlockRing
    );

extern VOID
BlockRingDisable(
    IN  PXENVBD_BLOCKRING           BlockRing
    );

extern VOID
BlockRingDisconnect(
    IN  PXENVBD_BLOCKRING           BlockRing
    );

extern VOID
BlockRingDebugCallback(
    IN  PXENVBD_BLOCKRING           BlockRing,
    IN  PXENBUS_DEBUG_INTERFACE     Debug,
    IN  PXENBUS_DEBUG_CALLBACK      Callback
    );

extern VOID
BlockRingPoll(
    IN  PXENVBD_BLOCKRING           BlockRing
    );

extern BOOLEAN
BlockRingSubmit(
    IN  PXENVBD_BLOCKRING           BlockRing,
    IN  PXENVBD_REQUEST             Request
    );

#endif // _XENVBD_BLOCKRING_H
