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

#ifndef _XENVBD_NOTIFIER_H
#define _XENVBD_NOTIFIER_H

typedef struct _XENVBD_NOTIFIER XENVBD_NOTIFIER, *PXENVBD_NOTIFIER;

#include "frontend.h"
#include <debug_interface.h>
#include <store_interface.h>

extern NTSTATUS
NotifierCreate(
    IN  PXENVBD_FRONTEND            Frontend,
    OUT PXENVBD_NOTIFIER*           Notifier
    );

extern VOID
NotifierDestroy(
    IN  PXENVBD_NOTIFIER            Notifier
    );

extern NTSTATUS
NotifierConnect(
    IN  PXENVBD_NOTIFIER            Notifier,
    IN  USHORT                      BackendDomain
    );

extern NTSTATUS
NotifierStoreWrite(
    IN  PXENVBD_NOTIFIER            Notifier,
    IN  PXENBUS_STORE_TRANSACTION   Transaction,
    IN  PCHAR                       FrontendPath
    );

extern VOID
NotifierEnable(
    IN  PXENVBD_NOTIFIER            Notifier
    );

extern VOID
NotifierDisable(
    IN  PXENVBD_NOTIFIER            Notifier
    );

extern VOID
NotifierDisconnect(
    IN  PXENVBD_NOTIFIER            Notifier
    );

extern VOID
NotifierDebugCallback(
    IN  PXENVBD_NOTIFIER            Notifier,
    IN  PXENBUS_DEBUG_INTERFACE     Debug,
    IN  PXENBUS_DEBUG_CALLBACK      Callback
    );

extern VOID
NotifierTrigger(
    IN  PXENVBD_NOTIFIER            Notifier
    );

extern VOID
NotifierSend(
    IN  PXENVBD_NOTIFIER            Notifier
    );

#endif // _XENVBD_NOTIFIER_H
