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

#include "notifier.h"
#include "frontend.h"
#include "pdo.h"
#include "fdo.h"
#include "util.h"
#include "debug.h"
#include <evtchn_interface.h>

struct _XENVBD_NOTIFIER {
    PXENVBD_FRONTEND                Frontend;
    BOOLEAN                         Connected;
    BOOLEAN                         Enabled;

    PXENBUS_STORE_INTERFACE         StoreInterface;
    PXENBUS_EVTCHN_INTERFACE        EvtchnInterface;

    PXENBUS_EVTCHN_DESCRIPTOR       Evtchn;
    ULONG                           Port;
    ULONG                           NumInts;
    ULONG                           NumDpcs;
    KDPC                            Dpc;
};

#define NOTIFIER_POOL_TAG           'yfNX'

static FORCEINLINE PVOID
__NotifierAllocate(
    IN  ULONG                       Length
    )
{
    return __AllocateNonPagedPoolWithTag(__FUNCTION__,
                                        __LINE__,
                                        Length,
                                        NOTIFIER_POOL_TAG);
}

static FORCEINLINE VOID
__NotifierFree(
    IN  PVOID                       Buffer
    )
{
    if (Buffer)
        __FreePoolWithTag(Buffer, NOTIFIER_POOL_TAG);
}

KSERVICE_ROUTINE NotifierInterrupt;

BOOLEAN
NotifierInterrupt(
    __in  PKINTERRUPT               Interrupt,
    _In_opt_ PVOID                  Context
    )
{
    PXENVBD_NOTIFIER    Notifier = Context;
    
    UNREFERENCED_PARAMETER(Interrupt);

    ASSERT(Notifier);

	++Notifier->NumInts;
	if (Notifier->Connected) {
		if (KeInsertQueueDpc(&Notifier->Dpc, NULL, NULL)) {
			++Notifier->NumDpcs;
        }
	}

    return TRUE;
}

KDEFERRED_ROUTINE NotifierDpc;

VOID 
NotifierDpc(
    __in  PKDPC                     Dpc,
    __in_opt PVOID                  Context,
    __in_opt PVOID                  Arg1,
    __in_opt PVOID                  Arg2
    )
{
    PXENVBD_NOTIFIER    Notifier = Context;
    PXENVBD_PDO         Pdo;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Arg1);
    UNREFERENCED_PARAMETER(Arg2);

    ASSERT(Notifier);
    Pdo = FrontendGetPdo(Notifier->Frontend);

    if (PdoIsPaused(Pdo)) {
        Warning("Target[%d] : Paused, %d outstanding\n",
                    PdoGetTargetId(Pdo), PdoOutstandingReqs(Pdo));
        if (PdoOutstandingReqs(Pdo) == 0)
            return;
    }

    for (;;) {
        if (Notifier->Connected)
            FrontendNotifyResponses(Notifier->Frontend);

        if (!Notifier->Connected)
            break;
        if (!EVTCHN(Unmask, Notifier->EvtchnInterface, Notifier->Evtchn, FALSE))
            break;
    }
}

NTSTATUS
NotifierCreate(
    IN  PXENVBD_FRONTEND            Frontend,
    OUT PXENVBD_NOTIFIER*           Notifier
    )
{
    *Notifier = __NotifierAllocate(sizeof(XENVBD_NOTIFIER));
    if (*Notifier == NULL)
        goto fail1;

    (*Notifier)->Frontend = Frontend;
    KeInitializeDpc(&(*Notifier)->Dpc, NotifierDpc, *Notifier);

    return STATUS_SUCCESS;

fail1:
    return STATUS_NO_MEMORY;
}

VOID
NotifierDestroy(
    IN  PXENVBD_NOTIFIER            Notifier
    )
{
    Notifier->Frontend = NULL;
    RtlZeroMemory(&Notifier->Dpc, sizeof(KDPC));

    ASSERT(IsZeroMemory(Notifier, sizeof(XENVBD_NOTIFIER)));
    
    __NotifierFree(Notifier);
}

NTSTATUS
NotifierConnect(
    IN  PXENVBD_NOTIFIER            Notifier,
    IN  USHORT                      BackendDomain
    )
{
    PXENVBD_FDO Fdo = PdoGetFdo(FrontendGetPdo(Notifier->Frontend));

    ASSERT(Notifier->Connected == FALSE);

    Notifier->StoreInterface = FdoAcquireStore(Fdo);
    Notifier->EvtchnInterface = FdoAcquireEvtchn(Fdo);

    Notifier->Evtchn = EVTCHN(Open, 
                                Notifier->EvtchnInterface, 
                                EVTCHN_UNBOUND, 
                                NotifierInterrupt,
                                Notifier, 
                                BackendDomain, 
                                TRUE);
    if (Notifier->Evtchn == NULL)
        goto fail1;

    Notifier->Port = EVTCHN(Port, Notifier->EvtchnInterface, Notifier->Evtchn);

    if (EVTCHN(Unmask, Notifier->EvtchnInterface, Notifier->Evtchn, FALSE))
        EVTCHN(Trigger, Notifier->EvtchnInterface, Notifier->Evtchn);

    Notifier->Connected = TRUE;
    return STATUS_SUCCESS;

fail1:
    EVTCHN(Release, Notifier->EvtchnInterface);
    Notifier->EvtchnInterface = NULL;

    STORE(Release, Notifier->StoreInterface);
    Notifier->StoreInterface = NULL;

    return STATUS_NO_MEMORY;
}

NTSTATUS
NotifierStoreWrite(
    IN  PXENVBD_NOTIFIER            Notifier,
    IN  PXENBUS_STORE_TRANSACTION   Transaction,
    IN  PCHAR                       FrontendPath
    )
{
    return STORE(Printf, 
                Notifier->StoreInterface, 
                Transaction, 
                FrontendPath, 
                "event-channel", 
                "%u", 
                Notifier->Port);
}

VOID
NotifierEnable(
    IN  PXENVBD_NOTIFIER            Notifier
    )
{
    ASSERT(Notifier->Enabled == FALSE);

    EVTCHN(Trigger, Notifier->EvtchnInterface, Notifier->Evtchn);

    Notifier->Enabled = TRUE;
}

VOID
NotifierDisable(
    IN  PXENVBD_NOTIFIER            Notifier
    )
{
    ASSERT(Notifier->Enabled == TRUE);

    Notifier->Enabled = FALSE;
}

VOID
NotifierDisconnect(
    IN  PXENVBD_NOTIFIER            Notifier
    )
{
    ASSERT(Notifier->Connected == TRUE);

    EVTCHN(Close, Notifier->EvtchnInterface, Notifier->Evtchn);
    Notifier->Evtchn = NULL;
    Notifier->Port = 0;

    EVTCHN(Release, Notifier->EvtchnInterface);
    Notifier->EvtchnInterface = NULL;

    STORE(Release, Notifier->StoreInterface);
    Notifier->StoreInterface = NULL;

    Notifier->NumInts = Notifier->NumDpcs = 0;

    Notifier->Connected = FALSE;
}

VOID
NotifierDebugCallback(
    IN  PXENVBD_NOTIFIER            Notifier,
    IN  PXENBUS_DEBUG_INTERFACE     Debug,
    IN  PXENBUS_DEBUG_CALLBACK      Callback
    )
{
    DEBUG(Printf, Debug, Callback,
            "NOTIFIER: Int / DPC : %d / %d\n",
            Notifier->NumInts, Notifier->NumDpcs);

    if (Notifier->Evtchn) {
        DEBUG(Printf, Debug, Callback,
            "NOTIFIER: Evtchn : %p (%d)\n", 
            Notifier->Evtchn, Notifier->Port);
    }

    Notifier->NumInts = 0;
    Notifier->NumDpcs = 0;
}

VOID
NotifierTrigger(
    IN  PXENVBD_NOTIFIER            Notifier
    )
{
    if (Notifier->Enabled)
        EVTCHN(Trigger, Notifier->EvtchnInterface, Notifier->Evtchn);
}

VOID
NotifierSend(
    IN  PXENVBD_NOTIFIER            Notifier
    )
{
    if (Notifier->Enabled)
        EVTCHN(Send, Notifier->EvtchnInterface, Notifier->Evtchn);
}

