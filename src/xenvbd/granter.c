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

#include "frontend.h"
#include "pdo.h"
#include "fdo.h"
#include "util.h"
#include "debug.h"
#include "thread.h"
#include <gnttab_interface.h>

struct _XENVBD_GRANTER {
    PXENVBD_FRONTEND                Frontend;
    BOOLEAN                         Connected;
    BOOLEAN                         Enabled;

    PXENBUS_GNTTAB_INTERFACE        GnttabInterface;

    USHORT                          BackendDomain;
};
#define GRANTER_POOL_TAG            'tnGX'

static FORCEINLINE PVOID
__GranterAllocate(
    IN  ULONG                       Length
    )
{
    return __AllocateNonPagedPoolWithTag(__FUNCTION__,
                                        __LINE__,
                                        Length,
                                        GRANTER_POOL_TAG);
}

static FORCEINLINE VOID
__GranterFree(
    IN  PVOID                       Buffer
    )
{
    if (Buffer)
        __FreePoolWithTag(Buffer, GRANTER_POOL_TAG);
}

NTSTATUS
GranterCreate(
    IN  PXENVBD_FRONTEND            Frontend,
    OUT PXENVBD_GRANTER*            Granter
    )
{
    NTSTATUS    status;

    status = STATUS_NO_MEMORY;
    *Granter = __GranterAllocate(sizeof(XENVBD_GRANTER));
    if (*Granter == NULL)
        goto fail1;

    (*Granter)->Frontend = Frontend;

    return STATUS_SUCCESS;

fail1:
    return status;
}

VOID
GranterDestroy(
    IN  PXENVBD_GRANTER             Granter
    )
{
    Granter->Frontend = NULL;

    ASSERT(IsZeroMemory(Granter, sizeof(XENVBD_GRANTER)));
    
    __GranterFree(Granter);
}

NTSTATUS
GranterConnect(
    IN  PXENVBD_GRANTER             Granter,
    IN  USHORT                      BackendDomain
    )
{
    PXENVBD_FDO Fdo = PdoGetFdo(FrontendGetPdo(Granter->Frontend));

    ASSERT(Granter->Connected == FALSE);

    Granter->GnttabInterface = FdoAcquireGnttab(Fdo);
    Granter->BackendDomain = BackendDomain;

    Granter->Connected = TRUE;
    return STATUS_SUCCESS;
}

NTSTATUS
GranterStoreWrite(
    IN  PXENVBD_GRANTER             Granter,
    IN  PXENBUS_STORE_TRANSACTION   Transaction,
    IN  PCHAR                       FrontendPath
    )
{
    UNREFERENCED_PARAMETER(Granter);
    UNREFERENCED_PARAMETER(Transaction);
    UNREFERENCED_PARAMETER(FrontendPath);

    return STATUS_SUCCESS;
}

VOID
GranterEnable(
    IN  PXENVBD_GRANTER             Granter
    )
{
    ASSERT(Granter->Enabled == FALSE);

    Granter->Enabled = TRUE;
}

VOID
GranterDisable(
    IN  PXENVBD_GRANTER             Granter
    )
{
    ASSERT(Granter->Enabled == TRUE);

    Granter->Enabled = FALSE;
}

VOID
GranterDisconnect(
    IN  PXENVBD_GRANTER             Granter
    )
{
    ASSERT(Granter->Connected == TRUE);

    Granter->BackendDomain = 0;

    GNTTAB(Release, Granter->GnttabInterface);
    Granter->GnttabInterface = NULL;

    Granter->Connected = FALSE;
}

VOID
GranterDebugCallback(
    IN  PXENVBD_GRANTER             Granter,
    IN  PXENBUS_DEBUG_INTERFACE     Debug,
    IN  PXENBUS_DEBUG_CALLBACK      Callback
    )
{
    DEBUG(Printf, Debug, Callback,
        "GRANTER: %s %s\n", 
        Granter->Connected ? "CONNECTED" : "DISCONNECTED",
        Granter->Enabled ? "ENABLED" : "DISABLED");
}

NTSTATUS
GranterGet(
    IN  PXENVBD_GRANTER         Granter,
    IN  PFN_NUMBER              Pfn,
    IN  BOOLEAN                 ReadOnly,
    OUT PVOID                   *Handle
    )
{
    PXENBUS_GNTTAB_DESCRIPTOR   Descriptor;
    NTSTATUS                    status;

    Descriptor = GNTTAB(Get, 
                        Granter->GnttabInterface);

    status = STATUS_INSUFFICIENT_RESOURCES;
    if (Descriptor == NULL)
        goto fail1;

    status = GNTTAB(PermitForeignAccess, 
                    Granter->GnttabInterface, 
                    Descriptor, 
                    Granter->BackendDomain,
                    GNTTAB_ENTRY_FULL_PAGE,
                    Pfn,
                    ReadOnly);
    ASSERT(NT_SUCCESS(status));
    
    *Handle = Descriptor;
    return STATUS_SUCCESS;

fail1:
    return status;
}

VOID
GranterPut(
    IN  PXENVBD_GRANTER         Granter,
    IN  PVOID                   Handle
    )
{
    PXENBUS_GNTTAB_DESCRIPTOR   Descriptor = Handle;
    NTSTATUS                    status;

    status = GNTTAB(RevokeForeignAccess,
                    Granter->GnttabInterface,
                    Descriptor);
    ASSERT(NT_SUCCESS(status));

    GNTTAB(Put, Granter->GnttabInterface, Descriptor);
}

ULONG
GranterReference(
    IN  PXENVBD_GRANTER         Granter,
    IN  PVOID                   Handle
    )
{
    PXENBUS_GNTTAB_DESCRIPTOR   Descriptor = Handle;

    return GNTTAB(Reference, Granter->GnttabInterface, Descriptor);
}
