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

#include <wdm.h>
#include "..\..\include\xenvbd-storport.h"


#include "..\..\include\xen-version.h"
#include "..\..\include\xen\xen-compat.h"

#include "..\..\include\xen-types.h"
#include "..\..\include\xen-warnings.h"
#include "..\..\include\xen-errno.h"
#include "..\..\include\xen\memory.h"
#include "..\..\include\xen\event_channel.h"
#include "..\..\include\xen\grant_table.h"
#include "..\..\include\xen\hvm\params.h"
#include "..\..\include\xen\io\xs_wire.h"

#include "evtchn.h"
#include "hypercall.h"

#include "log.h"
#include "assert.h"

static FORCEINLINE LONG_PTR
EventChannelOp(
    IN  ULONG   Command,
    IN  PVOID   Argument
    )
{
    return Hypercall2(LONG_PTR, event_channel_op, Command, Argument);
}

NTSTATUS
EventChannelSend(
    IN  ULONG           LocalPort
    )
{
    struct evtchn_send  op;
    LONG_PTR            rc;
    NTSTATUS            status;

    op.port = LocalPort;

    rc = EventChannelOp(EVTCHNOP_send, &op);
    
    if (rc < 0) {
        ERRNO_TO_STATUS(-rc, status);
        goto fail1;
    }

    return STATUS_SUCCESS;

fail1:
    LogError("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
EventChannelAllocate(
    IN  ULONG           Domain,
    OUT PULONG          LocalPort
    )
{
    struct evtchn_alloc_unbound op;
    LONG_PTR                    rc;
    NTSTATUS                    status;

    op.dom = DOMID_SELF;
    op.remote_dom = (domid_t)Domain;

    rc = EventChannelOp(EVTCHNOP_alloc_unbound, &op);

    if (rc < 0) {
        ERRNO_TO_STATUS(-rc, status);
        goto fail1;
    }

    *LocalPort = op.port;
    
    return STATUS_SUCCESS;

fail1:
    LogError("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
EventChannelClose(
    IN  ULONG           LocalPort
    )
{
    struct evtchn_close op;
    LONG_PTR            rc;
    NTSTATUS            status;

    op.port = LocalPort;

    rc = EventChannelOp(EVTCHNOP_close, &op);

    if (rc < 0) {
        ERRNO_TO_STATUS(-rc, status);
        goto fail1;
    }

    return STATUS_SUCCESS;

fail1:
    LogError("fail1 (%08x)\n", status);

    return status;
}
