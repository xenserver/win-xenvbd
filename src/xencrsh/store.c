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

#pragma section(".store_section", nopage,read,write)
#include <wdm.h>
#include "..\..\include\xenvbd-storport.h"


#include "..\..\include\xen-version.h"
#include "..\..\include\xen\xen-compat.h"

#include "..\..\include\xen-types.h"
#include "..\..\include\xen-errno.h"
#include "..\..\include\xen-warnings.h"
#include "..\..\include\xen\memory.h"
#include "..\..\include\xen\event_channel.h"
#include "..\..\include\xen\grant_table.h"
#include "..\..\include\xen\io\xs_wire.h"
#include "..\..\include\xen\hvm\params.h"

#include "store.h"
#include "evtchn.h"
#include "hvm.h"
#include "austere.h"
#include "hypercall.h"

#include "..\..\include\xenvbd-ntstrsafe.h"
#include "log.h"
#include "assert.h"
#include "util.h"

#include <stdlib.h>

typedef struct _XENBUS_STORE_TRANSACTION {
    uint32_t    Id;
} XENBUS_STORE_TRANSACTION, *PXENBUS_STORE_TRANSACTION;

#define WATCH_SIGNATURE   'HCTW'

typedef enum _STORE_REQUEST_STATE {
    REQUEST_INVALID = 0,
    REQUEST_PREPARED,
    REQUEST_SUBMITTED,
    REQUEST_PENDING,
    REQUEST_COMPLETED
} STORE_REQUEST_STATE, *PSTORE_REQUEST_STATE;

typedef struct _STORE_SEGMENT {
    PCHAR                   Data;
    ULONG                   Offset;
    ULONG                   Length;
} STORE_SEGMENT, *PSTORE_SEGMENT;

enum {
    RESPONSE_HEADER_SEGMENT = 0,
    RESPONSE_PAYLOAD_SEGMENT,
    RESPONSE_SEGMENT_COUNT
};

typedef struct _STORE_RESPONSE {
    struct xsd_sockmsg  Header;
    STORE_SEGMENT       Segment[RESPONSE_SEGMENT_COUNT];
    ULONG               Index;
} STORE_RESPONSE, *PSTORE_RESPONSE;

#define REQUEST_SEGMENT_COUNT   8

typedef struct _STORE_REQUEST {
    volatile STORE_REQUEST_STATE State;
    struct xsd_sockmsg  Header;
    STORE_SEGMENT       Segment[REQUEST_SEGMENT_COUNT];
    ULONG               Count;
    ULONG               Index;
    LIST_ENTRY          ListEntry;
    STORE_RESPONSE      Response;
} STORE_REQUEST, *PSTORE_REQUEST;

typedef struct _XENBUS_STORE_CONTEXT {
    LIST_ENTRY                          SubmittedList;
    LIST_ENTRY                          PendingList;
    STORE_RESPONSE                      Response;
    evtchn_port_t                       Port;
    struct xenstore_domain_interface    *Shared;
} XENBUS_STORE_CONTEXT, *PXENBUS_STORE_CONTEXT;

static XENBUS_STORE_CONTEXT     StoreContext;

__declspec(allocate(".store_section"))
static UCHAR __StoreRingSection[2 * PAGE_SIZE];

C_ASSERT(sizeof (struct xenstore_domain_interface) <= PAGE_SIZE);

static VOID
StorePrepareRequest(
    OUT PSTORE_REQUEST              Request,
    IN  PXENBUS_STORE_TRANSACTION   Transaction OPTIONAL,
    IN  enum xsd_sockmsg_type       Type,
    IN  ...
    )
{
    static LONG                     Sequence;
    PSTORE_SEGMENT                  Segment;
    va_list                         Arguments;

    ASSERT(IsZeroMemory(Request, sizeof (STORE_REQUEST)));

    Request->Header.type = Type;
    Request->Header.tx_id = (Transaction != NULL) ? Transaction->Id : 0;
    Request->Header.req_id = InterlockedIncrement(&Sequence);
    Request->Header.len = 0;

    Request->Count = 0;
    Segment = &Request->Segment[Request->Count++];

    Segment->Data = (PCHAR)&Request->Header;
    Segment->Offset = 0;
    Segment->Length = sizeof (struct xsd_sockmsg);

    va_start(Arguments, Type);
    for (;;) {
        PCHAR   Data;
        ULONG   Length;

        Data = va_arg(Arguments, PCHAR);
        Length = va_arg(Arguments, ULONG);
        
        if (Data == NULL) {
            ASSERT3U(Length, ==, 0);
            break;
        }

        Segment = &Request->Segment[Request->Count++];
        ASSERT3U(Request->Count, <, REQUEST_SEGMENT_COUNT);

        Segment->Data = Data;
        Segment->Offset = 0;
        Segment->Length = Length;

        Request->Header.len += Segment->Length;
    }
    va_end(Arguments);

    Request->State = REQUEST_PREPARED;
}

#define MIN(_x, _y) (((_x) < (_y)) ? (_x) : (_y))

static FORCEINLINE ULONG
__StoreCopyToRing(
    IN  PCHAR                           Data,
    IN  ULONG                           Length
    )
{
    struct xenstore_domain_interface    *Shared;
    XENSTORE_RING_IDX                   cons;
    XENSTORE_RING_IDX                   prod;
    ULONG                               Offset;

    Shared = StoreContext.Shared;

    prod = Shared->req_prod;
    cons = Shared->req_cons;

    KeMemoryBarrier();

    Offset = 0;
    while (Length != 0) {
        ULONG   Available;
        ULONG   Index;
        ULONG   CopyLength;

        Available = cons + XENSTORE_RING_SIZE - prod;

        if (Available == 0)
            break;

        Index = MASK_XENSTORE_IDX(prod);

        CopyLength = MIN(Length, Available);
        CopyLength = MIN(CopyLength, XENSTORE_RING_SIZE - Index);

        RtlCopyMemory(&Shared->req[Index], Data + Offset, CopyLength);

        Offset += CopyLength;
        Length -= CopyLength;

        prod += CopyLength;
    }

    KeMemoryBarrier();

    Shared->req_prod = prod;
    _ReadWriteBarrier();

    return Offset;    
}

static FORCEINLINE NTSTATUS
StoreSendSegment(
    IN OUT  PSTORE_SEGMENT          Segment,
    IN OUT  PULONG                  Written
    )
{
    ULONG                           Copied;

    Copied = __StoreCopyToRing(Segment->Data + Segment->Offset,
                               Segment->Length - Segment->Offset);

    Segment->Offset += Copied;
    *Written += Copied;

    ASSERT3U(Segment->Offset, <=, Segment->Length);
    return (Segment->Offset == Segment->Length) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

static VOID
StoreSendRequests(
    IN OUT  PULONG                  Written
    )
{
    if (IsListEmpty(&StoreContext.SubmittedList))
        return;

    while (!IsListEmpty(&StoreContext.SubmittedList)) {
        PLIST_ENTRY             ListEntry;
        PSTORE_REQUEST   Request;

        ListEntry = StoreContext.SubmittedList.Flink;
        ASSERT3P(ListEntry, !=, &StoreContext.SubmittedList);

        Request = CONTAINING_RECORD(ListEntry, STORE_REQUEST, ListEntry);

        ASSERT3U(Request->State, ==, REQUEST_SUBMITTED);

        while (Request->Index < Request->Count) {
            NTSTATUS    status;

            status = StoreSendSegment(&Request->Segment[Request->Index],
                                      Written);
            if (!NT_SUCCESS(status))
                break;

            Request->Index++;
        }

        if (Request->Index < Request->Count)
            break;

        ListEntry = RemoveHeadList(&StoreContext.SubmittedList);
        ASSERT3P(ListEntry, ==, &Request->ListEntry);

        InsertTailList(&StoreContext.PendingList, &Request->ListEntry);
        Request->State = REQUEST_PENDING;
    }
}

static FORCEINLINE ULONG
__StoreCopyFromRing(
    IN  PCHAR                           Data,
    IN  ULONG                           Length
    )
{
    struct xenstore_domain_interface    *Shared;
    XENSTORE_RING_IDX                   cons;
    XENSTORE_RING_IDX                   prod;
    ULONG                               Offset;

    Shared = StoreContext.Shared;

    cons = Shared->rsp_cons;
    prod = Shared->rsp_prod;

    KeMemoryBarrier();

    Offset = 0;
    while (Length != 0) {
        ULONG   Available;
        ULONG   Index;
        ULONG   CopyLength;

        Available = prod - cons;

        if (Available == 0)
            break;

        Index = MASK_XENSTORE_IDX(cons);

        CopyLength = MIN(Length, Available);
        CopyLength = MIN(CopyLength, XENSTORE_RING_SIZE - Index);

        RtlCopyMemory(Data + Offset, &Shared->rsp[Index], CopyLength);

        Offset += CopyLength;
        Length -= CopyLength;

        cons += CopyLength;
    }

    KeMemoryBarrier();

    Shared->rsp_cons = cons;
    _ReadWriteBarrier();

    return Offset;    
}

static NTSTATUS
StoreReceiveSegment(
    IN OUT  PSTORE_SEGMENT          Segment,
    IN OUT  PULONG                  Read
    )
{
    ULONG                           Copied;

    Copied = __StoreCopyFromRing(Segment->Data + Segment->Offset,
                                 Segment->Length - Segment->Offset);
    if (Copied == 0)
        return STATUS_UNSUCCESSFUL;

    Segment->Offset += Copied;
    *Read += Copied;

    ASSERT3U(Segment->Offset, <=, Segment->Length);
    return (Segment->Offset == Segment->Length) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

static FORCEINLINE BOOLEAN
__StoreVerifyHeader(
    struct xsd_sockmsg  *Header
    )
{
    BOOLEAN             Valid;

    Valid = TRUE;

    if (Header->type != XS_DIRECTORY &&
        Header->type != XS_READ &&
        Header->type != XS_WATCH &&
        Header->type != XS_UNWATCH &&
        Header->type != XS_TRANSACTION_START &&
        Header->type != XS_TRANSACTION_END &&
        Header->type != XS_WRITE &&
        Header->type != XS_RM &&
        Header->type != XS_WATCH_EVENT &&
        Header->type != XS_ERROR) {
        LogError("UNRECOGNIZED TYPE 0x%08x\n", Header->type);
        Valid = FALSE;
    }

    if (Header->len >= XENSTORE_PAYLOAD_MAX) {
        LogError("ILLEGAL LENGTH 0x%08x\n", Header->len);
        Valid = FALSE;
    }

    return Valid;    
}

static FORCEINLINE NTSTATUS
StoreReceiveResponse(
    IN OUT  PULONG                  Read
    )
{
    PSTORE_RESPONSE                 Response = &StoreContext.Response;
    NTSTATUS                        status;

    if (Response->Segment[RESPONSE_PAYLOAD_SEGMENT].Data != NULL)
        goto payload;

    status = StoreReceiveSegment(&Response->Segment[RESPONSE_HEADER_SEGMENT], Read);
    if (!NT_SUCCESS(status))
        goto done;

    ASSERT(__StoreVerifyHeader(&Response->Header));
    
    if (Response->Header.len == 0)
        goto done;

    Response->Segment[RESPONSE_PAYLOAD_SEGMENT].Length = Response->Header.len;
    Response->Segment[RESPONSE_PAYLOAD_SEGMENT].Data = AustereAllocate(Response->Segment[RESPONSE_PAYLOAD_SEGMENT].Length);
    ASSERT(Response->Segment[RESPONSE_PAYLOAD_SEGMENT].Data != NULL);

payload:
    status = StoreReceiveSegment(&Response->Segment[RESPONSE_PAYLOAD_SEGMENT], Read);

done:
    return status;    
}

static FORCEINLINE PSTORE_REQUEST
StoreFindRequest(
    IN  uint32_t                req_id
    )
{
    PLIST_ENTRY                 ListEntry;
    PSTORE_REQUEST              Request;

    Request = NULL;
    for (ListEntry = StoreContext.PendingList.Flink;
         ListEntry != &StoreContext.PendingList;
         ListEntry = ListEntry->Flink) {

        Request = CONTAINING_RECORD(ListEntry, STORE_REQUEST, ListEntry);

        if (Request->Header.req_id == req_id)
            break;

        Request = NULL;
    }

    return Request;
}

static FORCEINLINE VOID
__StoreResetResponse(
    OUT PSTORE_RESPONSE  Response
    )
{
    PSTORE_SEGMENT       Segment;

    RtlZeroMemory(Response, sizeof (STORE_RESPONSE));

    Segment = &Response->Segment[RESPONSE_HEADER_SEGMENT];

    Segment->Data = (PCHAR)&Response->Header;
    Segment->Offset = 0;
    Segment->Length = sizeof (struct xsd_sockmsg);
}

static FORCEINLINE VOID
StoreProcessResponse(
    )
{
    PSTORE_RESPONSE             Response = &StoreContext.Response;
    PSTORE_REQUEST   Request;

    if (Response->Header.type != XS_WATCH_EVENT) {
        Request = StoreFindRequest(Response->Header.req_id);
        ASSERT(Request != NULL);
        ASSERT3U(Request->State, ==, REQUEST_PENDING);

        RemoveEntryList(&Request->ListEntry);

        Request->Response = StoreContext.Response;
        Request->State = REQUEST_COMPLETED;
        KeMemoryBarrierWithoutFence();

    }
    __StoreResetResponse(&StoreContext.Response);
}

VOID
StorePoll()
{
    ULONG                   Read;
    ULONG                   Written;
    NTSTATUS                status;
 
    do {
        Read = Written = 0;

        StoreSendRequests(&Written);
        if (Written != 0) {
            EventChannelSend(StoreContext.Port);
        }

        status = StoreReceiveResponse(&Read);
        if (NT_SUCCESS(status))
            StoreProcessResponse();

        if (Read != 0) {
            EventChannelSend(StoreContext.Port);
        }

    } while (Written != 0 || Read != 0);
}

#define STORE_PERIOD    50 // ms

static PSTORE_RESPONSE
StoreSubmitRequest(
    IN  PSTORE_REQUEST          Request
    )
{
    PSTORE_RESPONSE             Response;
    
    ASSERT3U(Request->State, ==, REQUEST_PREPARED);

    InsertTailList(&StoreContext.SubmittedList, &Request->ListEntry);

    for (Request->State = REQUEST_SUBMITTED; 
         Request->State != REQUEST_COMPLETED; 
         KeStallExecutionProcessor(STORE_PERIOD * 1000)) {
        StorePoll();
    }

    Response = &Request->Response;
    ASSERT(Response->Header.type == XS_ERROR ||
           Response->Header.type == Request->Header.type);

    RtlZeroMemory(Request, FIELD_OFFSET(STORE_REQUEST, Response));

    return Response;
}

static FORCEINLINE NTSTATUS
__StoreCheckResponse(
    IN  PSTORE_RESPONSE Response
    )
{
    NTSTATUS            status;

    status = STATUS_UNSUCCESSFUL;
    if (Response->Header.type == XS_ERROR) {
        ULONG   Index;

        for (Index = 0;
             Index < sizeof (xsd_errors) / sizeof (xsd_errors[0]);
             Index++) {
            struct xsd_errors   *Entry = &xsd_errors[Index];
            PCHAR               Error = Response->Segment[RESPONSE_PAYLOAD_SEGMENT].Data;
            ULONG               Length = Response->Segment[RESPONSE_PAYLOAD_SEGMENT].Length;
            
            if (strncmp(Error, Entry->errstring, Length) == 0) {
                LogTrace("%s\n", Error);
                ERRNO_TO_STATUS(Entry->errnum, status);
                break;
            }
        }

        goto fail1;
    }

    return STATUS_SUCCESS;

fail1:
    return status;
}

static FORCEINLINE ULONG
__StorePayloadLength(
    IN  PSTORE_RESPONSE Response
    )
{
    return Response->Segment[RESPONSE_PAYLOAD_SEGMENT].Length;
}

static FORCEINLINE PCHAR
__StorePayloadData(
    IN  PSTORE_RESPONSE Response
    )
{
    return Response->Segment[RESPONSE_PAYLOAD_SEGMENT].Data;
}

static FORCEINLINE VOID
StoreFreeResponse(
    IN  PSTORE_RESPONSE Response
    )
{
    PSTORE_SEGMENT      Segment;

    Segment = &Response->Segment[RESPONSE_PAYLOAD_SEGMENT];

    if (Segment->Length != 0)
        AustereFree(Segment->Data);

    RtlZeroMemory(Response, sizeof (STORE_RESPONSE));
}

NTSTATUS
StoreRead(
    IN  PXENBUS_STORE_TRANSACTION   Transaction OPTIONAL,
    IN  PCHAR                       Prefix OPTIONAL,
    IN  PCHAR                       Node,
    OUT PCHAR                       *Value
    )
{
    STORE_REQUEST                   Request;
    PSTORE_RESPONSE                 Response;
    ULONG                           Length;
    PCHAR                           Data;
    PCHAR                           Buffer;
    NTSTATUS                        status;

    LogTrace("===> %p %s %s\n", Transaction, Prefix ? Prefix : "NULL", Node);

    RtlZeroMemory(&Request, sizeof (STORE_REQUEST));

    if (Prefix == NULL) {
        StorePrepareRequest(&Request,
                            Transaction,
                            XS_READ,
                            Node, strlen(Node),
                            "", 1,
                            NULL, 0);
    } else {
        StorePrepareRequest(&Request,
                            Transaction,
                            XS_READ,
                            Prefix, strlen(Prefix),
                            "/", 1,
                            Node, strlen(Node),
                            "", 1,
                            NULL, 0);
    }

    Response = StoreSubmitRequest(&Request);

    status = __StoreCheckResponse(Response);
    if (!NT_SUCCESS(status))
        goto fail1;

    Length = __StorePayloadLength(Response);
    Buffer = AustereAllocate(Length + sizeof (CHAR));

    status = STATUS_NO_MEMORY;
    if (Buffer == NULL)
        goto fail2;

    Data = __StorePayloadData(Response);
    RtlCopyMemory(Buffer, Data, Length);

    StoreFreeResponse(Response);
    ASSERT(IsZeroMemory(&Request, sizeof (STORE_REQUEST)));

    *Value = Buffer;

    LogTrace("<=== %s\n", Buffer);
    return STATUS_SUCCESS;

fail2:
    LogError("fail2\n");

fail1:
    LogError("fail1 %s/%s (%08x)\n", Prefix, Node, status);

    StoreFreeResponse(Response);
    ASSERT(IsZeroMemory(&Request, sizeof (STORE_REQUEST)));

    return status;
}

NTSTATUS
StoreWrite(
    IN  PXENBUS_STORE_TRANSACTION   Transaction OPTIONAL,
    IN  PCHAR                       Prefix OPTIONAL,
    IN  PCHAR                       Node,
    IN  PCHAR                       Value
    )
{
    STORE_REQUEST                   Request;
    PSTORE_RESPONSE                 Response;
    NTSTATUS                        status;

    RtlZeroMemory(&Request, sizeof (STORE_REQUEST));

    if (Prefix == NULL) {
        StorePrepareRequest(&Request,
                            Transaction,
                            XS_WRITE,
                            Node, strlen(Node),
                            "", 1,
                            Value, strlen(Value),
                            NULL, 0);
    } else {
        StorePrepareRequest(&Request,
                            Transaction,
                            XS_WRITE,
                            Prefix, strlen(Prefix),
                            "/", 1,
                            Node, strlen(Node),
                            "", 1,
                            Value, strlen(Value),
                            NULL, 0);
    }

    Response = StoreSubmitRequest(&Request);

    status = __StoreCheckResponse(Response);
    if (!NT_SUCCESS(status))
        goto fail1;

    StoreFreeResponse(Response);
    ASSERT(IsZeroMemory(&Request, sizeof (STORE_REQUEST)));

    return STATUS_SUCCESS;

fail1:
    LogError("fail1 (%08x)\n", status);

    StoreFreeResponse(Response);
    ASSERT(IsZeroMemory(&Request, sizeof (STORE_REQUEST)));

    return status;
}

static FORCEINLINE NTSTATUS
StoreVPrintf(
    IN  PXENBUS_STORE_TRANSACTION   Transaction OPTIONAL,
    IN  PCHAR                       Prefix OPTIONAL,
    IN  PCHAR                       Node,
    IN  const CHAR                  *Format,
    IN  va_list                     Arguments
    )
{
    PCHAR                           Buffer;
    ULONG                           Length;
    NTSTATUS                        status;

    Length = 32;
    for (;;) {
        Buffer = AustereAllocate(Length);

        status = STATUS_NO_MEMORY;
        if (Buffer == NULL)
            goto fail1;

        status = RtlStringCbVPrintfA(Buffer,
                                     Length,
                                     Format,
                                     Arguments);
        if (NT_SUCCESS(status))
            break;

        if (status != STATUS_BUFFER_OVERFLOW)
            goto fail2;

        AustereFree(Buffer);
        Length <<= 1;

        ASSERT3U(Length, <=, 1024);
    }

    LogTrace("===> %p %s %s %s\n", Transaction, Prefix ? Prefix : "NULL", Node, Buffer);

    status = StoreWrite(Transaction,
                        Prefix,
                        Node,
                        Buffer);
    if (!NT_SUCCESS(status))
        goto fail3;

    AustereFree(Buffer);

    LogTrace("<===\n");
    return STATUS_SUCCESS;

fail3:
    LogError("fail3\n");

fail2:
    LogError("fail2\n");

    AustereFree(Buffer);

fail1:
    LogError("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
StorePrintf(
    IN  PXENBUS_STORE_TRANSACTION   Transaction OPTIONAL,
    IN  PCHAR                       Prefix OPTIONAL,
    IN  PCHAR                       Node,
    IN  const CHAR                  *Format,
    ...
    )
{
    va_list                         Arguments;
    NTSTATUS                        status;

    va_start(Arguments, Format);
    status = StoreVPrintf(Transaction,
                          Prefix,
                          Node,
                          Format,
                          Arguments);
    va_end(Arguments);

    return status;
}

NTSTATUS
StoreRemove(
    IN  PXENBUS_STORE_TRANSACTION   Transaction OPTIONAL,
    IN  PCHAR                       Prefix OPTIONAL,
    IN  PCHAR                       Node
    )
{
    STORE_REQUEST                   Request;
    PSTORE_RESPONSE                 Response;
    NTSTATUS                        status;

    LogTrace("===> %p %s %s\n", Transaction, Prefix ? Prefix : "NULL", Node);

    RtlZeroMemory(&Request, sizeof (STORE_REQUEST));

    if (Prefix == NULL) {
        StorePrepareRequest(&Request,
                            Transaction,
                            XS_RM,
                            Node, strlen(Node),
                            "", 1,
                            NULL, 0);
    } else {
        StorePrepareRequest(&Request,
                            Transaction,
                            XS_RM,
                            Prefix, strlen(Prefix),
                            "/", 1,
                            Node, strlen(Node),
                            "", 1,
                            NULL, 0);
    }

    Response = StoreSubmitRequest(&Request);

    status = __StoreCheckResponse(Response);
    if (!NT_SUCCESS(status))
        goto fail1;

    StoreFreeResponse(Response);
    ASSERT(IsZeroMemory(&Request, sizeof (STORE_REQUEST)));

    LogTrace("<===\n");
    return STATUS_SUCCESS;

fail1:
    LogError("fail1 (%08x)\n", status);

    StoreFreeResponse(Response);
    ASSERT(IsZeroMemory(&Request, sizeof (STORE_REQUEST)));

    return status;
}

NTSTATUS
StoreDirectory(
    IN  PXENBUS_STORE_TRANSACTION   Transaction OPTIONAL,
    IN  PCHAR                       Prefix OPTIONAL,
    IN  PCHAR                       Node,
    OUT PCHAR                       *Value
    )
{
    STORE_REQUEST                   Request;
    PSTORE_RESPONSE                 Response;
    ULONG                           Length;
    PCHAR                           Data;
    PCHAR                           Buffer;
    NTSTATUS                        status;

    LogTrace("===> %p %s %s\n", Transaction, Prefix ? Prefix : "NULL", Node);

    RtlZeroMemory(&Request, sizeof (STORE_REQUEST));

    if (Prefix == NULL) {
        StorePrepareRequest(&Request,
                            Transaction,
                            XS_DIRECTORY,
                            Node, strlen(Node),
                            "", 1,
                            NULL, 0);
    } else {
        StorePrepareRequest(&Request,
                            Transaction,
                            XS_DIRECTORY,
                            Prefix, strlen(Prefix),
                            "/", 1,
                            Node, strlen(Node),
                            "", 1,
                            NULL, 0);
    }

    Response = StoreSubmitRequest(&Request);

    status = __StoreCheckResponse(Response);
    if (!NT_SUCCESS(status))
        goto fail1;

    Length = __StorePayloadLength(Response);
    Buffer = AustereAllocate(Length + sizeof (CHAR));

    status = STATUS_NO_MEMORY;
    if (Buffer == NULL)
        goto fail2;

    Data = __StorePayloadData(Response);
    RtlCopyMemory(Buffer, Data, Length);

    StoreFreeResponse(Response);
    ASSERT(IsZeroMemory(&Request, sizeof (STORE_REQUEST)));

    *Value = Buffer;

    LogTrace("<===\n");
    return STATUS_SUCCESS;

fail2:
    LogError("fail2\n");

fail1:
    LogError("fail1 (%08x)\n", status);

    StoreFreeResponse(Response);
    ASSERT(IsZeroMemory(&Request, sizeof (STORE_REQUEST)));

    return status;
}

NTSTATUS
StoreTransactionStart(
    OUT PXENBUS_STORE_TRANSACTION   *Transaction
    )
{
    STORE_REQUEST                   Request;
    PSTORE_RESPONSE                 Response;
    NTSTATUS                        status;

    LogTrace("===>\n");

    *Transaction = AustereAllocate(sizeof (XENBUS_STORE_TRANSACTION));

    status = STATUS_NO_MEMORY;
    if (*Transaction == NULL)
        goto fail1;

    RtlZeroMemory(&Request, sizeof (STORE_REQUEST));

    StorePrepareRequest(&Request,
                        NULL,
                        XS_TRANSACTION_START,
                        "", 1,
                        NULL, 0);

    Response = StoreSubmitRequest(&Request);

    status = __StoreCheckResponse(Response);
    if (!NT_SUCCESS(status))
        goto fail2;

    (*Transaction)->Id = strtoul(__StorePayloadData(Response), NULL, 10);
    ASSERT((*Transaction)->Id != 0);

    StoreFreeResponse(Response);
    ASSERT(IsZeroMemory(&Request, sizeof (STORE_REQUEST)));

    LogTrace("<=== %p\n", *Transaction);
    return STATUS_SUCCESS;

fail2:
    LogError("fail2\n");

    StoreFreeResponse(Response);
    ASSERT(IsZeroMemory(&Request, sizeof (STORE_REQUEST)));

    ASSERT(IsZeroMemory(*Transaction, sizeof (XENBUS_STORE_TRANSACTION)));
    AustereFree(*Transaction);

fail1:
    LogError("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
StoreTransactionEnd(
    IN  PXENBUS_STORE_TRANSACTION   Transaction,
    IN  BOOLEAN                     Commit
    )
{
    STORE_REQUEST                   Request;
    PSTORE_RESPONSE                 Response;
    NTSTATUS                        status;

    RtlZeroMemory(&Request, sizeof (STORE_REQUEST));

    LogTrace("===> %p %s\n", Transaction, Commit ? "T" : "F");

    StorePrepareRequest(&Request,
                        Transaction,
                        XS_TRANSACTION_END,
                        (Commit) ? "T" : "F", 2,
                        NULL, 0);

    Response = StoreSubmitRequest(&Request);

    status = __StoreCheckResponse(Response);
    if (!NT_SUCCESS(status))
        goto fail1;

    StoreFreeResponse(Response);
    ASSERT(IsZeroMemory(&Request, sizeof (STORE_REQUEST)));

    Transaction->Id = 0;

    ASSERT(IsZeroMemory(Transaction, sizeof (XENBUS_STORE_TRANSACTION)));
    AustereFree(Transaction);

    LogTrace("<=== %p\n", Transaction);
    return STATUS_SUCCESS;

fail1:
    ASSERT3U(status, ==, STATUS_RETRY);

    StoreFreeResponse(Response);
    ASSERT(IsZeroMemory(&Request, sizeof (STORE_REQUEST)));

    return status;
}

extern PHYSICAL_ADDRESS MmGetPhysicalAddress(IN PVOID  BaseAddress);

static FORCEINLINE int
MemoryOp(
    IN  ULONG   Command,
    IN  PVOID   Argument
    )
{
    return Hypercall2(int, memory_op, Command, Argument);
}

static FORCEINLINE PVOID
__Round(
    IN  PVOID               Buffer,
    IN  ULONG               RoundTo
    )
{
    // round buffer to (normally PAGE_SIZE) boundary
    ULONG_PTR   Mask = (ULONG_PTR)RoundTo - 1;
    return (PVOID)(((ULONG_PTR)Buffer + Mask) & ~Mask);
}
NTSTATUS
StoreInitialize()
{
    ULONG_PTR                   Mfn;
    ULONG_PTR                   Port;
    PHYSICAL_ADDRESS            PhysAddr;
    NTSTATUS                    Status;
    struct xenstore_domain_interface*  StoreRingPtr;

    InitializeListHead(&StoreContext.SubmittedList);
    InitializeListHead(&StoreContext.PendingList);

    Status = HvmGetParameter(HVM_PARAM_STORE_EVTCHN, &Port);
    if (!NT_SUCCESS(Status))
        goto fail1;

    LogVerbose("HVM_PARAM_STORE_EVTCHN = %08x\n", (ULONG)Port);
    StoreContext.Port = (evtchn_port_t)Port;

    Status = HvmGetParameter(HVM_PARAM_STORE_PFN, &Mfn);
    if (!NT_SUCCESS(Status))
        goto fail2;
    
    LogVerbose("HVM_PARAM_STORE_PFN = %p\n", (PVOID)Mfn);
    StoreRingPtr = __Round(&__StoreRingSection[0], PAGE_SIZE);
    PhysAddr = MmGetPhysicalAddress(StoreRingPtr);

    StoreRingPtr->req_cons = 0x01020304;
    Status = HvmAddToPhysMap((PFN_NUMBER)(PhysAddr.QuadPart >> PAGE_SHIFT), 
                             XENMAPSPACE_gmfn, (ULONG)Mfn);
    if (NT_SUCCESS(Status)) {
        LogVerbose("Page Swizzled\n");
        if (StoreRingPtr->req_cons == 0x01020304)
            LogWarning("Page Swizzle to map store ring succeeded, but didn't actually do anything!\n");
    } else {
        LogVerbose("Page Swizzle failed\n");
        PhysAddr.QuadPart = (ULONGLONG)Mfn << PAGE_SHIFT;
        StoreRingPtr = MmMapIoSpace(PhysAddr, PAGE_SIZE, MmCached);
        if (StoreRingPtr == NULL)
            goto fail3;
    }

    LogVerbose("xenstore_domain_interface *: %p\n", StoreRingPtr);
    StoreContext.Shared = StoreRingPtr;

    __StoreResetResponse(&StoreContext.Response);

    LogVerbose("current store ring : (%d, %d, %d, %d)\n", 
                    StoreRingPtr->req_cons, StoreRingPtr->req_prod, 
                    StoreRingPtr->rsp_cons, StoreRingPtr->rsp_prod);
    RtlZeroMemory(StoreRingPtr, PAGE_SIZE);
    KeMemoryBarrier();
    EventChannelSend(StoreContext.Port);
    KeMemoryBarrier();
    LogVerbose("cleared store ring : (%d, %d, %d, %d)\n", 
                    StoreRingPtr->req_cons, StoreRingPtr->req_prod, 
                    StoreRingPtr->rsp_cons, StoreRingPtr->rsp_prod);

    return STATUS_SUCCESS;

fail3:
    LogError("fail3\n");

fail2:
    LogError("fail2\n");

fail1:
    LogError("fail1 (%08x)\n", Status);

    return Status;
}


VOID
StoreTerminate()
{
    RtlZeroMemory(&StoreContext, sizeof(XENBUS_STORE_CONTEXT));
}
